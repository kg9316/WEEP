using System.Buffers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Weep.Client;
using Weep.Server.Auth;
using Weep.Protocol;
using Weep.Server.Profiles;
using P = Weep.Protocol.Profiles;

namespace Weep.Server;

/// <summary>
/// One WebSocket connection = one ServerSession.
/// Mirrors Python's Session class.
/// </summary>
public sealed class ServerSession
{
    private readonly WebSocket                _ws;
    private readonly bool                     _requireAuth;
    private readonly Dictionary<int, object>  _channels   = new();
    // Tiebreaker (long) ensures FIFO order within the same priority level —
    // .NET PriorityQueue does NOT guarantee insertion order for equal-priority items.
    private readonly PriorityQueue<(byte[] data, WebSocketMessageType type), (int, long)> _sendQueue = new();
    private readonly SemaphoreSlim            _sendSignal  = new(0);
    private          long                     _enqueueOrder = 0;
    private          Auth.AuthResult?          _auth;
    private readonly string                    _serverNonce;
    private readonly ServerAuthHandler         _authHandler;

    public ServerSession(WebSocket ws, UserStore userStore, bool requireAuth = true)
    {
        _ws          = ws;
        _requireAuth = requireAuth;
        _serverNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16))
                             .ToLowerInvariant();
        _authHandler = new ServerAuthHandler(SendJsonAsync, userStore, _serverNonce);
    }

    public bool IsAuthenticated => _auth is not null || !_requireAuth;

    // ------------------------------------------------------------------
    // Run
    // ------------------------------------------------------------------

    public async Task RunAsync(CancellationToken ct)
    {
        var pump = Task.Run(() => SendPumpAsync(ct));

        await SendGreetingAsync();

        var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            while (!ct.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                int total = 0;
                ValueWebSocketReceiveResult result = default;
                try
                {
                    // Accumulate a complete WebSocket message. The .NET WebSocket layer
                    // may deliver a large frame in multiple ReceiveAsync calls
                    // (EndOfMessage=false) when the underlying TCP hasn't reassembled
                    // the full payload yet (e.g., frame > TCP MSS ~16 KB on loopback).
                    do
                    {
                        result = await _ws.ReceiveAsync(buffer.AsMemory(total), ct);
                        total += result.Count;
                    } while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close) break;
                }
                catch (OperationCanceledException) { break; }

                if (result.MessageType == WebSocketMessageType.Binary)
                    await DispatchBinaryAsync(buffer.AsMemory(0, total));
                else
                    await DispatchTextAsync(Encoding.UTF8.GetString(buffer, 0, total));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            if (_ws.State == WebSocketState.Open)
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", default);
        }
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------

    private async Task DispatchTextAsync(string json)
    {
        try
        {
            var node    = JsonNode.Parse(json)!.AsObject();
            var channel = node["channel"]?.GetValue<int>() ?? 0;
            var msgno   = node["msgno"]?.GetValue<int>()   ?? 0;
            var type    = node["type"]?.GetValue<string>() ?? "";
            var payload = node["payload"]?.AsObject() ?? new JsonObject();

            if (channel == 0)
            {
                await HandleManagementAsync(type, msgno, payload);
                return;
            }

            if (!IsAuthenticated)
            {
                await SendJsonAsync(MessageFactory.Error(channel, msgno, 401, "Not authenticated"));
                return;
            }

            await RouteToChannelAsync(channel, msgno, payload);
        }
        catch (Exception ex)
        {
            await SendJsonAsync(MessageFactory.Error(0, 0, 500, ex.Message));
        }
    }

    private async Task DispatchBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        var channel = BinaryFrame.ReadChannel(frame.Span);
        if (_channels.TryGetValue(channel, out var handler))
        {
            switch (handler)
            {
                case ServerFileProfile   fp: await fp.HandleBinaryAsync(frame); break;
                case ServerStreamProfile sp: await sp.HandleBinaryAsync(frame); break;
            }
        }
    }

    private async Task HandleManagementAsync(string type, int msgno, JsonObject payload)
    {
        if (type == MsgType.MSG.ToString() && payload["mechanism"] is not null)
        {
            var result = await _authHandler.HandleAsync(payload, msgno);
            if (result is not null)
                _auth = result;
            return;
        }

        if (type == "start")
        {
            if (!IsAuthenticated)
            {
                await SendJsonAsync(MessageFactory.Error(0, msgno, 401,
                    "Authenticate before opening channels"));
                return;
            }
            await OpenChannelAsync(msgno, payload);
            return;
        }

        if (type == "close")
        {
            var ch = payload["channel"]?.GetValue<int>();
            if (ch is not null) _channels.Remove(ch.Value);
            await SendJsonAsync(MessageFactory.Ok(msgno));
            return;
        }

        if (type == "clientInfo")
        {
            // Device allowlist check would go here (accept all if none configured)
            await SendJsonAsync(MessageFactory.Ok(msgno));
            return;
        }

        await SendJsonAsync(MessageFactory.Error(0, msgno, 400,
            $"Unknown management message: {type}"));
    }

    private async Task OpenChannelAsync(int msgno, JsonObject payload)
    {
        var channelId = payload["channel"]?.GetValue<int>();
        var profile   = payload["profile"]?.GetValue<string>();

        if (channelId is null || profile is null)
        {
            await SendJsonAsync(MessageFactory.Error(0, msgno, 400,
                "channel and profile required"));
            return;
        }

        if (_channels.ContainsKey(channelId.Value))
        {
            await SendJsonAsync(MessageFactory.Error(0, msgno, 409,
                $"Channel {channelId} already open"));
            return;
        }

        if (!HasPermission(profile))
        {
            await SendJsonAsync(MessageFactory.Error(0, msgno, 403,
                $"Insufficient roles for {profile}"));
            return;
        }

        var negotiatedChunkSize = Math.Min(
            payload["chunkSize"]?.GetValue<int>() ?? 65_536, 65_536);

        object? handler = profile switch
        {
            P.File   => new ServerFileProfile(channelId.Value, SendJsonAsync,
                            data => EnqueueBinary(data, SendPriority.Low),
                            ack  => EnqueueBinary(ack,  SendPriority.High),
                            negotiatedChunkSize),
            P.Stream => new ServerStreamProfile(channelId.Value, SendJsonAsync,
                            data => EnqueueBinary(data, SendPriority.Normal)),
            _ => null,
        };

        if (handler is null)
        {
            await SendJsonAsync(MessageFactory.Error(0, msgno, 501,
                $"Profile not supported: {profile}"));
            return;
        }

        _channels[channelId.Value] = handler;
        await SendJsonAsync(MessageFactory.Ok(msgno));
    }

    private async Task RouteToChannelAsync(int channel, int msgno, JsonObject payload)
    {
        if (!_channels.TryGetValue(channel, out var handler))
        {
            await SendJsonAsync(MessageFactory.Error(channel, msgno, 404,
                $"Channel {channel} not open"));
            return;
        }

        switch (handler)
        {
            case ServerFileProfile   fp: await fp.HandleAsync(payload, msgno);   break;
            case ServerStreamProfile sp: await sp.HandleAsync(payload, msgno);   break;
            default:
                await SendJsonAsync(MessageFactory.Error(channel, msgno, 500,
                    "No handler for channel"));
                break;
        }
    }

    // ------------------------------------------------------------------
    // Permission check
    // ------------------------------------------------------------------

    private bool HasPermission(string profile)
    {
        if (!_requireAuth) return true;
        var roles       = _auth?.Roles ?? [];
        bool isAdmin    = roles.Contains("admin");
        bool canWrite   = isAdmin || roles.Contains("write");
        bool canRead    = isAdmin || roles.Contains("read");
        bool needsWrite = profile is P.File or P.Stream
                                     or P.Write or P.Pub or P.Invoke;
        return needsWrite ? canWrite : canRead;
    }

    // ------------------------------------------------------------------
    // Send helpers
    // ------------------------------------------------------------------

    private async Task SendGreetingAsync()
    {
        var profiles = new JsonArray(
            P.File, P.Stream, P.Read, P.Write,
            P.Sub, P.Pub, P.Invoke, P.Query);
        var auth = new JsonArray("auth:challenge", "auth:scram-sha256");

        await SendJsonAsync(new JsonObject
        {
            ["type"]    = "greeting",
            ["channel"] = 0,
            ["msgno"]   = 0,
            ["payload"] = new JsonObject
            {
                ["profiles"]     = profiles,
                ["auth"]         = auth,
                ["version"]      = "1.1",
                ["productName"]  = "weep",
                ["maxChunkSize"] = 65_536,
                ["serverNonce"]  = _serverNonce,
                ["serverInfo"]   = new JsonObject
                {
                    ["brand"]    = "Weep",
                    ["model"]    = "WeepServer",
                    ["firmware"] = "1.1.0",
                },
            },
        }.ToJsonString());
    }

    private Task SendJsonAsync(string json)
    {
        Enqueue(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, SendPriority.High);
        return Task.CompletedTask;
    }

    private Task EnqueueBinary(byte[] data, SendPriority priority)
    {
        Enqueue(data, WebSocketMessageType.Binary, priority);
        return Task.CompletedTask;
    }

    private void Enqueue(byte[] data, WebSocketMessageType type, SendPriority priority)
    {
        var order = Interlocked.Increment(ref _enqueueOrder);
        lock (_sendQueue)
            _sendQueue.Enqueue((data, type), ((int)priority, order));
        _sendSignal.Release();
    }

    // Single background task — sole owner of ws.SendAsync.
    // Always picks the highest-priority frame next (High=0 before Normal=1 before Low=2).
    private async Task SendPumpAsync(CancellationToken ct)
    {
        try
        {
            while (await _sendSignal.WaitAsync(Timeout.Infinite, ct))
            {
                (byte[] data, WebSocketMessageType type) item;
                lock (_sendQueue)
                {
                    if (!_sendQueue.TryDequeue(out item, out _)) continue;
                }
                await _ws.SendAsync(item.data, item.type, endOfMessage: true, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (WebSocketException) { }
    }
}
