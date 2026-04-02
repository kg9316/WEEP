using System.Buffers;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Client;

/// <summary>
/// weep client — manages one WebSocket connection to a weep server.
///
/// Text frames  → JSON control messages routed by channel
/// Binary frames → raw file data routed by channel (7-byte header, see BinaryFrame)
/// </summary>
public sealed class WeepClient : IAsyncDisposable
{
    private readonly ClientWebSocket                             _ws       = new();
    private readonly ConcurrentDictionary<int, IChannelHandler> _channels = new();
    // Priority queue: lower number = higher priority (High=0, Normal=1, Low=2)
    // Tiebreaker (long) ensures FIFO order within the same priority level —
    // .NET PriorityQueue does NOT guarantee insertion order for equal-priority items.
    private readonly PriorityQueue<(byte[] data, WebSocketMessageType type), (int, long)> _sendQueue = new();
    private readonly SemaphoreSlim                    _sendSignal  = new(0);
    private          int                              _nextMsgno   = 1;
    private          int                              _nextChannel = 1;
    private          long                             _enqueueOrder = 0;
    private          CancellationTokenSource?         _cts;
    private          Task?                            _receiveLoop;
    private          Task?                            _sendPump;

    public event Action<IReadOnlyList<string>>? OnGreeting;
    public event Action<string>?                OnManagementMessage;

    public bool IsConnected      => _ws.State == WebSocketState.Open;
    /// <summary>Server's hard maximum chunk size, parsed from the greeting.</summary>
    public int  ServerMaxChunkSize { get; private set; } = 65_536;

    // ------------------------------------------------------------------
    // Connect / Disconnect
    // ------------------------------------------------------------------

    public async Task ConnectAsync(Uri serverUri, CancellationToken ct = default)
    {
        await _ws.ConnectAsync(serverUri, ct);
        _cts         = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_cts.Token), _cts.Token);
        _sendPump    = Task.Run(() => SendPumpAsync(_cts.Token), _cts.Token);
    }

    public async Task DisconnectAsync()
    {
        _cts?.Cancel();
        if (_sendPump is not null)
            await _sendPump.ConfigureAwait(false);
        if (_ws.State == WebSocketState.Open)
            await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", default);
        if (_receiveLoop is not null)
            await _receiveLoop.ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _ws.Dispose();
        _sendSignal.Dispose();
        _cts?.Dispose();
    }

    // ------------------------------------------------------------------
    // Channel management
    // ------------------------------------------------------------------

    public async Task<int> OpenChannelAsync(string profile, IChannelHandler handler,
                                             int preferredChunkSize = 65_536,
                                             CancellationToken ct   = default)
    {
        int channel = Interlocked.Increment(ref _nextChannel);
        _channels[channel] = handler;
        await SendRawAsync(MessageFactory.Start(channel, NextMsgno(), profile, preferredChunkSize), ct);
        return channel;
    }

    public async Task CloseChannelAsync(int channel, CancellationToken ct = default)
    {
        if (!_channels.TryRemove(channel, out _)) return;
        var msg = new JsonObject
        {
            ["type"]    = "close",
            ["channel"] = 0,
            ["msgno"]   = NextMsgno(),
            ["payload"] = new JsonObject { ["channel"] = channel },
        };
        await SendRawAsync(msg.ToJsonString(), ct);
    }

    // ------------------------------------------------------------------
    // Send — text (JSON)
    // ------------------------------------------------------------------

    public Task SendAsync(Message msg, CancellationToken ct = default) =>
        SendRawAsync(msg.Serialize(), ct);

    internal Task SendRawAsync(string json, CancellationToken ct = default)
    {
        Enqueue(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, SendPriority.High);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Send — binary frame
    // ------------------------------------------------------------------

    // priority defaults to Normal; FileTransferClient passes Low
    internal Task SendBinaryAsync(ReadOnlyMemory<byte> frame,
                                   SendPriority priority = SendPriority.Normal,
                                   CancellationToken ct  = default)
    {
        Enqueue(frame.ToArray(), WebSocketMessageType.Binary, priority);
        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // Priority queue helpers
    // ------------------------------------------------------------------

    private void Enqueue(byte[] data, WebSocketMessageType type, SendPriority priority)
    {
        var order = Interlocked.Increment(ref _enqueueOrder);
        lock (_sendQueue)
            _sendQueue.Enqueue((data, type), ((int)priority, order));
        _sendSignal.Release();
    }

    // ------------------------------------------------------------------
    // Send pump — single background task owns all ws.SendAsync calls.
    // Always dequeues the highest-priority frame next, so High-priority
    // frames (control, pub/sub) are never delayed by a Low-priority
    // file-transfer chunk sitting ahead in the queue.
    // ------------------------------------------------------------------

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

    // ------------------------------------------------------------------
    // Receive loop  (handles both text and binary frames)
    // ------------------------------------------------------------------

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        // Use a resizable buffer via ArrayPool to avoid large fixed allocations
        var buffer = ArrayPool<byte>.Shared.Rent(256 * 1024);
        try
        {
            while (!ct.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                try
                {
                    // Accumulate a complete WebSocket message. The .NET WebSocket layer
                    // may deliver a large frame across multiple ReceiveAsync calls
                    // (EndOfMessage=false) when the underlying TCP hasn't reassembled
                    // the full payload yet (e.g., frame > TCP MSS ~16 KB on loopback).
                    int total = 0;
                    ValueWebSocketReceiveResult result;
                    do
                    {
                        result = await _ws.ReceiveAsync(buffer.AsMemory(total), ct);
                        total += result.Count;
                    } while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close) break;

                    if (result.MessageType == WebSocketMessageType.Binary)
                        await DispatchBinaryAsync(buffer.AsMemory(0, total));
                    else
                        await DispatchTextAsync(Encoding.UTF8.GetString(buffer, 0, total));
                }
                catch (OperationCanceledException) { break; }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            // Cancel the session so blocked AcquireAsync / WaitAsync calls fail immediately
            // instead of waiting forever for ACKs that will never arrive.
            _cts?.Cancel();
        }
    }

    // ------------------------------------------------------------------
    // Dispatch — text
    // ------------------------------------------------------------------

    private async Task DispatchTextAsync(string json)
    {
        var node    = JsonNode.Parse(json)!.AsObject();
        var type    = node["type"]?.GetValue<string>();
        var channel = node["channel"]?.GetValue<int>() ?? 0;

        if (channel == 0)
        {
            OnManagementMessage?.Invoke(json);
            if (type == "greeting")
            {
                var greetingPayload = node["payload"]!;
                ServerMaxChunkSize  = greetingPayload["maxChunkSize"]?.GetValue<int>() ?? 65_536;
                var profiles = greetingPayload["profiles"]!.AsArray()
                    .Select(p => p!.GetValue<string>()).ToList();
                OnGreeting?.Invoke(profiles);
            }
            return;
        }

        if (_channels.TryGetValue(channel, out var handler))
            await handler.HandleAsync(json);
    }

    // ------------------------------------------------------------------
    // Dispatch — binary
    // ------------------------------------------------------------------

    private async Task DispatchBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        int channel = BinaryFrame.ReadChannel(frame.Span);
        if (_channels.TryGetValue(channel, out var handler))
            await handler.HandleBinaryAsync(frame);
    }

    internal int NextMsgno() => Interlocked.Increment(ref _nextMsgno);
}

// ------------------------------------------------------------------
// Binary frame helpers
// Binary layout (big-endian):
//   offset 0 : uint16  channel
//   offset 2 : uint32  seq
//   offset 6 : uint8   flags  (bit 0 = final)
//   offset 7+: data
// ------------------------------------------------------------------

public static class BinaryFrame
{
    public const int  HeaderSize = 7;
    public const byte FlagFinal  = 0x01;
    public const byte FlagAck    = 0x02;   // ACK frame: seq = acked seq, no data

    public static int    ReadChannel(ReadOnlySpan<byte> frame) =>
        (frame[0] << 8) | frame[1];

    public static uint   ReadSeq(ReadOnlySpan<byte> frame) =>
        ((uint)frame[2] << 24) | ((uint)frame[3] << 16) |
        ((uint)frame[4] << 8)  |  frame[5];

    public static bool   ReadFinal(ReadOnlySpan<byte> frame) =>
        (frame[6] & FlagFinal) != 0;

    public static bool   ReadIsAck(ReadOnlySpan<byte> frame) =>
        (frame[6] & FlagAck) != 0 && frame.Length == HeaderSize;

    public static ReadOnlyMemory<byte> ReadData(ReadOnlyMemory<byte> frame) =>
        frame[HeaderSize..];

    public static byte[] Encode(int channel, uint seq, ReadOnlySpan<byte> data,
                                 bool final)
    {
        var buf = new byte[HeaderSize + data.Length];
        buf[0] = (byte)(channel >> 8);
        buf[1] = (byte)(channel & 0xFF);
        buf[2] = (byte)(seq >> 24);
        buf[3] = (byte)(seq >> 16);
        buf[4] = (byte)(seq >> 8);
        buf[5] = (byte)(seq & 0xFF);
        buf[6] = final ? FlagFinal : (byte)0;
        data.CopyTo(buf.AsSpan(HeaderSize));
        return buf;
    }

    /// <summary>Encode a 7-byte ACK frame (no data payload).</summary>
    public static byte[] EncodeAck(int channel, uint ackSeq)
    {
        var buf = new byte[HeaderSize];
        buf[0] = (byte)(channel >> 8);
        buf[1] = (byte)(channel & 0xFF);
        buf[2] = (byte)(ackSeq >> 24);
        buf[3] = (byte)(ackSeq >> 16);
        buf[4] = (byte)(ackSeq >> 8);
        buf[5] = (byte)(ackSeq & 0xFF);
        buf[6] = FlagAck;
        return buf;
    }
}

// ------------------------------------------------------------------
// Channel handler interface
// ------------------------------------------------------------------

public interface IChannelHandler
{
    Task HandleAsync(string json);
    Task HandleBinaryAsync(ReadOnlyMemory<byte> frame) => Task.CompletedTask;
}

// ------------------------------------------------------------------
// Send priority
//   High   — control messages, auth, RPY/ERR, pub/sub events
//   Normal — stream data
//   Low    — file transfer chunks (large, latency-insensitive)
// ------------------------------------------------------------------

public enum SendPriority { High = 0, Normal = 1, Low = 2 }
