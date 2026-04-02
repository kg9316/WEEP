using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Client;

/// <summary>
/// Query client for weep:query profile.
/// Query text is treated as an opaque string. Server implementation decides
/// how to evaluate it; current server returns a fixed JSON array payload.
/// </summary>
public sealed class QueryClient : IChannelHandler, IAsyncDisposable
{
    private readonly WeepClient _client;
    private          int        _channel = -1;
    private          int        _msgno   = 0;

    private readonly Dictionary<int, TaskCompletionSource<JsonObject>> _pending = new();

    public QueryClient(WeepClient client)
    {
        _client = client;
    }

    public async Task OpenAsync(CancellationToken ct = default)
    {
        _channel = await _client.OpenChannelAsync(Profiles.Query, this, ct: ct);
        await Task.Delay(100, ct);
    }

    public async Task<JsonObject> QueryAsync(string q, CancellationToken ct = default)
    {
        var msgno = Interlocked.Increment(ref _msgno);
        var tcs   = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;

        var node = new JsonObject
        {
            ["type"]    = MsgType.MSG.ToString(),
            ["channel"] = _channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["op"] = "query",
                ["q"]  = q,
            },
        };

        try
        {
            await _client.SendRawAsync(node.ToJsonString(), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        finally
        {
            _pending.Remove(msgno);
        }
    }

    public Task HandleAsync(string json)
    {
        var node    = JsonNode.Parse(json)!.AsObject();
        var typeStr = node["type"]?.GetValue<string>() ?? "";
        var msgno   = node["msgno"]?.GetValue<int>() ?? -1;
        var payload = node["payload"]?.AsObject() ?? new JsonObject();

        if (!_pending.TryGetValue(msgno, out var tcs))
            return Task.CompletedTask;

        if (typeStr == MsgType.RPY.ToString())
            tcs.TrySetResult(payload);
        else if (typeStr == MsgType.ERR.ToString())
            tcs.TrySetException(new WeepException(
                payload["code"]?.GetValue<int>() ?? 500,
                payload["message"]?.GetValue<string>() ?? "Query error"));

        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync() =>
        await _client.CloseChannelAsync(_channel);
}
