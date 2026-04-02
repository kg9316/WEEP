using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Weep.Protocol;

namespace Weep.Client;

/// <summary>
/// Bidirectional binary stream over a weep:stream channel.
///
/// Incoming data is buffered in a System.Threading.Channel (bounded)
/// and exposed as IAsyncEnumerable — natural backpressure: the producer
/// (network receive loop) blocks when the consumer is slow.
///
/// Usage:
///   var stream = new StreamChannel(client);
///   await stream.OpenAsync(mime: "application/octet-stream");
///
///   // Write to server
///   await stream.WriteAsync(data);
///   await stream.CloseWriteAsync();   // sends final frame
///
///   // Read from server
///   await foreach (var chunk in stream.ReadAllAsync(ct))
///       Process(chunk);
/// </summary>
public sealed class StreamChannel : IChannelHandler, IAsyncDisposable
{
    private readonly WeepClient              _client;
    private readonly Channel<ReadOnlyMemory<byte>> _rxChannel;
    private          int                       _channelId = -1;
    private          int                       _msgno     = 0;
    private          uint                      _txSeq     = 0;
    private          uint                      _rxSeqNext = 0;
    private          long                      _bytesTx   = 0;
    private          long                      _bytesRx   = 0;

    // RPY waiters for control messages
    private readonly Dictionary<int, TaskCompletionSource<JsonObject>> _pending = new();

    public StreamChannel(WeepClient client, int rxBufferChunks = 64)
    {
        _client    = client;
        _rxChannel = Channel.CreateBounded<ReadOnlyMemory<byte>>(
            new BoundedChannelOptions(rxBufferChunks)
            {
                FullMode     = BoundedChannelFullMode.Wait,  // backpressure
                SingleReader = true,
                SingleWriter = true,
            });
    }

    public long BytesSent     => _bytesTx;
    public long BytesReceived => _bytesRx;

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    public async Task OpenAsync(string mime = "application/octet-stream",
                                 IDictionary<string, string>? metadata = null,
                                 CancellationToken ct = default)
    {
        _channelId = await _client.OpenChannelAsync(Profiles.Stream, this, ct: ct);
        await Task.Delay(150, ct);  // allow server to confirm channel

        var payload = new JsonObject
        {
            ["op"]   = "open",
            ["mime"] = mime,
        };
        if (metadata is not null)
        {
            var meta = new JsonObject();
            foreach (var (k, v) in metadata)
                meta[k] = v;
            payload["metadata"] = meta;
        }

        await SendAndWaitAsync(payload, ct);
    }

    public async ValueTask DisposeAsync()
    {
        _rxChannel.Writer.TryComplete();
        await _client.CloseChannelAsync(_channelId);
    }

    // ------------------------------------------------------------------
    // Write (client → server)
    // ------------------------------------------------------------------

    public async Task WriteAsync(ReadOnlyMemory<byte> data,
                                  CancellationToken ct = default)
    {
        var frame = BinaryFrame.Encode(_channelId, _txSeq++, data.Span, final: false);
        _bytesTx += data.Length;
        await _client.SendBinaryAsync(frame, SendPriority.Normal, ct);
    }

    /// <summary>Send final frame to signal end of client → server stream.</summary>
    public async Task CloseWriteAsync(CancellationToken ct = default)
    {
        var frame = BinaryFrame.Encode(_channelId, _txSeq++,
                                        ReadOnlySpan<byte>.Empty, final: true);
        await _client.SendBinaryAsync(frame, SendPriority.Normal, ct);
    }

    // ------------------------------------------------------------------
    // Read (server → client) — IAsyncEnumerable with backpressure
    // ------------------------------------------------------------------

    public async IAsyncEnumerable<ReadOnlyMemory<byte>> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var chunk in _rxChannel.Reader.ReadAllAsync(ct))
            yield return chunk;
    }

    // ------------------------------------------------------------------
    // IChannelHandler — text frames (control)
    // ------------------------------------------------------------------

    public Task HandleAsync(string json)
    {
        var node    = JsonNode.Parse(json)!.AsObject();
        var typeStr = node["type"]!.GetValue<string>();
        var msgno   = node["msgno"]?.GetValue<int>() ?? -1;
        var payload = node["payload"]?.AsObject() ?? new JsonObject();

        if (!Enum.TryParse<MsgType>(typeStr, out var type)) return Task.CompletedTask;

        switch (type)
        {
            case MsgType.RPY:
                if (_pending.TryGetValue(msgno, out var tcs))
                    tcs.TrySetResult(payload);
                break;

            case MsgType.ERR:
                if (_pending.TryGetValue(msgno, out var errTcs))
                    errTcs.TrySetException(new WeepException(
                        payload["code"]?.GetValue<int>()       ?? 500,
                        payload["message"]?.GetValue<string>() ?? "Stream error"));
                break;

            case MsgType.NUL:
                // Server closed the stream
                _rxChannel.Writer.TryComplete();
                break;
        }

        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // IChannelHandler — binary frames (stream data)
    // ------------------------------------------------------------------

    public async Task HandleBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        var seq   = BinaryFrame.ReadSeq(frame.Span);
        var final = BinaryFrame.ReadFinal(frame.Span);
        var data  = BinaryFrame.ReadData(frame);

        if (seq != _rxSeqNext)
        {
            // Out-of-order frame — complete channel with error
            _rxChannel.Writer.TryComplete(
                new InvalidOperationException(
                    $"Out-of-order seq: expected {_rxSeqNext}, got {seq}"));
            return;
        }

        _rxSeqNext++;
        _bytesRx += data.Length;

        // Copy because the underlying buffer will be reused by the receive loop
        var copy = data.ToArray();
        await _rxChannel.Writer.WriteAsync(copy);

        if (final)
            _rxChannel.Writer.TryComplete();
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    private async Task<JsonObject> SendAndWaitAsync(JsonObject payload,
                                                     CancellationToken ct)
    {
        var msgno = Interlocked.Increment(ref _msgno);
        var tcs   = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;
        try
        {
            var node = new JsonObject
            {
                ["type"]    = MsgType.MSG.ToString(),
                ["channel"] = _channelId,
                ["msgno"]   = msgno,
                ["payload"] = payload,
            };
            await _client.SendRawAsync(node.ToJsonString(), ct);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        finally { _pending.Remove(msgno); }
    }
}
