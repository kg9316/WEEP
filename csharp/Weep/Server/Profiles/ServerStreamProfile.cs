using System.Text.Json.Nodes;
using System.Threading.Channels;
using Weep.Client;
using Weep.Protocol;

namespace Weep.Server.Profiles;

/// <summary>
/// Server-side weep:stream handler — mirrors Python StreamProfile.
/// Exposes WriteAsync / ReadAllAsync for application code.
/// Bounded channel provides backpressure on the receive path.
/// </summary>
public sealed class ServerStreamProfile(
    int                channel,
    Func<string, Task> sendJson,
    Func<byte[], Task> sendBinary,
    int                rxBufferChunks = 64)
{
    private readonly Channel<ReadOnlyMemory<byte>> _rx =
        Channel.CreateBounded<ReadOnlyMemory<byte>>(
            new BoundedChannelOptions(rxBufferChunks)
            {
                FullMode     = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = true,
            });

    private uint _txSeq     = 0;
    private uint _rxSeqNext = 0;
    private long _bytesTx   = 0;
    private long _bytesRx   = 0;
    private int  _openMsgno = 0;

    public long BytesSent     => _bytesTx;
    public long BytesReceived => _bytesRx;

    // ------------------------------------------------------------------
    // JSON control
    // ------------------------------------------------------------------

    public async Task HandleAsync(JsonObject payload, int msgno)
    {
        var op = payload["op"]?.GetValue<string>();
        switch (op)
        {
            case "open":
                _openMsgno = msgno;
                await sendJson(new JsonObject
                {
                    ["type"]    = MsgType.RPY.ToString(),
                    ["channel"] = channel,
                    ["msgno"]   = msgno,
                    ["payload"] = new JsonObject { ["ok"] = true },
                }.ToJsonString());
                break;

            case "close":
                _rx.Writer.TryComplete();
                await sendJson(new JsonObject
                {
                    ["type"]    = MsgType.NUL.ToString(),
                    ["channel"] = channel,
                    ["msgno"]   = msgno,
                    ["payload"] = new JsonObject
                    {
                        ["bytesReceived"] = _bytesRx,
                        ["bytesSent"]     = _bytesTx,
                    },
                }.ToJsonString());
                break;

            default:
                await sendJson(MessageFactory.Error(channel, msgno, 400, $"Unknown op: {op}"));
                break;
        }
    }

    // ------------------------------------------------------------------
    // Binary frame reception (client → server data)
    // ------------------------------------------------------------------

    public async Task HandleBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        var seq   = BinaryFrame.ReadSeq(frame.Span);
        var final = BinaryFrame.ReadFinal(frame.Span);
        var data  = BinaryFrame.ReadData(frame);

        if (seq != _rxSeqNext)
        {
            _rx.Writer.TryComplete(
                new InvalidOperationException($"Out-of-order seq: expected {_rxSeqNext}, got {seq}"));
            return;
        }

        _rxSeqNext++;
        _bytesRx += data.Length;

        await _rx.Writer.WriteAsync(data.ToArray());

        if (final)
            _rx.Writer.TryComplete();
    }

    // ------------------------------------------------------------------
    // Write (server → client)
    // ------------------------------------------------------------------

    public async Task WriteAsync(ReadOnlyMemory<byte> data,
                                  CancellationToken ct = default)
    {
        var frame = BinaryFrame.Encode(channel, _txSeq++, data.Span, final: false);
        _bytesTx += data.Length;
        await sendBinary(frame);
    }

    public async Task CloseWriteAsync(CancellationToken ct = default)
    {
        var frame = BinaryFrame.Encode(channel, _txSeq++,
                                        ReadOnlySpan<byte>.Empty, final: true);
        await sendBinary(frame);
    }

    // ------------------------------------------------------------------
    // Read (server reads from client) — IAsyncEnumerable
    // ------------------------------------------------------------------

    public IAsyncEnumerable<ReadOnlyMemory<byte>> ReadAllAsync(
        CancellationToken ct = default) =>
        _rx.Reader.ReadAllAsync(ct);
}
