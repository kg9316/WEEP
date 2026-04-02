using System.Text.Json.Nodes;
using Weep.Protocol;

namespace Weep.Client;

/// <summary>
/// Provides file upload and download over a weep:file channel.
///
/// Control messages (upload/download request) use JSON text frames.
/// File data uses binary WebSocket frames — no base64, zero overhead.
/// Both directions use sliding-window ACK flow control (SendWindow).
///
/// Usage:
///   var ft = new FileTransferClient(client);
///   await ft.OpenAsync();
///   await ft.UploadAsync("local.bin", "/files/remote.bin", progress);
///   await ft.DownloadAsync("/files/remote.bin", "local.bin", progress);
/// </summary>
public sealed class FileTransferClient : IChannelHandler, IAsyncDisposable
{
    private readonly int _preferredMaxChunkSize;
    private const    int WindowSize = 8;     // must match server-side WindowSize

    private readonly WeepClient _client;
    private          int          _channel = -1;
    private          int          _msgno   = 0;

    // RPY waiters: msgno → TCS<payload>
    private readonly Dictionary<int, TaskCompletionSource<JsonObject>> _pending = new();

    // Active upload send window (released by incoming ACK frames)
    private SendWindow? _uploadWindow;

    // One active download at a time on this channel.
    // Registered BEFORE the request is sent to avoid race between RPY
    // and incoming binary frames (server streams immediately after RPY).
    private DownloadState? _activeDownload;

    // Binary frames that arrived before DownloadState was wired up
    private readonly Queue<ReadOnlyMemory<byte>> _earlyFrames = new();

    public FileTransferClient(WeepClient client, int preferredMaxChunkSize = 65_536)
    {
        _client               = client;
        _preferredMaxChunkSize = preferredMaxChunkSize;
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    public async Task OpenAsync(CancellationToken ct = default)
    {
        _channel = await _client.OpenChannelAsync(Profiles.File, this, _preferredMaxChunkSize, ct);
        await Task.Delay(150, ct);
    }

    public async ValueTask DisposeAsync() =>
        await _client.CloseChannelAsync(_channel);

    // ------------------------------------------------------------------
    // Browse — list directory
    // ------------------------------------------------------------------

    public async Task<FileListResult> ListAsync(string path = "/",
                                                 CancellationToken ct = default)
    {
        var msgno = NextMsgno();
        var rpy   = await SendAndWaitAsync(msgno,
            new JsonObject { ["op"] = "list", ["path"] = path }, ct);

        var entries = rpy["entries"]?.AsArray()
            .Select(e => FileEntry.FromJson(e!.AsObject()))
            .ToList() ?? [];

        return new FileListResult(
            Path    : rpy["path"]?.GetValue<string>() ?? path,
            Entries : entries);
    }

    // ------------------------------------------------------------------
    // Browse — stat single entry
    // ------------------------------------------------------------------

    public async Task<FileEntry> StatAsync(string path,
                                            CancellationToken ct = default)
    {
        var msgno = NextMsgno();
        var rpy   = await SendAndWaitAsync(msgno,
            new JsonObject { ["op"] = "stat", ["path"] = path }, ct);
        return FileEntry.FromJson(rpy);
    }

    // ------------------------------------------------------------------
    // Upload  (request=JSON, data=binary)
    // ------------------------------------------------------------------

    public async Task UploadAsync(string localPath, string remotePath,
                                   IProgress<double>? progress = null,
                                   CancellationToken  ct       = default)
    {
        var fi    = new FileInfo(localPath);
        var msgno = NextMsgno();

        // 1. Request upload — server replies with transferId + negotiated chunkSize
        var uploadRpy = await SendAndWaitAsync(msgno, new JsonObject
        {
            ["op"]   = "upload",
            ["path"] = remotePath,
            ["size"] = fi.Length,
            ["mime"] = "application/octet-stream",
        }, ct);
        int chunkSize = uploadRpy["chunkSize"]?.GetValue<int>() ?? _preferredMaxChunkSize;

        // 2. Stream raw binary chunks with sliding-window flow control.
        // Pre-register the TCS for the final confirmation RPY *before* we start
        // streaming so it can't arrive and be dispatched while _pending[msgno] is
        // absent (SendAndWaitAsync removes it in its finally block).
        var confirmTcs = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = confirmTcs;

        var window = new SendWindow(WindowSize);
        _uploadWindow = window;

        long  bytesSent = 0;
        uint  seq       = 0;
        var   buffer    = new byte[chunkSize];

        try
        {
            using var fs = fi.OpenRead();
            while (true)
            {
                int  read  = await fs.ReadAsync(buffer, ct);
                bool final = read < chunkSize || fs.Position == fi.Length;

                // Wait for a send credit before transmitting the next frame.
                // The server releases one credit per ACK binary frame it sends back.
                await window.AcquireAsync(ct);

                var frame = BinaryFrame.Encode(_channel, seq, buffer.AsSpan(0, read), final);
                await _client.SendBinaryAsync(frame, SendPriority.Low, ct);

                bytesSent += read;
                progress?.Report((double)bytesSent / fi.Length);
                seq++;

                if (final) break;
            }
        }
        finally
        {
            _uploadWindow = null;
        }

        // 3. Wait for server confirmation (RPY {ok:true, bytesReceived})
        try
        {
            using var reg = ct.Register(() => confirmTcs.TrySetCanceled(ct));
            await confirmTcs.Task;
        }
        finally { _pending.Remove(msgno); }
    }

    // ------------------------------------------------------------------
    // Download  (request=JSON, data=binary)
    // ------------------------------------------------------------------

    public async Task DownloadAsync(string remotePath, string localPath,
                                     IProgress<double>? progress = null,
                                     CancellationToken  ct       = default)
    {
        var msgno = NextMsgno();

        // Pre-create the file so early binary frames aren't lost.
        Directory.CreateDirectory(Path.GetDirectoryName(localPath) ?? ".");
        var fs = File.Create(localPath);

        // Register state BEFORE sending the request — the server starts
        // streaming binary frames immediately after the RPY, and they may
        // arrive before we resume after awaiting SendAndWaitAsync.
        var state = new DownloadState(fs, totalSize: 0, progress, ct);
        _activeDownload = state;

        try
        {
            // Send request and wait for RPY {transferId, size}
            var rpy = await SendAndWaitAsync(msgno, new JsonObject
            {
                ["op"]   = "download",
                ["path"] = remotePath,
            }, ct);

            // Update size now that we know it
            state.SetTotalSize(rpy["size"]?.GetValue<long>() ?? 0L);

            // Drain any binary frames that arrived before we got here
            while (_earlyFrames.TryDequeue(out var early))
                DeliverFrame(early, state);

            await state.CompletionTask;
        }
        finally
        {
            _activeDownload = null;
            _earlyFrames.Clear();
            await fs.DisposeAsync();
        }
    }

    // ------------------------------------------------------------------
    // IChannelHandler — text frames (JSON control messages)
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
                        payload["code"]?.GetValue<int>()    ?? 500,
                        payload["message"]?.GetValue<string>() ?? "Server error"));
                break;

            case MsgType.NUL:
                _activeDownload?.Complete();
                break;
        }

        return Task.CompletedTask;
    }

    // ------------------------------------------------------------------
    // IChannelHandler — binary frames (file data)
    // ------------------------------------------------------------------

    public async Task HandleBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        var copy = frame.ToArray();   // copy before buffer is reused

        if (BinaryFrame.ReadIsAck(copy.AsSpan()))
        {
            // ACK from server for an upload frame — release one window credit
            var ackSeq = BinaryFrame.ReadSeq(copy.AsSpan());
            _uploadWindow?.Acknowledge(ackSeq);
            return;
        }

        // Download data frame — acknowledge it so the server's window advances
        var seq = BinaryFrame.ReadSeq(copy.AsSpan());
        await _client.SendBinaryAsync(BinaryFrame.EncodeAck(_channel, seq), SendPriority.High);

        if (_activeDownload is { } state)
            DeliverFrame(copy, state);
        else
            _earlyFrames.Enqueue(copy);   // arrived before DownloadAsync registered state
    }

    private static void DeliverFrame(ReadOnlyMemory<byte> frame, DownloadState state)
    {
        var data  = BinaryFrame.ReadData(frame).ToArray();
        var final = BinaryFrame.ReadFinal(frame.Span);
        state.Write(data, final);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private async Task<JsonObject> SendAndWaitAsync(int msgno, JsonObject payload,
                                                      CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;
        try
        {
            await SendJsonAsync(MsgType.MSG, msgno, payload);
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        finally { _pending.Remove(msgno); }
    }

    private async Task<JsonObject> WaitForRpyAsync(int msgno, CancellationToken ct)
    {
        if (_pending.TryGetValue(msgno, out var existing))
            return await existing.Task;

        var tcs = new TaskCompletionSource<JsonObject>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[msgno] = tcs;
        try
        {
            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }
        finally { _pending.Remove(msgno); }
    }

    private async Task SendJsonAsync(MsgType type, int msgno, JsonObject payload)
    {
        var node = new JsonObject
        {
            ["type"]    = type.ToString(),
            ["channel"] = _channel,
            ["msgno"]   = msgno,
            ["payload"] = payload,
        };
        await _client.SendRawAsync(node.ToJsonString());
    }

    private int NextMsgno() => Interlocked.Increment(ref _msgno);

    // ------------------------------------------------------------------
    // Download state
    // ------------------------------------------------------------------

    private sealed class DownloadState
    {
        private readonly Stream             _stream;
        private          long               _totalSize;
        private readonly IProgress<double>? _progress;
        private readonly TaskCompletionSource<bool> _tcs = new();
        private          long                       _bytesReceived;

        public Task CompletionTask => _tcs.Task;

        public DownloadState(Stream stream, long totalSize,
                             IProgress<double>? progress, CancellationToken ct)
        {
            _stream    = stream;
            _totalSize = totalSize;
            _progress  = progress;
            ct.Register(() => _tcs.TrySetCanceled(ct));
        }

        public void SetTotalSize(long size) => _totalSize = size;

        public void Write(byte[] data, bool final)
        {
            _stream.Write(data);
            _bytesReceived += data.Length;
            if (_totalSize > 0)
                _progress?.Report((double)_bytesReceived / _totalSize);
            if (final) Complete();
        }

        public void Complete() => _tcs.TrySetResult(true);
    }
}

public sealed class WeepException(int code, string message) : Exception(message)
{
    public int Code { get; } = code;
}

public sealed record FileEntry(
    string Name,
    string Path,
    string Type,      // "file" | "dir"
    long   Size,
    string Modified,  // ISO-8601
    string Mime)
{
    public bool IsFile => Type == "file";
    public bool IsDir  => Type == "dir";

    internal static FileEntry FromJson(JsonObject j) => new(
        Name     : j["name"]?.GetValue<string>()     ?? "",
        Path     : j["path"]?.GetValue<string>()     ?? "",
        Type     : j["type"]?.GetValue<string>()     ?? "file",
        Size     : j["size"]?.GetValue<long>()       ?? 0,
        Modified : j["modified"]?.GetValue<string>() ?? "",
        Mime     : j["mime"]?.GetValue<string>()     ?? "application/octet-stream");
}

public sealed record FileListResult(
    string                   Path,
    IReadOnlyList<FileEntry> Entries)
{
    public IEnumerable<FileEntry> Files => Entries.Where(e => e.IsFile);
    public IEnumerable<FileEntry> Dirs  => Entries.Where(e => e.IsDir);
}
