using System.Text.Json.Nodes;
using Weep.Client;
using Weep.Protocol;

namespace Weep.Server.Profiles;

/// <summary>
/// Server-side weep:file handler — mirrors Python FileProfile.
/// Upload: receives binary frames, writes to disk, sends per-frame ACK.
/// Download: reads from disk, sends binary frames within a sliding window.
/// </summary>
public sealed class ServerFileProfile(
    int                    channel,
    Func<string, Task>     sendJson,
    Func<byte[], Task>     sendBinary,
    Func<byte[], Task>     sendAck,      // high-priority sender for ACK frames
    int                    negotiatedChunkSize = 65_536,
    string                 basePath = "./files")
{
    private const int MaxChunkSize = 65_536;
    private const int WindowSize   = 8;     // max in-flight frames
    private readonly int _chunkSize = Math.Min(negotiatedChunkSize, 65_536);

    private UploadState? _upload;
    private SendWindow?  _downloadWindow;

    // ------------------------------------------------------------------
    // JSON control messages
    // ------------------------------------------------------------------

    public async Task HandleAsync(JsonObject payload, int msgno)
    {
        var op = payload["op"]?.GetValue<string>();
        switch (op)
        {
            case "upload":   await BeginUploadAsync(msgno, payload);   break;
            case "download": await BeginDownloadAsync(msgno, payload); break;
            case "list":     await ListAsync(msgno, payload);          break;
            case "stat":     await StatAsync(msgno, payload);          break;
            case "delete":   await DeleteAsync(msgno, payload);        break;
            default:
                await sendJson(MessageFactory.Error(channel, msgno, 400, $"Unknown op: {op}"));
                break;
        }
    }

    // ------------------------------------------------------------------
    // Binary frames (upload data)
    // ------------------------------------------------------------------

    public async Task HandleBinaryAsync(ReadOnlyMemory<byte> frame)
    {
        if (BinaryFrame.ReadIsAck(frame.Span))
        {
            // ACK from client for a download frame — release one window credit
            _downloadWindow?.Acknowledge(BinaryFrame.ReadSeq(frame.Span));
            return;
        }

        // Upload data frame
        if (_upload is null) return;

        var seq   = BinaryFrame.ReadSeq(frame.Span);
        var final = BinaryFrame.ReadFinal(frame.Span);
        var data  = BinaryFrame.ReadData(frame);

        if (seq != _upload.NextSeq)
        {
            await sendJson(MessageFactory.Error(channel, _upload.Msgno, 400,
                $"Expected seq {_upload.NextSeq}, got {seq}"));
            _upload.Stream.Dispose();
            _upload = null;
            return;
        }

        await _upload.Stream.WriteAsync(data);
        _upload.BytesReceived += data.Length;
        _upload.NextSeq++;

        // Acknowledge this frame so the client's send window advances
        await sendAck(BinaryFrame.EncodeAck(channel, seq));

        if (final)
        {
            await _upload.Stream.DisposeAsync();
            var received = _upload.BytesReceived;
            var msgno    = _upload.Msgno;
            _upload = null;

            await sendJson(new JsonObject
            {
                ["type"]    = MsgType.RPY.ToString(),
                ["channel"] = channel,
                ["msgno"]   = msgno,
                ["payload"] = new JsonObject { ["ok"] = true, ["bytesReceived"] = received },
            }.ToJsonString());
        }
    }

    // ------------------------------------------------------------------
    // Browse — list directory
    // ------------------------------------------------------------------

    private async Task ListAsync(int msgno, JsonObject payload)
    {
        var path    = payload["path"]?.GetValue<string>() ?? "/";
        var rel     = path.TrimStart('/', '\\');
        var dirInfo = new DirectoryInfo(Path.Combine(basePath, rel));

        if (!dirInfo.Exists)
        {
            await sendJson(MessageFactory.Error(channel, msgno, 404,
                $"Not a directory: {path}"));
            return;
        }

        var entries = new JsonArray();
        // Directories first, then files, both alphabetical
        foreach (var item in dirInfo
                     .EnumerateFileSystemInfos()
                     .OrderBy(e => e is FileInfo)
                     .ThenBy(e => e.Name))
        {
            entries.Add(EntryJson(item));
        }

        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["path"]    = ToVirtualPath(dirInfo.FullName),
                ["entries"] = entries,
            },
        }.ToJsonString());
    }

    // ------------------------------------------------------------------
    // Browse — stat single entry
    // ------------------------------------------------------------------

    private async Task StatAsync(int msgno, JsonObject payload)
    {
        var path = payload["path"]?.GetValue<string>() ?? "";
        var info = ResolvePath(path);

        FileSystemInfo fsi;
        if (Directory.Exists(info.FullName))
            fsi = new DirectoryInfo(info.FullName);
        else if (info.Exists)
            fsi = info;
        else
        {
            await sendJson(MessageFactory.Error(channel, msgno, 404,
                $"Not found: {path}"));
            return;
        }

        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = EntryJson(fsi),
        }.ToJsonString());
    }

    // ------------------------------------------------------------------
    // Delete file or directory (recursive)
    // ------------------------------------------------------------------

    private async Task DeleteAsync(int msgno, JsonObject payload)
    {
        var path = payload["path"]?.GetValue<string>() ?? "";
        if (string.IsNullOrWhiteSpace(path) || path is "/" or "\\")
        {
            await sendJson(MessageFactory.Error(channel, msgno, 400, "path required"));
            return;
        }

        var info = ResolvePath(path);
        var full = info.FullName;

        if (Directory.Exists(full))
        {
            Directory.Delete(full, recursive: true);
        }
        else if (File.Exists(full))
        {
            File.Delete(full);
        }
        else
        {
            await sendJson(MessageFactory.Error(channel, msgno, 404, $"Not found: {path}"));
            return;
        }

        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["ok"] = true,
                ["path"] = path,
            },
        }.ToJsonString());
    }

    // ------------------------------------------------------------------
    // Upload begin
    // ------------------------------------------------------------------

    private async Task BeginUploadAsync(int msgno, JsonObject payload)
    {
        var path = payload["path"]?.GetValue<string>() ?? "";
        if (string.IsNullOrEmpty(path))
        {
            await sendJson(MessageFactory.Error(channel, msgno, 400, "path required"));
            return;
        }

        var dest = ResolvePath(path);
        Directory.CreateDirectory(dest.DirectoryName!);

        _upload = new UploadState(msgno, File.Create(dest.FullName));

        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["transferId"] = Guid.NewGuid().ToString(),
                ["chunkSize"]  = _chunkSize,
            },
        }.ToJsonString());
    }

    // ------------------------------------------------------------------
    // Download
    // ------------------------------------------------------------------

    private async Task BeginDownloadAsync(int msgno, JsonObject payload)
    {
        var path = payload["path"]?.GetValue<string>() ?? "";
        var src  = ResolvePath(path);

        if (!src.Exists)
        {
            await sendJson(MessageFactory.Error(channel, msgno, 404, $"Not found: {path}"));
            return;
        }

        var transferId = Guid.NewGuid().ToString();
        await sendJson(new JsonObject
        {
            ["type"]    = MsgType.RPY.ToString(),
            ["channel"] = channel,
            ["msgno"]   = msgno,
            ["payload"] = new JsonObject
            {
                ["transferId"] = transferId,
                ["size"]       = src.Length,
                ["mime"]       = "application/octet-stream",
            },
        }.ToJsonString());

        _ = Task.Run(() => StreamFileAsync(msgno, src));
    }

    private async Task StreamFileAsync(int msgno, FileInfo src)
    {
        var window = new SendWindow(WindowSize);
        _downloadWindow = window;

        uint seq    = 0;
        var  buffer = new byte[_chunkSize];

        try
        {
            using var fs = src.OpenRead();
            while (true)
            {
                int  read  = await fs.ReadAsync(buffer);
                bool final = read < _chunkSize || fs.Position == fs.Length;
                // Block here if the client hasn't ACKed enough frames yet
                await window.AcquireAsync();
                await sendBinary(BinaryFrame.Encode(channel, seq++, buffer.AsSpan(0, read), final));
                if (final) break;
            }
        }
        finally
        {
            _downloadWindow = null;
        }
        // Binary frame with final=true signals end-of-download (no NUL needed:
        // NUL would race ahead of data in the priority queue).
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private FileInfo ResolvePath(string path)
    {
        var rel = path.TrimStart('/', '\\');
        return new FileInfo(Path.Combine(basePath, rel));
    }

    private string ToVirtualPath(string absolute)
    {
        var rel = Path.GetRelativePath(Path.GetFullPath(basePath), absolute)
                      .Replace('\\', '/');
        return rel == "." ? "/" : "/" + rel;
    }

    private JsonObject EntryJson(FileSystemInfo fsi)
    {
        bool isFile  = fsi is FileInfo;
        long size    = isFile ? ((FileInfo)fsi).Length : 0;
        var  entry   = new JsonObject
        {
            ["name"]     = fsi.Name,
            ["path"]     = ToVirtualPath(fsi.FullName),
            ["type"]     = isFile ? "file" : "dir",
            ["size"]     = size,
            ["modified"] = fsi.LastWriteTimeUtc.ToString("o"),
        };
        if (isFile)
            entry["mime"] = GuessMime(fsi.Name);
        return entry;
    }

    private static readonly Dictionary<string, string> MimeMap = new(StringComparer.OrdinalIgnoreCase)
    {
        [".json"]  = "application/json",
        [".xml"]   = "application/xml",
        [".txt"]   = "text/plain",
        [".csv"]   = "text/csv",
        [".html"]  = "text/html",
        [".pdf"]   = "application/pdf",
        [".zip"]   = "application/zip",
        [".gz"]    = "application/gzip",
        [".png"]   = "image/png",
        [".jpg"]   = "image/jpeg",
        [".jpeg"]  = "image/jpeg",
        [".bin"]   = "application/octet-stream",
        [".bog"]   = "application/x-weep",
    };

    private static string GuessMime(string filename) =>
        MimeMap.TryGetValue(Path.GetExtension(filename), out var mime)
            ? mime
            : "application/octet-stream";

    private sealed class UploadState(int msgno, FileStream stream)
    {
        public int        Msgno         { get; } = msgno;
        public FileStream Stream        { get; } = stream;
        public long       BytesReceived { get; set; }
        public uint       NextSeq       { get; set; }
    }
}
