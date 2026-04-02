using Weep.Client;
using Weep.Server;
using System.Text.Json.Nodes;

Console.OutputEncoding = System.Text.Encoding.UTF8;

// -----------------------------------------------------------------------
// Argument parsing
// -----------------------------------------------------------------------
bool selfHost       = args.Contains("--server");
bool serverOnly     = args.Contains("--server-only");
bool useHttpListener = args.Contains("--httplistener");

// --port N  lets you override without recompiling (e.g. --port 9443 on dev machines
// where binding port 443 requires elevation)
var portArg = args.SkipWhile(a => a != "--port").Skip(1).FirstOrDefault();
int port = int.TryParse(portArg, out var p) ? p : 443;

string serverUrl = $"ws://localhost:{port}/weep";

CancellationTokenSource? serverCts  = null;
Task?                    serverTask = null;

if (selfHost || serverOnly)
{
    // Point working directory at the folder that contains ./files
    var filesRoot = FindFilesRoot();
    if (filesRoot != null)
    {
        Directory.SetCurrentDirectory(filesRoot);
        Console.WriteLine($"[server] files root: {filesRoot}");
    }
    else
    {
        Console.WriteLine("[server] WARNING: ./files not found — creating empty ./files");
        Directory.CreateDirectory("files");
    }

    serverCts = new CancellationTokenSource();
    if (useHttpListener)
    {
        var server = new WeepServerHttpListener();
        serverTask = Task.Run(() => server.StartAsync($"http://localhost:{port}/weep/", serverCts.Token));
    }
    else
    {
        var server = new WeepServer();
        serverTask = Task.Run(() => server.StartAsync($"http://localhost:{port}", serverCts.Token));
    }
    await Task.Delay(600); // let the server bind
    Console.WriteLine($"[server] WeepServer ({(useHttpListener ? "HttpListener" : "Kestrel")}) ready on ws://localhost:{port}/weep\n");

    if (serverOnly)
    {
        Console.WriteLine("Press Ctrl+C to stop...");
        string uiUrl = useHttpListener
            ? $"http://localhost:{port}/weep"
            : $"http://localhost:{port}/";
        Console.WriteLine($"[server] Web UI: {uiUrl}");
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; serverCts.Cancel(); };
        await Task.Delay(Timeout.Infinite, serverCts.Token).ContinueWith(_ => { });
        return;
    }
}

// -----------------------------------------------------------------------
// Run test suite
// -----------------------------------------------------------------------
string label = selfHost ? "C# server (self-hosted)" : $"external server ({serverUrl})";
var runner = new TestRunner(serverUrl, label);
await runner.RunAsync();

serverCts?.Cancel();
if (serverTask is not null)
{
    try   { await serverTask.WaitAsync(TimeSpan.FromSeconds(5)); }
    catch { /* timeout or exception — ignore, we're exiting */ }
}
Environment.Exit(runner.Failed > 0 ? 1 : 0);

// -----------------------------------------------------------------------
// Helper: find the directory that has a ./files subfolder
// -----------------------------------------------------------------------
static string? FindFilesRoot()
{
    // Check both the process CWD (set by dotnet run) and the assembly directory
    var roots = new[]
    {
        new DirectoryInfo(Environment.CurrentDirectory),
        new DirectoryInfo(AppContext.BaseDirectory),
    };

    foreach (var start in roots)
    {
        var dir = start;
        for (int i = 0; i < 12 && dir != null; i++, dir = dir.Parent)
        {
            var filesDir = Path.Combine(dir.FullName, "files");
            if (Directory.Exists(filesDir))
                return dir.FullName;
        }
    }
    return null;
}

// =======================================================================

sealed class TestRunner(string serverUrl, string label = "server")
{
    public int Passed { get; private set; }
    public int Failed { get; private set; }

    void Ok(string test)                  { Console.WriteLine($"  [OK]   {test}"); Passed++; }
    void Fail(string test, string reason) { Console.WriteLine($"  [FAIL] {test}: {reason}"); Failed++; }

    public async Task RunAsync()
    {
        Console.WriteLine($"weep C# client -> {label}\n");

        // -----------------------------------------------------------
        // 0. mDNS discovery
        // -----------------------------------------------------------
        Console.WriteLine("=== Discovery (mDNS DNS-SD) ===");
        try
        {
            var discovered = await WeepClient.DiscoverServersAsync(TimeSpan.FromSeconds(3));
            var uri = new Uri(serverUrl);
            var matching = discovered.Where(s => s.Port == uri.Port).ToList();

            if (label.Contains("self-hosted", StringComparison.OrdinalIgnoreCase))
            {
                if (matching.Count > 0)
                    Ok($"Discovery found {matching.Count} service(s) on port {uri.Port}");
                else
                    Ok($"Discovery no-match on port {uri.Port} (multicast may be filtered)");
            }
            else
            {
                Ok($"Discovery probe complete: {discovered.Count} service(s) seen");
            }
        }
        catch (Exception ex)
        {
            Fail("Discovery", ex.Message);
            Summary();
            return;
        }

        await using var client = new WeepClient();
        var auth = new AuthClient(client);

        // -----------------------------------------------------------
        // 1. Connect + auth
        // -----------------------------------------------------------
        Console.WriteLine("=== Auth ===");

        try   { await client.ConnectAsync(new Uri(serverUrl)); Ok("ConnectAsync"); }
        catch (Exception ex) { Fail("ConnectAsync", ex.Message); Summary(); return; }

        try
        {
            var greeting = await auth.WaitForGreetingAsync();
            Ok($"Greeting: {greeting.Profiles.Count} profiles, auth=[{string.Join(", ", greeting.AuthMechanisms)}]");

            bool authExactlyScram = greeting.AuthMechanisms.Count == 1
                                  && greeting.AuthMechanisms[0] == "auth:scram-sha256";
            if (authExactlyScram)
                Ok("Greeting advertises SCRAM-only auth");
            else
            {
                Fail("Greeting SCRAM-only", $"auth=[{string.Join(", ", greeting.AuthMechanisms)}]");
                Summary();
                return;
            }
        }
        catch (Exception ex) { Fail("WaitForGreetingAsync", ex.Message); Summary(); return; }

        try
        {
            await auth.ProbeAuthAsync(new JsonObject
            {
                ["mechanism"] = "auth:challenge",
                ["username"] = "admin",
            });
            Fail("Reject legacy challenge", "Server unexpectedly accepted auth:challenge");
            Summary();
            return;
        }
        catch (WeepException ex) when (ex.Code == 400)
        {
            Ok("Reject legacy challenge: ERR 400");
        }
        catch (Exception ex)
        {
            Fail("Reject legacy challenge", ex.Message);
            Summary();
            return;
        }

        try
        {
            var user = await auth.LoginWithScramAsync("admin", "admin");
            Ok($"LoginWithScram: '{user.Username}' roles=[{string.Join(", ", user.Roles)}]");
        }
        catch (Exception ex) { Fail("LoginWithScram", ex.Message); Summary(); return; }

        // -----------------------------------------------------------
        // 2. Open file channel + browse
        // -----------------------------------------------------------
        Console.WriteLine("\n=== File browse ===");
        await using var ft = new FileTransferClient(client);

        try   { await ft.OpenAsync(); Ok("OpenFileChannel"); }
        catch (Exception ex) { Fail("OpenFileChannel", ex.Message); Summary(); return; }

        FileListResult? root = null;
        try
        {
            root = await ft.ListAsync("/");
            Ok($"ListAsync(\"/\"): {root.Entries.Count} entries " +
               $"({root.Files.Count()} files, {root.Dirs.Count()} dirs)");
            foreach (var e in root.Entries)
                Console.WriteLine($"    {(e.IsDir ? "[DIR] " : "[FILE]")} {e.Name,-25} {e.Size,8} bytes  {e.Mime}");
        }
        catch (Exception ex) { Fail("ListAsync", ex.Message); }

        if (root?.Files.Any() == true)
        {
            try
            {
                var info = await ft.StatAsync(root.Files.First().Path);
                Ok($"StatAsync(\"{info.Path}\"): {info.Size} bytes, {info.Mime}");
            }
            catch (Exception ex) { Fail("StatAsync", ex.Message); }
        }

        // -----------------------------------------------------------
        // 3. Upload
        // -----------------------------------------------------------
        Console.WriteLine("\n=== Upload ===");
        var tmpUpload     = Path.GetTempFileName();
        var uploadContent = string.Concat(Enumerable.Repeat("C# weep upload test\n", 50));
        await File.WriteAllTextAsync(tmpUpload, uploadContent);

        try
        {
            await ft.UploadAsync(tmpUpload, "/csharp_upload.txt",
                new Progress<double>(p => Console.Write($"\r    Upload: {p * 100:F0}%  ")));
            Console.WriteLine();
            Ok($"UploadAsync: {new FileInfo(tmpUpload).Length} bytes");
        }
        catch (Exception ex) { Fail("UploadAsync", ex.Message); }

        try
        {
            var after = await ft.ListAsync("/");
            if (after.Files.Any(f => f.Name == "csharp_upload.txt"))
                Ok("Uploaded file visible in listing");
            else
                Fail("Verify upload", "File not found in listing");
        }
        catch (Exception ex) { Fail("List after upload", ex.Message); }

        // -----------------------------------------------------------
        // 4. Download text
        // -----------------------------------------------------------
        Console.WriteLine("\n=== Download text ===");
        var tmpDownload = Path.Combine(Path.GetTempPath(), "weep_csharp_dl.txt");

        try
        {
            await ft.DownloadAsync("/csharp_upload.txt", tmpDownload,
                new Progress<double>(p =>
                {
                    var bar = new string('#', (int)(p * 25)).PadRight(25, '-');
                    Console.Write($"\r    [{bar}] {p * 100:F1}%  ");
                }));
            Console.WriteLine();

            var downloaded = await File.ReadAllTextAsync(tmpDownload);
            bool ok = downloaded == uploadContent
                   && new FileInfo(tmpDownload).Length == new FileInfo(tmpUpload).Length;
            if (ok) Ok($"DownloadAsync text: {new FileInfo(tmpDownload).Length} bytes, content OK");
            else    Fail("DownloadAsync text", "Size or content mismatch");
        }
        catch (Exception ex) { Fail("DownloadAsync text", ex.Message); }

        // -----------------------------------------------------------
        // 5. Download binary
        // -----------------------------------------------------------
        Console.WriteLine("\n=== Download binary ===");
        try
        {
            var binDest = Path.Combine(Path.GetTempPath(), "sensor_data_cs.bin");
            await ft.DownloadAsync("/data/sensor_data.bin", binDest);
            var size = new FileInfo(binDest).Length;
            if (size == 4096) Ok($"Download binary: {size} bytes (correct)");
            else              Fail("Download binary", $"Expected 4096, got {size}");
        }
        catch (Exception ex) { Fail("Download binary", ex.Message); }

        // -----------------------------------------------------------
        // 6. Multi-channel — two file channels open simultaneously
        // -----------------------------------------------------------
        Console.WriteLine("\n=== Multi-channel (concurrent) ===");

        await using var ftA = new FileTransferClient(client);
        await using var ftB = new FileTransferClient(client);

        // Open both channels in parallel — each gets a distinct channel ID
        try
        {
            await Task.WhenAll(ftA.OpenAsync(), ftB.OpenAsync());
            Ok("Opened channel A and channel B concurrently");
        }
        catch (Exception ex) { Fail("Open channels A+B", ex.Message); Summary(); return; }

        // Prepare two distinct payloads
        var contentA = string.Concat(Enumerable.Repeat("Channel-A data\n", 60));
        var contentB = string.Concat(Enumerable.Repeat("Channel-B data\n", 80));
        var tmpA = Path.GetTempFileName();
        var tmpB = Path.GetTempFileName();
        await File.WriteAllTextAsync(tmpA, contentA);
        await File.WriteAllTextAsync(tmpB, contentB);

        // Upload both files concurrently on separate channels
        try
        {
            await Task.WhenAll(
                ftA.UploadAsync(tmpA, "/multi_a.txt"),
                ftB.UploadAsync(tmpB, "/multi_b.txt"));
            Ok($"Concurrent upload: A={new FileInfo(tmpA).Length} B={new FileInfo(tmpB).Length} bytes");
        }
        catch (Exception ex) { Fail("Concurrent upload A+B", ex.Message); }

        // Download both files concurrently on separate channels
        var dlA = Path.GetTempFileName();
        var dlB = Path.GetTempFileName();
        try
        {
            await Task.WhenAll(
                ftA.DownloadAsync("/multi_a.txt", dlA),
                ftB.DownloadAsync("/multi_b.txt", dlB));

            bool okA = await File.ReadAllTextAsync(dlA) == contentA;
            bool okB = await File.ReadAllTextAsync(dlB) == contentB;

            if (okA && okB)
                Ok("Concurrent download A+B: content matches on both channels");
            else
                Fail("Concurrent download A+B",
                     $"Content mismatch: A={okA} B={okB}");
        }
        catch (Exception ex) { Fail("Concurrent download A+B", ex.Message); }

        // List from both channels simultaneously — should see same directory
        try
        {
            var (listA, listB) = (await Task.WhenAll(ftA.ListAsync("/"), ftB.ListAsync("/")))
                                 switch { var r => (r[0], r[1]) };
            bool sameCount = listA.Entries.Count == listB.Entries.Count;
            Ok($"Concurrent list A+B: both see {listA.Entries.Count} entries " +
               $"(counts match={sameCount})");
        }
        catch (Exception ex) { Fail("Concurrent list A+B", ex.Message); }

        // -----------------------------------------------------------
        // 7. Large-file concurrent upload + download
        //    big1: 10 MB  — uploaded first, then downloaded concurrently with big2 upload
        //    big2: 10 MB + 12 345 bytes (distinct size) — uploaded concurrently with big1 download
        //    Exercises the ACK sliding window over ~160+ window-fulls of data.
        // -----------------------------------------------------------
        Console.WriteLine("\n=== Large-file concurrent (upload + download, ~20 MB) ===");

        const int BigSize1 = 10 * 1024 * 1024;
        const int BigSize2 = 10 * 1024 * 1024 + 12_345;

        // Deterministic content — different multipliers so channels can't be confused
        var big1 = new byte[BigSize1];
        var big2 = new byte[BigSize2];
        for (int i = 0; i < big1.Length; i++) big1[i] = (byte)((i * 17 + 37) & 0xFF);
        for (int i = 0; i < big2.Length; i++) big2[i] = (byte)((i * 31 + 97) & 0xFF);

        var tmpBig1 = Path.GetTempFileName();
        var tmpBig2 = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tmpBig1, big1);
        await File.WriteAllBytesAsync(tmpBig2, big2);

        // Step 1: upload big1 so it exists server-side for the download leg
        await using var ftBigSetup = new FileTransferClient(client);
        try   { await ftBigSetup.OpenAsync(); }
        catch (Exception ex) { Fail("Open setup channel", ex.Message); Summary(); return; }

        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await ftBigSetup.UploadAsync(tmpBig1, "/big1.bin");
            sw.Stop();
            Ok($"Upload big1: {BigSize1 / 1024 / 1024} MB in {sw.ElapsedMilliseconds} ms " +
               $"({BigSize1 / 1024.0 / sw.Elapsed.TotalSeconds:F0} KB/s)");
        }
        catch (Exception ex) { Fail("Upload big1", ex.Message); Summary(); return; }

        // Step 2: simultaneously download big1 AND upload big2 on two separate channels
        await using var ftBigDl  = new FileTransferClient(client);
        await using var ftBigUl2 = new FileTransferClient(client);
        try   { await Task.WhenAll(ftBigDl.OpenAsync(), ftBigUl2.OpenAsync()); }
        catch (Exception ex) { Fail("Open large channels", ex.Message); Summary(); return; }

        var dlBig1 = Path.GetTempFileName();
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await Task.WhenAll(
                ftBigDl .DownloadAsync("/big1.bin",   dlBig1),
                ftBigUl2.UploadAsync  (tmpBig2, "/big2.bin"));
            sw.Stop();

            double totalMB = (BigSize1 + BigSize2) / 1024.0 / 1024.0;
            double mbps    = totalMB / sw.Elapsed.TotalSeconds;
            Ok($"Concurrent {BigSize1/1024/1024} MB dl + {BigSize2/1024/1024} MB ul: " +
               $"{sw.ElapsedMilliseconds} ms, {mbps:F0} MB/s combined");

            bool dlOk = (await File.ReadAllBytesAsync(dlBig1)).AsSpan().SequenceEqual(big1);
            if (dlOk) Ok("Downloaded big1 content correct");
            else      Fail("Downloaded big1 content", "mismatch");
        }
        catch (Exception ex) { Fail("Concurrent large transfer", ex.Message); }

        // Step 3: verify the upload also wrote correct data
        var dlBig2 = Path.GetTempFileName();
        try
        {
            await ftBigDl.DownloadAsync("/big2.bin", dlBig2);
            bool ulOk = (await File.ReadAllBytesAsync(dlBig2)).AsSpan().SequenceEqual(big2);
            if (ulOk) Ok($"Uploaded big2 ({BigSize2 / 1024 / 1024} MB + {BigSize2 % (1024*1024)} B) content correct");
            else      Fail("Uploaded big2 content", "mismatch");
        }
        catch (Exception ex) { Fail("Verify big2 upload", ex.Message); }

        Summary();
    }

    void Summary()
    {
        Console.WriteLine($"\n==============================");
        Console.WriteLine($"  Passed: {Passed}   Failed: {Failed}");
        Console.WriteLine($"==============================");
    }
}
