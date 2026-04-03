using System.Net;
using System.Text;
using System.Text.Json;
using Weep.Discovery;
using Weep.Server.Auth;

namespace Weep.Server;

/// <summary>
/// WEEP WebSocket server — uses <see cref="HttpListener"/> (no ASP.NET Core dependency).
///
/// Simpler to embed and has no additional NuGet package requirements.
/// Suitable for development, LAN deployments, and scenarios where the
/// lighter footprint matters.
///
/// <b>Prefix format:</b> must include the path, e.g.
///   <c>"http://localhost:9443/weep/"</c>
///
/// <b>Windows note:</b> binding any port below 1024 requires elevation
/// (run as Administrator), or a prior <c>netsh http add urlacl</c> reservation.
///
/// To use this server instead of the default Kestrel version:
/// <code>
///   var server = new WeepServerHttpListener();
///   await server.StartAsync("http://localhost:9443/weep/", ct);
/// </code>
/// </summary>
public sealed class WeepServerHttpListener
{
    public UserStore UserStore   { get; } = new();
    public bool      RequireAuth { get; set; } = true;
    public bool      EnableMdnsDiscovery { get; set; } = true;
    public string?   DiscoveryInstanceName { get; set; }

    private HttpListener? _listener;
    private WeepMdnsAdvertiser? _mdnsAdvertiser;
    private string _htmlFile = Path.Combine(Environment.CurrentDirectory, "js", "index.html");
    private string _filesRoot = Path.GetFullPath("files");

    private static string ResolveRepoRoot()
    {
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
                var hasFiles = Directory.Exists(Path.Combine(dir.FullName, "files"));
                var hasJs = File.Exists(Path.Combine(dir.FullName, "js", "index.html"));
                if (hasFiles && hasJs)
                    return dir.FullName;
            }
        }

        return Environment.CurrentDirectory;
    }

    // ------------------------------------------------------------------
    // Start
    // ------------------------------------------------------------------

    public async Task StartAsync(string prefix = "http://localhost:9443/weep/",
                                  CancellationToken ct = default)
    {
        // Seed default accounts if the store is empty
        UserStore.AddUser("admin", "admin", "admin", "read", "write");
        UserStore.AddUser("guest", "guest", "read");

        var repoRoot = ResolveRepoRoot();
        _htmlFile = Path.Combine(repoRoot, "js", "index.html");
        _filesRoot = Path.Combine(repoRoot, "files");
        Directory.CreateDirectory(_filesRoot);

        // On Linux/Mac, use "+" instead of "localhost" to bind all interfaces,
        // e.g. "http://+:9443/weep/".  "localhost" binds loopback on all platforms.
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
        _listener.Start();

        // Stop the listener the moment cancellation is requested so that
        // the pending GetContextAsync() unblocks via HttpListenerException.
        using var reg = ct.Register(() => _listener?.Stop());

        Console.WriteLine($"[weep] HttpListener listening on {prefix}  (auth={RequireAuth})");

        if (EnableMdnsDiscovery)
        {
            var uri = new Uri(prefix);
            var instanceName = DiscoveryInstanceName
                ?? $"{Environment.MachineName}-weep";
            _mdnsAdvertiser = new WeepMdnsAdvertiser(
                instanceName,
                uri.Port,
                path: "/weep",
                version: "1.2",
                authMechanisms: ["auth:scram-sha256"]);
            _mdnsAdvertiser.Start();
            Console.WriteLine($"[weep] mDNS advertised as '{instanceName}._weep._tcp.local'");
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try   { ctx = await _listener.GetContextAsync(); }
                catch (HttpListenerException) { break; }

                // Each connection runs on its own Task so the accept loop stays free.
                _ = Task.Run(() => HandleClientAsync(ctx, ct), ct);
            }
        }
        finally
        {
            _mdnsAdvertiser?.Dispose();
            _mdnsAdvertiser = null;
        }
    }

    public void Stop()
    {
        _mdnsAdvertiser?.Dispose();
        _mdnsAdvertiser = null;
        _listener?.Stop();
    }

    // ------------------------------------------------------------------
    // Per-connection handling
    // ------------------------------------------------------------------

    private async Task HandleClientAsync(HttpListenerContext ctx,
                                          CancellationToken ct)
    {
        var reqPath = ctx.Request.Url?.AbsolutePath ?? "/";
        var isWeep  = reqPath == "/weep" || reqPath == "/weep/";

        // Plain HTTP — serve the JS web UI on GET /weep
        if (!ctx.Request.IsWebSocketRequest)
        {
            if (ctx.Request.HttpMethod == "GET" && reqPath == "/weep/discover")
            {
                var services = await Weep.Client.WeepClient.DiscoverServersAsync(TimeSpan.FromSeconds(1.5), ct);
                var payload = services.Select(s => new
                {
                    instanceName = s.InstanceName,
                    hostName = s.HostName,
                    port = s.Port,
                    path = s.Path,
                    version = s.Version,
                    authMechanisms = s.AuthMechanisms,
                    addresses = s.Addresses,
                    wsUrl = s.BuildWebSocketUrl(),
                }).ToList();

                var localPort = ctx.Request.LocalEndPoint?.Port ?? 0;
                if (!payload.Any(s => s.port == localPort && s.path == "/weep"))
                {
                    var selfAddresses = Dns.GetHostAddresses(Dns.GetHostName())
                        .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        .Select(ip => ip.ToString())
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    payload.Add(new
                    {
                        instanceName = (DiscoveryInstanceName ?? $"{Environment.MachineName}-weep") + "._weep._tcp.local",
                        hostName = Environment.MachineName,
                        port = localPort,
                        path = "/weep",
                        version = "1.2",
                        authMechanisms = (IReadOnlyList<string>)new[] { "auth:scram-sha256" },
                        addresses = (IReadOnlyList<string>)selfAddresses,
                        wsUrl = $"ws://{(selfAddresses.FirstOrDefault() ?? "localhost")}:{localPort}/weep",
                    });
                }

                var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
                ctx.Response.ContentType = "application/json; charset=utf-8";
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.AddHeader("Cache-Control", "no-cache");
                await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length, ct);
                ctx.Response.Close();
                return;
            }

            if (ctx.Request.HttpMethod == "GET" && isWeep)
            {
                if (File.Exists(_htmlFile))
                {
                    var html  = await File.ReadAllTextAsync(_htmlFile, ct);
                    var bytes = Encoding.UTF8.GetBytes(html);
                    ctx.Response.ContentType     = "text/html; charset=utf-8";
                    ctx.Response.ContentLength64 = bytes.Length;
                    ctx.Response.AddHeader("Cache-Control", "no-cache");
                    await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length, ct);
                    ctx.Response.Close();
                    return;
                }
            }
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
            return;
        }

        // Only accept WebSocket upgrades on /weep
        if (!isWeep)
        {
            ctx.Response.StatusCode = 404;
            ctx.Response.Close();
            return;
        }

        var wsCtx  = await ctx.AcceptWebSocketAsync(subProtocol: null);
        var remote = ctx.Request.RemoteEndPoint;
        Console.WriteLine($"[weep] Connected: {remote}");

        var session = new ServerSession(wsCtx.WebSocket, UserStore, RequireAuth, _filesRoot);
        try
        {
            await session.RunAsync(ct);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[weep] Session error ({remote}): {ex.Message}");
        }
        finally
        {
            Console.WriteLine($"[weep] Disconnected: {remote}");
        }
    }
}
