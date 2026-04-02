using System.Net;
using System.Text;
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

    private HttpListener? _listener;

    // ------------------------------------------------------------------
    // Start
    // ------------------------------------------------------------------

    public async Task StartAsync(string prefix = "http://localhost:9443/weep/",
                                  CancellationToken ct = default)
    {
        // Seed default accounts if the store is empty
        UserStore.AddUser("admin", "admin", "admin", "read", "write");
        UserStore.AddUser("guest", "guest", "read");

        // On Linux/Mac, use "+" instead of "localhost" to bind all interfaces,
        // e.g. "http://+:9443/weep/".  "localhost" binds loopback on all platforms.
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
        _listener.Start();

        // Stop the listener the moment cancellation is requested so that
        // the pending GetContextAsync() unblocks via HttpListenerException.
        using var reg = ct.Register(() => _listener?.Stop());

        Console.WriteLine($"[weep] HttpListener listening on {prefix}  (auth={RequireAuth})");

        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try   { ctx = await _listener.GetContextAsync(); }
            catch (HttpListenerException) { break; }

            // Each connection runs on its own Task so the accept loop stays free.
            _ = Task.Run(() => HandleClientAsync(ctx, ct), ct);
        }
    }

    public void Stop() => _listener?.Stop();

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
            if (ctx.Request.HttpMethod == "GET" && isWeep)
            {
                var htmlFile = Path.Combine(
                    Directory.GetCurrentDirectory(), "js", "index.html");
                if (File.Exists(htmlFile))
                {
                    var html  = await File.ReadAllTextAsync(htmlFile, ct);
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

        var session = new ServerSession(wsCtx.WebSocket, UserStore, RequireAuth);
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
