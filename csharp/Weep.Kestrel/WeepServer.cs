using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using System.Text;
using Weep.Server.Auth;

namespace Weep.Server;

/// <summary>
/// WEEP WebSocket server — hosted on ASP.NET Core Kestrel.
///
/// Usage:
///   var server = new WeepServer();
///   server.UserStore.AddUser("admin", "secret", "admin", "read", "write");
///   await server.StartAsync("http://localhost:9443");
///
/// For TLS in production, configure Kestrel with a certificate:
///   builder.WebHost.ConfigureKestrel(k =>
///       k.ListenAnyIP(443, o => o.UseHttps("cert.pfx", "password")));
/// </summary>
public sealed class WeepServer
{
    public UserStore UserStore   { get; } = new();
    public bool      RequireAuth { get; set; } = true;

    private WebApplication? _app;

    // ------------------------------------------------------------------
    // Start
    // ------------------------------------------------------------------

    public async Task StartAsync(string url = "http://localhost:9443",
                                  CancellationToken ct = default)
    {
        // Seed default accounts if the store is empty
        UserStore.AddUser("admin", "admin", "admin", "read", "write");
        UserStore.AddUser("guest", "guest", "read");

        var builder = WebApplication.CreateBuilder();

        // Suppress ASP.NET Core startup banner and reduce log noise
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.WebHost.SuppressStatusMessages(true);
        builder.WebHost.UseUrls(url);

        _app = builder.Build();
        _app.UseWebSockets(new WebSocketOptions
        {
            KeepAliveInterval = TimeSpan.FromSeconds(30),
        });

        // Serve the JS web UI on GET /
        _app.MapGet("/", async ctx =>
        {
            var htmlFile = Path.Combine(Directory.GetCurrentDirectory(), "js", "index.html");
            if (!File.Exists(htmlFile))
            {
                ctx.Response.StatusCode = 404;
                return;
            }
            var html  = await File.ReadAllTextAsync(htmlFile, ct);
            var bytes = Encoding.UTF8.GetBytes(html);
            ctx.Response.ContentType   = "text/html; charset=utf-8";
            ctx.Response.ContentLength = bytes.Length;
            ctx.Response.Headers["Cache-Control"] = "no-cache";
            await ctx.Response.Body.WriteAsync(bytes, ct);
        });

        // WEEP WebSocket endpoint at /weep
        _app.Map("/weep", async ctx =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                ctx.Response.StatusCode = 400;
                await ctx.Response.WriteAsync("Expected a WebSocket upgrade request.", ct);
                return;
            }

            var remote = ctx.Connection.RemoteIpAddress;
            Console.WriteLine($"[weep] Connected: {remote}");

            var ws      = await ctx.WebSockets.AcceptWebSocketAsync();
            var session = new ServerSession(ws, UserStore, RequireAuth);
            try
            {
                await session.RunAsync(ctx.RequestAborted);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[weep] Session error ({remote}): {ex.Message}");
            }
            finally
            {
                Console.WriteLine($"[weep] Disconnected: {remote}");
            }
        });

        Console.WriteLine($"[weep] Kestrel listening on {url}  (auth={RequireAuth})");
        Console.WriteLine($"[weep] Web UI:    {url}/");
        Console.WriteLine($"[weep] Endpoint:  {url}/weep");

        await _app.RunAsync(ct);
    }

    public void Stop() => _app?.StopAsync().GetAwaiter().GetResult();
}
