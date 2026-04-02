using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Text.Json;
using Weep.Discovery;
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
    public bool      EnableMdnsDiscovery { get; set; } = true;
    public string?   DiscoveryInstanceName { get; set; }

    private WebApplication? _app;
    private WeepMdnsAdvertiser? _mdnsAdvertiser;

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

        _app.MapGet("/weep/discover", async ctx =>
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
            });

            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload);
            ctx.Response.ContentType = "application/json; charset=utf-8";
            ctx.Response.Headers["Cache-Control"] = "no-cache";
            await ctx.Response.Body.WriteAsync(bytes, ct);
        });

        // /weep serves the JS web UI for normal GET requests and
        // promotes to a WebSocket session for Upgrade requests.
        _app.Map("/weep", async ctx =>
        {
            if (!ctx.WebSockets.IsWebSocketRequest)
            {
                // Serve the browser UI
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
        Console.WriteLine($"[weep] Web UI + WS: {url}/weep");

        if (EnableMdnsDiscovery)
        {
            var uri = new Uri(url);
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
            await _app.RunAsync(ct);
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
        _app?.StopAsync().GetAwaiter().GetResult();
    }
}
