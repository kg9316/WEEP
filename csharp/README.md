# WEEP C# Guide

This folder contains the .NET implementation of WEEP.

## Projects

- `Weep/` - core protocol library (client + server session + profiles)
- `Weep.Kestrel/` - ASP.NET Core host wrapper (`WeepServer`)
- `Weep.TestRunner/` - end-to-end runner and local host launcher

## Server options

### Kestrel server (`WeepServer`)

Use when you want ASP.NET Core hosting behavior.

```csharp
var server = new Weep.Server.WeepServer();
server.UserStore.AddUser("admin", "admin", "admin", "read", "write");
await server.StartAsync("http://localhost:9443", ct);
```

### HttpListener server (`WeepServerHttpListener`)

Use for minimal dependency hosting.

```csharp
var server = new Weep.Server.WeepServerHttpListener();
server.UserStore.AddUser("admin", "admin", "admin", "read", "write");
await server.StartAsync("http://localhost:9443/weep/", ct);
```

## Default HTTP/WebSocket surface

- `GET /weep` -> serves browser UI when hosted with the repo `js/index.html`
- `GET /weep` + `Upgrade: websocket` -> WEEP WebSocket session
- `GET /weep/discover` -> LAN discovery JSON

Root path (`/`) is intentionally left free so WEEP can coexist with other sites.

## Run locally

From repository root:

```powershell
dotnet build WEEP.sln
dotnet run --project csharp/Weep.TestRunner/Weep.TestRunner.csproj -- --server-only --port 9443
```

Open:

- `http://localhost:9443/weep`
- `http://localhost:9443/weep/discover`

## Discovery and protocol details

See `../docs/` for all project documentation.
Primary protocol spec: `../docs/protocol-spec.md`.
