# WEEP

WEEP (WebSocket Event Exchange Protocol) is a multiplexed protocol for running multiple logical channels over one WebSocket connection.

WEEP is designed with two primary priorities:

- **Security first**: SCRAM-based authentication, TLS-ready deployment (`wss://`), and explicit auth before profile channels open.
- **High throughput under load**: binary data frames, channel multiplexing, and flow-control/queueing tuned for sustained transfer.

WEEP is also designed for unreliable and high-latency networks, including
satellite links, modem-class connections, and VPN paths, with per-channel flow
control and backpressure to keep sessions stable on poor lines.

## Easter vibe-coding note

Some parts of this project were refined during Easter holiday vibe-coding.
If you find an unusually clean queue implementation, that was probably coffee.
If you find a weird edge case already handled, that was probably chocolate.

This repository includes:

- C# reference implementation (server, client, examples)
- Python port (server, client, compatibility tests)
- Browser UI for testing file/query workflows
- ESP32-POE implementation (SCRAM auth, file/query profiles, mDNS discovery)
- LAN discovery with mDNS/DNS-SD and an HTTP discovery API

## Background: BEEP and FOX

WEEP is inspired by two earlier protocol families:

- **BEEP (RFC 3080/3081)**: a channel-multiplexed application protocol framework over TCP.
- **FOX (Niagara)**: a building-automation protocol that applies similar channel/profile ideas in real deployments.

Like BEEP and FOX, WEEP uses profile-driven channels and bidirectional communication.
Unlike them, WEEP is built directly on WebSocket so it works naturally with browsers,
HTTPS infrastructure, and modern reverse-proxy environments.

For a deeper comparison and protocol history, see `docs/protocol-spec.md` (section
"Differences from BEEP (RFC 3080)").

## Deployment model (port 443 + coexistence)

Production deployments should prefer **port 443** over TLS (`wss://`) so WEEP can run through standard HTTPS infrastructure.

WEEP is intentionally path-scoped under `/weep` so it can coexist with existing services on the same host and port:

- Existing app: `https://example.com/`
- WEEP UI + WS endpoint: `https://example.com/weep`
- WEEP discovery API: `https://example.com/weep/discover`

## Repository layout

- `csharp/` - .NET projects and libraries
- `python/` - Python implementation and tests
- `esp32-poe/` - PlatformIO ESP32-POE implementation (HTTP UI + WEEP WS server)
- `js/` - Browser UI (`index.html`)
- `docs/` - Detailed protocol and implementation documentation

## Quick start (C# server)

From repository root:

```powershell
dotnet build WEEP.sln
dotnet run --project csharp/Weep.TestRunner/Weep.TestRunner.csproj -- --server-only --port 9443
```

Endpoints:

- Web UI: `http://localhost:9443/weep`
- Discovery API: `http://localhost:9443/weep/discover`
- WebSocket endpoint: `ws://localhost:9443/weep`

## Quick start (Python server)

From repository root:

```powershell
python -m pip install -r python/requirements.txt
cd python
python -m weep.server --port 9566
```

Endpoints:

- Web UI: `http://localhost:9566/weep`
- Discovery API: `http://localhost:9566/weep/discover`
- WebSocket endpoint: `ws://localhost:9566/weep`

## Documentation

- Protocol specification: `docs/protocol-spec.md`
- C# usage: `csharp/README.md`
- Python usage: `python/README.md`
- ESP32 guide: `esp32-poe/README.md`

## TODO

- Pub/Sub on points
- Niagara WEEP service (Fox service clone)
- Niagara WEEP Network (Niagara Network clone)
