# WEEP Protocol Specification

**WebSocket Event Exchange Protocol**

Version 1.2 — April 2026

| Version | Date | Change |
|---------|------|--------|
| 1.2 | April 2026 | `auth:scram-sha256` mutual auth (PBKDF2 + HMAC), `clientInfo` / device allowlist, SCRAM-only auth advertisement |
| 1.1 | April 2026 | Chunk-size negotiation; `preferredChunkSize` in `start`; server-advertised `maxChunkSize` |
| 1.0 | March 2026 | Initial release |

---

## Table of Contents

1. [Overview](#1-overview)
2. [Transport Layer](#2-transport-layer)
3. [Channel Model](#3-channel-model)
4. [JSON Message Envelope](#4-json-message-envelope)
5. [Connection Lifecycle](#5-connection-lifecycle)
6. [Authentication](#6-authentication) — `auth:scram-sha256` (PBKDF2 + HMAC), device identity, allowlist
7. [Binary Frame Format](#7-binary-frame-format)
8. [Send Priority Queue](#8-send-priority-queue)
9. [Flow Control — Sliding Window ACK](#9-flow-control--sliding-window-ack)
10. [Profile: weep:file](#10-profile-weepfile)
11. [Profile: weep:stream](#11-profile-weepstream)
12. [Planned Profiles](#12-planned-profiles)
13. [Error Handling](#13-error-handling)
14. [Implementation Checklist](#14-implementation-checklist)
15. [Arduino and ESP32 Implementation Notes](#15-arduino-and-esp32-implementation-notes)
16. [Differences from BEEP (RFC 3080)](#16-differences-from-beep-rfc-3080)

---

## 1. Overview

weep is a lightweight **multiplexed, bidirectional messaging protocol** that
runs over a single WebSocket connection. Multiple independent logical *channels*
share the connection simultaneously — one channel might transfer a file while
another streams sensor readings in real time, without either blocking the other.

**Inspiration:** BEEP (RFC 3080), but redesigned to use WebSocket instead of
raw TCP, JSON instead of XML, and native binary frames instead of base64.

**Design goals:**

| Goal | Mechanism |
|------|-----------|
| Many logical channels over one TCP connection | Integer channel IDs on every message |
| Human-readable control plane | UTF-8 JSON text frames |
| Zero-overhead bulk transfer | Raw binary WebSocket frames |
| Auth before data | Channel 0 mandatory auth before any profile channel opens |
| **Mutual authentication** | Both client and server prove identity; neither trusts the other blindly |
| **Device identity & allowlisting** | Client declares brand/model/firmware in greeting; server can reject unknown devices |
| Real-time channels never starved by bulk transfers | Priority send queue (High → Normal → Low) |
| Embeddable on MCUs (ESP32) | 7-byte binary header; no dynamic memory required for send pump |
| High-latency and slow-receiver support | Per-channel sliding-window ACK (W = 8 frames) |

**Reference implementation:** C# (.NET 8). A Python port exists. ESP32 port is
feasible.

---

## 2. Transport Layer

weep runs exclusively over **WebSocket (RFC 6455)**, which itself runs over
TCP (plain `ws://`) or TLS (`wss://`). TLS is handled entirely by the WebSocket
layer — weep does not negotiate or manage TLS itself.

### 2.1 WebSocket frame types used

| WebSocket frame type | weep usage |
|----------------------|--------------|
| **Text** (UTF-8)     | All JSON control messages |
| **Binary**           | File chunks, stream data, ACK frames |
| **Close**            | Normal WebSocket connection close |
| Ping / Pong          | Not used by weep; handled by WebSocket layer |

### 2.2 Concurrent send restriction

WebSocket **prohibits calling `send` concurrently** — only one send may be in
progress at a time per connection. Because weep has many channels that may
want to send simultaneously, both sides use a **single background pump task**
that is the sole caller of the WebSocket send function. All other code enqueues
frames into a priority queue and returns immediately without blocking.

See [Section 8](#8-send-priority-queue) for the priority queue algorithm.

### 2.3 Multiple simultaneous clients

A WEEP server handles **any number of clients connected at the same time**.
Each accepted WebSocket connection gets its own independent session running in
a separate async task:

```
WeepServer
  ├── Session A  (client 192.168.1.10)   ── channel 0 (auth) ── channel 1 (file) ──►
  ├── Session B  (client 192.168.1.11)   ── channel 0 (auth) ── channel 1 (file) ── channel 2 (stream) ──►
  ├── Session C  (client 10.0.0.5)       ── channel 0 (auth) ──►
  └── …
```

Sessions are **completely isolated**:
- Each session has its own send queue, sliding-window credits, auth state, and
  set of open channels.
- A slow or misbehaving client cannot block or delay another client.
- Channel IDs (1, 2, 3…) are scoped per session — channel 1 in session A is
  unrelated to channel 1 in session B.
- The user store is shared and read-only during operation; all sessions read
  from it concurrently without locking (it is a `ConcurrentDictionary`).

**Practical limits and scaling:** The server is limited only by OS resources
(file descriptors, memory). There is no hard-coded connection cap.

The C# reference implementation ships two separate server classes in two
separate NuGet/project packages so that consumers only take the dependencies
they need:

| Package | Class | SDK | Suitable for |
|---------|-------|-----|--------------|
| `Weep` | `WeepServerHttpListener` | `Microsoft.NET.Sdk` (plain) | Development, LAN, embedded tools |
| `Weep.Kestrel` | `WeepServer` | `Microsoft.NET.Sdk.Web` (ASP.NET Core) | Production, cloud, public-facing |

Both classes expose the same public API (`UserStore`, `RequireAuth`,
`StartAsync()`, `Stop()`) and use the same `ServerSession` underneath —
switching is a one-line change in the host program.

---

#### `WeepServerHttpListener` — built-in, no extra dependencies

`WeepServerHttpListener` uses `System.Net.HttpListener`, which is part of the
.NET base class library. No NuGet packages are needed beyond .NET itself.

```csharp
var server = new WeepServerHttpListener();
server.UserStore.AddUser("admin", "secret", "admin", "read", "write");
await server.StartAsync("http://localhost:9443/weep/", ct);
```

Note: the prefix **must include the path** (`/weep/`). HttpListener routes by
prefix string, not by middleware.

**Limitations of `HttpListener`:**

| Limitation | Detail |
|------------|--------|
| **Windows elevation** | Binding any port requires the process to run as Administrator, *or* a prior URL reservation: `netsh http add urlacl url=http://+:9443/weep/ user=DOMAIN\user`. On Linux/macOS, ports below 1024 require `CAP_NET_BIND_SERVICE` or `sudo`. |
| **No native TLS** | `HttpListener` cannot serve `https://` / `wss://` on its own. You need a TLS terminating reverse proxy (nginx, Caddy, IIS) in front of it, or replace it with Kestrel. |
| **No HTTP/2** | Only HTTP/1.1 is supported. WebSocket upgrades work, but HTTP/2 multiplexing does not. |
| **Single-path routing** | Routes by prefix string only. Hosting WEEP alongside other HTTP services on the same port requires a reverse proxy. |
| **No middleware pipeline** | No compression, no header transformations, no rate limiting — you implement everything manually. |
| **Windows-only graceful shutdown** | On Windows, `Stop()` is clean. On Linux, cancellation relies on the `GetContextAsync()` throwing `HttpListenerException`, which is not always immediate. |
| **Build size (self-contained)** | `Weep.dll` alone is ~130 KB. Because no extra framework is pulled in, a self-contained publish stays small (~325 KB output folder before trimming). |

**When to use it:** local development, CLI tools, embedded controllers,
automated test harnesses, any scenario where installing ASP.NET Core runtime
is undesirable or where the client count stays in the tens.

---

#### `WeepServer` — ASP.NET Core Kestrel

`WeepServer` uses the `Microsoft.NET.Sdk.Web` SDK and ASP.NET Core's Kestrel
web server. It lives in the separate `Weep.Kestrel` project so that users of
`Weep` alone do not pull in ASP.NET Core.

```csharp
// No path in the URL — Kestrel maps paths via middleware
var server = new WeepServer();
server.UserStore.AddUser("admin", "secret", "admin", "read", "write");
await server.StartAsync("http://localhost:9443", ct);
// or for TLS: "https://localhost:443"
```

**Advantages over HttpListener:**

| Feature | Detail |
|---------|--------|
| **No elevation needed** | Kestrel binds ports without Administrator rights on Windows or Linux. |
| **Native TLS / `wss://`** | Configure with `UseHttps("cert.pfx", "password")` — no reverse proxy required. |
| **I/O completion ports / epoll** | Kestrel uses the most efficient async I/O primitives on each OS, giving higher throughput under load. |
| **Middleware pipeline** | Add rate limiting, request logging, authentication middleware, CORS, and more with a single `.Use…()` call. |
| **Reverse-proxy aware** | Reads `X-Forwarded-For` / `X-Forwarded-Proto` natively, so it works correctly behind nginx or a cloud load balancer. |
| **HTTP/2 support** | Optional; allows future protocol evolution without changing the WebSocket layer. |
| **Build size (self-contained)** | `Weep.Kestrel.dll` is only ~12 KB, but a self-contained publish bundles the entire ASP.NET Core runtime (~30–40 MB before trimming). In a framework-dependent deployment this cost is zero — the runtime is shared on the machine. |

**When to use it:** production services, public-facing deployments, any
scenario requiring TLS without a proxy, or where you already depend on
ASP.NET Core.

---

`ServerSession` is transport-agnostic in both cases — it only needs a
`System.Net.WebSockets.WebSocket` instance. Switching host requires no
protocol changes.

### 2.4 Default ports

| Scheme | Default port | Notes |
|--------|--------------|-------|
| `ws://`  | 9443 | Development / LAN (port 443 requires OS elevation) |
| `wss://` | 443  | Production; TLS required |

The protocol endpoint is always served at the **path `/weep`**
(`ws://host:9443/weep`). This allows WEEP to coexist with other HTTP
services behind the same reverse proxy or on the same port.

These are not fixed — the server may listen on any port.

---

## 3. Channel Model

Every JSON message and every binary frame carries a **channel** integer field
that identifies which logical channel it belongs to.

| Channel number | Role |
|----------------|------|
| `0`            | Management channel — always open; handles greeting, auth, channel open/close |
| `1` … `65535`  | Application channels — one profile per channel per lifetime |

### 3.1 Channel lifetime

1. Client sends `start` on channel 0 to open a new channel.
2. Server replies `ok` to confirm, or `ERR` to refuse.
3. Application messages flow on the new channel.
4. Either side may initiate close with `close` on channel 0.
5. Server replies `ok`.
6. The channel number may **not** be reused within the same WebSocket connection.

### 3.2 Channel ID assignment

The **client** assigns channel IDs. Rules:
- Channel IDs start at `1` and increment by `1` for each new channel.
- IDs must be unique within the connection lifetime (never reuse a closed channel's ID).
- Channel `0` is always reserved for management.

In the reference implementation, the client maintains a counter initialized to
`1` and atomically increments it each time `OpenChannelAsync` is called. The
returned value is the new channel's ID.

### 3.3 Profile

A **profile** is a string URI that names the message contract for a channel.
Defined profiles:

| Profile string | Purpose |
|----------------|---------|
| `"weep:file"`   | File upload, download, directory browse |
| `"weep:stream"` | Bidirectional real-time binary stream |
| `"weep:read"`   | Read a named value (planned) |
| `"weep:write"`  | Write a named value (planned) |
| `"weep:sub"`    | Subscribe to value changes (planned) |
| `"weep:pub"`    | Publish value change events (planned) |
| `"weep:invoke"` | Remote procedure call (planned) |
| `"weep:query"`  | Structured data query (planned) |

---

### 3.4 Query Profile (Server Handler Map)

The query payload is intentionally treated as an opaque string so application
code can use SQL, BQL-like syntax, or any custom DSL without protocol changes.

**Request shape (channel opened with `weep:query`):**

```json
{
  "type": "MSG",
  "channel": 2,
  "msgno": 11,
  "payload": {
    "op": "query",
    "q": "select * from station where kind='point'"
  }
}
```

**Current default response shape (stub):**

```json
{
  "type": "RPY",
  "channel": 2,
  "msgno": 11,
  "payload": {
    "resultType": "array",
    "query": "select * from station where kind='point'",
    "items": [
      {"name": "row1", "value": 123},
      {"name": "row2", "value": 456},
      {"name": "row3", "value": 789}
    ]
  }
}
```

#### C# server: function call path for incoming query

1. `ServerSession.DispatchTextAsync(...)`
2. `ServerSession.RouteToChannelAsync(...)`
3. `ServerQueryProfile.HandleAsync(payload, msgno)`

Files:
- `csharp/Weep/Server/ServerSession.cs`
- `csharp/Weep/Server/Profiles/ServerQueryProfile.cs`

#### Python server: function call path for incoming query

1. `ServerSession._dispatch_text(...)`
2. `ServerSession._open_channel(...)` opened a `QueryProfile`
3. `QueryProfile.handle_text(payload, msgno)`

File:
- `python/weep/server.py`

#### Where to implement your real query backend

- C#: replace fixed `items` generation inside `ServerQueryProfile.HandleAsync`.
- Python: replace fixed `items` generation inside `QueryProfile.handle_text`.

Keep the wire contract stable (`op`, `q` in; JSON payload out) so JS/C#/Python
clients continue to work unchanged.

---

## 4. JSON Message Envelope

Every **text** WebSocket frame contains exactly one JSON object with this
structure:

```json
{
  "type":    "<string>",
  "channel": <integer>,
  "msgno":   <integer>,
  "payload": { ... }
}
```

All four fields are always present. There are no optional top-level fields
(except in future extensions).

### 4.1 Field definitions

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Message type identifier (see table below) |
| `channel` | integer ≥ 0 | Channel this message belongs to |
| `msgno` | integer ≥ 0 | Message sequence number for correlation |
| `payload` | object | Message-specific data; never `null` (use `{}` if empty) |

### 4.2 `msgno` rules

`msgno` is a **per-sender** counter that starts at `1` and increments by `1`
for each new outgoing message that expects a reply (`MSG`, `start`). The
counter is shared across all channels — channel 1 and channel 2 messages from
the same sender advance the same counter.

**Replies** (`RPY`, `ERR`, `ANS`, `NUL`, `ok`) echo the `msgno` of the
request they answer. This allows the sender to match replies to pending requests.

Implementations must treat the pair `(channel, msgno)` as the correlation key
because both sides use the same `msgno` space but on different channels.

### 4.3 Message types

#### Application message types (uppercase, on any channel ≥ 0)

| `type` | Direction | Meaning |
|--------|-----------|---------|
| `"MSG"` | requester → responder | A request. Expects exactly one `RPY` or `ERR` reply. |
| `"RPY"` | responder → requester | Successful reply to a `MSG`. |
| `"ERR"` | responder → requester | Error reply to a `MSG`. Always contains `code` and `message` in payload. |
| `"ANS"` | responder → requester | One of many answers (streaming reply). Zero or more `ANS` followed by one `NUL`. |
| `"NUL"` | responder → requester | Terminates an `ANS` stream, or signals a stream channel has been closed. |

#### Management message types (lowercase, channel 0 only)

| `type` | Direction | Meaning |
|--------|-----------|---------|
| `"greeting"` | server → client | First message after connect; lists available profiles, auth mechanisms, and server identity. |
| `"clientInfo"` | client → server | Client's response to greeting — declares its own identity (brand, model, firmware). |
| `"start"` | client → server | Open a new application channel. |
| `"close"` | client → server | Close an existing application channel. |
| `"ok"` | server → client | Generic success reply to `start`, `close`, or `clientInfo`. |

### 4.4 Example messages

**Greeting (server → client, channel 0):**
```json
{
  "type":    "greeting",
  "channel": 0,
  "msgno":   0,
  "payload": {
    "profiles": ["weep:file","weep:stream","weep:read","weep:write",
                 "weep:sub","weep:pub","weep:invoke","weep:query"],
    "auth":       ["auth:scram-sha256"],
    "version":    "1.2",
    "productName":"weep",
    "maxChunkSize": 65536,
    "serverNonce": "a3f8d2c1e9b047560f1234abcd56789e",
    "serverInfo": {
      "brand": "Acme", "model": "WeepGateway-1000", "firmware": "1.4.2"
    }
  }
}
```
  }
}
```

**Open a channel (client → server, channel 0):**
```json
{ "type":"start", "channel":0, "msgno":3,
  "payload": { "channel":1, "profile":"weep:file" } }
```

**Server accepts (server → client, channel 0):**
```json
{ "type":"ok", "channel":0, "msgno":3, "payload":{} }
```

**Error reply:**
```json
{ "type":"ERR", "channel":1, "msgno":7,
  "payload": { "code":404, "message":"Not found: /missing.txt" } }
```

### 4.5 JSON encoding requirements

- Encoding: **UTF-8, no BOM**.
- All field names are lowercase with no spaces.
- String values are UTF-8. Paths use forward slashes `/`.
- Numbers are plain integers (no decimal point for `channel` or `msgno`).
- The JSON object may contain any whitespace-equivalent serialization; the
  receiver must not depend on compact vs. pretty-printed format.
- Unknown top-level fields must be silently ignored by the receiver (forward
  compatibility).

---

## 5. Connection Lifecycle

### 5.1 Full state diagram

```
[TCP connect]
      │
      ▼
[WebSocket handshake]
      │
      ▼  Server sends greeting (includes serverInfo + server nonce)
[GREETING received]
      │
      ▼  Client sends clientInfo (brand/model/firmware) + client nonce
[DEVICE CHECK]  ── ERR 403 ──► [CLOSED]  (brand/model not on allowlist)
      │ ok
      ▼  Client sends auth:scram-sha256 step 1 (username + clientNonce)
[AUTH STEP 1]  ── ERR 401 ──► [CLOSED]
      │ RPY { serverNonce, serverProof }
      │  ← Client VERIFIES serverProof here (mutual auth)
      ▼  Client sends auth:scram-sha256 step 2 (clientProof)
[AUTH STEP 2]  ── ERR 401 ──► [CLOSED]
      │ RPY { ok, username, roles }
      ▼
[AUTHENTICATED]
      │  Client sends start { channel:N, profile:"weep:file" }
      ▼
[CHANNEL OPEN]  ◄──────────────────────────────────┐
      │  Application messages on channel N          │
      ▼                                             │
[CHANNEL ACTIVE] ── close { channel:N } ──► [ok] ──┘
      │
      ▼  WebSocket close frame
[DISCONNECTED]
```

### 5.2 Complete message trace

```
Client                                          Server
  │                                               │
  │═══ TCP + WebSocket handshake (HTTP Upgrade) ══│
  │                                               │
  │  ◄── greeting (channel=0, msgno=0) ───────────│
  │       payload: { profiles:[…],                 │
  │                  auth:["auth:scram-sha256"],    │
  │                  serverInfo:{brand,model,fw},  │
  │                  serverNonce:"<32-hex>" }       │
  │                                               │
  │  ─── clientInfo (channel=0, msgno=1) ─────────►│  declare device identity
  │       payload: { brand:"Acme",                 │
  │                  model:"ESP32-S3",             │
  │                  firmware:"2.1.0" }            │
  │                                               │
  │  ◄── ok (channel=0, msgno=1) ─────────────────│  device accepted
  │                                               │
  │  ─── MSG (channel=0, msgno=2) ───────────────►│  auth step 1
  │       payload: { mechanism:"auth:scram-sha256",│
  │                  username:"alice",             │
  │                  clientNonce:"<32-hex>" }      │
  │                                               │
  │  ◄── RPY (channel=0, msgno=2) ────────────────│
  │       payload: { serverNonce:"<64-hex>",       │
  │                  serverProof:"<64-hex>" }      │
  │   ← Client verifies serverProof               │
  │                                               │
  │  ─── MSG (channel=0, msgno=3) ───────────────►│  auth step 2
  │       payload: { mechanism:"auth:scram-sha256",│
  │                  username:"alice",             │
  │                  clientProof:"<64-hex>" }      │
  │                                               │
  │  ◄── RPY (channel=0, msgno=3) ────────────────│
  │       payload: { ok:true, username:"alice",    │
  │                  roles:["read","write"] }      │
  │                                               │
  │  ─── start (channel=0, msgno=3) ─────────────►│  open channel 1
  │       payload: { channel:1, profile:"weep:file" } │
  │                                               │
  │  ◄── ok (channel=0, msgno=3) ─────────────────│
  │                                               │
  │  ═══ channel 1 traffic (weep:file) ═══════════│
  │                                               │
  │  ─── close (channel=0, msgno=N) ─────────────►│
  │       payload: { channel:1 }                  │
  │                                               │
  │  ◄── ok (channel=0, msgno=N) ─────────────────│
  │                                               │
  │═══ WebSocket close ════════════════════════════│
```

### 5.3 Constraints

- The server **must** send the greeting immediately after the WebSocket upgrade
  completes — before receiving anything from the client.
- The client **must** complete authentication before sending any `start` message.
  If the client sends `start` before authentication, the server returns
  `ERR 401 "Authenticate before opening channels"`.
- The greeting `msgno` is always `0`. All subsequent messages from each side
  start at `msgno = 1` and increment monotonically.
- If the server receives a message type it does not understand on channel 0,
  it returns `ERR 400`.
- If the server receives a message for a channel that is not open, it returns
  `ERR 404 "Channel N not open"`.

---

## 6. Authentication

### 6.1 Overview

WEEP uses a single authentication mechanism: `auth:scram-sha256`.
The greeting `auth` array contains exactly:

```json
["auth:scram-sha256"]
```

Legacy `auth:challenge` is no longer part of the protocol. Servers should
reject it with `ERR 400`.

Authentication always happens **on channel 0** before any application channel
may be opened. It consists of up to two phases:

1. **Device handshake** (`clientInfo`) — the client announces its brand/model/
   firmware. The server can reject unknown device types *before* any credentials
   are exchanged. Optional — if the server has no allowlist configured, this
   step can be skipped by the client.
2. **Credential exchange** — SCRAM-SHA-256 with PBKDF2 + HMAC.

---

### 6.1b Security properties

`auth:scram-sha256` provides mutual authentication:
- The client verifies the server proof before sending client proof.
- The server verifies client proof before granting roles.
- Passwords are never transmitted on the wire.
- Proof verification must use constant-time comparison.

---

### 6.2 Greeting — server announces itself and its nonce

The **greeting** is the very first message the server sends. It now carries a
`serverInfo` block and a `serverNonce` — 16 cryptographically random bytes in
lowercase hex:

```json
{
  "type":    "greeting",
  "channel": 0,
  "msgno":   0,
  "payload": {
    "profiles": ["weep:file", "weep:stream"],
    "auth":     ["auth:scram-sha256"],
    "serverInfo": {
      "brand":    "Acme",
      "model":    "WeepGateway-1000",
      "firmware": "1.4.2"
    },
    "serverNonce": "a3f8d2c1e9b047560f1234abcd56789e"
  }
}
```

The `serverNonce` is always included and is incorporated into SCRAM key derivation.

---

### 6.3 Device handshake — client declares identity

Immediately after receiving the greeting, **before** the password exchange, the
client sends a `clientInfo` message on channel 0:

**Client → Server:**
```json
{
  "type":    "clientInfo",
  "channel": 0,
  "msgno":   1,
  "payload": {
    "brand":    "Acme",
    "model":    "ESP32-S3-Sensor",
    "firmware": "2.1.0"
  }
}
```

The server checks the `brand` and `model` fields against its configured
**device allowlist** (see §6.4). If the device is rejected, the server responds:

```json
{ "type":"ERR", "channel":0, "msgno":1,
  "payload": { "code":403, "message":"Device not allowed: Acme/UnknownSensor" } }
```
and immediately closes the WebSocket connection.

If the device is accepted:
```json
{ "type":"ok", "channel":0, "msgno":1, "payload":{} }
```

The `firmware` field is informational only — the server may log it but must not
reject a connection solely because of the firmware version (use `"*"` in the
allowlist to express this).

---

### 6.4 Device allowlist

The server maintains a list of permitted `(brand, model)` combinations. A `"*"`
in either position is a wildcard that matches anything.

**Example allowlist (JSON / config file):**
```json
{
  "deviceAllowList": [
    { "brand": "Acme",  "model": "ESP32-S3-Sensor" },
    { "brand": "Acme",  "model": "WeepGateway-1000" },
    { "brand": "*",     "model": "WeepClient-Dev" },
    { "brand": "Acme",  "model": "*" }
  ]
}
```

Matching rules (applied in order; first match wins):

| Rule entry | Matches |
|------------|---------|
| `brand:"Acme"`, `model:"ESP32-S3-Sensor"` | Exactly that brand + model |
| `brand:"*"`, `model:"WeepClient-Dev"` | Any brand with that model |
| `brand:"Acme"`, `model:"*"` | Any Acme device |
| `brand:"*"`, `model:"*"` | All devices (open server) |

If the allowlist is empty or absent, the server accepts all devices (open mode).
If the allowlist is non-empty and no entry matches, the server rejects with
`ERR 403`.

The `clientInfo` fields are not authenticated at this stage. The allowlist is
a coarse filter; credential exchange is the security boundary.

---

### 6.5 Credential storage (server side)

Server-side users store PBKDF2 output metadata:
- `passwordSalt`: 16 random bytes (hex)
- `passwordIterations`: integer work factor (for example 120000)
- `passwordKey`: PBKDF2-SHA256 derived key (32 bytes, hex)

```
pdk = PBKDF2-HMAC-SHA256(password_utf8, salt, iterations, 32 bytes)
```

---

### 6.6 auth:scram-sha256 step 1 — client sends username + clientNonce

The client picks 16 random bytes for its own nonce and sends both:

**Client → Server:**
```json
{
  "type":    "MSG",
  "channel": 0,
  "msgno":   2,
  "payload": {
    "mechanism":   "auth:scram-sha256",
    "username":    "admin",
    "clientNonce": "f47ac10b58cc4372a5670e02b2c3d479"
  }
}
```

The server now has both nonces. It computes a **combined nonce** and derives the
shared key material:

```
combinedNonce = serverNonce + clientNonce           (concatenate hex strings)
pdk           = stored PBKDF2 key for username
sharedKey     = lowercase_hex( HMAC-SHA256( key=pdk, message=combinedNonce ) )
```

The server computes its own proof and sends it back:

```
serverProof = lowercase_hex( HMAC-SHA256( key=sharedKey, message="server:" + combinedNonce ) )
```

**Server → Client:**
```json
{
  "type":    "RPY",
  "channel": 0,
  "msgno":   2,
  "payload": {
    "combinedNonce": "a3f8d2c1e9b047560f1234abcd56789ef47ac10b58cc4372a5670e02b2c3d479",
    "serverProof":   "<64-hex-char HMAC digest>",
    "salt":          "<hex>",
    "iterations":    120000
  }
}
```

**The client MUST verify `serverProof` before sending step 2.** The client
independently computes `sharedKey` (it knows the password) and derives:

```
expectedServerProof = lowercase_hex( HMAC-SHA256( key=sharedKey, message="server:" + combinedNonce ) )
```

If the server proof does not match, the client MUST close the connection — it is
talking to an impostor server. This is the **mutual** part of mutual auth.

---

### 6.7 auth:scram-sha256 step 2 — client proves knowledge of password

After verifying the server, the client sends its own proof:

```
clientProof = lowercase_hex( HMAC-SHA256( key=sharedKey, message="client:" + combinedNonce ) )
```

**Client → Server:**
```json
{
  "type":    "MSG",
  "channel": 0,
  "msgno":   3,
  "payload": {
    "mechanism":   "auth:scram-sha256",
    "username":    "admin",
    "clientProof": "<64-hex-char SHA-256 digest>"
  }
}
```

**Server → Client (success):**
```json
{
  "type":    "RPY",
  "channel": 0,
  "msgno":   3,
  "payload": {
    "ok":       true,
    "username": "admin",
    "roles":    ["admin", "read", "write"]
  }
}
```

**Server → Client (failure):**
```json
{
  "type":    "ERR",
  "channel": 0,
  "msgno":   3,
  "payload": { "code": 401, "message": "Invalid credentials" }
}
```

---

### 6.9 Complete key derivation summary

All HMAC outputs are 64-character lowercase
hex strings.

```
combinedNonce = serverNonce + clientNonce
passwordKey   = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
sharedKey     = HMAC-SHA256(passwordKey, combinedNonce)

# Server sends this; client verifies it:
serverProof   = HMAC-SHA256(sharedKey, "server:" + combinedNonce)

# Client sends this; server verifies it:
clientProof   = HMAC-SHA256(sharedKey, "client:" + combinedNonce)
```

**Why two separate prefix strings?** `"server:"` and `"client:"` ensure that
the server proof and client proof are always different values even when derived
from the same `sharedKey`. Without this, a replay attack would let a
man-in-the-middle echo the server's proof back as the client's proof.

**ESP32 implementation notes:**
- PBKDF2-HMAC-SHA256 and HMAC-SHA256 are available through mbedTLS in ESP-IDF.
- Recommended MCU optimization: pre-store derived key (`passwordKey`) and avoid
  running PBKDF2 during every login.

**Browser (JavaScript) implementation notes:**
- Use Web Crypto PBKDF2 (`deriveBits`) and HMAC (`subtle.sign`).
- For random nonces: `crypto.getRandomValues(new Uint8Array(16))`.

---

### 6.10 Server-side verification

The server recomputes `clientProof` using the stored derived key and the
combined nonce, then compares using **constant-time equality**:

```
expected = HMAC-SHA256(sharedKey, "client:" + combinedNonce)
```

In C#: `CryptographicOperations.FixedTimeEquals(expected, received)`.
In C/ESP32: compare byte-by-byte using a loop without early return.
In Python: `hmac.compare_digest(expected, received)`.

Never use `==` or `strcmp` for this comparison.

---

### 6.11 Roles and permissions

| Role | Can open these profiles |
|------|------------------------|
| `"admin"` | All profiles (implicitly has read + write) |
| `"write"` | `weep:file`, `weep:stream`, `weep:pub`, `weep:invoke` |
| `"read"`  | `weep:read`, `weep:sub`, `weep:query` |

A user may have multiple roles. Presence of `"admin"` overrides all checks.
If a client attempts to open a profile it does not have permission for, the
server returns `ERR 403 "Insufficient roles for <profile>"`.

---

### 6.12 Authentication state machine

```
CONNECTED
  │  greeting sent (serverNonce + auth:scram-sha256)
    ▼
AWAITING_MSG  (clientInfo optional; auth MSG accepted in any order)
    │
    ├── clientInfo { brand, model, firmware }
    │       ├── NOT in allowlist ──► ERR 403 ──► [CLOSED]
    │       └── accepted ──► ok  (still AWAITING_MSG)
    │
  └── auth:scram-sha256
     step 1: MSG { mechanism:"auth:scram-sha256", username, clientNonce }
       ├── unknown user ─► ERR 401 ─► AWAITING_MSG
       └─ send RPY { combinedNonce, serverProof, salt, iterations } ─► SCRAM_STEP1
     step 2: MSG { username, clientProof }
       ├── wrong ─► ERR 401 ─► AWAITING_MSG
       └── correct ─► AUTHENTICATED
```

After `AUTHENTICATED`, re-authentication is accepted but not required.
Unsupported mechanisms (including `auth:challenge`) are rejected with `ERR 400`.

---

## 7. Binary Frame Format

Binary frames carry bulk data for `weep:file` and `weep:stream` profiles. They
are sent as WebSocket **binary** frames, never text frames. They are never
base64-encoded.

### 7.1 Header layout

```
Byte offset  Size    Type     Field
───────────  ──────  ───────  ────────────────────────────────────────────
0 – 1        2 B     uint16   channel   (big-endian, network byte order)
2 – 5        4 B     uint32   seq       (big-endian, network byte order)
6            1 B     uint8    flags
7 …          N B     bytes    data      (absent for ACK frames)
```

**Total header size: 7 bytes.**

All multi-byte integers are **big-endian** (most significant byte first, also
called "network byte order").

### 7.2 Flags byte

| Bit | Mask   | Name    | Meaning |
|-----|--------|---------|---------|
| 0   | `0x01` | `final` | This is the last data frame of the current transfer or segment. |
| 1   | `0x02` | `ack`   | This is a flow-control ACK frame (no data, header only). |
| 2–7 | —      | reserved | Must be `0`; receiver should ignore unknown bits. |

A frame may not have both `final` and `ack` set simultaneously.

### 7.3 `seq` field

- Starts at `0` for the first frame of each transfer.
- Increments by `1` for each subsequent data frame on the same channel.
- The receiver checks `seq` against the expected next value; if there is a gap
  the receiver must abort with `ERR 400 "Expected seq N, got M"`.
- ACK frames carry the `seq` of the data frame being acknowledged in this field
  (not an incrementing counter of ACKs).
- The sequence counter resets to `0` for each new transfer on the same channel.

### 7.4 Data frames

A **data frame** has `flags & 0x02 == 0` and contains `N ≥ 0` bytes of payload
starting at byte offset 7. The channel and seq uniquely identify the frame.

When `flags & 0x01 == 1` (`final` set), this is the last frame of the current
transfer. No more data frames will follow on this channel until a new transfer
is initiated by a JSON control message.

### 7.5 ACK frames

An **ACK frame** has `flags == 0x02` and a total length of exactly **7 bytes**
(header only, no data payload).

```
Byte 0: (channel >> 8) & 0xFF          high byte of channel ID
Byte 1: (channel     ) & 0xFF          low  byte of channel ID
Byte 2: (seq >> 24) & 0xFF             high byte of acknowledged seq
Byte 3: (seq >> 16) & 0xFF
Byte 4: (seq >>  8) & 0xFF
Byte 5: (seq      ) & 0xFF             low  byte of acknowledged seq
Byte 6: 0x02                           flags = ACK
```

Each received data frame generates exactly one ACK. ACKs are sent at `High`
priority (see Section 8).

### 7.6 Encoding examples

**Data frame, channel=1, seq=0, final=false, data=`[0xDE, 0xAD, 0xBE]`:**
```
01 00                 channel = 1 (big-endian)
00 00 00 00           seq = 0
00                    flags = 0x00 (not final, not ack)
DE AD BE              data (3 bytes)

Full frame: 01 00 00 00 00 00 00 DE AD BE   (10 bytes)
```

**Data frame, channel=1, seq=5, final=true, data=`[0xAB, 0xCD]`:**
```
01 00                 channel = 1
00 00 00 05           seq = 5
01                    flags = 0x01 (final)
AB CD                 data

Full frame: 01 00 00 00 00 05 01 AB CD   (9 bytes)
```

**ACK frame, channel=1, acknowledging seq=5:**
```
01 00                 channel = 1
00 00 00 05           seq being acknowledged = 5
02                    flags = 0x02 (ack)

Full frame: 01 00 00 00 00 05 02   (7 bytes)
```

### 7.7 Receiver algorithm (pseudocode)

```
on receive_binary_frame(raw_bytes):
    if len(raw_bytes) < 7:
        abort("frame too short")

    channel = (raw_bytes[0] << 8) | raw_bytes[1]
    seq     = (raw_bytes[2] << 24) | (raw_bytes[3] << 16)
            | (raw_bytes[4] <<  8) |  raw_bytes[5]
    flags   = raw_bytes[6]
    data    = raw_bytes[7:]           # empty slice for ACK frames

    is_final = (flags & 0x01) != 0
    is_ack   = (flags & 0x02) != 0

    if is_ack:
        if len(raw_bytes) != 7:
            abort("ACK frame must be exactly 7 bytes")
        dispatch_ack(channel, seq)    # releases one send-window credit
        return

    # Data frame — route to the channel handler
    if channel not in open_channels:
        return  # silently ignore (channel may have been closed)
    handler = open_channels[channel]
    handler.on_data_frame(seq, is_final, data)
```

---

## 8. Send Priority Queue

### 8.1 Purpose

Every send on a WebSocket connection must be serialised — only one frame may be
in progress at a time. weep may have many channels active simultaneously
(real-time stream, file download, auth reply all competing). The priority queue
ensures that small, latency-sensitive frames (auth replies, ACKs, sub/pub
events) are never blocked behind a 64 KB file chunk.

### 8.2 Queue structure

The queue is a **min-heap** keyed by priority integer. Lower value = higher
priority = dequeued first.

| Priority name | Integer value | Used by |
|---------------|--------------|---------|
| `High`   | `0` | All JSON control frames (any type, any channel), ACK binary frames |
| `Normal` | `1` | `weep:stream` data binary frames |
| `Low`    | `2` | `weep:file` data binary frames |

### 8.3 Algorithm (pseudocode)

```
# Shared state
queue    = MinHeap()           # element: (data_bytes, ws_frame_type), key: priority
signal   = Semaphore(0)        # counting semaphore; count = items in queue

# Called by any thread/coroutine to enqueue a frame
function enqueue(data, frame_type, priority):
    lock(queue):
        queue.push((data, frame_type), priority)
    signal.release()           # wake the pump

# Single background task — sole owner of ws.send()
function send_pump(cancellation):
    loop:
        signal.acquire(cancellation)     # block until something to send
        lock(queue):
            (data, frame_type) = queue.pop_min()   # highest priority first
        ws.send(data, frame_type)        # blocks until this frame is fully sent
```

**Important:** The pump is the *only* place where `ws.send` is called. All
other code calls `enqueue` only.

### 8.4 Priority inversion hazard

A low-priority frame already in progress (being sent by the pump) cannot be
interrupted — a WebSocket frame must be sent atomically. At 64 KB per chunk over
a 1 Mbit/s link, the worst-case delay for a `High` frame behind a `Low` frame
is ≈ 500 ms. This is acceptable for auth replies and ACKs. For `High`-priority
pub/sub events, it is also acceptable because the latency bound is predictable.

The hazard occurs if a `High`-priority control message (e.g., a download NUL
terminator) is enqueued *after* a `Low`-priority data frame for the same
transfer: both sit in the queue, and the NUL is dequeued before the data. To
avoid this, the `weep:file` download protocol uses `final=1` in the last binary
frame to signal completion (see Section 10), rather than a separate NUL JSON
message.

---

## 9. Flow Control — Sliding Window ACK

### 9.1 Why it is needed

Without flow control, a fast sender overwhelms a slow receiver's buffers. On
high-latency links (WAN, satellite), a single-frame-at-a-time stop-and-wait
approach wastes the pipe. The sliding window allows up to **W** frames to be
in-flight simultaneously while still preventing buffer overflow.

### 9.2 Window parameters

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `W` | `8` | Window size (max in-flight unacknowledged frames) |
| Chunk size | `65536` (64 KB) | Maximum bytes per data frame |
| Max in-flight | `W × 65536 = 524288` (512 KB) | Maximum unacknowledged data |

`W = 8` is the default. Both sides must use the same `W`; it is not negotiated
per-connection in the current version (change `WindowSize` at compile time on
both ends if a different value is needed).

### 9.3 Sender algorithm

The sender maintains a counting semaphore initialized to `W`:

```
window = Semaphore(W)       # starts full; each acquire = consume one credit

for each data frame to send:
    window.acquire()         # blocks when W frames are already unacknowledged
    send_frame(data, seq, final)

# Receiving an ACK from the other side:
on receive_ack(channel, acked_seq):
    window.release()         # one more frame may now be sent
```

### 9.4 Receiver algorithm

```
on receive_data_frame(channel, seq, final, data):
    write_data_to_destination(data)
    send_ack_frame(channel, seq)     # always, for every data frame

    if final:
        signal_transfer_complete()
```

### 9.5 Throughput formula

```
throughput ≈ W × ChunkSize / RTT

Examples:
  LAN  (RTT = 1 ms):  8 × 64 KB / 0.001 s  =  512 MB/s  (network-bound in practice)
  WiFi (RTT = 5 ms):  8 × 64 KB / 0.005 s  =  102 MB/s
  WAN  (RTT = 100 ms): 8 × 64 KB / 0.1 s   =  5.1 MB/s  = 40 Mbit/s
  SAT  (RTT = 600 ms): 8 × 64 KB / 0.6 s   =  0.85 MB/s =  6.8 Mbit/s
```

Increase `W` to fill higher bandwidth-delay products.

### 9.6 Flow control scope

Flow control is applied per **channel**, not per connection. Two concurrent file
transfers on channels 1 and 2 each have their own independent window of 8
credits. They do not share credits.

The `weep:stream` profile does **not** use ACK-based flow control. It relies
instead on the TCP receive buffer and application-level backpressure via a
bounded queue (see Section 11).

---

## 10. Profile: weep:file

### 10.1 Purpose

Provides chunked file **upload**, **download**, and **directory browsing** over a
dedicated channel. File data is transferred as raw binary frames.

### 10.2 Opening the channel

```json
// Client → Server (channel 0)
{ "type":"start", "channel":0, "msgno":3,
  "payload": { "channel":1, "profile":"weep:file" } }

// Server → Client (channel 0)
{ "type":"ok", "channel":0, "msgno":3, "payload":{} }
```

Required roles: `write` (for upload) or `read` (for download/browse). In
practice the server opens the channel for any authenticated user that has the
`write` role; role checking happens per-operation.

### 10.3 Control messages

All control messages on the channel are `MSG` from client and `RPY` or `ERR`
from server.

| `op` | Request payload fields | Reply payload fields |
|------|----------------------|---------------------|
| `"list"`     | `path` (string)                       | `path` (string), `entries` (array) |
| `"stat"`     | `path` (string)                       | entry object (see 10.4) |
| `"upload"`   | `path`, `size` (int), `mime?` (string) | `transferId` (string), `chunkSize` (int) |
| `"download"` | `path` (string)                       | `transferId` (string), `size` (int), `mime` (string) |

`path` is always an **absolute virtual path** rooted at `/` using forward slashes.
It is mapped to a real filesystem path by the server. Clients must not include
`..` components; the server rejects paths that would escape the root.

### 10.4 Directory entry object

```json
{
  "name":     "sensor_data.bin",
  "path":     "/data/sensor_data.bin",
  "type":     "file",
  "size":     4096,
  "modified": "2026-04-02T08:00:00Z",
  "mime":     "application/octet-stream"
}
```

| Field | Type | Values |
|-------|------|--------|
| `name` | string | File or directory name (no path separators) |
| `path` | string | Full virtual path from root |
| `type` | string | `"file"` or `"dir"` |
| `size` | integer | Bytes for files; `0` for directories |
| `modified` | string | ISO-8601 UTC datetime |
| `mime` | string | MIME type for files; `"application/octet-stream"` for directories |

### 10.5 List operation

```json
// Request
{ "type":"MSG", "channel":1, "msgno":4,
  "payload": { "op":"list", "path":"/" } }

// Reply
{ "type":"RPY", "channel":1, "msgno":4,
  "payload": {
    "path": "/",
    "entries": [
      { "name":"data",   "path":"/data",   "type":"dir",  "size":0,    "modified":"…", "mime":"application/octet-stream" },
      { "name":"log.txt","path":"/log.txt","type":"file", "size":1024, "modified":"…", "mime":"text/plain" }
    ]
  }
}
```

Entries are sorted: directories first, then files, both alphabetically by name.
If `path` does not refer to an existing directory, the server returns
`ERR 404 "Not a directory: <path>"`.

### 10.6 Stat operation

```json
// Request
{ "type":"MSG", "channel":1, "msgno":5,
  "payload": { "op":"stat", "path":"/log.txt" } }

// Reply (entry object directly in payload)
{ "type":"RPY", "channel":1, "msgno":5,
  "payload": { "name":"log.txt", "path":"/log.txt", "type":"file",
               "size":1024, "modified":"2026-04-01T10:00:00Z", "mime":"text/plain" } }
```

### 10.7 Upload operation

#### Overview

The client announces the upload, the server responds with a transfer ID and
chunk size, and the client streams binary frames. The server acknowledges each
frame. After the final frame the server sends a JSON confirmation.

#### Full message trace

```
Client                                       Server
  │  JSON MSG { op:"upload", path, size }      │
  │ ─────────────────────────────────────────► │
  │                                            │
  │  JSON RPY { transferId, chunkSize }        │
  │ ◄───────────────────────────────────────── │
  │                                            │
  │  [acquire window credit]                   │
  │  BIN data(seq=0, final=false, data=[…])    │
  │ ─────────────────────────────────────────► │
  │                                            │
  │  BIN ACK(seq=0)    [High priority]         │
  │ ◄───────────────────────────────────────── │  releases 1 credit
  │                                            │
  │  [acquire window credit]                   │
  │  BIN data(seq=1, final=false, data=[…])    │
  │ ─────────────────────────────────────────► │
  │  BIN ACK(seq=1)                            │
  │ ◄───────────────────────────────────────── │
  │                                            │
  │  … (up to W=8 frames in-flight) …          │
  │                                            │
  │  BIN data(seq=N, final=true, data=[…])     │
  │ ─────────────────────────────────────────► │
  │  BIN ACK(seq=N)                            │
  │ ◄───────────────────────────────────────── │
  │                                            │
  │  JSON RPY { ok:true, bytesReceived:M }     │
  │ ◄───────────────────────────────────────── │
```

#### Rules for the client

1. Send the `MSG { op:"upload", path, size }` and wait for the `RPY`.
2. **Pre-register** a handler for the final `RPY { ok:true, bytesReceived }`
   before sending the first binary frame. (The `RPY` uses the same `msgno` as
   the original `MSG`. Register it before streaming to prevent a race where the
   server's reply arrives before the client is listening.)
3. For each chunk:
   - Read up to `chunkSize` bytes from the source file.
   - Acquire one window credit (block if window is full).
   - Encode the binary frame with the correct `channel`, `seq`, and `final` flag.
   - Enqueue at `Low` priority.
4. Set `final=true` when `bytes_read < chunkSize` OR when source position equals
   file size (i.e., last read).
5. After sending the final frame, wait for the server's `RPY { ok:true }`.

#### Rules for the server

1. On receiving the `MSG { op:"upload" }`, open the destination file for writing
   and send `RPY { transferId, chunkSize }`.
2. For each incoming binary data frame (identified by `flags & 0x02 == 0`):
   - Verify `seq == expected_next_seq`; if not, send `ERR 400` and abort.
   - Write `data` to the file.
   - Increment `expected_next_seq`.
   - Send `ACK(seq)` at `High` priority.
3. On `final=true`:
   - Close and flush the file.
   - Send `RPY { ok:true, bytesReceived: <total> }` at `High` priority.

#### Chunk size

`chunkSize` is always `65536` (64 KB). The server includes it in the `RPY` so
clients need not hardcode it. A client may use smaller chunks but must not
exceed `chunkSize`.

#### `transferId`

An opaque string (UUID or similar) the server generates per transfer. Currently
used for logging only; the client does not need to send it back.

### 10.8 Download operation

#### Full message trace

```
Client                                       Server
  │  JSON MSG { op:"download", path }          │
  │ ─────────────────────────────────────────► │
  │                                            │
  │  JSON RPY { transferId, size, mime }       │
  │ ◄───────────────────────────────────────── │
  │                                            │
  │  [Server acquires window credit]            │
  │  BIN data(seq=0, final=false, data=[…])    │
  │ ◄───────────────────────────────────────── │
  │  BIN ACK(seq=0)    [High priority]         │
  │ ─────────────────────────────────────────► │  releases 1 server credit
  │                                            │
  │  [Server acquires window credit]            │
  │  BIN data(seq=1, final=false, data=[…])    │
  │ ◄───────────────────────────────────────── │
  │  BIN ACK(seq=1)                            │
  │ ─────────────────────────────────────────► │
  │                                            │
  │  … (up to W=8 frames in-flight) …          │
  │                                            │
  │  BIN data(seq=N, final=true, data=[…])     │
  │ ◄───────────────────────────────────────── │
  │  BIN ACK(seq=N)                            │
  │ ─────────────────────────────────────────► │
```

The download is **complete** when the client receives a data frame with
`final=true`. No separate NUL JSON message is sent. (Reason: a NUL sent via
`sendJson` would travel at `High` priority and would be dequeued *before* the
`Low`-priority binary data still in the send queue, causing the client to see
completion before receiving the data.)

#### Rules for the client

1. **Pre-register** the download state *before* sending the `MSG`. Binary frames
   from the server may arrive immediately after the `RPY`, possibly before the
   client processes the `RPY` and installs a handler. Any frame that arrives
   before the handler is ready must be buffered (early-frame queue) and replayed
   once the handler is installed.
2. Send `MSG { op:"download", path }` and await `RPY { transferId, size, mime }`.
3. For each received binary data frame:
   - Verify `flags & 0x02 == 0` (not an ACK).
   - Write `data` to the local file.
   - Send `ACK(seq)` at `High` priority.
   - If `final=true`, signal download completion.
4. Report progress as `bytes_written / size` (size from the RPY).

#### Rules for the server

1. On receiving `MSG { op:"download" }`:
   - Check the file exists; return `ERR 404` if not.
   - Send `RPY { transferId, size, mime }`.
   - Start streaming in a background task.
2. In the streaming task:
   - Maintain a window semaphore initialized to `W`.
   - For each chunk read from the file:
     - Acquire one credit (block if window full — client is slow).
     - Encode and enqueue the binary frame at `Low` priority.
     - Set `final=true` on the last chunk.
   - After the final frame is enqueued, the task exits.
3. When an ACK frame arrives for this channel, release one window credit.

#### Empty file edge case

If the file has 0 bytes:
- The server reads 0 bytes → `read = 0`.
- `final = (0 < chunkSize)` = `true`.
- A binary frame with `data = []` (0-byte payload) and `final=true` is sent.
- The client receives a 7-byte frame (header only with `final=true`), sends ACK,
  and marks the download complete with 0 bytes written.

### 10.9 Channel lifecycle — reuse and concurrency

A `weep:file` channel is a **long-lived, reusable resource**. After opening it
once with `start`, you may issue any number of `list`, `stat`, `upload`, and
`download` operations sequentially without closing and reopening the channel.
The `seq` counter resets to `0` for each new transfer because the server creates
a fresh transfer-state object per `upload`/`download` call.

```
Client                             Server
  │  start { channel:1, profile:"weep:file" }
  │ ─────────────────────────────────────────►
  │  ok                               │
  │ ◄─────────────────────────────────│
  │                                   │
  │  MSG { op:"list", path:"/" }      │   ← first operation
  │  ──► RPY { entries:[…] }          │
  │                                   │
  │  MSG { op:"download", path:"/a" } │   ← second operation, seq resets to 0
  │  ──► RPY { size, mime }           │
  │  ◄── BIN seq=0 … seq=N final      │
  │                                   │
  │  MSG { op:"download", path:"/b" } │   ← third operation, seq resets to 0
  │  ──► RPY { size, mime }           │
  │  ◄── BIN seq=0 … seq=M final      │
  │                                   │
  │  close { channel:1 }              │   ← close only when done
  │ ─────────────────────────────────►│
```

**Concurrency rule:** Only **one** transfer may be in progress on a channel at a
time. The binary frames of two simultaneous transfers would be interleaved and
unreadable. If you need to transfer files in parallel, open two separate
channels:

```
channel 1 (weep:file) ── download /big1.bin ──────────────────►
channel 2 (weep:file) ──────────── upload /big2.bin ──────────►
```

**Bandwidth sharing:** All channels share the same underlying TCP connection
and therefore the same total bandwidth. Opening two channels does **not** give
you more throughput — it splits the available bandwidth between them. Each
channel's binary frames are interleaved by the single send pump:

```
send queue (interleaved):
  [ch1 seq=0][ch2 seq=0][ch1 seq=1][ch2 seq=1][ch1 seq=2] …
```

| Scenario | Total throughput | Per-channel throughput |
|----------|-----------------|----------------------|
| 1 channel downloading | 100 % | 100 % |
| 2 channels downloading simultaneously | 100 % | ~50 % each |
| 4 channels downloading simultaneously | 100 % | ~25 % each |

**When parallel channels are useful:**
- Downloading one file while uploading another (upload and download use
  separate TCP receive/send buffers — they can genuinely run in parallel
  on a full-duplex connection without halving each other).
- Keeping latency low on a control channel (`list`, `stat`) while a large
  file transfer runs on a separate channel. The control messages travel at
  `Normal` priority and cut ahead of the `Low`-priority data frames.
- Saturating the link when the remote end is the bottleneck (e.g. slow disk
  on the server), not the network.

For a single large file, one channel is always optimal.

**Idle channels:** There is no server-side timeout for idle file channels.
A channel stays alive until the client sends `close` or the WebSocket
connection drops.

### 10.10 Error cases

| Condition | Error code | Message |
|-----------|-----------|---------|
| `path` is missing from request | 400 | `"path required"` |
| `channel` or `profile` missing from `start` | 400 | `"channel and profile required"` |
| Directory does not exist | 404 | `"Not a directory: <path>"` |
| File not found | 404 | `"Not found: <path>"` |
| Sequence gap in upload | 400 | `"Expected seq N, got M"` |
| Unknown `op` | 400 | `"Unknown op: <op>"` |

---

## 11. Profile: weep:stream

### 11.1 Purpose

Provides a **bidirectional real-time binary stream** for continuous data such as
sensor readings, telemetry, audio, or video. Unlike `weep:file`, there is no
predetermined size — the stream runs until one side closes it.

### 11.2 Opening the channel

```json
{ "type":"start", "channel":0, "msgno":5,
  "payload": { "channel":2, "profile":"weep:stream" } }
```

### 11.3 Control messages

| `op` | Request payload | Reply payload |
|------|----------------|--------------|
| `"open"`  | `mime?` (string), `metadata?` (object) | `{ "ok": true }` |
| `"close"` | (empty) | NUL `{ "bytesReceived": N, "bytesSent": M }` |

### 11.4 Data flow

After `open` is acknowledged, both sides may send binary frames on the channel
at any time.

**Client → Server:**
- Binary frames, `seq` starting at 0, incrementing by 1.
- Set `final=true` on the last frame of a logical segment (optional; application-defined).
- The server writes incoming data to a **bounded receive queue** (capacity 64
  frames). If the queue is full, the server suspends reading from the WebSocket,
  which propagates TCP-level backpressure to the client.

**Server → Client:**
- Same format. `seq` is independent of the client-to-server sequence.

**No ACK frames are used for weep:stream.** Backpressure is provided entirely
by the bounded receive queue and TCP flow control.

### 11.5 Close sequence

```json
// Client → Server MSG
{ "type":"MSG", "channel":2, "msgno":6,
  "payload": { "op":"close" } }

// Server → Client NUL (not RPY — this terminates the stream)
{ "type":"NUL", "channel":2, "msgno":6,
  "payload": { "bytesReceived": 12345, "bytesSent": 6789 } }
```

After sending the `close` MSG, the client should not send further binary frames
on that channel. After receiving the `NUL`, the client may close the channel
with a `close` management message.

### 11.6 Send priority

`weep:stream` binary frames use `Normal` priority (value `1`). They are
therefore sent after any `High`-priority control messages but before `Low`-
priority file chunks.

---

## 12. Planned Profiles

These profiles are declared in the server greeting but not yet implemented.
Opening them returns `ERR 501 "Profile not supported: <profile>"`.

| Profile | Purpose | Expected type |
|---------|---------|---------------|
| `weep:read`   | Read a single named value and get its current data | Request/reply (MSG/RPY) |
| `weep:write`  | Write a value | Request/reply |
| `weep:sub`    | Subscribe to value change events (server pushes ANS on each change) | MSG to subscribe, ANS per event, NUL to unsubscribe |
| `weep:pub`    | Publish value change events to all subscribers | MSG per event |
| `weep:invoke` | Call a named remote operation with input/output | MSG/RPY |
| `weep:query`  | Structured query for tabular or hierarchical data | MSG/ANS/NUL |

Sub/pub events will use `High` send priority to avoid latency from concurrent
file transfers.

---

## 13. Error Handling

### 13.1 ERR message format

All errors use message type `"ERR"`. The payload always contains exactly two
fields:

```json
{ "code": <integer>, "message": "<human-readable description>" }
```

The `msgno` of the `ERR` echoes the `msgno` of the `MSG` that caused the error,
allowing the requester to identify which pending request failed.

### 13.2 Error codes

| Code | HTTP equivalent | Meaning |
|------|----------------|---------|
| `400` | Bad Request | Malformed message; missing required field; unknown op; seq gap |
| `401` | Unauthorized | Not authenticated, or authentication failed |
| `403` | Forbidden | Authenticated but lacking the required role |
| `404` | Not Found | Channel not open; path does not exist |
| `409` | Conflict | Channel ID already in use |
| `500` | Internal Server Error | Unexpected server-side exception |
| `501` | Not Implemented | Profile declared in greeting but not yet implemented |

### 13.3 Fatal vs. recoverable errors

All errors in weep are **per-message** — they do not close the connection or
any channel. The client may retry or open a new channel after receiving an
`ERR`. Only the WebSocket close frame ends the session.

### 13.4 Unhandled exceptions

If the server encounters an unhandled exception while processing a message on
any channel, it sends `ERR 500` with the exception message. The channel remains
open and the client may continue sending.

---

## 14. Implementation Checklist

Use this list to verify a new implementation.

### Transport & framing

- [ ] Connect via WebSocket (RFC 6455); handle both `ws://` and `wss://`.
- [ ] Parse incoming frames by WebSocket frame type (text → JSON, binary → binary header parser).
- [ ] Implement the priority send queue: min-heap, `Semaphore(0)`, single pump task.
- [ ] Never call the WebSocket send function from more than one thread simultaneously.

### Management — channel 0

- [ ] Server sends greeting immediately after WebSocket upgrade, before reading.
- [ ] Greeting payload includes `profiles` array and `auth` array.
- [ ] Client parses greeting and extracts `auth` mechanisms.
- [ ] `start` message opens a channel; store `(channel_id → handler)` mapping.
- [ ] `close` message removes the channel from the mapping.
- [ ] Reject `start` for a channel ID that is already open (`ERR 409`).
- [ ] Reject `start` if not authenticated (`ERR 401`).

### Authentication

**SCRAM-only requirements**
- [ ] Include `serverNonce` (16 random bytes, lowercase hex) in every greeting.
- [ ] Advertise only `"auth:scram-sha256"` in `auth` array.
- [ ] Include `serverInfo` block in greeting (`brand`, `model`, `firmware`).
- [ ] Accept `clientInfo` message; check `brand`/`model` against device allowlist.
- [ ] Reject with `ERR 403` and close if device not on allowlist.
- [ ] Reject `start` with `ERR 401` if not yet authenticated.

**auth:scram-sha256 (mutual)**
- [ ] Reject unsupported auth mechanisms (including `auth:challenge`) with `ERR 400`.
- [ ] Store password key metadata as PBKDF2 output (`salt`, `iterations`, `passwordKey`).
- [ ] Step 1: receive `username` + `clientNonce`; compute `combinedNonce = serverNonce + clientNonce`.
- [ ] Compute `sharedKey = HMAC-SHA256(passwordKey, combinedNonce)`.
- [ ] Compute and send `serverProof = HMAC-SHA256(sharedKey, "server:" + combinedNonce)` in step-1 reply.
- [ ] Include `salt` and `iterations` in the step-1 SCRAM reply.
- [ ] Step 2: receive `clientProof`; compute `expected = HMAC-SHA256(sharedKey, "client:" + combinedNonce)`.
- [ ] Compare `clientProof` vs `expected` using **constant-time equality**.
- [ ] **Client-side**: verify `serverProof` before sending step 2; abort connection if wrong.

### Binary frames

- [ ] Parse 7-byte header: `channel` (uint16 BE), `seq` (uint32 BE), `flags` (uint8).
- [ ] Detect ACK frames: `flags & 0x02 != 0`, total length == 7.
- [ ] Detect final data frames: `flags & 0x01 != 0`.
- [ ] Encode ACK frames: 7-byte header, `flags = 0x02`, no data.
- [ ] Encode data frames: 7-byte header + data, `flags = 0x01` on last frame.

### Flow control

- [ ] Implement `SendWindow(W=8)`: counting semaphore starting at W.
- [ ] Sender acquires credit before each data frame; blocks when W frames in-flight.
- [ ] Receiver sends ACK for every data frame received.
- [ ] ACK reception calls `window.release()` once.
- [ ] ACKs are enqueued at `High` priority.
- [ ] Data frames for `weep:file` are enqueued at `Low` priority.
- [ ] Data frames for `weep:stream` are enqueued at `Normal` priority.

### weep:file — upload

- [ ] Server opens file for write on `MSG { op:"upload" }`.
- [ ] Server sends `RPY { transferId, chunkSize:65536 }`.
- [ ] Server checks `seq` continuity; aborts on gap.
- [ ] Server sends ACK after each chunk write.
- [ ] Server sends `RPY { ok:true, bytesReceived }` after `final=true` frame.
- [ ] Client pre-registers final-RPY handler before streaming binary data.
- [ ] Client acquires window credit before each frame.

### weep:file — download

- [ ] Server sends `RPY { transferId, size, mime }`.
- [ ] Server streams from a background task using the send window.
- [ ] Server sends `final=true` on the last frame (NOT a NUL JSON message).
- [ ] Client pre-registers download state before sending the request.
- [ ] Client buffers "early" binary frames that arrive before the RPY is processed.
- [ ] Client sends ACK for every data frame.
- [ ] Client completes download on `final=true`, not on NUL.

### weep:file — browse

- [ ] `list`: returns sorted entries (dirs first, then files, alphabetical).
- [ ] `stat`: returns a single entry object.
- [ ] `ERR 404` for non-existent paths.

### weep:stream

- [ ] Buffer incoming frames in a bounded queue (capacity ≥ 64 frames).
- [ ] Apply backpressure to the WebSocket receive loop when the queue is full.
- [ ] Send `NUL { bytesReceived, bytesSent }` in response to `MSG { op:"close" }`.

---

## 15. Arduino and ESP32 Implementation Notes

Short answer: yes, WEEP is practical on ESP32 and Arduino-class boards.

### 15.1 Supported deployment patterns

| Pattern | Recommended for | Notes |
|---------|------------------|-------|
| ESP32 as WEEP client | Sensors and field devices | Connects to C# or Python WEEP server over `ws://` or `wss://` |
| ESP32 as small WEEP server | Small LAN deployments | Keep channel/profile set minimal to control RAM usage |
| Browser UI + MCU backend | Human operator tools | Browser cannot do mDNS directly; keep `/discover` HTTP endpoint on server/gateway |

### 15.2 Discovery on ESP32 (mDNS/DNS-SD)

Use service type `_weep._tcp.local` and advertise these TXT records:

- `path=/weep`
- `version=1.2`
- `auth=auth:scram-sha256`

For ESP-IDF, typical APIs are:

- `mdns_init()`
- `mdns_hostname_set()`
- `mdns_instance_name_set()`
- `mdns_service_add("<instance>", "_weep", "_tcp", port, txt, txt_count)`

For discovery, query `_weep._tcp.local` and build connect URLs from SRV + A/AAAA + TXT data. If multiple addresses are present, prefer in this order:

1. `127.0.0.1` or `::1` (local testing only)
2. `192.168.x.x`
3. `172.16.x.x` to `172.31.x.x`
4. `10.x.x.x`
5. global IPv6
6. link-local (`169.254.x.x`, `fe80::/10`) as last resort

### 15.3 Security and crypto on MCU

- SCRAM flow is supported on ESP32 via mbedTLS (PBKDF2 + HMAC-SHA256).
- Use constant-time digest compare for `clientProof` validation.
- Store `passwordKey` (derived key) rather than plain password to avoid PBKDF2 on every login.
- Prefer `wss://` in production; use plain `ws://` only on trusted local networks.

### 15.4 Resource budgeting guidance

- Keep binary chunk size at 4096 to 16384 bytes on constrained devices.
- Keep the sliding window at `W=8` unless profiling shows memory pressure.
- Use fixed-size buffers and avoid dynamic allocations inside the send loop.
- Limit simultaneously open channels on MCU targets (for example: auth + one file or stream channel).

### 15.5 Arduino practical note

Arduino-class boards can interoperate if they have:

- a WebSocket client/server library with binary frame access,
- SHA-256/HMAC/PBKDF2 capability, and
- enough RAM for channel state plus in-flight frame buffers.

For non-ESP Arduino targets, running as a WEEP client is usually easier than hosting a multi-channel WEEP server.

---

## 16. Differences from BEEP (RFC 3080)

### Historical context

**BEEP and HTTP once competed to become the universal application protocol for
the internet.**

Around 2000–2003, Marshall Rose and colleagues published BEEP (RFC 3080/3081)
as a general-purpose application-level protocol framework. The vision was
ambitious: a single protocol that could carry email, file transfer, instant
messaging, remote procedure calls, pub/sub events, and any other application
protocol — all multiplexed over one connection, with authentication,
confidentiality, and flow control built in. Profile URIs (`beep:tls`,
`beep:sasl`) let you mix-and-match capabilities without reinventing them per
application.

At the same moment, the web community was pushing **HTTP** in the same
direction. REST (2000, Fielding's dissertation) showed that HTTP's uniform
interface was sufficient for most distributed-systems use cases. HTTP/1.1
already existed everywhere; BEEP required new server support. Pragmatism won:
HTTP became the de-facto universal transport, and BEEP remained a niche
protocol used by specialists.

BEEP did, however, deeply influence a generation of protocol designers who
needed something more powerful than HTTP for real-time, bidirectional, or
high-throughput use cases.

**Tridium's FOX protocol is one such descendant.**

FOX is the wire protocol of Niagara Framework — the most widely deployed
building-automation platform in the world (HVAC, lighting, access control,
energy management). FOX takes direct inspiration from BEEP:

- **Multiplexed channels** over a single TCP connection (default port 1911,
  SSL on 4911).
- **Profile-based extensibility** — `fox:session`, `fox:auth`, `fox:service`
  map directly to the BEEP profile concept.
- **Channel 0 / management lane** for session negotiation and authentication
  before application channels open — identical in spirit to BEEP's tuning
  profiles.
- **Bidirectional push** — the server can push property-change events to the
  client on an open channel without the client polling.

FOX predates WebSocket and uses raw TCP with a custom binary framing layer.
Because it lives behind firewalls on proprietary port 1911, it is invisible to
the broader internet and therefore never achieved the adoption BEEP or HTTP
reached.

**WEEP occupies the same design space** as BEEP and FOX, but built on the
infrastructure that actually won: WebSocket over HTTP/S, JSON for the control
plane, and native binary frames for bulk data. The goal is the same —
multiplexed, authenticated, bidirectional application channels — delivered in a
form that runs in a browser, on an ESP32, and behind every corporate reverse
proxy that speaks HTTPS.

---

### Deliberate divergences from BEEP

BEEP (Blocks Extensible Exchange Protocol) is the primary inspiration for
WEEP. The table documents deliberate divergences.

| Aspect | BEEP (RFC 3080) | WEEP |
|--------|-----------------|------|
| **Transport** | Raw TCP | WebSocket (RFC 6455) over HTTP/S |
| **Framing** | Custom text framing with `SEQ` frames | WebSocket frames — framing handled by the protocol layer |
| **Message encoding** | XML (profiles may change it) | JSON for control; raw binary for data |
| **Binary data** | Must be base64 or MIME encoded | Native binary WebSocket frames; zero overhead |
| **Multiplexing** | Interleaved bytes in one TCP stream; explicit `SEQ`/window management | Separate WebSocket frames; window per channel via ACK binary frames |
| **Flow control** | Per-channel sliding window (`SEQ` frames, advertised `window` parameter) | Per-channel sliding window via ACK binary frames (W=8, not advertised); `BoundedChannel` for stream profile |
| **Channel 0** | Management only (tuning, profile negotiation, channel close) | Management + mandatory authentication |
| **Authentication** | SASL via `beep:tls` and `beep:sasl` tuning profiles | `auth:scram-sha256` only (mutual auth with PBKDF2 + HMAC); password never on wire |
| **Device identity** | No concept of device type filtering | `clientInfo` message + server-side device allowlist (`brand`/`model`) filters connections before credentials are checked |
| **TLS** | Negotiated via `beep:tls` profile on channel 0 | Delegated to WebSocket layer (`wss://`) |
| **Profile negotiation** | Both sides advertise and confirm profile URIs | Server advertises in greeting; client picks per `start` message |
| **`ANS`/`NUL`** | Full support; one MSG may receive many ANS replies | `NUL` used for stream close; download termination uses `final=1` flag in binary frame |
| **Send ordering** | FIFO per channel | Priority queue across all channels (High → Normal → Low) |
| **Implementations** | C, Java, Perl (RFC-standardised) | C# reference; Python port; ESP32 feasible |
| **Complexity** | High — SEQ frames, window negotiation, MIME, XML | Medium — 7-byte binary header, flat JSON, fixed-size window |
| **Deployment** | Port 10288 (IANA); blocked by most firewalls | Port 443 (`wss://`); traverses every corporate firewall and reverse proxy |

### Why `final=1` instead of NUL for download termination

In WEEP, all JSON messages travel at `High` send priority. Binary data frames
for `weep:file` travel at `Low`. If the server enqueued a `NUL` JSON message
after the last binary data frame, the priority queue would dequeue and send the
`NUL` *before* the data frame — the client would see "download complete" before
receiving any bytes. This is a **priority inversion** inherent to the design.
The solution is to embed the termination signal in the last binary frame itself
(`final=1`), which travels at the same `Low` priority as the data and is
therefore guaranteed to arrive in order.

---

*End of specification.*
