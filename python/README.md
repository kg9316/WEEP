# WEEP Python Port

This folder contains the Python implementation of WEEP, compatible with the C# implementation.

## What's included

- `weep/server.py` - Python WEEP server
- `weep/client.py` - Python client, auth client, and file-transfer client
- `tests/compat_runner.py` - cross-language compatibility matrix

## Install

From repository root:

```powershell
python -m pip install -r python/requirements.txt
```

## Run Python server

Option A (from this folder):

```powershell
cd python
python -m weep.server --port 9566
```

Option B (from repo root):

```powershell
$env:PYTHONPATH = "python"
python -m weep.server --port 9566
```

Endpoints:

- Web UI: `http://localhost:9566/weep`
- Discovery API: `http://localhost:9566/weep/discover`
- WebSocket endpoint: `ws://localhost:9566/weep`

Root path (`/`) is not redirected by WEEP and may be used by other web apps.

## Run compatibility matrix

```powershell
python python/tests/compat_runner.py
```

Expected final line:

- `All compatibility tests passed.`

## Query profile handler

Incoming query flow (Python server):

1. `ServerSession._dispatch_text(...)`
2. `ServerSession._open_channel(...)` maps `weep:query` to `QueryProfile`
3. `QueryProfile.handle_text(payload, msgno)`

Current behavior returns a fixed JSON array in `QueryProfile.handle_text`.
Replace that stub with your real backend while keeping request/response field names stable.

## Full documentation

See `../docs/` for all project documentation.
Primary protocol spec: `../docs/protocol-spec.md`.
