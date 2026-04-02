# WEEP Python Port

This folder contains a Python implementation of WEEP client/server behavior compatible with the C# implementation.

## What's included

- `weep/server.py`: Python WEEP server with WebSocket endpoint at `/weep` and JS page served at `/`
- `weep/client.py`: Python client, auth client, and file-transfer client
- `tests/compat_runner.py`: Cross-language compatibility test matrix

## Install

From repository root:

```powershell
python -m pip install -r python/requirements.txt
```

## Run Python server

```powershell
python -m weep.server --port 9555
```

Then open:

- `http://localhost:9555/`
- WebSocket endpoint: `ws://localhost:9555/weep`

## Run compatibility matrix

This executes:

1. C# server + JS page check
2. Python client against C# server
3. Python server + JS page check
4. C# client against Python server
5. Python client against Python server

```powershell
python python/tests/compat_runner.py
```

Expected final line:

- `All compatibility tests passed.`

## Notes

- Test fixture `files/data/sensor_data.bin` is auto-created by the compatibility runner if missing.
- C# invocations in the runner use `--no-build` to avoid rebuild locks from already-running processes.

## Query profile: what fires on server

Query is sent as a raw string (`payload.q`). The protocol layer does not parse
SQL/BQL syntax; it forwards the string to the query profile handler.

### Incoming query flow (Python server)

1. `ServerSession._dispatch_text(...)`
2. `ServerSession._open_channel(...)` maps `weep:query` to `QueryProfile`
3. `QueryProfile.handle_text(payload, msgno)` is called

File:

- `python/weep/server.py`

### How to answer query now

Current behavior returns a fixed JSON array in `QueryProfile.handle_text`:

```json
{
	"resultType": "array",
	"query": "<incoming query string>",
	"items": [
		{"name": "row1", "value": 123},
		{"name": "row2", "value": 456},
		{"name": "row3", "value": 789}
	]
}
```

To implement real behavior, replace the fixed `items` with your database or
Niagara/BQL adapter result, while keeping request/response field names stable.

### C# equivalent handler (reference)

If you are implementing in C#, the corresponding entry point is:

- `ServerQueryProfile.HandleAsync(payload, msgno)` in `csharp/Weep/Server/Profiles/ServerQueryProfile.cs`
