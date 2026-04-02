import argparse
import asyncio
import json
import mimetypes
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import websockets
from websockets.legacy.server import WebSocketServerProtocol

from .auth import ServerAuthHandler, UserStore
from .protocol import (
    PROFILE_FILE,
    PROFILE_INVOKE,
    PROFILE_PUB,
    PROFILE_QUERY,
    PROFILE_READ,
    PROFILE_STREAM,
    PROFILE_SUB,
    PROFILE_WRITE,
    dumps,
    encode_ack_frame,
    encode_data_frame,
    msg_err,
    msg_ok,
    parse_binary_frame,
)


class SendWindow:
    def __init__(self, size: int = 8) -> None:
        self._sem = asyncio.Semaphore(size)

    async def acquire(self) -> None:
        await self._sem.acquire()

    def acknowledge(self, _seq: int) -> None:
        self._sem.release()


@dataclass
class UploadState:
    msgno: int
    handle: Any
    next_seq: int = 0
    bytes_received: int = 0


class FileProfile:
    def __init__(self, session: "ServerSession", channel: int, base_path: Path, chunk_size: int) -> None:
        self._session = session
        self._channel = channel
        self._base_path = base_path
        self._chunk_size = min(chunk_size, 65536)
        self._upload: UploadState | None = None
        self._download_window: SendWindow | None = None

    async def handle_text(self, payload: dict, msgno: int) -> None:
        op = payload.get("op")
        if op == "list":
            await self._list(msgno, str(payload.get("path", "/")))
            return
        if op == "stat":
            await self._stat(msgno, str(payload.get("path", "/")))
            return
        if op == "upload":
            await self._begin_upload(msgno, str(payload.get("path", "")))
            return
        if op == "download":
            await self._begin_download(msgno, str(payload.get("path", "")))
            return
        await self._session.send_json(msg_err(self._channel, msgno, 400, f"Unknown op: {op}"))

    async def handle_binary(self, frame: bytes) -> None:
        channel, seq, is_ack, is_final, data = parse_binary_frame(frame)
        if channel != self._channel:
            return

        if is_ack:
            if self._download_window is not None:
                self._download_window.acknowledge(seq)
            return

        if self._upload is None:
            return

        if seq != self._upload.next_seq:
            self._upload.handle.close()
            self._upload = None
            await self._session.send_json(msg_err(self._channel, 0, 400, f"Expected seq, got {seq}"))
            return

        self._upload.handle.write(data)
        self._upload.bytes_received += len(data)
        self._upload.next_seq += 1
        await self._session.send_binary(encode_ack_frame(self._channel, seq), priority=0)

        if is_final:
            msgno = self._upload.msgno
            received = self._upload.bytes_received
            self._upload.handle.flush()
            self._upload.handle.close()
            self._upload = None
            await self._session.send_json(
                dumps(
                    {
                        "type": "RPY",
                        "channel": self._channel,
                        "msgno": msgno,
                        "payload": {"ok": True, "bytesReceived": received},
                    }
                )
            )

    def _resolve(self, virtual_path: str) -> Path:
        rel = virtual_path.lstrip("/\\")
        candidate = (self._base_path / rel).resolve()
        base = self._base_path.resolve()
        if base not in candidate.parents and candidate != base:
            raise PermissionError("Path escapes base directory")
        return candidate

    def _to_virtual(self, path: Path) -> str:
        rel = path.resolve().relative_to(self._base_path.resolve()).as_posix()
        return "/" if rel == "." else "/" + rel

    def _entry_json(self, path: Path) -> dict:
        is_file = path.is_file()
        mime, _ = mimetypes.guess_type(path.name)
        return {
            "name": path.name,
            "path": self._to_virtual(path),
            "type": "file" if is_file else "dir",
            "size": path.stat().st_size if is_file else 0,
            "modified": "",
            "mime": mime or "application/octet-stream",
        }

    async def _list(self, msgno: int, virtual_path: str) -> None:
        path = self._resolve(virtual_path)
        if not path.exists() or not path.is_dir():
            await self._session.send_json(msg_err(self._channel, msgno, 404, f"Not a directory: {virtual_path}"))
            return

        entries = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        await self._session.send_json(
            dumps(
                {
                    "type": "RPY",
                    "channel": self._channel,
                    "msgno": msgno,
                    "payload": {
                        "path": self._to_virtual(path),
                        "entries": [self._entry_json(p) for p in entries],
                    },
                }
            )
        )

    async def _stat(self, msgno: int, virtual_path: str) -> None:
        path = self._resolve(virtual_path)
        if not path.exists():
            await self._session.send_json(msg_err(self._channel, msgno, 404, f"Not found: {virtual_path}"))
            return

        await self._session.send_json(
            dumps({"type": "RPY", "channel": self._channel, "msgno": msgno, "payload": self._entry_json(path)})
        )

    async def _begin_upload(self, msgno: int, virtual_path: str) -> None:
        if not virtual_path:
            await self._session.send_json(msg_err(self._channel, msgno, 400, "path required"))
            return
        path = self._resolve(virtual_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._upload = UploadState(msgno=msgno, handle=path.open("wb"))
        await self._session.send_json(
            dumps(
                {
                    "type": "RPY",
                    "channel": self._channel,
                    "msgno": msgno,
                    "payload": {"transferId": secrets.token_hex(8), "chunkSize": self._chunk_size},
                }
            )
        )

    async def _begin_download(self, msgno: int, virtual_path: str) -> None:
        path = self._resolve(virtual_path)
        if not path.exists() or not path.is_file():
            await self._session.send_json(msg_err(self._channel, msgno, 404, f"Not found: {virtual_path}"))
            return

        await self._session.send_json(
            dumps(
                {
                    "type": "RPY",
                    "channel": self._channel,
                    "msgno": msgno,
                    "payload": {
                        "transferId": secrets.token_hex(8),
                        "size": path.stat().st_size,
                        "mime": "application/octet-stream",
                    },
                }
            )
        )
        asyncio.create_task(self._stream_file(path))

    async def _stream_file(self, path: Path) -> None:
        window = SendWindow(8)
        self._download_window = window
        seq = 0
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(self._chunk_size)
                if not chunk:
                    break
                final = len(chunk) < self._chunk_size or fh.tell() == path.stat().st_size
                await window.acquire()
                await self._session.send_binary(encode_data_frame(self._channel, seq, chunk, final), priority=2)
                seq += 1
                if final:
                    break
        self._download_window = None


class StreamProfile:
    def __init__(self, session: "ServerSession", channel: int, rx_buffer_chunks: int = 64) -> None:
        self._session = session
        self._channel = channel
        self._rx_queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=rx_buffer_chunks)
        self._tx_seq = 0
        self._rx_seq_next = 0
        self._bytes_tx = 0
        self._bytes_rx = 0

    @property
    def bytes_sent(self) -> int:
        return self._bytes_tx

    @property
    def bytes_received(self) -> int:
        return self._bytes_rx

    async def handle_text(self, payload: dict, msgno: int) -> None:
        op = payload.get("op")
        if op == "open":
            await self._session.send_json(
                dumps(
                    {
                        "type": "RPY",
                        "channel": self._channel,
                        "msgno": msgno,
                        "payload": {"ok": True},
                    }
                )
            )
            return

        if op == "close":
            await self._rx_queue.put(None)
            await self._session.send_json(
                dumps(
                    {
                        "type": "NUL",
                        "channel": self._channel,
                        "msgno": msgno,
                        "payload": {
                            "bytesReceived": self._bytes_rx,
                            "bytesSent": self._bytes_tx,
                        },
                    }
                )
            )
            return

        await self._session.send_json(msg_err(self._channel, msgno, 400, f"Unknown op: {op}"))

    async def handle_binary(self, frame: bytes) -> None:
        channel, seq, _is_ack, is_final, data = parse_binary_frame(frame)
        if channel != self._channel:
            return

        if seq != self._rx_seq_next:
            await self._rx_queue.put(None)
            return

        self._rx_seq_next += 1
        self._bytes_rx += len(data)
        await self._rx_queue.put(bytes(data))

        if is_final:
            await self._rx_queue.put(None)

    async def write(self, data: bytes) -> None:
        frame = encode_data_frame(self._channel, self._tx_seq, data, final=False)
        self._tx_seq += 1
        self._bytes_tx += len(data)
        await self._session.send_binary(frame, priority=1)

    async def close_write(self) -> None:
        frame = encode_data_frame(self._channel, self._tx_seq, b"", final=True)
        self._tx_seq += 1
        await self._session.send_binary(frame, priority=1)

    async def read_all(self):
        while True:
            chunk = await self._rx_queue.get()
            if chunk is None:
                break
            yield chunk


class QueryProfile:
    def __init__(self, session: "ServerSession", channel: int) -> None:
        self._session = session
        self._channel = channel
        self._fixed_rows = [
            {"name": "row1", "value": 123},
            {"name": "row2", "value": 456},
            {"name": "row3", "value": 789},
        ]

    async def handle_text(self, payload: dict, msgno: int) -> None:
        op = str(payload.get("op", "query")).lower()
        if op != "query":
            await self._session.send_json(msg_err(self._channel, msgno, 400, f"Unknown op: {op}"))
            return

        q = payload.get("q")
        if not isinstance(q, str) or not q.strip():
            await self._session.send_json(msg_err(self._channel, msgno, 400, "q required"))
            return

        await self._session.send_json(
            dumps(
                {
                    "type": "RPY",
                    "channel": self._channel,
                    "msgno": msgno,
                    "payload": {
                        "resultType": "array",
                        "query": q,
                        "items": list(self._fixed_rows),
                    },
                }
            )
        )

    async def handle_binary(self, _frame: bytes) -> None:
        return


class ServerSession:
    def __init__(self, ws: WebSocketServerProtocol, store: UserStore, files_dir: Path, require_auth: bool) -> None:
        self._ws = ws
        self._store = store
        self._files_dir = files_dir
        self._require_auth = require_auth
        self._server_nonce = secrets.token_hex(16)
        self._auth_handler = ServerAuthHandler(store, self._server_nonce)
        self._auth_roles: list[str] | None = None
        self._send_q: asyncio.PriorityQueue[tuple[int, int, tuple[bool, Any]]] = asyncio.PriorityQueue()
        self._send_counter = 0
        self._send_task: asyncio.Task | None = None
        self._channels: dict[int, Any] = {}

    def _is_authenticated(self) -> bool:
        return (not self._require_auth) or self._auth_roles is not None

    async def run(self) -> None:
        self._send_task = asyncio.create_task(self._send_pump())
        await self._send_greeting()
        try:
            async for message in self._ws:
                if isinstance(message, str):
                    await self._dispatch_text(message)
                else:
                    await self._dispatch_binary(bytes(message))
        finally:
            if self._send_task is not None:
                self._send_task.cancel()

    async def send_json(self, text: str) -> None:
        self._send_counter += 1
        await self._send_q.put((0, self._send_counter, (True, text)))

    async def send_binary(self, data: bytes, priority: int = 1) -> None:
        self._send_counter += 1
        await self._send_q.put((priority, self._send_counter, (False, data)))

    async def _send_pump(self) -> None:
        while True:
            _p, _o, item = await self._send_q.get()
            is_text, payload = item
            await self._ws.send(payload if is_text else payload)

    async def _send_greeting(self) -> None:
        await self.send_json(
            dumps(
                {
                    "type": "greeting",
                    "channel": 0,
                    "msgno": 0,
                    "payload": {
                        "profiles": [
                            PROFILE_FILE,
                            PROFILE_STREAM,
                            PROFILE_READ,
                            PROFILE_WRITE,
                            PROFILE_SUB,
                            PROFILE_PUB,
                            PROFILE_INVOKE,
                            PROFILE_QUERY,
                        ],
                        "auth": ["auth:challenge", "auth:scram-sha256"],
                        "version": "1.1",
                        "productName": "weep",
                        "maxChunkSize": 65536,
                        "serverNonce": self._server_nonce,
                        "serverInfo": {"brand": "Weep", "model": "WeepServerPy", "firmware": "1.1.0"},
                    },
                }
            )
        )

    async def _dispatch_text(self, message: str) -> None:
        try:
            node = json.loads(message)
        except json.JSONDecodeError:
            return

        channel = int(node.get("channel", 0))
        msgno = int(node.get("msgno", 0))
        mtype = str(node.get("type", ""))
        payload = node.get("payload", {})

        if channel == 0:
            await self._handle_management(mtype, msgno, payload)
            return

        if not self._is_authenticated():
            await self.send_json(msg_err(channel, msgno, 401, "Not authenticated"))
            return

        handler = self._channels.get(channel)
        if handler is None:
            await self.send_json(msg_err(channel, msgno, 404, f"Channel {channel} not open"))
            return

        await handler.handle_text(payload, msgno)

    async def _dispatch_binary(self, frame: bytes) -> None:
        channel, _seq, _is_ack, _is_final, _data = parse_binary_frame(frame)
        handler = self._channels.get(channel)
        if handler is not None:
            await handler.handle_binary(frame)

    async def _handle_management(self, mtype: str, msgno: int, payload: dict) -> None:
        if mtype == "MSG" and payload.get("mechanism") is not None:
            rpy, auth_user = await self._auth_handler.handle(payload, msgno)
            if rpy is not None:
                await self.send_json(dumps(rpy))
                if auth_user is not None:
                    user = self._store.get_user(auth_user)
                    self._auth_roles = list(user.roles) if user else []
            else:
                await self.send_json(msg_err(0, msgno, 401, "Invalid credentials"))
            return

        if mtype == "start":
            if not self._is_authenticated():
                await self.send_json(msg_err(0, msgno, 401, "Authenticate before opening channels"))
                return
            await self._open_channel(msgno, payload)
            return

        if mtype == "close":
            ch = payload.get("channel")
            if isinstance(ch, int):
                self._channels.pop(ch, None)
            await self.send_json(msg_ok(msgno))
            return

        if mtype == "clientInfo":
            await self.send_json(msg_ok(msgno))
            return

        await self.send_json(msg_err(0, msgno, 400, f"Unknown management message: {mtype}"))

    def _has_permission(self, profile: str) -> bool:
        if not self._require_auth:
            return True
        roles = self._auth_roles or []
        is_admin = "admin" in roles
        can_write = is_admin or "write" in roles
        can_read = is_admin or "read" in roles
        needs_write = profile in {PROFILE_FILE, PROFILE_STREAM, PROFILE_WRITE, PROFILE_PUB, PROFILE_INVOKE}
        return can_write if needs_write else can_read

    async def _open_channel(self, msgno: int, payload: dict) -> None:
        channel = payload.get("channel")
        profile = payload.get("profile")
        if not isinstance(channel, int) or not isinstance(profile, str):
            await self.send_json(msg_err(0, msgno, 400, "channel and profile required"))
            return
        if channel in self._channels:
            await self.send_json(msg_err(0, msgno, 409, f"Channel {channel} already open"))
            return
        if not self._has_permission(profile):
            await self.send_json(msg_err(0, msgno, 403, f"Insufficient roles for {profile}"))
            return

        if profile == PROFILE_FILE:
            negotiated = min(int(payload.get("chunkSize", 65536)), 65536)
            self._channels[channel] = FileProfile(self, channel, self._files_dir, negotiated)
            await self.send_json(msg_ok(msgno))
            return

        if profile == PROFILE_STREAM:
            self._channels[channel] = StreamProfile(self, channel)
            await self.send_json(msg_ok(msgno))
            return

        if profile == PROFILE_QUERY:
            self._channels[channel] = QueryProfile(self, channel)
            await self.send_json(msg_ok(msgno))
            return

        await self.send_json(msg_err(0, msgno, 501, f"Profile not supported: {profile}"))


class WeepServer:
    def __init__(self, host: str = "localhost", port: int = 9555, require_auth: bool = True, files_dir: str = "files") -> None:
        self.host = host
        self.port = port
        self.require_auth = require_auth
        self.files_dir = Path(files_dir)
        self.user_store = UserStore()
        self.user_store.add_user("admin", "admin", "admin", "read", "write")
        self.user_store.add_user("guest", "guest", "read")
        self._server = None

    async def start(self) -> None:
        self.files_dir.mkdir(parents=True, exist_ok=True)

        async def process_request(path: str, request_headers: Any):
            if path == "/":
                html_path = Path("js") / "index.html"
                if html_path.exists():
                    body = html_path.read_bytes()
                    return 200, [
                        ("Content-Type", "text/html; charset=utf-8"),
                        ("Cache-Control", "no-cache"),
                    ], body
                return 404, [("Content-Type", "text/plain")], b"index.html not found"

            if path == "/weep":
                # Friendly hint for users who open /weep directly in a browser tab.
                # Real WebSocket clients send Upgrade: websocket and must pass through.
                upgrade = str(request_headers.get("Upgrade", "")).lower()
                if upgrade != "websocket":
                    body = (
                        b"This endpoint is WebSocket-only. Open http://localhost:9555/ "
                        b"for the web UI, which connects to ws://localhost:9555/weep."
                    )
                    return 400, [("Content-Type", "text/plain; charset=utf-8")], body
            return None

        async def handler(ws: WebSocketServerProtocol, path: str):
            if path != "/weep":
                await ws.close(code=1008, reason="Invalid endpoint")
                return
            session = ServerSession(ws, self.user_store, self.files_dir, self.require_auth)
            await session.run()

        self._server = await websockets.legacy.server.serve(
            handler,
            self.host,
            self.port,
            process_request=process_request,
            max_size=2**24,
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def _main_async() -> None:
    parser = argparse.ArgumentParser(description="Run Python WEEP server")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=9555)
    parser.add_argument("--files", default="files")
    args = parser.parse_args()

    server = WeepServer(host=args.host, port=args.port, files_dir=args.files)
    await server.start()
    print(f"[weep-py] listening on http://{args.host}:{args.port}")
    print(f"[weep-py] web ui:    http://{args.host}:{args.port}/")
    print(f"[weep-py] endpoint:  ws://{args.host}:{args.port}/weep")
    stop = asyncio.Event()

    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


def main() -> None:
    asyncio.run(_main_async())


if __name__ == "__main__":
    main()
