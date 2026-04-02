import asyncio
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import websockets
from websockets.client import WebSocketClientProtocol

from .protocol import (
    PROFILE_FILE,
    PROFILE_QUERY,
    PROFILE_STREAM,
    WeepError,
    dumps,
    encode_ack_frame,
    encode_data_frame,
    parse_binary_frame,
)
from .discovery import DiscoveredWeepService, discover_services


class SendWindow:
    def __init__(self, size: int = 8) -> None:
        self._sem = asyncio.Semaphore(size)

    async def acquire(self) -> None:
        await self._sem.acquire()

    def acknowledge(self, _seq: int) -> None:
        self._sem.release()


class WeepClient:
    def __init__(self) -> None:
        self._ws: WebSocketClientProtocol | None = None
        self._send_q: asyncio.PriorityQueue[tuple[int, int, tuple[bool, Any]]] = asyncio.PriorityQueue()
        self._send_counter = 0
        self._send_task: asyncio.Task | None = None
        self._recv_task: asyncio.Task | None = None
        self._msgno = 0
        self._next_channel = 0
        self._channels: dict[int, Any] = {}
        self._on_management: list[Any] = []
        self._greeting: dict | None = None

    @property
    def greeting(self) -> dict | None:
        return self._greeting

    @staticmethod
    async def discover_servers(timeout: float = 2.0) -> list[DiscoveredWeepService]:
        return await discover_services(timeout=timeout)

    async def connect(self, url: str) -> None:
        self._ws = await websockets.connect(url, max_size=2**24)
        self._send_task = asyncio.create_task(self._send_pump())
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
        for task in [self._recv_task, self._send_task]:
            if task is not None:
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass

    def register_channel(self, channel: int, handler: Any) -> None:
        self._channels[channel] = handler

    def add_management_listener(self, callback: Any) -> None:
        self._on_management.append(callback)

    async def send_json(self, obj: dict, priority: int = 0) -> None:
        self._send_counter += 1
        await self._send_q.put((priority, self._send_counter, (True, dumps(obj))))

    async def send_binary(self, data: bytes, priority: int = 1) -> None:
        self._send_counter += 1
        await self._send_q.put((priority, self._send_counter, (False, data)))

    async def open_channel(self, profile: str, handler: Any, chunk_size: int = 65536) -> int:
        self._next_channel += 1
        ch = self._next_channel
        self.register_channel(ch, handler)
        await self.send_json(
            {
                "type": "start",
                "channel": 0,
                "msgno": self.next_msgno(),
                "payload": {"channel": ch, "profile": profile, "chunkSize": chunk_size},
            },
            priority=0,
        )
        await asyncio.sleep(0.15)
        return ch

    async def close_channel(self, ch: int) -> None:
        self._channels.pop(ch, None)
        await self.send_json(
            {
                "type": "close",
                "channel": 0,
                "msgno": self.next_msgno(),
                "payload": {"channel": ch},
            },
            priority=0,
        )

    def next_msgno(self) -> int:
        self._msgno += 1
        return self._msgno

    async def _send_pump(self) -> None:
        while True:
            _p, _o, item = await self._send_q.get()
            is_text, payload = item
            ws = self._ws
            if ws is None:
                return
            if is_text:
                await ws.send(payload)
            else:
                await ws.send(payload)

    async def _recv_loop(self) -> None:
        ws = self._ws
        if ws is None:
            return
        async for message in ws:
            if isinstance(message, str):
                await self._dispatch_text(message)
            else:
                await self._dispatch_binary(bytes(message))

    async def _dispatch_text(self, message: str) -> None:
        node = json.loads(message)
        channel = int(node.get("channel", 0))
        if channel == 0:
            if node.get("type") == "greeting":
                self._greeting = node.get("payload", {})
            for cb in self._on_management:
                await cb(node)
            return

        handler = self._channels.get(channel)
        if handler is not None:
            await handler.handle_text(node)

    async def _dispatch_binary(self, frame: bytes) -> None:
        channel, _seq, _is_ack, _is_final, _data = parse_binary_frame(frame)
        handler = self._channels.get(channel)
        if handler is not None:
            await handler.handle_binary(frame)


@dataclass
class GreetingInfo:
    profiles: list[str]
    auth_mechanisms: list[str]
    server_nonce: str | None


class AuthClient:
    def __init__(self, client: WeepClient) -> None:
        self._client = client
        self._msgno = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._greeting: asyncio.Future = asyncio.get_running_loop().create_future()
        self._client.add_management_listener(self._on_management)

    async def wait_for_greeting(self) -> GreetingInfo:
        payload = await self._greeting
        return GreetingInfo(
            profiles=list(payload.get("profiles", [])),
            auth_mechanisms=list(payload.get("auth", [])),
            server_nonce=payload.get("serverNonce"),
        )

    async def login_with_scram(self, username: str, password: str) -> dict:
        greeting = await self.wait_for_greeting()
        if not greeting.server_nonce:
            raise WeepError(400, "Server did not send serverNonce")

        client_nonce = secrets.token_hex(16)
        step1 = await self._send_auth(
            {
                "mechanism": "auth:scram-sha256",
                "username": username,
                "clientNonce": client_nonce,
            }
        )

        combined_nonce = step1["combinedNonce"]
        server_proof = step1["serverProof"]
        salt = step1["salt"]
        iterations = int(step1["iterations"])
        password_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(str(salt)),
            iterations,
            dklen=32,
        ).hex()
        shared_key = hmac.new(
            bytes.fromhex(password_key),
            combined_nonce.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        expected_server = hmac.new(
            bytes.fromhex(shared_key),
            f"server:{combined_nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if expected_server != server_proof:
            raise WeepError(401, "Server proof mismatch")

        client_proof = hmac.new(
            bytes.fromhex(shared_key),
            f"client:{combined_nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return await self._send_auth(
            {
                "mechanism": "auth:scram-sha256",
                "username": username,
                "clientProof": client_proof,
            }
        )

    async def _send_auth(self, payload: dict) -> dict:
        self._msgno += 1
        msgno = self._msgno
        fut = asyncio.get_running_loop().create_future()
        self._pending[msgno] = fut
        await self._client.send_json(
            {
                "type": "MSG",
                "channel": 0,
                "msgno": msgno,
                "payload": payload,
            },
            priority=0,
        )
        try:
            return await fut
        finally:
            self._pending.pop(msgno, None)

    async def _on_management(self, node: dict) -> None:
        if node.get("type") == "greeting":
            if not self._greeting.done():
                self._greeting.set_result(node.get("payload", {}))
            return

        msgno = int(node.get("msgno", -1))
        fut = self._pending.get(msgno)
        if fut is None:
            return

        payload = node.get("payload", {})
        if node.get("type") == "RPY":
            if not fut.done():
                fut.set_result(payload)
        elif node.get("type") == "ERR":
            if not fut.done():
                fut.set_exception(WeepError(int(payload.get("code", 500)), str(payload.get("message", "Error"))))


class FileTransferClient:
    def __init__(self, client: WeepClient, preferred_chunk_size: int = 65536) -> None:
        self._client = client
        self._preferred_chunk_size = preferred_chunk_size
        self._channel = -1
        self._msgno = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._upload_window: SendWindow | None = None
        self._download_state: DownloadState | None = None
        self._early_frames: list[bytes] = []

    async def open(self) -> None:
        self._channel = await self._client.open_channel(PROFILE_FILE, self, self._preferred_chunk_size)

    async def close(self) -> None:
        await self._client.close_channel(self._channel)

    async def list(self, path: str = "/") -> dict:
        return await self._rpc({"op": "list", "path": path})

    async def stat(self, path: str) -> dict:
        return await self._rpc({"op": "stat", "path": path})

    async def upload(self, local_path: str, remote_path: str) -> None:
        local = Path(local_path)
        req_msgno = self._next_msgno()
        setup = await self._rpc_with_msgno(
            req_msgno,
            {
                "op": "upload",
                "path": remote_path,
                "size": local.stat().st_size,
                "mime": "application/octet-stream",
            },
        )
        chunk_size = int(setup.get("chunkSize", self._preferred_chunk_size))

        confirm_fut = asyncio.get_running_loop().create_future()
        self._pending[req_msgno] = confirm_fut
        window = SendWindow(8)
        self._upload_window = window

        seq = 0
        with local.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                final = len(chunk) < chunk_size or fh.tell() == local.stat().st_size
                await window.acquire()
                frame = encode_data_frame(self._channel, seq, chunk, final)
                await self._client.send_binary(frame, priority=2)
                seq += 1
                if final:
                    break

        try:
            await confirm_fut
        finally:
            self._pending.pop(req_msgno, None)
            self._upload_window = None

    async def download(self, remote_path: str, local_path: str) -> None:
        dest = Path(local_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        state = DownloadState(dest)
        self._download_state = state

        setup = await self._rpc({"op": "download", "path": remote_path})
        state.total_size = int(setup.get("size", 0))

        for frame in self._early_frames:
            await self._deliver_download_frame(frame)
        self._early_frames.clear()

        await state.wait_done()
        self._download_state = None

    async def handle_text(self, node: dict) -> None:
        msgno = int(node.get("msgno", -1))
        fut = self._pending.get(msgno)
        if fut is None:
            return

        payload = node.get("payload", {})
        t = node.get("type")
        if t == "RPY":
            if not fut.done():
                fut.set_result(payload)
        elif t == "ERR":
            if not fut.done():
                fut.set_exception(WeepError(int(payload.get("code", 500)), str(payload.get("message", "Error"))))

    async def handle_binary(self, frame: bytes) -> None:
        channel, seq, is_ack, _is_final, _data = parse_binary_frame(frame)
        if channel != self._channel:
            return

        if is_ack:
            if self._upload_window is not None:
                self._upload_window.acknowledge(seq)
            return

        await self._client.send_binary(encode_ack_frame(self._channel, seq), priority=0)
        if self._download_state is None:
            self._early_frames.append(frame)
        else:
            await self._deliver_download_frame(frame)

    async def _deliver_download_frame(self, frame: bytes) -> None:
        if self._download_state is None:
            return
        _channel, _seq, _is_ack, is_final, data = parse_binary_frame(frame)
        self._download_state.write(data, is_final)

    async def _rpc(self, payload: dict) -> dict:
        return await self._rpc_with_msgno(self._next_msgno(), payload)

    async def _rpc_with_msgno(self, msgno: int, payload: dict) -> dict:
        fut = asyncio.get_running_loop().create_future()
        self._pending[msgno] = fut
        await self._client.send_json(
            {"type": "MSG", "channel": self._channel, "msgno": msgno, "payload": payload},
            priority=0,
        )
        try:
            return await fut
        finally:
            self._pending.pop(msgno, None)

    def _next_msgno(self) -> int:
        self._msgno += 1
        return self._msgno


class DownloadState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.total_size = 0
        self.bytes_received = 0
        self._done = asyncio.get_running_loop().create_future()
        self._fh = path.open("wb")

    def write(self, data: bytes, final: bool) -> None:
        self._fh.write(data)
        self.bytes_received += len(data)
        if final:
            self.complete()

    def complete(self) -> None:
        if not self._done.done():
            self._done.set_result(True)
        self._fh.flush()
        self._fh.close()

    async def wait_done(self) -> None:
        await self._done


class StreamChannel:
    def __init__(self, client: WeepClient, rx_buffer_chunks: int = 64) -> None:
        self._client = client
        self._channel = -1
        self._msgno = 0
        self._tx_seq = 0
        self._rx_seq_next = 0
        self._bytes_tx = 0
        self._bytes_rx = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._rx_queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=rx_buffer_chunks)
        self._closed = False

    @property
    def bytes_sent(self) -> int:
        return self._bytes_tx

    @property
    def bytes_received(self) -> int:
        return self._bytes_rx

    async def open(self, mime: str = "application/octet-stream", metadata: dict[str, str] | None = None) -> None:
        self._channel = await self._client.open_channel(PROFILE_STREAM, self)
        payload: dict[str, Any] = {"op": "open", "mime": mime}
        if metadata is not None:
            payload["metadata"] = metadata
        await self._rpc(payload)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._client.close_channel(self._channel)

    async def write(self, data: bytes) -> None:
        frame = encode_data_frame(self._channel, self._tx_seq, data, final=False)
        self._tx_seq += 1
        self._bytes_tx += len(data)
        await self._client.send_binary(frame, priority=1)

    async def close_write(self) -> None:
        frame = encode_data_frame(self._channel, self._tx_seq, b"", final=True)
        self._tx_seq += 1
        await self._client.send_binary(frame, priority=1)

    async def read_all(self):
        while True:
            chunk = await self._rx_queue.get()
            if chunk is None:
                break
            yield chunk

    async def handle_text(self, node: dict) -> None:
        msgno = int(node.get("msgno", -1))
        t = node.get("type")
        payload = node.get("payload", {})

        if t == "NUL":
            await self._rx_queue.put(None)
            return

        fut = self._pending.get(msgno)
        if fut is None:
            return

        if t == "RPY":
            if not fut.done():
                fut.set_result(payload)
        elif t == "ERR":
            if not fut.done():
                fut.set_exception(
                    WeepError(int(payload.get("code", 500)), str(payload.get("message", "Stream error")))
                )

    async def handle_binary(self, frame: bytes) -> None:
        channel, seq, _is_ack, is_final, data = parse_binary_frame(frame)
        if channel != self._channel:
            return

        if seq != self._rx_seq_next:
            await self._rx_queue.put(None)
            raise WeepError(400, f"Out-of-order seq: expected {self._rx_seq_next}, got {seq}")

        self._rx_seq_next += 1
        self._bytes_rx += len(data)
        await self._rx_queue.put(bytes(data))

        if is_final:
            await self._rx_queue.put(None)

    async def _rpc(self, payload: dict) -> dict:
        msgno = self._next_msgno()
        fut = asyncio.get_running_loop().create_future()
        self._pending[msgno] = fut
        await self._client.send_json(
            {"type": "MSG", "channel": self._channel, "msgno": msgno, "payload": payload},
            priority=0,
        )
        try:
            return await fut
        finally:
            self._pending.pop(msgno, None)

    def _next_msgno(self) -> int:
        self._msgno += 1
        return self._msgno


class QueryClient:
    def __init__(self, client: WeepClient) -> None:
        self._client = client
        self._channel = -1
        self._msgno = 0
        self._pending: dict[int, asyncio.Future] = {}

    async def open(self) -> None:
        self._channel = await self._client.open_channel(PROFILE_QUERY, self)

    async def close(self) -> None:
        await self._client.close_channel(self._channel)

    async def query(self, q: str) -> dict:
        msgno = self._next_msgno()
        fut = asyncio.get_running_loop().create_future()
        self._pending[msgno] = fut
        await self._client.send_json(
            {
                "type": "MSG",
                "channel": self._channel,
                "msgno": msgno,
                "payload": {
                    "op": "query",
                    "q": q,
                },
            },
            priority=0,
        )
        try:
            return await fut
        finally:
            self._pending.pop(msgno, None)

    async def handle_text(self, node: dict) -> None:
        msgno = int(node.get("msgno", -1))
        fut = self._pending.get(msgno)
        if fut is None:
            return

        payload = node.get("payload", {})
        t = node.get("type")
        if t == "RPY":
            if not fut.done():
                fut.set_result(payload)
        elif t == "ERR":
            if not fut.done():
                fut.set_exception(WeepError(int(payload.get("code", 500)), str(payload.get("message", "Error"))))

    async def handle_binary(self, _frame: bytes) -> None:
        return

    def _next_msgno(self) -> int:
        self._msgno += 1
        return self._msgno
