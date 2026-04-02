import json
import struct
from dataclasses import dataclass


HEADER_SIZE = 7
FLAG_FINAL = 0x01
FLAG_ACK = 0x02

PROFILE_FILE = "weep:file"
PROFILE_STREAM = "weep:stream"
PROFILE_READ = "weep:read"
PROFILE_WRITE = "weep:write"
PROFILE_SUB = "weep:sub"
PROFILE_PUB = "weep:pub"
PROFILE_INVOKE = "weep:invoke"
PROFILE_QUERY = "weep:query"


def encode_data_frame(channel: int, seq: int, data: bytes, final: bool) -> bytes:
    flags = FLAG_FINAL if final else 0
    return struct.pack(">HIB", channel, seq, flags) + data


def encode_ack_frame(channel: int, seq: int) -> bytes:
    return struct.pack(">HIB", channel, seq, FLAG_ACK)


def parse_binary_frame(frame: bytes) -> tuple[int, int, bool, bool, bytes]:
    if len(frame) < HEADER_SIZE:
        raise ValueError("invalid binary frame: too short")
    channel, seq, flags = struct.unpack(">HIB", frame[:HEADER_SIZE])
    is_ack = (flags & FLAG_ACK) != 0 and len(frame) == HEADER_SIZE
    is_final = (flags & FLAG_FINAL) != 0
    data = b"" if is_ack else frame[HEADER_SIZE:]
    return channel, seq, is_ack, is_final, data


def dumps(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"))


def msg_err(channel: int, msgno: int, code: int, message: str) -> str:
    return dumps(
        {
            "type": "ERR",
            "channel": channel,
            "msgno": msgno,
            "payload": {"code": code, "message": message},
        }
    )


def msg_ok(msgno: int) -> str:
    return dumps({"type": "ok", "channel": 0, "msgno": msgno, "payload": {}})


@dataclass
class WeepError(Exception):
    code: int
    message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"
