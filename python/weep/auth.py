import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class User:
    username: str
    password_salt: str
    password_iterations: int
    password_key: str
    roles: list[str]


class UserStore:
    DEFAULT_ITERATIONS = 120_000

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add_user(self, username: str, password: str, *roles: str) -> None:
        salt, iterations, key = self.hash_password(password)
        self._users[username] = User(
            username=username,
            password_salt=salt,
            password_iterations=iterations,
            password_key=key,
            roles=list(roles) if roles else ["read"],
        )

    def get_user(self, username: str) -> User | None:
        return self._users.get(username)

    @staticmethod
    def hash_password(password: str) -> tuple[str, int, str]:
        salt = secrets.token_hex(16)
        iterations = UserStore.DEFAULT_ITERATIONS
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt),
            iterations,
            dklen=32,
        ).hex()
        return salt, iterations, key


class ServerAuthHandler:
    def __init__(self, store: UserStore, server_nonce: str) -> None:
        self._store = store
        self._server_nonce = server_nonce
        self._pending_scram: dict[str, tuple[str, str]] = {}

    async def handle(self, payload: dict, msgno: int) -> tuple[dict | None, str | None]:
        mechanism = payload.get("mechanism", "")
        if mechanism == "auth:scram-sha256":
            return await self._scram(payload, msgno)
        return None, "unsupported"

    async def _scram(self, payload: dict, msgno: int) -> tuple[dict | None, str | None]:
        username = str(payload.get("username", ""))
        client_nonce = payload.get("clientNonce")
        client_proof = payload.get("clientProof")

        if not username:
            return None, "username required"

        if client_proof is None:
            if not client_nonce:
                return None, "clientNonce required"
            user = self._store.get_user(username)
            if user is None:
                return None, "Invalid credentials"
            combined_nonce = self._server_nonce + str(client_nonce)
            shared_key = hmac.new(
                bytes.fromhex(user.password_key),
                combined_nonce.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            server_proof = hmac.new(
                bytes.fromhex(shared_key),
                f"server:{combined_nonce}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self._pending_scram[username] = (combined_nonce, shared_key)
            return {
                "type": "RPY",
                "channel": 0,
                "msgno": msgno,
                "payload": {
                    "combinedNonce": combined_nonce,
                    "serverProof": server_proof,
                    "salt": user.password_salt,
                    "iterations": user.password_iterations,
                },
            }, None

        state = self._pending_scram.pop(username, None)
        user = self._store.get_user(username)
        if state is None or user is None:
            return None, "Invalid credentials"

        combined_nonce, shared_key = state
        expected = hmac.new(
            bytes.fromhex(shared_key),
            f"client:{combined_nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, str(client_proof)):
            return None, "Invalid credentials"

        return {
            "type": "RPY",
            "channel": 0,
            "msgno": msgno,
            "payload": {
                "ok": True,
                "username": user.username,
                "roles": user.roles,
            },
        }, user.username
