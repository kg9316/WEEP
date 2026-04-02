import hashlib
import hmac
import secrets
from dataclasses import dataclass


@dataclass
class User:
    username: str
    password_hash: str
    roles: list[str]


class UserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def add_user(self, username: str, password: str, *roles: str) -> None:
        self._users[username] = User(
            username=username,
            password_hash=self.hash_password(password),
            roles=list(roles) if roles else ["read"],
        )

    def get_user(self, username: str) -> User | None:
        return self._users.get(username)

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


class ServerAuthHandler:
    def __init__(self, store: UserStore, server_nonce: str) -> None:
        self._store = store
        self._server_nonce = server_nonce
        self._pending_challenges: dict[str, str] = {}
        self._pending_scram: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _sha256_hex(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    async def handle(self, payload: dict, msgno: int) -> tuple[dict | None, str | None]:
        mechanism = payload.get("mechanism", "")
        if mechanism == "auth:challenge":
            return await self._challenge(payload, msgno)
        if mechanism == "auth:scram-sha256":
            return await self._scram(payload, msgno)
        return None, "unsupported"

    async def _challenge(self, payload: dict, msgno: int) -> tuple[dict | None, str | None]:
        username = str(payload.get("username", ""))
        response = payload.get("response")
        if not username:
            return None, "username required"

        if response is None:
            nonce = secrets.token_hex(16)
            self._pending_challenges[username] = nonce
            return {
                "type": "RPY",
                "channel": 0,
                "msgno": msgno,
                "payload": {"challenge": nonce},
            }, None

        stored = self._pending_challenges.pop(username, None)
        user = self._store.get_user(username)
        if stored is None or user is None:
            return None, "Invalid credentials"

        expected = self._sha256_hex(f"{username}:{stored}:{user.password_hash}")
        if not hmac.compare_digest(expected, str(response)):
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
            shared_key = self._sha256_hex(f"{user.password_hash}:{combined_nonce}")
            server_proof = self._sha256_hex(f"server:{shared_key}")
            self._pending_scram[username] = (combined_nonce, shared_key)
            return {
                "type": "RPY",
                "channel": 0,
                "msgno": msgno,
                "payload": {
                    "combinedNonce": combined_nonce,
                    "serverProof": server_proof,
                },
            }, None

        state = self._pending_scram.pop(username, None)
        user = self._store.get_user(username)
        if state is None or user is None:
            return None, "Invalid credentials"

        _combined_nonce, shared_key = state
        expected = self._sha256_hex(f"client:{shared_key}")
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
