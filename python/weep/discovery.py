from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Iterable
import ipaddress

from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

SERVICE_TYPE = "_weep._tcp.local."


@dataclass
class DiscoveredWeepService:
    instance_name: str
    host_name: str
    port: int
    path: str
    version: str
    auth_mechanisms: list[str]
    addresses: list[str]

    def build_websocket_url(self) -> str:
        host = _pick_preferred_host(self.addresses) or self.host_name.rstrip(".")
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"ws://{host}:{self.port}{path}"

    def to_dict(self) -> dict:
        return {
            "instanceName": self.instance_name,
            "hostName": self.host_name,
            "port": self.port,
            "path": self.path,
            "version": self.version,
            "authMechanisms": self.auth_mechanisms,
            "addresses": self.addresses,
            "wsUrl": self.build_websocket_url(),
        }


class WeepMdnsAdvertiser:
    def __init__(
        self,
        instance_name: str,
        port: int,
        path: str = "/weep",
        version: str = "1.2",
        auth_mechanisms: Iterable[str] | None = None,
    ) -> None:
        if port < 1 or port > 65535:
            raise ValueError("port must be in range 1..65535")

        self._instance_name = instance_name
        self._port = int(port)
        self._path = path
        self._version = version
        self._auth_mechanisms = list(auth_mechanisms or ["auth:scram-sha256"])

        self._zeroconf: Zeroconf | None = None
        self._service_info: ServiceInfo | None = None

    def start(self) -> None:
        if self._zeroconf is not None:
            return

        host = socket.gethostname()
        server = f"{host}.local."
        addresses = _local_ipv4_addresses()
        props = {
            b"path": self._path.encode("utf-8"),
            b"version": self._version.encode("utf-8"),
            b"auth": ",".join(self._auth_mechanisms).encode("utf-8"),
        }

        self._zeroconf = Zeroconf(ip_version=IPVersion.All)
        self._service_info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self._instance_name}.{SERVICE_TYPE}",
            addresses=addresses,
            port=self._port,
            properties=props,
            server=server,
        )
        self._zeroconf.register_service(self._service_info, allow_name_change=True)

    def stop(self) -> None:
        if self._zeroconf is None:
            return

        if self._service_info is not None:
            try:
                self._zeroconf.unregister_service(self._service_info)
            except Exception:
                pass

        self._zeroconf.close()
        self._zeroconf = None
        self._service_info = None

    async def start_async(self) -> None:
        await asyncio.to_thread(self.start)

    async def stop_async(self) -> None:
        await asyncio.to_thread(self.stop)


class _WeepServiceCollector(ServiceListener):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if type_ == SERVICE_TYPE:
            self.names.add(name)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if type_ == SERVICE_TYPE:
            self.names.add(name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.names.discard(name)


def discover_services_sync(timeout: float = 2.0) -> list[DiscoveredWeepService]:
    zc = Zeroconf(ip_version=IPVersion.All)
    collector = _WeepServiceCollector()
    browser = ServiceBrowser(zc, SERVICE_TYPE, collector)

    try:
        import time
        time.sleep(timeout)

        discovered: list[DiscoveredWeepService] = []
        for name in sorted(collector.names):
            info = zc.get_service_info(SERVICE_TYPE, name, timeout=1000)
            if info is None:
                continue

            props = {
                _decode(k): _decode(v)
                for k, v in info.properties.items()
            }
            path = props.get("path", "/weep")
            version = props.get("version", "1.2")
            auth = [a.strip() for a in props.get("auth", "auth:scram-sha256").split(",") if a.strip()]

            discovered.append(
                DiscoveredWeepService(
                    instance_name=name.removesuffix(SERVICE_TYPE).rstrip("."),
                    host_name=(info.server or "").rstrip("."),
                    port=int(info.port),
                    path=path,
                    version=version,
                    auth_mechanisms=auth,
                    addresses=list(dict.fromkeys(info.parsed_addresses(version=IPVersion.All))),
                )
            )

        return discovered
    finally:
        browser.cancel()
        zc.close()


async def discover_services(timeout: float = 2.0) -> list[DiscoveredWeepService]:
    return await asyncio.to_thread(discover_services_sync, timeout)


def _decode(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _local_ipv4_addresses() -> list[bytes]:
    addrs: set[bytes] = set()
    for fam, _stype, _proto, _canon, sockaddr in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
        if fam != socket.AF_INET:
            continue
        ip = sockaddr[0]
        if ip.startswith("127."):
            continue
        addrs.add(socket.inet_aton(ip))

    if not addrs:
        addrs.add(socket.inet_aton("127.0.0.1"))
    return list(addrs)


def _pick_preferred_host(addresses: list[str]) -> str | None:
    def rank(value: str) -> int:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return 999

        if ip.is_loopback:
            return 0
        if isinstance(ip, ipaddress.IPv4Address):
            first = int(str(ip).split(".")[0])
            second = int(str(ip).split(".")[1])
            if first == 192 and second == 168:
                return 1
            if first == 172 and 16 <= second <= 31:
                return 2
            if first == 10:
                return 3
            if first == 169 and second == 254:
                return 50
            return 10

        return 20 if ip.is_link_local else 15

    if not addresses:
        return None
    return sorted(dict.fromkeys(addresses), key=rank)[0]
