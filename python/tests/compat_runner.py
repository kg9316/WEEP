import asyncio
import os
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from weep import AuthClient, FileTransferClient, StreamChannel, WeepClient  # noqa: E402


class RunnerError(RuntimeError):
    pass


def ensure_fixtures() -> None:
    files = ROOT / "files"
    data = files / "data"
    data.mkdir(parents=True, exist_ok=True)
    sensor = data / "sensor_data.bin"
    if not sensor.exists() or sensor.stat().st_size != 4096:
        payload = bytearray(4096)
        for i in range(4096):
            payload[i] = (i * 13 + 7) % 256
        sensor.write_bytes(payload)


async def run_command(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        out, err = await proc.communicate()
        raise RunnerError(f"Command timed out: {' '.join(cmd)}\n{out.decode()}\n{err.decode()}")
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


async def start_process(cmd: list[str], env: dict | None = None) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *cmd,
        cwd=str(ROOT),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


def check_http_contains(url: str, expected: str) -> None:
    with urlopen(url, timeout=5) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status != 200:
            raise RunnerError(f"HTTP {resp.status} for {url}")
        if expected not in body:
            raise RunnerError(f"Expected marker not found at {url}")


async def wait_http(url: str, expected: str, retries: int = 40) -> None:
    last = None
    for _ in range(retries):
        try:
            check_http_contains(url, expected)
            return
        except Exception as ex:  # noqa: BLE001
            last = ex
            await asyncio.sleep(0.25)
    raise RunnerError(f"Server did not become ready at {url}: {last}")


async def stop_process(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=8)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


async def python_client_smoke(ws_url: str) -> None:
    client = WeepClient()
    await client.connect(ws_url)
    auth = AuthClient(client)
    await auth.wait_for_greeting()
    await auth.login_with_scram("admin", "admin")

    ft = FileTransferClient(client)
    await ft.open()

    listing = await ft.list("/")
    assert "entries" in listing

    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "py_upload.txt"
        dst = Path(td) / "py_download.txt"
        content = ("python-client-test\n" * 32).encode("utf-8")
        src.write_bytes(content)

        await ft.upload(str(src), "/py_upload.txt")
        await ft.download("/py_upload.txt", str(dst))
        if dst.read_bytes() != content:
            raise RunnerError("Python upload/download mismatch")

    await ft.close()
    await client.close()


async def python_stream_smoke(ws_url: str) -> None:
    client = WeepClient()
    await client.connect(ws_url)
    auth = AuthClient(client)
    await auth.wait_for_greeting()
    await auth.login_with_scram("admin", "admin")

    stream = StreamChannel(client)
    await stream.open(mime="application/octet-stream")
    await stream.write(b"stream-chunk-1")
    await stream.write(b"stream-chunk-2")
    await stream.close_write()
    await stream.close()
    await client.close()


async def run_matrix() -> None:
    ensure_fixtures()
    csharp_port = 9643
    python_port = 9655

    print("[1/5] Start C# server and verify JS page")
    csharp_server = await start_process(
        [
            "dotnet",
            "run",
            "--no-build",
            "--project",
            "csharp/Weep.TestRunner/Weep.TestRunner.csproj",
            "--",
            "--server-only",
            "--port",
            str(csharp_port),
        ]
    )
    try:
        await wait_http(f"http://localhost:{csharp_port}/", "File Browser")

        print("[2/5] Python client against C# server")
        await python_client_smoke(f"ws://localhost:{csharp_port}/weep")
        await python_stream_smoke(f"ws://localhost:{csharp_port}/weep")
    finally:
        await stop_process(csharp_server)

    print("[3/5] Start Python server and verify JS page")
    py_env = os.environ.copy()
    py_env["PYTHONPATH"] = str(PYTHON_DIR) + (os.pathsep + py_env.get("PYTHONPATH", ""))
    py_server = await start_process(
        [sys.executable, "-m", "weep.server", "--port", str(python_port)],
        env=py_env,
    )
    try:
        await wait_http(f"http://localhost:{python_port}/", "File Browser")

        print("[4/5] C# client against Python server")
        rc, out, err = await run_command(
            [
                "dotnet",
                "run",
                "--no-build",
                "--project",
                "csharp/Weep.TestRunner/Weep.TestRunner.csproj",
                "--",
                "--port",
                str(python_port),
            ],
            timeout=420,
        )
        if rc != 0:
            raise RunnerError(f"C# client vs Python server failed\nSTDOUT:\n{out}\nSTDERR:\n{err}")

        print("[5/5] Python client against Python server")
        await python_client_smoke(f"ws://localhost:{python_port}/weep")
        await python_stream_smoke(f"ws://localhost:{python_port}/weep")
    finally:
        await stop_process(py_server)

    print("All compatibility tests passed.")


def main() -> None:
    try:
        asyncio.run(run_matrix())
    except Exception as ex:  # noqa: BLE001
        print(f"Compatibility run failed: {ex}")
        raise


if __name__ == "__main__":
    main()
