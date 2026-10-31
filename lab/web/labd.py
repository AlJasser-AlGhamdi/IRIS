#!/usr/bin/env python3
"""lab-web's daemon: applies the state the worker renders into /state, once a second.

Installs the nginx site and page (a config ``nginx -t`` refuses is not applied) and opens or closes the decoy
listeners in ``ports.json``. ``version.json`` is read first (the worker writes it last), so the version
acknowledged in ``applied-web.json`` never runs ahead of the files it covers. Decoys speak just enough
protocol to be identified; no login succeeds, nothing is stored, and no reply carries a version a
release-cycle check could date.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import signal
import string
import struct
import sys
import time

STATE = os.environ.get("LAB_STATE", "/state")
CONF = "/etc/nginx/conf.d/lab.conf"
SITE = "/srv/site/index.html"
ACK = os.path.join(STATE, "applied-web.json")
PID = "/var/run/nginx.pid"
IDLE = 10.0  # seconds a decoy waits on a silent client

FALLBACK_CONF = """server {
    listen 80 default_server;
    server_tokens off;
    location / { return 503; }
}
"""


def log(message: str) -> None:
    print(f"labd {time.strftime('%H:%M:%S')} {message}", flush=True)


def read(name: str) -> bytes | None:
    try:
        with open(os.path.join(STATE, name), "rb") as fh:
            return fh.read()
    except OSError:
        return None


def digest(data: bytes | None) -> str:
    return hashlib.sha256(data or b"").hexdigest()[:16]


def write_atomic(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


# Decoys


def mysql_greeting() -> bytes:
    """A MySQL protocol-10 handshake from a current, supported release (8.4 LTS)."""
    alphabet = (string.ascii_letters + string.digits).encode()
    salt = bytes(secrets.choice(alphabet) for _ in range(20))
    caps = 0xDFFFF7FF
    body = (
        bytes([10])
        + b"8.4.6\x00"
        + struct.pack("<I", secrets.randbelow(2**31))
        + salt[:8]
        + b"\x00"
        + struct.pack("<H", caps & 0xFFFF)
        + bytes([255])
        + struct.pack("<H", 0x0002)
        + struct.pack("<H", caps >> 16)
        + bytes([21])
        + b"\x00" * 10
        + salt[8:]
        + b"\x00"
        + b"caching_sha2_password\x00"
    )
    return len(body).to_bytes(3, "little") + b"\x00" + body


class Decoys:
    def __init__(self) -> None:
        self.servers: dict[int, tuple[str, asyncio.base_events.Server]] = {}
        self.printer_reply = ""

    def handler(self, kind: str):  # noqa: ANN201
        async def close(writer: asyncio.StreamWriter) -> None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), 2)
            except Exception:  # the peer may already be gone
                pass

        async def mysql(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(mysql_greeting())
            await writer.drain()
            if not await asyncio.wait_for(reader.read(1024), IDLE):
                return
            # Any reply to the handshake is refused, as a server refuses an unknown user.
            denied = b"\xff\x15\x04#28000Access denied"
            writer.write(len(denied).to_bytes(3, "little") + b"\x02" + denied)
            await writer.drain()

        async def redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            while True:
                data = await asyncio.wait_for(reader.read(1024), IDLE)
                if not data:
                    return
                writer.write(b"-NOAUTH Authentication required.\r\n")
                await writer.drain()

        async def ipp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            data = await asyncio.wait_for(reader.read(4096), IDLE)
            if not data:
                return
            body = (self.printer_reply or "IPP printer ready").encode("utf-8", "replace") + b"\n"
            head = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            writer.write(head + body)
            await writer.drain()

        async def lpd(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if self.printer_reply:
                writer.write(self.printer_reply.encode("utf-8", "replace") + b"\n")
                await writer.drain()

        async def ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"SSH-2.0-OpenSSH\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), IDLE)

        async def ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"220 FTP service ready\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), IDLE)
                if not line:
                    return
                if line.strip().upper().startswith(b"QUIT"):
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    return
                writer.write(b"530 Please login with USER and PASS.\r\n")
                await writer.drain()

        speak = {"mysql": mysql, "redis": redis, "ipp": ipp, "lpd": lpd, "ssh": ssh, "ftp": ftp}[kind]

        async def run(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await speak(reader, writer)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                await close(writer)

        return run

    async def reconcile(self, wanted: dict[int, str]) -> None:
        for port in list(self.servers):
            if wanted.get(port) != self.servers[port][0]:
                _kind, server = self.servers.pop(port)
                server.close()  # stop accepting; connections in flight end on their own timeout
                log(f"closed decoy {port}")
        for port, kind in sorted(wanted.items()):
            if port in self.servers:
                continue
            server = await asyncio.start_server(self.handler(kind), host="0.0.0.0", port=port, reuse_address=True)
            self.servers[port] = (kind, server)
            log(f"opened decoy {port} ({kind})")


# nginx


async def run(*argv: str) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await proc.communicate()
    return proc.returncode or 0, out.decode("utf-8", "replace")


def nginx_running() -> bool:
    try:
        with open(PID, encoding="ascii") as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    try:  # a zombie (exited, not yet reaped) still answers kill(0)
        with open(f"/proc/{pid}/stat", encoding="ascii") as fh:
            return fh.read().split()[2] != "Z"
    except OSError:
        return False


async def ensure_nginx() -> None:
    if not nginx_running():
        # nginx daemonizes and its master keeps the descriptors it was given: it must inherit the
        # container's own output, never a pipe this process would wait on for ever.
        proc = await asyncio.create_subprocess_exec("nginx")
        log(f"started nginx (exit {await proc.wait()})")


# The loop


class Daemon:
    def __init__(self) -> None:
        self.decoys = Decoys()
        self.applied: dict[str, object] = {"version": -1, "nginx": "", "page": "", "ports": "", "error": None}
        self.acked: dict[str, object] = {}

    async def start(self) -> None:
        os.makedirs(os.path.dirname(SITE), exist_ok=True)
        conf = read("nginx.conf")
        write_atomic(CONF, conf or FALLBACK_CONF.encode())
        page = read("index.html")
        if page is not None:
            write_atomic(SITE, page)
        code, out = await run("nginx", "-t")
        if code != 0:
            log(f"state nginx.conf refused at start, serving fallback: {out.strip()}")
            write_atomic(CONF, FALLBACK_CONF.encode())
            self.applied["error"] = "nginx_conf_invalid"
        else:
            self.applied["nginx"] = digest(conf)
        self.applied["page"] = digest(page)
        await ensure_nginx()

    async def cycle(self) -> None:
        try:
            version = int(json.loads(read("version.json") or b"{}").get("version", 0))
        except (ValueError, AttributeError):
            version = 0
        conf, page, ports = read("nginx.conf"), read("index.html"), read("ports.json")
        reload = False
        if page is not None and digest(page) != self.applied["page"]:
            write_atomic(SITE, page)
            self.applied["page"] = digest(page)
        if conf is not None and digest(conf) != self.applied["nginx"]:
            previous = open(CONF, "rb").read()
            write_atomic(CONF, conf)
            code, out = await run("nginx", "-t")
            if code == 0:
                self.applied["nginx"], self.applied["error"] = digest(conf), None
                reload = True
            else:
                write_atomic(CONF, previous)
                self.applied["nginx"], self.applied["error"] = digest(conf), "nginx_conf_invalid"
                log(f"nginx.conf refused: {out.strip()}")
        await ensure_nginx()
        if reload:
            code, out = await run("nginx", "-s", "reload")
            log(f"nginx reload (exit {code}) {out.strip()}")
            await asyncio.sleep(0.3)  # new workers take over within milliseconds
        if ports is not None and digest(ports) != self.applied["ports"]:
            try:
                table = json.loads(ports)
                wanted = {int(p): str(k) for p, k in table.get("listeners", {}).items()}
                self.decoys.printer_reply = str(table.get("printer_reply") or "")
                await self.decoys.reconcile(wanted)
                self.applied["ports"] = digest(ports)
            except (ValueError, OSError) as exc:
                log(f"ports.json not applied: {exc}")
                self.applied["error"] = "ports_invalid"
        ack = {**self.applied, "version": version, "listening": sorted(self.decoys.servers)}
        if ack != self.acked:
            write_atomic(ACK, json.dumps({**ack, "at": time.time()}).encode())
            self.acked = ack


async def main() -> None:
    daemon = Daemon()
    await daemon.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    log("ready")
    while not stop.is_set():
        try:
            await daemon.cycle()
        except Exception as exc:  # one bad cycle must not end the lab
            log(f"cycle failed: {type(exc).__name__}: {exc}")
        try:
            await asyncio.wait_for(stop.wait(), 1.0)
        except asyncio.TimeoutError:
            pass
    await run("nginx", "-s", "quit")
    log("stopped")


if __name__ == "__main__":
    asyncio.run(main())
    sys.exit(0)
