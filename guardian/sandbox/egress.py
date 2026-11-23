"""Egress allow-list proxy for sandboxed tools.

Sandboxed containers run with `--network=none`, so they cannot open any connection themselves. When a step
needs a registry (today: npm lockfile resolution), Guardian starts this proxy in its own process, listening on
a Unix socket that is mounted into the container. A tiny bridge inside the container (`bridge.js`) exposes the
socket as `127.0.0.1:3128`, and the tool is pointed at it as its HTTPS proxy. That socket is the container's
only way out, and this proxy only allows `CONNECT <allow-listed host>:443`. Plain HTTP, other ports and other
hosts are refused, and every decision is recorded so the report can show what the repository tried to reach.
"""
from __future__ import annotations

import asyncio
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class EgressProxy:
    """Context manager: `with EgressProxy({"registry.npmjs.org"}) as px: ... px.socket_dir ... px.decisions`."""

    allow: set[str]
    decisions: list[dict] = field(default_factory=list)  # {"host", "port", "allowed"} in arrival order

    def __post_init__(self) -> None:
        self.allow = {h.lower() for h in self.allow}
        self.socket_dir = Path(tempfile.mkdtemp(prefix="gsbx-"))  # short path: Unix socket names are limited to ~100 chars
        self.socket = self.socket_dir / "egress.sock"
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True, name="guardian-egress")

    # --- lifecycle -------------------------------------------------------------
    def __enter__(self) -> EgressProxy:
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("egress proxy did not start")
        return self

    def __exit__(self, *exc) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self.socket.unlink(missing_ok=True)
        self.socket_dir.rmdir()

    def _serve(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(asyncio.start_unix_server(self._handle, path=str(self.socket)))
        self.socket.chmod(0o600)  # only our own uid (the container runs as the same uid via --userns=keep-id)
        self._ready.set()
        self._loop.run_forever()

    @property
    def denied(self) -> list[str]:
        return sorted({f"{d['host']}:{d['port']}" for d in self.decisions if not d["allowed"]})

    # --- one client connection -------------------------------------------------
    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            request = (await asyncio.wait_for(cr.readline(), 30)).decode("latin-1").split()
            while (await asyncio.wait_for(cr.readline(), 30)) not in (b"\r\n", b"\n", b""):
                pass  # request headers are not needed
            if len(request) < 2:
                return
            method, target = request[0].upper(), request[1]
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
            else:  # plain HTTP is never allowed: it can be read and changed in transit
                u = urlsplit(target)
                host, port = u.hostname or target, str(u.port or 80)
            host = host.strip("[]").lower()
            allowed = method == "CONNECT" and port == "443" and host in self.allow
            self.decisions.append({"host": host, "port": port, "allowed": allowed})
            if not allowed:
                cw.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await cw.drain()
                return
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, 443), 20)
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cw.drain()
            await asyncio.gather(_pipe(cr, uw), _pipe(ur, cw))
        except (OSError, asyncio.TimeoutError, ValueError):
            pass
        finally:
            cw.close()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
