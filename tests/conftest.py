"""Shared fixtures: tiny local TCP servers that mimic real services."""

from __future__ import annotations

import socket
import threading

import pytest


class FakeServer:
    """Accepts connections on 127.0.0.1 and answers with a canned behaviour."""

    def __init__(self, greeting: bytes = b"", reply_to_request: bytes = b"") -> None:
        self.greeting = greeting
        self.reply = reply_to_request
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                if self.greeting:
                    conn.sendall(self.greeting)
                if self.reply:
                    conn.settimeout(3)
                    if conn.recv(1024):
                        conn.sendall(self.reply)
                else:
                    conn.settimeout(1)
                    conn.recv(1024)
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


@pytest.fixture
def fake_server():
    servers: list[FakeServer] = []

    def make(**kwargs) -> FakeServer:
        srv = FakeServer(**kwargs)
        servers.append(srv)
        return srv

    yield make
    for srv in servers:
        srv.close()


@pytest.fixture
def closed_port() -> int:
    """A localhost port with nothing listening on it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
