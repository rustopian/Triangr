"""Connection retries and per-call read timeouts in the backend client."""

import socket
import threading
import time

import pytest

from ghidra_mcp.backend import BackendError, GhidraBackend


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_only_connection_failures_are_retried():
    retry = GhidraBackend().session.get_adapter("http://127.0.0.1/").max_retries
    assert retry.connect == 2
    assert retry.read is False
    assert (retry.status, retry.redirect, retry.other) == (0, 0, 0)


def test_connection_refused_is_retried_until_the_backend_comes_up(fake_backend):
    """A backend that starts listening between attempts is reached on a retry."""
    port = free_port()
    fake_backend.ok("/program_info", {"name": "late"})
    target = fake_backend.server.server_address[1]

    def forward_later():
        time.sleep(0.1)
        listener = socket.create_server(("127.0.0.1", port))
        conn, _ = listener.accept()
        with conn, socket.create_connection(("127.0.0.1", target)) as upstream:
            upstream.sendall(conn.recv(65536))
            # The fake backend speaks HTTP/1.0 and closes the connection after replying.
            while chunk := upstream.recv(65536):
                conn.sendall(chunk)
        listener.close()

    threading.Thread(target=forward_later, daemon=True).start()
    backend = GhidraBackend(f"http://127.0.0.1:{port}/", connect_timeout=1)
    assert backend.get("program_info") == {"name": "late"}


def test_post_is_not_resent_when_the_connection_drops_after_sending():
    received = []
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def accept_and_drop():
        listener.settimeout(3)
        try:
            while True:
                conn, _ = listener.accept()
                with conn:
                    received.append(conn.recv(65536))
        except OSError:
            pass

    threading.Thread(target=accept_and_drop, daemon=True).start()
    with pytest.raises(BackendError):
        GhidraBackend(f"http://127.0.0.1:{port}/").post("write_bytes", address="0x1", bytes="90")
    listener.close()
    assert len(received) == 1


def test_read_timeout_can_be_raised_per_call(fake_backend):
    def slow(_params):
        time.sleep(0.5)
        return {"success": True, "data": "done"}

    fake_backend.routes["/decompile_function"] = (200, slow)
    backend = GhidraBackend(fake_backend.url, read_timeout=0.2)
    with pytest.raises(BackendError) as info:
        backend.get("decompile_function")
    assert info.value.code == "BACKEND_TIMEOUT"
    assert backend.request("GET", "decompile_function", read_timeout=5) == "done"
