"""Context manager that opens an SSH tunnel for the duration of a block."""

from __future__ import annotations

import re
import shlex
import socket
import subprocess
import time
from contextlib import contextmanager
from typing import Iterator


class SshTunnelError(Exception):
    """Raised when the SSH tunnel cannot be established."""


_LOCAL_FORWARD_RE = re.compile(
    r"""
    -L\s*                          # the flag itself
    (?:(\[[^\]]+\]|[^:]+):)?       # optional bind_address (IPv6 bracketed or plain)
    (\d+)                          # local port
    :                              # separator
    .+                             # remote_host:remote_port (we don't need these)
    """,
    re.VERBOSE,
)

_CONNECT_TIMEOUT = 15  # seconds to wait for the local port
_POLL_INTERVAL = 0.2


def _parse_local_endpoint(command: str) -> tuple[str, int]:
    """Extract (host, port) of the local side of a ``-L`` forward."""
    match = _LOCAL_FORWARD_RE.search(command)
    if not match:
        raise SshTunnelError(
            f"Cannot find a -L forward specification in: {command}"
        )
    host = match.group(1) or "127.0.0.1"
    port = int(match.group(2))
    return host, port


def _wait_for_port(host: str, port: int, timeout: float = _CONNECT_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(_POLL_INTERVAL)
    raise SshTunnelError(
        f"SSH tunnel port {host}:{port} not reachable after {timeout}s"
    )


@contextmanager
def ssh_tunnel(command: str) -> Iterator[subprocess.Popen[bytes]]:
    """Start an SSH tunnel, wait for the forwarded port, yield, then tear down.

    The command is expected to contain a ``-L`` flag.  ``-N`` is appended
    automatically if not already present so the SSH process stays open
    without executing a remote command.
    """
    args = shlex.split(command)
    if "-N" not in args:
        args.append("-N")

    host, port = _parse_local_endpoint(command)

    proc = subprocess.Popen(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(host, port)
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
