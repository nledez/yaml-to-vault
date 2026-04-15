"""Tests for the SSH tunnel context manager."""

from __future__ import annotations

import socket
import subprocess
import threading
from unittest.mock import MagicMock, patch

import pytest

from yaml_to_vault.ssh_tunnel import (
    SshTunnelError,
    _parse_local_endpoint,
    _wait_for_port,
    ssh_tunnel,
)


# -- _parse_local_endpoint -------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("ssh -L 127.0.0.1:8888:10.0.0.1:8888 host", ("127.0.0.1", 8888)),
        ("ssh -L 8888:10.0.0.1:8888 host", ("127.0.0.1", 8888)),
        ("ssh -L 0.0.0.0:9200:vault:8200 bastion", ("0.0.0.0", 9200)),
        ("ssh -L [::1]:4443:remote:443 gw", ("[::1]", 4443)),
    ],
)
def test_parse_local_endpoint(command, expected):
    assert _parse_local_endpoint(command) == expected


def test_parse_local_endpoint_no_L_flag():
    with pytest.raises(SshTunnelError, match="Cannot find a -L forward"):
        _parse_local_endpoint("ssh host")


# -- _wait_for_port --------------------------------------------------------


def test_wait_for_port_success():
    """Bind a port, then confirm _wait_for_port returns immediately."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    _, port = srv.getsockname()
    try:
        _wait_for_port("127.0.0.1", port, timeout=2)
    finally:
        srv.close()


def test_wait_for_port_timeout():
    with pytest.raises(SshTunnelError, match="not reachable"):
        _wait_for_port("127.0.0.1", 1, timeout=0.3)


# -- ssh_tunnel context manager --------------------------------------------


@patch("yaml_to_vault.ssh_tunnel.subprocess.Popen")
@patch("yaml_to_vault.ssh_tunnel._wait_for_port")
def test_ssh_tunnel_starts_and_stops(mock_wait, mock_popen):
    proc = MagicMock()
    mock_popen.return_value = proc

    with ssh_tunnel("ssh -L 127.0.0.1:8888:10.0.0.1:8888 bastion") as p:
        assert p is proc

    mock_popen.assert_called_once()
    args = mock_popen.call_args[0][0]
    assert "ssh" in args
    assert "-N" in args
    assert "-L" in args
    mock_wait.assert_called_once_with("127.0.0.1", 8888)
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once()


@patch("yaml_to_vault.ssh_tunnel.subprocess.Popen")
@patch("yaml_to_vault.ssh_tunnel._wait_for_port")
def test_ssh_tunnel_does_not_duplicate_N_flag(mock_wait, mock_popen):
    proc = MagicMock()
    mock_popen.return_value = proc

    with ssh_tunnel("ssh -N -L 127.0.0.1:8888:10.0.0.1:8888 bastion"):
        pass

    args = mock_popen.call_args[0][0]
    assert args.count("-N") == 1


@patch("yaml_to_vault.ssh_tunnel.subprocess.Popen")
@patch("yaml_to_vault.ssh_tunnel._wait_for_port")
def test_ssh_tunnel_kills_on_terminate_timeout(mock_wait, mock_popen):
    proc = MagicMock()
    proc.wait.side_effect = [subprocess.TimeoutExpired("ssh", 5), None]
    mock_popen.return_value = proc

    with ssh_tunnel("ssh -L 127.0.0.1:8888:10.0.0.1:8888 bastion"):
        pass

    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


@patch("yaml_to_vault.ssh_tunnel.subprocess.Popen")
@patch("yaml_to_vault.ssh_tunnel._wait_for_port")
def test_ssh_tunnel_cleans_up_on_error(mock_wait, mock_popen):
    proc = MagicMock()
    mock_popen.return_value = proc

    with pytest.raises(RuntimeError, match="boom"):
        with ssh_tunnel("ssh -L 127.0.0.1:8888:10.0.0.1:8888 bastion"):
            raise RuntimeError("boom")

    proc.terminate.assert_called_once()


@patch("yaml_to_vault.ssh_tunnel.subprocess.Popen")
@patch("yaml_to_vault.ssh_tunnel._wait_for_port")
def test_ssh_tunnel_raises_on_port_wait_failure(mock_wait, mock_popen):
    proc = MagicMock()
    mock_popen.return_value = proc
    mock_wait.side_effect = SshTunnelError("not reachable")

    with pytest.raises(SshTunnelError, match="not reachable"):
        with ssh_tunnel("ssh -L 127.0.0.1:8888:10.0.0.1:8888 bastion"):
            pass

    proc.terminate.assert_called_once()
