import pytest

from yaml_to_vault.onepassword import OnePasswordError, OnePasswordResolver


class _Result:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_resolve_returns_value(mocker):
    mocker.patch("shutil.which", return_value="/usr/local/bin/op")
    run = mocker.patch("subprocess.run", return_value=_Result(0, "secret-value\n"))
    resolver = OnePasswordResolver()
    assert resolver.resolve("op://V/I/f") == "secret-value"
    run.assert_called_once()


def test_resolve_caches(mocker):
    mocker.patch("shutil.which", return_value="/usr/local/bin/op")
    run = mocker.patch("subprocess.run", return_value=_Result(0, "v\n"))
    resolver = OnePasswordResolver()
    resolver.resolve("op://V/I/f")
    resolver.resolve("op://V/I/f")
    assert run.call_count == 1


def test_resolve_op_missing(mocker):
    mocker.patch("shutil.which", return_value=None)
    resolver = OnePasswordResolver()
    with pytest.raises(OnePasswordError, match="not found in PATH"):
        resolver.resolve("op://V/I/f")


def test_resolve_op_failure(mocker):
    mocker.patch("shutil.which", return_value="/usr/local/bin/op")
    mocker.patch(
        "subprocess.run",
        return_value=_Result(1, "", "not signed in"),
    )
    resolver = OnePasswordResolver()
    with pytest.raises(OnePasswordError, match="not signed in"):
        resolver.resolve("op://V/I/f")


def test_resolve_many_dedupes(mocker):
    mocker.patch("shutil.which", return_value="/usr/local/bin/op")
    run = mocker.patch("subprocess.run", return_value=_Result(0, "v\n"))
    resolver = OnePasswordResolver()
    out = resolver.resolve_many(["op://V/I/f", "op://V/I/f", "op://V/I/g"])
    assert out == {"op://V/I/f": "v", "op://V/I/g": "v"}
    assert run.call_count == 2


def test_resolve_os_error(mocker):
    mocker.patch("shutil.which", return_value="/usr/local/bin/op")
    mocker.patch("subprocess.run", side_effect=OSError("exec format error"))
    resolver = OnePasswordResolver()
    with pytest.raises(OnePasswordError, match="Failed to invoke"):
        resolver.resolve("op://V/I/f")
