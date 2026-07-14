"""CLI tests: argument handling, IO plumbing, exit codes, JSON mode.

Most tests drive ``peelback.cli.main`` in-process for speed; one subprocess
test proves ``python -m peelback`` is wired up for real.
"""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys

import pytest

from peelback import __version__
from peelback.cli import main
from tokens import gz, make_jws

SRC = os.path.join(os.path.dirname(__file__), os.pardir, "src")


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def fake_stdin(monkeypatch, data: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))


class TestBasicInvocation:
    def test_token_argument_peels_prints_plain_tree_and_exits_zero(self, capsys):
        code, out, err = run(capsys, "aGVsbG8gd29ybGQ=")
        assert code == 0
        assert "peeled 1 layer" in out
        assert "hello world" in out
        assert "\x1b[" not in out  # captured stdout is not a tty → no color
        assert err == ""

    def test_unpeelable_input_exits_one(self, capsys):
        code, out, _ = run(capsys, "just some words")
        assert code == 1
        assert "peeled 0 layers" in out

    def test_stdin_is_read_and_trailing_newline_is_not_part_of_the_token(
        self, capsys, monkeypatch
    ):
        # Without the rstrip, the \r\n would break base64 validation.
        fake_stdin(monkeypatch, b"aGVsbG8gd29ybGQ=\r\n")
        code, out, _ = run(capsys)
        assert code == 0
        assert "hello world" in out

    def test_file_input_is_binary_safe(self, capsys, tmp_path):
        blob = gz(b'{"from": "file"}')
        path = tmp_path / "token.bin"
        path.write_bytes(blob)
        code, out, _ = run(capsys, "--file", str(path))
        assert code == 0
        assert '"from": "file"' in out

    def test_input_errors_exit_two_with_a_reason(self, capsys, tmp_path, monkeypatch):
        path = tmp_path / "t"
        path.write_text("x")
        code, _, err = run(capsys, "sometoken", "--file", str(path))
        assert code == 2 and "not both" in err

        code, _, err = run(capsys, "--file", str(tmp_path / "absent"))
        assert code == 2 and "cannot read" in err

        fake_stdin(monkeypatch, b"\n")
        code, _, err = run(capsys)
        assert code == 2 and "empty input" in err


class TestJsonMode:
    def test_json_trace_is_valid_versioned_and_uses_tree_ids(self, capsys, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        code, out, _ = run(capsys, "--json", token)
        assert code == 0
        payload = json.loads(out)
        assert payload["tool"] == "peelback"
        assert payload["version"] == __version__
        assert payload["layers_peeled"] == 2

        _, json_out, _ = run(capsys, "--json", make_jws())
        children = json.loads(json_out)["root"]["children"]
        assert [c["label"] for c in children] == ["header", "payload", "signature"]
        assert [c["id"] for c in children] == [1, 2, 3]


class TestExtract:
    def test_extract_default_writes_innermost_payload(self, capsysbinary, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        code = main(["--extract", token])
        # --extract writes raw bytes to stdout's buffer.
        out = capsysbinary.readouterr().out
        assert code == 0
        assert json.loads(out) == json.loads(sample_json)

    def test_extract_by_node_id_is_binary_safe_and_bad_ids_fail_cleanly(
        self, capsysbinary, sample_json
    ):
        token = base64.b64encode(gz(sample_json)).decode()
        code = main(["--extract", "--node", "1", token])
        out = capsysbinary.readouterr().out
        assert code == 0
        assert out == gz(sample_json)  # the intermediate gzip blob, verbatim

        code = main(["--extract", "--node", "42", token])
        captured = capsysbinary.readouterr()
        assert code == 2
        assert b"no node #42" in captured.err

    def test_extract_to_file_writes_bytes_exactly(self, capsys, tmp_path, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        target = tmp_path / "inner.json"
        code = main(["--extract", "-o", str(target), token])
        assert code == 0
        assert target.read_bytes() == sample_json
        assert "wrote node" in capsys.readouterr().err

    def test_unwritable_out_path_exits_two_with_a_reason_not_a_traceback(
        self, capsys, tmp_path, sample_json
    ):
        token = base64.b64encode(gz(sample_json)).decode()
        target = tmp_path / "no-such-dir" / "inner.json"
        code = main(["--extract", "-o", str(target), token])
        err = capsys.readouterr().err
        assert code == 2
        assert "cannot write" in err

    def test_node_and_out_without_extract_are_rejected(self, capsys):
        # Silently ignoring them would hide a typo'd command from the user.
        code, _, err = run(capsys, "--node", "1", "aGVsbG8gd29ybGQ=")
        assert code == 2 and "--extract" in err
        code, _, err = run(capsys, "-o", "somewhere", "aGVsbG8gd29ybGQ=")
        assert code == 2 and "--extract" in err


class TestOptions:
    def test_only_and_skip_flags_reach_the_engine(self, capsys, sample_json):
        token = base64.b64encode(gz(sample_json)).decode()
        code, out, _ = run(capsys, "--only", "base64", token)
        assert code == 0
        assert "· gzip ·" not in out  # the gzip layer was never peeled
        code, _, _ = run(capsys, "--skip", "base64", "aGVsbG8gd29ybGQ=")
        assert code == 1
        code, _, err = run(capsys, "--only", "rot13", "aGVsbG8=")
        assert code == 2 and "unknown detector" in err

        strict, _, _ = run(capsys, "--min-confidence", "1.0", "aGVsbG8gd29ybGQ=")
        loose, _, _ = run(capsys, "--min-confidence", "0.30", "deadbeef")
        assert strict == 1
        assert loose == 0

    def test_list_detectors_prints_the_registry(self, capsys):
        code, out, _ = run(capsys, "--list-detectors")
        assert code == 0
        for name in ("jwt", "gzip", "base64", "hex", "url", "base32"):
            assert name in out


class TestEntrypoints:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert capsys.readouterr().out.strip() == f"peelback {__version__}"

    def test_python_dash_m_runs_the_real_cli(self):
        env = dict(os.environ, PYTHONPATH=SRC)
        proc = subprocess.run(
            [sys.executable, "-m", "peelback", "aGVsbG8gd29ybGQ="],
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0
        assert "hello world" in proc.stdout

    def test_downstream_closing_the_pipe_is_not_an_error(self):
        # `peelback "$TOKEN" | head -1` closes stdout early; the CLI must
        # keep its normal exit code and print no traceback.
        env = dict(os.environ, PYTHONPATH=SRC)
        script = (
            "import subprocess, sys\n"
            "proc = subprocess.Popen(\n"
            "    [sys.executable, '-m', 'peelback', 'aGVsbG8gd29ybGQ='],\n"
            "    stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
            "proc.stdout.readline()\n"
            "proc.stdout.close()  # the downstream 'head -1' hangup\n"
            "proc.wait()\n"
            "sys.stderr.buffer.write(proc.stderr.read())\n"
            "sys.exit(proc.returncode)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0
        assert "Traceback" not in proc.stderr
