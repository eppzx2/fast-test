from pathlib import Path


SCRIPT = Path("bin/fast-cli")


def test_fast_cli_bootstraps_virtualenv_and_requirements():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'VENV_DIR="$ROOT_DIR/.venv"' in text
    assert 'python3-venv' in text
    assert 'python3-pip' in text
    assert '-m venv "$VENV_DIR"' in text
    assert '-r "$REQUIREMENTS"' in text
    assert 'touch "$INSTALL_MARKER"' in text


def test_fast_cli_runs_cli_with_virtualenv_python_and_forwards_args():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'exec "$VENV_DIR/bin/python" "$ROOT_DIR/cli.py" "$@"' in text
    assert 'set -- --help' in text
