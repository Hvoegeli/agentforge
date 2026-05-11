"""Smoke tests — verify the package imports and the CLI registers."""

from __future__ import annotations


def test_package_imports_and_has_version() -> None:
    import agentforge

    assert agentforge.__version__
    assert isinstance(agentforge.__version__, str)


def test_cli_app_registers() -> None:
    from agentforge.cli import app

    # Typer apps expose registered commands via their click group; existence is enough here.
    assert app is not None
