"""AgentForge CLI entrypoint.

Placeholder — agent loop and subcommands will be added during MVP-Tue.
"""

from __future__ import annotations

import typer
from rich.console import Console

from agentforge import __version__

app = typer.Typer(
    name="agentforge",
    help="Autonomous multi-agent adversarial-evaluation platform.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the AgentForge version."""
    console.print(f"agentforge {__version__}")


@app.command()
def status() -> None:
    """Show platform status (stub — will surface findings DB summary at MVP)."""
    console.print("[yellow]Not implemented yet — coming in MVP-Tue.[/yellow]")


if __name__ == "__main__":
    app()
