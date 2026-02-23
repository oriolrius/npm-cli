"""Output formatting utilities."""

import json
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

console = Console()


def format_output(data: Any, output_format: str = "table", columns: list | None = None) -> None:
    """Format and print output."""
    if output_format == "json":
        console.print_json(json.dumps(data, indent=2, default=str))
    elif output_format == "yaml":
        console.print(yaml.dump(data, default_flow_style=False))
    elif output_format == "table":
        if isinstance(data, list) and len(data) > 0:
            print_table(data, columns)
        elif isinstance(data, dict):
            print_dict(data)
        else:
            console.print(data)
    else:
        console.print(data)


def print_table(data: list[dict], columns: list | None = None) -> None:
    """Print data as a table."""
    if not data:
        console.print("[dim]No data[/dim]")
        return

    # Determine columns
    if columns is None:
        columns = list(data[0].keys())

    table = Table(show_header=True, header_style="bold cyan")

    for col in columns:
        table.add_column(col.replace("_", " ").title())

    for row in data:
        values = []
        for col in columns:
            val = row.get(col, "")
            # Format special values
            if isinstance(val, bool):
                val = "✓" if val else "✗"
            elif isinstance(val, list):
                val = ", ".join(str(v) for v in val[:3])
                if len(row.get(col, [])) > 3:
                    val += "..."
            elif val is None:
                val = "-"
            values.append(str(val))
        table.add_row(*values)

    console.print(table)


def print_dict(data: dict, title: str | None = None) -> None:
    """Print dictionary as key-value pairs."""
    if title:
        console.print(f"[bold]{title}[/bold]")

    table = Table(show_header=False, box=None)
    table.add_column("Key", style="cyan")
    table.add_column("Value")

    for key, value in data.items():
        if isinstance(value, bool):
            value = "✓" if value else "✗"
        elif isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            value = json.dumps(value, indent=2)
        elif value is None:
            value = "-"
        table.add_row(key.replace("_", " ").title(), str(value))

    console.print(table)


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print error message."""
    console.print(f"[red]✗[/red] {message}")


def print_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[yellow]![/yellow] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[blue]ℹ[/blue] {message}")
