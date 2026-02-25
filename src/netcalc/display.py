"""Rich terminal display for netcalc.

All display functions accept data objects from core.py and render
beautiful terminal output using the Rich library.
"""

from __future__ import annotations

import json as json_module
import csv as csv_module
import io
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from netcalc.core import (
    NetworkInfo,
    SubnettingResult,
    VLSMResult,
    ConversionResult,
    SubnetSuggestion,
    ComparisonResult,
)


console = Console()
_quiet_console = Console(quiet=True)


def get_console(no_color: bool = False) -> Console:
    """Return the appropriate console."""
    if no_color:
        return Console(highlight=False, no_color=True)
    return console


# ---------------------------------------------------------------------------
# Network Analysis
# ---------------------------------------------------------------------------

def display_analysis(info: NetworkInfo, *, no_color: bool = False) -> None:
    """Display a full network analysis."""
    c = get_console(no_color)

    # Build the info grid
    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column("Label", style="bold", min_width=20)
    grid.add_column("Value")

    grid.add_row("IP Address", f"[cyan]{info.ip_address}[/]")
    grid.add_row("Network", f"[green]{info.network}[/]")
    grid.add_row("Network Address", f"[green]{info.network_address}[/]")
    grid.add_row("Broadcast Address", f"[green]{info.broadcast_address}[/]")
    grid.add_row(
        "Subnet Mask",
        f"[green]{info.subnet_mask}[/] [dim](/{info.prefix_length})[/]",
    )
    grid.add_row("Wildcard Mask", f"[yellow]{info.wildcard_mask}[/]")

    if info.first_host and info.last_host:
        grid.add_row(
            "Host Range",
            f"[cyan]{info.first_host}[/] → [cyan]{info.last_host}[/]",
        )
    else:
        grid.add_row("Host Range", "[dim]N/A (single host)[/]")

    grid.add_row("Usable Hosts", f"[magenta]{info.host_count:,}[/]")
    grid.add_row("IP Class", f"[blue]{info.ip_class}[/]")
    grid.add_row(
        "Private/Public",
        "[green]Private[/]" if info.is_private else "[red]Public[/]",
    )

    panel = Panel(
        grid,
        title="[bold]Network Analysis[/]",
        border_style="blue",
        padding=(1, 2),
    )
    c.print(panel)

    # Binary breakdown
    bin_grid = Table(show_header=False, box=None, padding=(0, 2))
    bin_grid.add_column("Label", style="bold", min_width=20)
    bin_grid.add_column("Value", style="dim")
    bin_grid.add_row("IP (binary)", info.ip_binary)
    bin_grid.add_row("Mask (binary)", info.mask_binary)
    bin_grid.add_row("Network (binary)", info.network_binary)

    c.print(Panel(
        bin_grid,
        title="[bold]Binary Breakdown[/]",
        border_style="dim",
        padding=(0, 2),
    ))


# ---------------------------------------------------------------------------
# Subnetting
# ---------------------------------------------------------------------------

def display_subnetting(result: SubnettingResult, *, no_color: bool = False) -> None:
    """Display subnetting results in a table."""
    c = get_console(no_color)

    c.print()
    c.print(f"[bold]Original Network:[/] [cyan]{result.original_network}[/]")
    c.print(f"[bold]New Prefix:[/] [yellow]/{result.new_prefix}[/]")
    c.print(f"[bold]Number of Subnets:[/] [magenta]{result.num_subnets}[/]")
    c.print()

    table = Table(
        title="Subnets",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("#", style="dim", justify="right")
    table.add_column("Network", style="green")
    table.add_column("First Host", style="cyan")
    table.add_column("Last Host", style="cyan")
    table.add_column("Broadcast", style="yellow")
    table.add_column("Hosts", justify="right", style="magenta")

    max_display = 64
    for sub in result.subnets[:max_display]:
        table.add_row(
            str(sub.index),
            f"{sub.network}/{sub.prefix_length}",
            sub.first_host or "N/A",
            sub.last_host or "N/A",
            sub.broadcast,
            f"{sub.host_count:,}",
        )

    if result.num_subnets > max_display:
        table.add_row(
            "…", f"… {result.num_subnets - max_display} more subnets …",
            "", "", "", "",
            style="dim",
        )

    c.print(table)


# ---------------------------------------------------------------------------
# VLSM
# ---------------------------------------------------------------------------

def display_vlsm(result: VLSMResult, *, no_color: bool = False) -> None:
    """Display VLSM calculation results."""
    c = get_console(no_color)

    c.print()
    c.print(f"[bold]Base Network:[/] [cyan]{result.base_network}[/]")
    c.print(
        f"[bold]Addresses:[/] [green]{result.used_addresses}[/] used / "
        f"[yellow]{result.remaining_addresses}[/] remaining / "
        f"[dim]{result.total_addresses} total[/]"
    )
    c.print()

    table = Table(
        title="VLSM Allocations",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Required", justify="right", style="bold")
    table.add_column("Network", style="green")
    table.add_column("Mask", style="dim")
    table.add_column("First Host", style="cyan")
    table.add_column("Last Host", style="cyan")
    table.add_column("Allocated", justify="right", style="magenta")
    table.add_column("Wasted", justify="right", style="yellow")

    for entry in result.entries:
        table.add_row(
            str(entry.required_hosts),
            f"{entry.network}/{entry.prefix_length}",
            entry.subnet_mask,
            entry.first_host or "N/A",
            entry.last_host or "N/A",
            str(entry.allocated_hosts),
            str(entry.wasted),
        )

    c.print(table)


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------

def display_conversion(result: ConversionResult, title: str = "Conversion", *, no_color: bool = False) -> None:
    """Display a conversion result."""
    c = get_console(no_color)

    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column("Label", style="bold", min_width=18)
    grid.add_column("Value")

    if result.cidr is not None:
        grid.add_row("CIDR", f"[cyan]/{result.cidr}[/]")
    if result.decimal is not None:
        grid.add_row("Decimal", f"[cyan]{result.decimal}[/]")
    if result.dotted_decimal is not None:
        grid.add_row("Dotted Decimal", f"[green]{result.dotted_decimal}[/]")
    if result.binary is not None:
        grid.add_row("Binary", f"[green]{result.binary[:4]} {result.binary[4:]}[/]")
    if result.dotted_binary is not None:
        grid.add_row("Dotted Binary", f"[green]{result.dotted_binary}[/]")
    if result.hexadecimal is not None:
        grid.add_row("Hexadecimal", f"[yellow]{result.hexadecimal}[/]")

    c.print(Panel(grid, title=f"[bold]{title}[/]", border_style="blue", padding=(0, 2)))


# ---------------------------------------------------------------------------
# Subnet Suggestion
# ---------------------------------------------------------------------------

def display_suggestion(sug: SubnetSuggestion, *, no_color: bool = False) -> None:
    """Display a subnet suggestion."""
    c = get_console(no_color)

    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column("Label", style="bold", min_width=20)
    grid.add_column("Value")

    grid.add_row("Required Hosts", f"[cyan]{sug.required_hosts:,}[/]")
    grid.add_row("Recommended CIDR", f"[green]/{sug.prefix_length}[/]")
    grid.add_row("Subnet Mask", f"[green]{sug.subnet_mask}[/]")
    grid.add_row("Available Hosts", f"[magenta]{sug.available_hosts:,}[/]")
    grid.add_row("Wasted Hosts", f"[yellow]{sug.wasted_hosts:,}[/]")
    grid.add_row("Network Size", f"[dim]{sug.network_size:,} addresses[/]")

    c.print(Panel(
        grid,
        title="[bold]Best Subnet Suggestion[/]",
        border_style="green",
        padding=(1, 2),
    ))


# ---------------------------------------------------------------------------
# Routing Table
# ---------------------------------------------------------------------------

def display_routes(routes: list[dict], fmt: str, *, no_color: bool = False) -> None:
    """Display generated routing commands."""
    c = get_console(no_color)

    table = Table(
        title=f"Routing Table ({fmt.title()} format)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Destination", style="green")
    table.add_column("Command", style="yellow")
    table.add_column("Status", justify="center")

    valid_count = 0
    for route in routes:
        status = "[green]✓[/]" if route["valid"] else "[red]✗[/]"
        table.add_row(
            route["destination"],
            route["command"] if route["valid"] else "[dim]—[/]",
            status,
        )
        if route["valid"]:
            valid_count += 1

    c.print(table)
    c.print(
        f"\n[bold]{valid_count}[/] valid / "
        f"[bold]{len(routes) - valid_count}[/] invalid "
        f"out of [bold]{len(routes)}[/] destinations"
    )


# ---------------------------------------------------------------------------
# Bitwise AND
# ---------------------------------------------------------------------------

def display_bitwise_and(ip: str, mask: str, result: str, *, no_color: bool = False) -> None:
    """Display a bitwise AND result."""
    c = get_console(no_color)

    grid = Table(show_header=False, box=None, padding=(0, 2))
    grid.add_column("Label", style="bold", min_width=18)
    grid.add_column("Value")

    grid.add_row("IP Address", f"[cyan]{ip}[/]")
    grid.add_row("Mask / CIDR", f"[cyan]{mask}[/]")
    grid.add_row("Result (AND)", f"[green bold]{result}[/]")

    c.print(Panel(grid, title="[bold]Bitwise AND[/]", border_style="blue", padding=(0, 2)))


# ---------------------------------------------------------------------------
# Network Comparison
# ---------------------------------------------------------------------------

def display_comparison(result: ComparisonResult, *, no_color: bool = False) -> None:
    """Display a network comparison."""
    c = get_console(no_color)

    grid = Table(show_header=True, box=box.SIMPLE, padding=(0, 2))
    grid.add_column("Property", style="bold", min_width=18)
    grid.add_column("Network A", style="cyan")
    grid.add_column("Network B", style="green")

    grid.add_row("Network", result.network_a, result.network_b)
    grid.add_row("Size", f"{result.size_a:,} addresses", f"{result.size_b:,} addresses")
    grid.add_row("Usable Hosts", f"{result.hosts_a:,}", f"{result.hosts_b:,}")

    c.print(Panel(grid, title="[bold]Network Comparison[/]", border_style="blue", padding=(0, 2)))

    # Relationship
    rel_grid = Table(show_header=False, box=None, padding=(0, 2))
    rel_grid.add_column("Label", style="bold", min_width=18)
    rel_grid.add_column("Value")

    if result.a_contains_b:
        rel_grid.add_row("Relationship", "[yellow]A contains B[/]")
    elif result.b_contains_a:
        rel_grid.add_row("Relationship", "[yellow]B contains A[/]")
    elif result.overlap:
        rel_grid.add_row("Relationship", "[red]Overlapping[/]")
    else:
        rel_grid.add_row("Relationship", "[green]No overlap[/]")

    overlap_icon = "[green]✓[/]" if result.overlap else "[dim]✗[/]"
    rel_grid.add_row("Overlap", overlap_icon)
    rel_grid.add_row("Shared Prefix", f"/{result.shared_prefix}")

    c.print(Panel(rel_grid, title="[bold]Relationship[/]", border_style="dim", padding=(0, 2)))


# ---------------------------------------------------------------------------
# Machine-readable output
# ---------------------------------------------------------------------------

def output_json(data: Any, *, no_color: bool = False) -> None:
    """Print data as formatted JSON."""
    c = get_console(no_color)
    if hasattr(data, "to_dict"):
        data = data.to_dict()
    c.print_json(json_module.dumps(data, indent=2, default=str))


def output_csv(rows: list[dict], *, no_color: bool = False) -> None:
    """Print data as CSV to stdout."""
    if not rows:
        return
    buf = io.StringIO()
    writer = csv_module.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    print(buf.getvalue(), end="")
