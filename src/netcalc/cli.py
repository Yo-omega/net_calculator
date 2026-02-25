"""Click-based CLI for netcalc.

Provides the `netcalc` command group with subcommands for every feature.
Uses a custom Click group that allows bare `netcalc <network>` shorthand
alongside proper subcommands.
"""

from __future__ import annotations

import sys
from typing import Optional

import click
from rich.console import Console

from netcalc import __version__
from netcalc import core
from netcalc import display


# ---------------------------------------------------------------------------
# Custom group to allow  `netcalc <network>`  shorthand
# ---------------------------------------------------------------------------

class SmartGroup(click.Group):
    """A Click group that treats unrecognized first args as network inputs.

    This allows `netcalc 192.168.1.0/24` to work as a shorthand for
    `netcalc analyze 192.168.1.0/24`.
    """

    def parse_args(self, ctx, args):
        """If the first non-option arg isn't a known command, insert 'analyze'."""
        # Find the first non-option argument
        if args:
            # Skip global options to find the first positional
            i = 0
            while i < len(args):
                if args[i].startswith("-"):
                    # Skip flag
                    if args[i] in ("-f", "--format"):
                        i += 2  # skip flag + value
                    else:
                        i += 1
                else:
                    break

            if i < len(args) and args[i] not in self.commands:
                # Not a known subcommand → treat as `analyze <network>`
                args = args[:i] + ["analyze"] + args[i:]

        return super().parse_args(ctx, args)


# ---------------------------------------------------------------------------
# Shared context
# ---------------------------------------------------------------------------

class NetcalcContext:
    """Holds global options passed through Click context."""

    def __init__(self, output_format: str = "table", no_color: bool = False):
        self.output_format = output_format
        self.no_color = no_color


pass_ctx = click.make_pass_decorator(NetcalcContext, ensure=True)


# ---------------------------------------------------------------------------
# Main group
# ---------------------------------------------------------------------------

@click.group(cls=SmartGroup, invoke_without_command=True)
@click.version_option(__version__, prog_name="netcalc")
@click.option(
    "-f", "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv"], case_sensitive=False),
    default="table",
    help="Output format (table, json, csv).",
)
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.pass_context
def cli(ctx, output_format: str, no_color: bool) -> None:
    """netcalc — A powerful CLI network calculator.

    \b
    Quick usage (no subcommand needed):
        netcalc 192.168.1.0/24
        netcalc 10.0.0.1 255.255.255.0

    \b
    Subcommands:
        analyze   Analyze a network
        subnet    Subnet a network
        vlsm      VLSM allocation
        find      Find best subnet for N hosts
        convert   Number/mask conversions
        and       Bitwise AND
        route     Generate routing commands
    """
    ctx.ensure_object(NetcalcContext)
    ctx.obj.output_format = output_format
    ctx.obj.no_color = no_color

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("network")
@pass_ctx
def analyze(ctx: NetcalcContext, network: str) -> None:
    """Analyze a network (addresses, mask, hosts, class).

    \b
    Examples:
        netcalc analyze 192.168.1.10/24
        netcalc analyze "10.0.0.1 255.255.0.0"
        netcalc 172.16.0.1              (shorthand)
    """
    try:
        info = core.analyze(network)
    except ValueError as e:
        msg = str(e)
        if "Expected 4 octets" in msg:
            _error(f"'{network}' doesn't look like a valid IPv4. IPv4 needs 4 octets (e.g., 192.168.1.1).")
        elif "Invalid prefix length" in msg:
            _error(f"Prefix must be between 0 and 32 (e.g., /24).")
        else:
            _error(msg)
        raise SystemExit(1)
    except Exception as e:
        _error(f"Unexpected error: {e}")
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(info, no_color=ctx.no_color)
    elif ctx.output_format == "csv":
        display.output_csv([info.to_dict()], no_color=ctx.no_color)
    else:
        display.display_analysis(info, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# subnet
# ---------------------------------------------------------------------------

@cli.command("subnet")
@click.argument("network")
@click.argument("new_prefix", type=int)
@pass_ctx
def subnet_cmd(ctx: NetcalcContext, network: str, new_prefix: int) -> None:
    """Subnet a network into smaller subnets.

    \b
    Examples:
        netcalc subnet 192.168.0.0/24 26
        netcalc subnet 10.0.0.0/8 12
    """
    try:
        result = core.subnet(network, new_prefix)
    except ValueError as e:
        _error(str(e))
        raise SystemExit(1)
    except Exception as e:
        _error(f"An error occurred during subnetting: {e}")
        raise SystemExit(1)

    if ctx.output_format == "json":
        data = {
            "original_network": result.original_network,
            "new_prefix": result.new_prefix,
            "num_subnets": result.num_subnets,
            "subnets": [
                {
                    "index": s.index,
                    "network": f"{s.network}/{s.prefix_length}",
                    "first_host": s.first_host,
                    "last_host": s.last_host,
                    "broadcast": s.broadcast,
                    "host_count": s.host_count,
                }
                for s in result.subnets
            ],
        }
        display.output_json(data, no_color=ctx.no_color)
    elif ctx.output_format == "csv":
        rows = [
            {
                "index": s.index,
                "network": f"{s.network}/{s.prefix_length}",
                "first_host": s.first_host or "",
                "last_host": s.last_host or "",
                "broadcast": s.broadcast,
                "host_count": s.host_count,
            }
            for s in result.subnets
        ]
        display.output_csv(rows, no_color=ctx.no_color)
    else:
        display.display_subnetting(result, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# vlsm
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("network")
@click.argument("hosts", nargs=-1, type=int, required=True)
@pass_ctx
def vlsm(ctx: NetcalcContext, network: str, hosts: tuple[int, ...]) -> None:
    """VLSM — allocate variable-length subnets by host count.

    \b
    Examples:
        netcalc vlsm 192.168.1.0/24 50 30 10 5
        netcalc vlsm 10.0.0.0/16 1000 500 200
    """
    try:
        result = core.vlsm(network, list(hosts))
    except (ValueError, Exception) as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        data = {
            "base_network": result.base_network,
            "total_addresses": result.total_addresses,
            "used_addresses": result.used_addresses,
            "remaining_addresses": result.remaining_addresses,
            "entries": [
                {
                    "required_hosts": e.required_hosts,
                    "network": f"{e.network}/{e.prefix_length}",
                    "subnet_mask": e.subnet_mask,
                    "first_host": e.first_host,
                    "last_host": e.last_host,
                    "allocated_hosts": e.allocated_hosts,
                    "wasted": e.wasted,
                }
                for e in result.entries
            ],
        }
        display.output_json(data, no_color=ctx.no_color)
    else:
        display.display_vlsm(result, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------

@cli.command("find")
@click.argument("hosts", type=int)
@pass_ctx
def find_cmd(ctx: NetcalcContext, hosts: int) -> None:
    """Find the best subnet for a given number of hosts.

    \b
    Examples:
        netcalc find 50
        netcalc find 1000
    """
    try:
        result = core.find_best_subnet(hosts)
    except (ValueError, Exception) as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(result.__dict__, no_color=ctx.no_color)
    else:
        display.display_suggestion(result, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# convert
# ---------------------------------------------------------------------------

@cli.group()
@pass_ctx
def convert(ctx: NetcalcContext) -> None:
    """Convert between decimal, binary, hex, and CIDR.

    \b
    Subcommands:
        decimal   Convert a decimal octet (0-255)
        binary    Convert an 8-bit binary string
        cidr      Convert a CIDR prefix (0-32) to masks
    """
    pass


@convert.command("decimal")
@click.argument("value", type=int)
@pass_ctx
def convert_decimal(ctx: NetcalcContext, value: int) -> None:
    """Convert a decimal octet (0-255) to binary and hex.

    \b
    Example:
        netcalc convert decimal 192
    """
    try:
        result = core.convert_decimal(value)
    except ValueError as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(result.__dict__, no_color=ctx.no_color)
    else:
        display.display_conversion(result, title=f"Decimal {value}", no_color=ctx.no_color)


@convert.command("binary")
@click.argument("value")
@pass_ctx
def convert_binary(ctx: NetcalcContext, value: str) -> None:
    """Convert an 8-bit binary string to decimal and hex.

    \b
    Example:
        netcalc convert binary 11000000
    """
    try:
        result = core.convert_binary(value)
    except ValueError as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(result.__dict__, no_color=ctx.no_color)
    else:
        display.display_conversion(result, title="Binary Conversion", no_color=ctx.no_color)


@convert.command("cidr")
@click.argument("prefix", type=int)
@pass_ctx
def convert_cidr(ctx: NetcalcContext, prefix: int) -> None:
    """Convert a CIDR prefix (0-32) to mask representations.

    \b
    Example:
        netcalc convert cidr 24
    """
    try:
        result = core.convert_cidr(prefix)
    except ValueError as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(result.__dict__, no_color=ctx.no_color)
    else:
        display.display_conversion(result, title=f"CIDR /{prefix}", no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# bitwise-and
# ---------------------------------------------------------------------------

@cli.command("and")
@click.argument("ip")
@click.argument("mask")
@pass_ctx
def bitwise_and_cmd(ctx: NetcalcContext, ip: str, mask: str) -> None:
    """Perform a bitwise AND between an IP and a mask.

    \b
    Examples:
        netcalc and 192.168.1.100 255.255.255.0
        netcalc and 10.0.0.1 /8
    """
    try:
        result = core.bitwise_and(ip, mask)
    except (ValueError, Exception) as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json({"ip": ip, "mask": mask, "result": result}, no_color=ctx.no_color)
    else:
        display.display_bitwise_and(ip, mask, result, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# route
# ---------------------------------------------------------------------------

@cli.command("route")
@click.argument("next_hop")
@click.argument("destinations", nargs=-1, required=True)
@click.option(
    "--style",
    type=click.Choice(["linux", "cisco", "simple"], case_sensitive=False),
    default="linux",
    help="Routing command format (default: linux).",
)
@pass_ctx
def route_cmd(ctx: NetcalcContext, next_hop: str, destinations: tuple[str, ...], style: str) -> None:
    """Generate routing table commands for destinations.

    \b
    Examples:
        netcalc route 10.0.0.1 192.168.1.0/24 172.16.0.0/12
        netcalc route 10.0.0.1 --style cisco 192.168.0.0/24
    """
    try:
        routes = core.generate_route_commands(list(destinations), next_hop, fmt=style)
    except (ValueError, Exception) as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(routes, no_color=ctx.no_color)
    elif ctx.output_format == "csv":
        display.output_csv(routes, no_color=ctx.no_color)
    else:
        display.display_routes(routes, style, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

@cli.command("compare")
@click.argument("network_a")
@click.argument("network_b")
@pass_ctx
def compare_cmd(ctx: NetcalcContext, network_a: str, network_b: str) -> None:
    """Compare two networks for overlap or containment."""
    try:
        result = core.compare(network_a, network_b)
    except (ValueError, Exception) as e:
        _error(str(e))
        raise SystemExit(1)

    if ctx.output_format == "json":
        display.output_json(result.__dict__, no_color=ctx.no_color)
    else:
        display.display_comparison(result, no_color=ctx.no_color)


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------

@cli.command("batch")
@click.option(
    "--file", "-i",
    "input_file",
    type=click.File("r"),
    default="-",
    help="Input file with one network per line (default: stdin).",
)
@pass_ctx
def batch_cmd(ctx: NetcalcContext, input_file) -> None:
    """Analyze multiple networks from a file or stdin.

    \b
    Examples:
        echo "192.168.1.0/24" | netcalc batch
        netcalc batch -i networks.txt
        netcalc batch -i networks.txt -f json
    """
    import sys

    lines = [line.strip() for line in input_file if line.strip() and not line.startswith("#")]

    if not lines:
        _error("No networks provided. Pipe networks or use -i <file>.")
        raise SystemExit(1)

    results = []
    errors = []
    for line in lines:
        try:
            info = core.analyze(line)
            results.append(info)
        except (ValueError, Exception) as e:
            errors.append({"input": line, "error": str(e)})

    if ctx.output_format == "json":
        data = {
            "results": [r.to_dict() for r in results],
            "errors": errors,
            "total": len(lines),
            "successful": len(results),
            "failed": len(errors),
        }
        display.output_json(data, no_color=ctx.no_color)
    elif ctx.output_format == "csv":
        display.output_csv([r.to_dict() for r in results], no_color=ctx.no_color)
    else:
        c = display.get_console(ctx.no_color)
        for info in results:
            display.display_analysis(info, no_color=ctx.no_color)
            c.print()
        if errors:
            c.print(f"\n[bold red]{len(errors)} error(s):[/]")
            for err in errors:
                c.print(f"  [dim]{err['input']}[/]: {err['error']}")
        c.print(f"\n[bold]{len(results)}[/] successful / [bold]{len(errors)}[/] failed / [bold]{len(lines)}[/] total")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _error(msg: str) -> None:
    """Print an error message to stderr."""
    c = Console(stderr=True)
    c.print(f"[bold red]Error:[/] {msg}")

