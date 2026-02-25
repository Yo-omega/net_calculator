"""Core network calculation engine.

Uses Python's ipaddress module for correctness, with additional
calculations for educational and engineering use.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NetworkInfo:
    """Complete analysis of a network."""

    ip_address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network
    prefix_length: int
    subnet_mask: ipaddress.IPv4Address
    wildcard_mask: ipaddress.IPv4Address
    network_address: ipaddress.IPv4Address
    broadcast_address: ipaddress.IPv4Address
    first_host: Optional[ipaddress.IPv4Address]
    last_host: Optional[ipaddress.IPv4Address]
    host_count: int
    ip_class: str
    is_private: bool
    ip_binary: str
    mask_binary: str
    network_binary: str

    def to_dict(self) -> dict:
        """Serialize to a plain dictionary."""
        return {
            "ip_address": str(self.ip_address),
            "network": str(self.network),
            "prefix_length": self.prefix_length,
            "subnet_mask": str(self.subnet_mask),
            "wildcard_mask": str(self.wildcard_mask),
            "network_address": str(self.network_address),
            "broadcast_address": str(self.broadcast_address),
            "first_host": str(self.first_host) if self.first_host else None,
            "last_host": str(self.last_host) if self.last_host else None,
            "host_count": self.host_count,
            "ip_class": self.ip_class,
            "is_private": self.is_private,
            "ip_binary": self.ip_binary,
            "mask_binary": self.mask_binary,
            "network_binary": self.network_binary,
        }


@dataclass
class SubnetInfo:
    """Info for a single subnet in a subnetting result."""

    index: int
    network: str
    prefix_length: int
    subnet_mask: str
    first_host: Optional[str]
    last_host: Optional[str]
    broadcast: str
    host_count: int


@dataclass
class SubnettingResult:
    """Result of a subnetting operation."""

    original_network: str
    original_prefix: int
    new_prefix: int
    num_subnets: int
    subnets: list[SubnetInfo] = field(default_factory=list)


@dataclass
class VLSMEntry:
    """A single VLSM allocation."""

    required_hosts: int
    network: str
    prefix_length: int
    subnet_mask: str
    first_host: Optional[str]
    last_host: Optional[str]
    broadcast: str
    allocated_hosts: int
    wasted: int


@dataclass
class VLSMResult:
    """Result of a VLSM calculation."""

    base_network: str
    base_prefix: int
    total_addresses: int
    used_addresses: int
    remaining_addresses: int
    entries: list[VLSMEntry] = field(default_factory=list)


@dataclass
class ConversionResult:
    """Result of a number/mask conversion."""

    decimal: Optional[int] = None
    binary: Optional[str] = None
    hexadecimal: Optional[str] = None
    cidr: Optional[int] = None
    dotted_decimal: Optional[str] = None
    dotted_binary: Optional[str] = None


@dataclass
class SubnetSuggestion:
    """Suggestion for the best subnet for N hosts."""

    required_hosts: int
    prefix_length: int
    subnet_mask: str
    available_hosts: int
    wasted_hosts: int
    network_size: int


@dataclass
class ComparisonResult:
    """Result of comparing two networks."""

    network_a: str
    network_b: str
    overlap: bool
    a_contains_b: bool
    b_contains_a: bool
    shared_prefix: int
    size_a: int
    size_b: int
    hosts_a: int
    hosts_b: int


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _ip_to_binary(ip: ipaddress.IPv4Address) -> str:
    """Convert an IPv4 address to dotted binary notation."""
    octets = str(ip).split(".")
    return ".".join(f"{int(o):08b}" for o in octets)


def _classify_ip(ip: ipaddress.IPv4Address) -> str:
    """Return the classful network class of an IP address."""
    first_octet = int(ip) >> 24
    if first_octet < 128:
        return "A"
    elif first_octet < 192:
        return "B"
    elif first_octet < 224:
        return "C"
    elif first_octet < 240:
        return "D (Multicast)"
    else:
        return "E (Reserved)"


def _hosts_to_prefix(hosts: int) -> int:
    """Calculate the smallest prefix length that can hold *hosts* usable hosts."""
    if hosts <= 0:
        return 32
    # Need hosts + 2 addresses (network + broadcast). 
    # For /31 and /32, this math changes but we handle that in analyze().
    needed = hosts + 2
    bits = math.ceil(math.log2(needed)) if needed > 1 else 1
    return max(32 - bits, 0)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_network(text: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]:
    """Parse flexible network input formats.

    Supported formats:
        - "192.168.1.10/24"          (CIDR)
        - "192.168.1.10 255.255.255.0" (IP + mask)
        - "192.168.1.10 24"          (IP + prefix)
        - "192.168.1.10"             (bare IP → /32)

    Returns:
        Tuple of (original_ip, network).

    Raises:
        ValueError: If the input cannot be parsed.
    """
    text = text.strip()

    # Try CIDR notation first  (192.168.1.10/24)
    if "/" in text:
        parts = text.split("/", 1)
        ip = ipaddress.IPv4Address(parts[0].strip())
        prefix = int(parts[1].strip())
        if not 0 <= prefix <= 32:
            raise ValueError(f"Invalid prefix length: {prefix}")
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return ip, network

    # Try space-separated  (IP mask  or  IP prefix)
    if " " in text:
        parts = text.split(None, 1)
        ip = ipaddress.IPv4Address(parts[0].strip())
        second = parts[1].strip()

        # Check if it's a prefix length (just a number)
        try:
            prefix = int(second)
            if 0 <= prefix <= 32:
                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                return ip, network
        except ValueError:
            pass

        # Must be a dotted-decimal mask
        mask = ipaddress.IPv4Address(second)
        prefix = _mask_to_prefix(mask)
        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return ip, network

    # Bare IP → /32
    ip = ipaddress.IPv4Address(text)
    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
    return ip, network


def _mask_to_prefix(mask: ipaddress.IPv4Address) -> int:
    """Convert a dotted-decimal mask to a prefix length.

    Raises ValueError if the mask is non-contiguous.
    """
    mask_int = int(mask)
    # Check contiguity: after the leading 1s, there should be only 0s.
    # An easy way to check this is (inverted & (inverted + 1)) == 0.
    if mask_int == 0:
        return 0
    # Invert, add 1 — must be a power of 2
    inverted = (~mask_int) & 0xFFFFFFFF
    if (inverted & (inverted + 1)) != 0:
        raise ValueError(f"Non-contiguous subnet mask: {mask}")
    return bin(mask_int).count("1")


def analyze(text: str) -> NetworkInfo:
    """Analyze a network and return comprehensive info."""
    ip, network = parse_network(text)
    prefix = network.prefixlen
    mask = network.netmask
    wildcard = network.hostmask

    net_addr = network.network_address
    bcast = network.broadcast_address

    if prefix == 32:
        first_host = None
        last_host = None
        host_count = 1  # It's a single host
    elif prefix == 31:
        # Point-to-point link (RFC 3021). No dedicated network/broadcast.
        first_host = net_addr
        last_host = bcast
        host_count = 2
    else:
        # Standard network: first usable is .1, last is .254 for /24
        first_host = ipaddress.IPv4Address(int(net_addr) + 1)
        last_host = ipaddress.IPv4Address(int(bcast) - 1)
        host_count = network.num_addresses - 2

    return NetworkInfo(
        ip_address=ip,
        network=network,
        prefix_length=prefix,
        subnet_mask=mask,
        wildcard_mask=wildcard,
        network_address=net_addr,
        broadcast_address=bcast,
        first_host=first_host,
        last_host=last_host,
        host_count=host_count,
        ip_class=_classify_ip(ip),
        is_private=ip.is_private,
        ip_binary=_ip_to_binary(ip),
        mask_binary=_ip_to_binary(mask),
        network_binary=_ip_to_binary(net_addr),
    )


def subnet(network_str: str, new_prefix: int) -> SubnettingResult:
    """Subnet a network into smaller subnets.

    Args:
        network_str: The network to subnet (e.g. "192.168.0.0/24").
        new_prefix: The new, larger prefix length (e.g., 26).

    Returns:
        SubnettingResult with all subnets.

    Raises:
        ValueError: If the new prefix is invalid.
    """
    _, network = parse_network(network_str)
    original_prefix = network.prefixlen

    if new_prefix <= original_prefix:
        raise ValueError(
            f"New prefix /{new_prefix} must be larger than "
            f"original /{original_prefix}"
        )
    if new_prefix > 32:
        raise ValueError(f"Prefix cannot exceed 32, got {new_prefix}")

    subnets_list = list(network.subnets(new_prefix=new_prefix))

    result = SubnettingResult(
        original_network=str(network),
        original_prefix=original_prefix,
        new_prefix=new_prefix,
        num_subnets=len(subnets_list),
    )

    for i, sub in enumerate(subnets_list):
        net_addr = sub.network_address
        bcast = sub.broadcast_address

        if new_prefix >= 31:
            first = str(net_addr) if new_prefix == 31 else None
            last = str(bcast) if new_prefix == 31 else None
            hcount = 2 if new_prefix == 31 else 1
        else:
            first = str(ipaddress.IPv4Address(int(net_addr) + 1))
            last = str(ipaddress.IPv4Address(int(bcast) - 1))
            hcount = sub.num_addresses - 2

        result.subnets.append(SubnetInfo(
            index=i + 1,
            network=str(sub.network_address),
            prefix_length=new_prefix,
            subnet_mask=str(sub.netmask),
            first_host=first,
            last_host=last,
            broadcast=str(bcast),
            host_count=hcount,
        ))

    return result


def vlsm(base_network_str: str, host_requirements: list[int]) -> VLSMResult:
    """Perform Variable Length Subnet Masking.

    Allocates subnets from *base_network_str* to satisfy each host
    requirement (sorted largest-first for optimal allocation).

    Args:
        base_network_str: Base network (e.g. "192.168.1.0/24").
        host_requirements: List of required host counts per subnet.

    Returns:
        VLSMResult with allocations.

    Raises:
        ValueError: If there is not enough address space.
    """
    _, base = parse_network(base_network_str)
    total = base.num_addresses
    sorted_reqs = sorted(host_requirements, reverse=True)

    current_ip = int(base.network_address)
    used = 0
    entries: list[VLSMEntry] = []

    for req in sorted_reqs:
        prefix = _hosts_to_prefix(req)
        if prefix < base.prefixlen:
            raise ValueError(
                f"Subnet for {req} hosts requires /{prefix}, which is "
                f"larger than base /{base.prefixlen}"
            )

        sub_size = 2 ** (32 - prefix)

        # Align to subnet boundary. This is crucial for VLSM to avoid 
        # overlapping incorrectly when stepping between different prefix sizes.
        if current_ip % sub_size != 0:
            current_ip = ((current_ip // sub_size) + 1) * sub_size

        used_after = (current_ip + sub_size) - int(base.network_address)
        if used_after > total:
            raise ValueError(
                "Not enough address space in the base network for all "
                "required subnets."
            )

        sub = ipaddress.IPv4Network(f"{ipaddress.IPv4Address(current_ip)}/{prefix}", strict=True)
        net_addr = sub.network_address
        bcast = sub.broadcast_address
        allocated = sub.num_addresses - 2 if prefix < 31 else (2 if prefix == 31 else 1)

        if prefix < 31:
            first = str(ipaddress.IPv4Address(int(net_addr) + 1))
            last = str(ipaddress.IPv4Address(int(bcast) - 1))
        elif prefix == 31:
            first = str(net_addr)
            last = str(bcast)
        else:
            first = None
            last = None

        entries.append(VLSMEntry(
            required_hosts=req,
            network=str(net_addr),
            prefix_length=prefix,
            subnet_mask=str(sub.netmask),
            first_host=first,
            last_host=last,
            broadcast=str(bcast),
            allocated_hosts=allocated,
            wasted=max(0, allocated - req),
        ))

        used += sub_size
        current_ip += sub_size

    return VLSMResult(
        base_network=str(base),
        base_prefix=base.prefixlen,
        total_addresses=total,
        used_addresses=used,
        remaining_addresses=total - used,
        entries=entries,
    )


def find_best_subnet(required_hosts: int) -> SubnetSuggestion:
    """Find the best-fitting subnet for a given number of hosts.

    Args:
        required_hosts: Number of usable hosts needed.

    Returns:
        SubnetSuggestion with the recommendation.

    Raises:
        ValueError: If required_hosts is non-positive.
    """
    if required_hosts <= 0:
        raise ValueError("Number of hosts must be positive.")

    prefix = _hosts_to_prefix(required_hosts)
    net_size = 2 ** (32 - prefix)
    available = net_size - 2 if prefix < 31 else (2 if prefix == 31 else 1)
    mask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask

    return SubnetSuggestion(
        required_hosts=required_hosts,
        prefix_length=prefix,
        subnet_mask=str(mask),
        available_hosts=available,
        wasted_hosts=max(0, available - required_hosts),
        network_size=net_size,
    )


def convert_decimal(octet: int) -> ConversionResult:
    """Convert a decimal octet (0-255) to binary and hex.

    Raises:
        ValueError: If octet is out of range.
    """
    if not 0 <= octet <= 255:
        raise ValueError(f"Octet must be 0-255, got {octet}")
    return ConversionResult(
        decimal=octet,
        binary=f"{octet:08b}",
        hexadecimal=f"0x{octet:02X}",
    )


def convert_binary(binary_str: str) -> ConversionResult:
    """Convert an 8-bit binary string to decimal and hex.

    Accepts spaces and dots as separators (e.g. "1100 0000" or "1100.0000").

    Raises:
        ValueError: If the input is not valid 8-bit binary.
    """
    cleaned = ""
    for ch in binary_str:
        if ch in ("0", "1"):
            cleaned += ch
        elif ch in (" ", "."):
            continue
        else:
            raise ValueError(f"Invalid character in binary: '{ch}'")

    if len(cleaned) != 8:
        raise ValueError(f"Expected 8 binary digits, got {len(cleaned)}")

    decimal = int(cleaned, 2)
    return ConversionResult(
        decimal=decimal,
        binary=cleaned,
        hexadecimal=f"0x{decimal:02X}",
    )


def convert_cidr(prefix: int) -> ConversionResult:
    """Convert a CIDR prefix to mask representations.

    Raises:
        ValueError: If prefix is out of range.
    """
    if not 0 <= prefix <= 32:
        raise ValueError(f"CIDR must be 0-32, got {prefix}")

    mask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
    mask_int = int(mask)

    return ConversionResult(
        cidr=prefix,
        dotted_decimal=str(mask),
        dotted_binary=_ip_to_binary(mask),
        hexadecimal=f"0x{mask_int:08X}",
    )


def bitwise_and(ip_str: str, mask_str: str) -> str:
    """Perform bitwise AND between an IP and a mask/CIDR.

    Returns the resulting network address as a string.
    """
    ip = ipaddress.IPv4Address(ip_str.strip())

    mask_str = mask_str.strip()
    # Try as prefix length
    if mask_str.startswith("/"):
        mask_str = mask_str[1:]
    try:
        prefix = int(mask_str)
        if 0 <= prefix <= 32:
            mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix > 0 else 0
        else:
            raise ValueError()
    except ValueError:
        # Must be dotted decimal
        mask_int = int(ipaddress.IPv4Address(mask_str))

    result = int(ip) & mask_int
    return str(ipaddress.IPv4Address(result))


def generate_route_commands(
    destinations: list[str],
    next_hop: str,
    fmt: str = "linux",
) -> list[dict]:
    """Generate routing table commands for multiple destinations.

    Args:
        destinations: List of destination networks.
        next_hop: Next-hop IP address.
        fmt: One of 'linux', 'cisco', 'simple'.

    Returns:
        List of dicts with 'destination', 'command', and 'valid' keys.
    """
    # Validate next-hop
    ipaddress.IPv4Address(next_hop.strip())

    results = []
    for dest in destinations:
        try:
            _, net = parse_network(dest.strip())
            net_str = str(net)

            if fmt == "cisco":
                cmd = f"ip route {net.network_address} {net.netmask} {next_hop}"
            elif fmt == "linux":
                cmd = f"ip route add {net_str} via {next_hop}"
            else:
                cmd = f"{net_str} => {next_hop}"

            results.append({
                "destination": net_str,
                "command": cmd,
                "valid": True,
            })
        except (ValueError, Exception):
            results.append({
                "destination": dest.strip(),
                "command": "",
                "valid": False,
            })

    return results


def compare(net_a_str: str, net_b_str: str) -> ComparisonResult:
    """Compare two networks for overlap, containment, and size.

    Args:
        net_a_str: First network (e.g. "192.168.1.0/24").
        net_b_str: Second network (e.g. "192.168.1.128/25").

    Returns:
        ComparisonResult with the comparison.
    """
    _, net_a = parse_network(net_a_str)
    _, net_b = parse_network(net_b_str)

    a_contains_b = net_b.subnet_of(net_a)
    b_contains_a = net_a.subnet_of(net_b)
    overlap = net_a.overlaps(net_b)

    # Find shared prefix bits
    a_int = int(net_a.network_address)
    b_int = int(net_b.network_address)
    xor = a_int ^ b_int
    shared = 0
    for i in range(31, -1, -1):
        if (xor >> i) & 1:
            break
        shared += 1

    hosts_a = max(net_a.num_addresses - 2, 0) if net_a.prefixlen < 31 else net_a.num_addresses
    hosts_b = max(net_b.num_addresses - 2, 0) if net_b.prefixlen < 31 else net_b.num_addresses

    return ComparisonResult(
        network_a=str(net_a),
        network_b=str(net_b),
        overlap=overlap,
        a_contains_b=a_contains_b,
        b_contains_a=b_contains_a,
        shared_prefix=shared,
        size_a=net_a.num_addresses,
        size_b=net_b.num_addresses,
        hosts_a=hosts_a,
        hosts_b=hosts_b,
    )

