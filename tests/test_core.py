"""Comprehensive tests for netcalc.core."""

from __future__ import annotations

import ipaddress
import pytest

from netcalc import core


# ===================================================================
# parse_network
# ===================================================================

class TestParseNetwork:
    """Tests for the flexible network parser."""

    def test_cidr_notation(self):
        ip, net = core.parse_network("192.168.1.10/24")
        assert ip == ipaddress.IPv4Address("192.168.1.10")
        assert net == ipaddress.IPv4Network("192.168.1.0/24")

    def test_ip_with_mask(self):
        ip, net = core.parse_network("192.168.1.10 255.255.255.0")
        assert ip == ipaddress.IPv4Address("192.168.1.10")
        assert net.prefixlen == 24

    def test_ip_with_prefix(self):
        ip, net = core.parse_network("10.0.0.1 8")
        assert ip == ipaddress.IPv4Address("10.0.0.1")
        assert net.prefixlen == 8

    def test_bare_ip(self):
        ip, net = core.parse_network("172.16.0.1")
        assert ip == ipaddress.IPv4Address("172.16.0.1")
        assert net.prefixlen == 32

    def test_invalid_input(self):
        with pytest.raises(ValueError):
            core.parse_network("not.an.ip")

    def test_invalid_prefix(self):
        with pytest.raises(ValueError):
            core.parse_network("10.0.0.1/33")

    def test_non_contiguous_mask(self):
        with pytest.raises(ValueError):
            core.parse_network("10.0.0.1 255.240.255.0")

    def test_whitespace_handling(self):
        ip, net = core.parse_network("  192.168.1.1/24  ")
        assert ip == ipaddress.IPv4Address("192.168.1.1")


# ===================================================================
# analyze
# ===================================================================

class TestAnalyze:
    """Tests for network analysis."""

    def test_class_c_network(self):
        info = core.analyze("192.168.1.100/24")
        assert str(info.network_address) == "192.168.1.0"
        assert str(info.broadcast_address) == "192.168.1.255"
        assert str(info.first_host) == "192.168.1.1"
        assert str(info.last_host) == "192.168.1.254"
        assert info.host_count == 254
        assert info.prefix_length == 24
        assert str(info.subnet_mask) == "255.255.255.0"
        assert str(info.wildcard_mask) == "0.0.0.255"

    def test_class_a_network(self):
        info = core.analyze("10.0.0.1/8")
        assert str(info.network_address) == "10.0.0.0"
        assert info.ip_class == "A"
        assert info.is_private is True
        assert info.host_count == 16777214

    def test_slash_32(self):
        info = core.analyze("192.168.1.1/32")
        assert info.host_count == 1
        assert info.first_host is None
        assert info.last_host is None

    def test_slash_31(self):
        info = core.analyze("192.168.1.100/31")
        assert info.host_count == 2
        assert str(info.first_host) == "192.168.1.100"
        assert str(info.last_host) == "192.168.1.101"

    def test_slash_16(self):
        info = core.analyze("172.16.5.10/16")
        assert str(info.network_address) == "172.16.0.0"
        assert str(info.broadcast_address) == "172.16.255.255"
        assert info.host_count == 65534

    def test_public_ip(self):
        info = core.analyze("8.8.8.8/32")
        assert info.is_private is False
        assert info.ip_class == "A"

    def test_multicast(self):
        info = core.analyze("224.0.0.1/32")
        assert info.ip_class == "D (Multicast)"

    def test_binary_fields(self):
        info = core.analyze("192.168.1.1/24")
        assert info.ip_binary == "11000000.10101000.00000001.00000001"
        assert info.mask_binary == "11111111.11111111.11111111.00000000"

    def test_to_dict(self):
        info = core.analyze("10.0.0.1/8")
        d = info.to_dict()
        assert isinstance(d, dict)
        assert d["ip_address"] == "10.0.0.1"
        assert d["prefix_length"] == 8


# ===================================================================
# subnet
# ===================================================================

class TestSubnet:
    """Tests for subnetting."""

    def test_basic_subnetting(self):
        result = core.subnet("192.168.0.0/24", 26)
        assert result.num_subnets == 4
        assert len(result.subnets) == 4
        assert result.subnets[0].network == "192.168.0.0"
        assert result.subnets[0].host_count == 62
        assert result.subnets[3].network == "192.168.0.192"

    def test_subnetting_to_32(self):
        result = core.subnet("192.168.1.0/30", 32)
        assert result.num_subnets == 4

    def test_invalid_prefix_smaller(self):
        with pytest.raises(ValueError, match="must be larger"):
            core.subnet("192.168.0.0/24", 20)

    def test_invalid_prefix_equal(self):
        with pytest.raises(ValueError, match="must be larger"):
            core.subnet("192.168.0.0/24", 24)

    def test_large_subnetting(self):
        result = core.subnet("10.0.0.0/8", 16)
        assert result.num_subnets == 256


# ===================================================================
# VLSM
# ===================================================================

class TestVLSM:
    """Tests for VLSM calculation."""

    def test_basic_vlsm(self):
        result = core.vlsm("192.168.1.0/24", [50, 30, 10])
        assert len(result.entries) == 3
        # Should be sorted largest-first
        assert result.entries[0].required_hosts == 50
        assert result.entries[1].required_hosts == 30
        assert result.entries[2].required_hosts == 10
        assert result.used_addresses <= result.total_addresses

    def test_vlsm_not_enough_space(self):
        with pytest.raises(ValueError, match="larger than base"):
            core.vlsm("192.168.1.0/28", [100])

    def test_vlsm_single_host(self):
        result = core.vlsm("192.168.1.0/24", [1])
        assert len(result.entries) == 1
        assert result.entries[0].allocated_hosts >= 1


# ===================================================================
# find_best_subnet
# ===================================================================

class TestFindBestSubnet:
    """Tests for subnet suggestion."""

    def test_small_network(self):
        sug = core.find_best_subnet(10)
        assert sug.prefix_length == 28
        assert sug.available_hosts == 14
        assert sug.wasted_hosts == 4

    def test_exact_fit(self):
        sug = core.find_best_subnet(254)
        assert sug.prefix_length == 24
        assert sug.available_hosts == 254

    def test_large_network(self):
        sug = core.find_best_subnet(1000)
        assert sug.prefix_length == 22
        assert sug.available_hosts >= 1000

    def test_single_host(self):
        sug = core.find_best_subnet(1)
        assert sug.prefix_length == 30
        assert sug.available_hosts == 2

    def test_invalid_zero(self):
        with pytest.raises(ValueError):
            core.find_best_subnet(0)

    def test_invalid_negative(self):
        with pytest.raises(ValueError):
            core.find_best_subnet(-5)


# ===================================================================
# Conversions
# ===================================================================

class TestConversions:
    """Tests for number conversions."""

    def test_decimal_to_binary(self):
        r = core.convert_decimal(192)
        assert r.decimal == 192
        assert r.binary == "11000000"
        assert r.hexadecimal == "0xC0"

    def test_decimal_zero(self):
        r = core.convert_decimal(0)
        assert r.binary == "00000000"
        assert r.hexadecimal == "0x00"

    def test_decimal_255(self):
        r = core.convert_decimal(255)
        assert r.binary == "11111111"
        assert r.hexadecimal == "0xFF"

    def test_decimal_out_of_range(self):
        with pytest.raises(ValueError):
            core.convert_decimal(256)
        with pytest.raises(ValueError):
            core.convert_decimal(-1)

    def test_binary_to_decimal(self):
        r = core.convert_binary("11000000")
        assert r.decimal == 192
        assert r.hexadecimal == "0xC0"

    def test_binary_with_spaces(self):
        r = core.convert_binary("1100 0000")
        assert r.decimal == 192

    def test_binary_with_dots(self):
        r = core.convert_binary("1100.0000")
        assert r.decimal == 192

    def test_binary_invalid_length(self):
        with pytest.raises(ValueError, match="8 binary digits"):
            core.convert_binary("1100")

    def test_binary_invalid_chars(self):
        with pytest.raises(ValueError, match="Invalid character"):
            core.convert_binary("1100abcd")

    def test_cidr_to_mask(self):
        r = core.convert_cidr(24)
        assert r.cidr == 24
        assert r.dotted_decimal == "255.255.255.0"
        assert r.hexadecimal == "0xFFFFFF00"

    def test_cidr_zero(self):
        r = core.convert_cidr(0)
        assert r.dotted_decimal == "0.0.0.0"

    def test_cidr_32(self):
        r = core.convert_cidr(32)
        assert r.dotted_decimal == "255.255.255.255"

    def test_cidr_out_of_range(self):
        with pytest.raises(ValueError):
            core.convert_cidr(33)


# ===================================================================
# Bitwise AND
# ===================================================================

class TestBitwiseAnd:
    """Tests for bitwise AND."""

    def test_basic_and(self):
        result = core.bitwise_and("192.168.1.100", "255.255.255.0")
        assert result == "192.168.1.0"

    def test_and_with_cidr(self):
        result = core.bitwise_and("10.0.0.1", "8")
        assert result == "10.0.0.0"

    def test_and_with_slash_cidr(self):
        result = core.bitwise_and("10.0.0.1", "/8")
        assert result == "10.0.0.0"

    def test_and_class_b(self):
        result = core.bitwise_and("172.16.5.10", "255.255.0.0")
        assert result == "172.16.0.0"


# ===================================================================
# Route generation
# ===================================================================

class TestRouteGeneration:
    """Tests for routing table generation."""

    def test_linux_format(self):
        routes = core.generate_route_commands(
            ["192.168.1.0/24"], "10.0.0.1", fmt="linux"
        )
        assert len(routes) == 1
        assert routes[0]["valid"] is True
        assert "ip route add" in routes[0]["command"]

    def test_cisco_format(self):
        routes = core.generate_route_commands(
            ["192.168.1.0/24"], "10.0.0.1", fmt="cisco"
        )
        assert "ip route" in routes[0]["command"]
        assert "255.255.255.0" in routes[0]["command"]

    def test_simple_format(self):
        routes = core.generate_route_commands(
            ["192.168.1.0/24"], "10.0.0.1", fmt="simple"
        )
        assert "=>" in routes[0]["command"]

    def test_invalid_destination(self):
        routes = core.generate_route_commands(
            ["not-a-network"], "10.0.0.1", fmt="linux"
        )
        assert routes[0]["valid"] is False

    def test_multiple_destinations(self):
        routes = core.generate_route_commands(
            ["192.168.1.0/24", "10.0.0.0/8", "invalid"],
            "10.0.0.1",
            fmt="linux",
        )
        assert len(routes) == 3
        assert routes[0]["valid"] is True
        assert routes[1]["valid"] is True
        assert routes[2]["valid"] is False


# ===================================================================
# Helper functions
# ===================================================================

class TestHelpers:
    """Tests for internal helper functions."""

    def test_ip_to_binary(self):
        ip = ipaddress.IPv4Address("192.168.1.1")
        assert core._ip_to_binary(ip) == "11000000.10101000.00000001.00000001"

    def test_classify_ip_class_a(self):
        assert core._classify_ip(ipaddress.IPv4Address("10.0.0.1")) == "A"

    def test_classify_ip_class_b(self):
        assert core._classify_ip(ipaddress.IPv4Address("172.16.0.1")) == "B"

    def test_classify_ip_class_c(self):
        assert core._classify_ip(ipaddress.IPv4Address("192.168.1.1")) == "C"

    def test_classify_ip_class_d(self):
        assert core._classify_ip(ipaddress.IPv4Address("224.0.0.1")) == "D (Multicast)"

    def test_classify_ip_class_e(self):
        assert core._classify_ip(ipaddress.IPv4Address("240.0.0.1")) == "E (Reserved)"

    def test_hosts_to_prefix(self):
        assert core._hosts_to_prefix(254) == 24
        assert core._hosts_to_prefix(10) == 28
        assert core._hosts_to_prefix(1) == 30
        assert core._hosts_to_prefix(0) == 32

    def test_mask_to_prefix(self):
        assert core._mask_to_prefix(ipaddress.IPv4Address("255.255.255.0")) == 24
        assert core._mask_to_prefix(ipaddress.IPv4Address("255.255.0.0")) == 16
        assert core._mask_to_prefix(ipaddress.IPv4Address("255.0.0.0")) == 8
        assert core._mask_to_prefix(ipaddress.IPv4Address("0.0.0.0")) == 0


# ===================================================================
# Compare
# ===================================================================

class TestCompare:
    """Tests for network comparison."""

    def test_containment(self):
        result = core.compare("192.168.1.0/24", "192.168.1.128/25")
        assert result.a_contains_b is True
        assert result.b_contains_a is False
        assert result.overlap is True

    def test_no_overlap(self):
        result = core.compare("192.168.1.0/24", "10.0.0.0/8")
        assert result.overlap is False
        assert result.a_contains_b is False
        assert result.b_contains_a is False

    def test_identical(self):
        result = core.compare("192.168.1.0/24", "192.168.1.0/24")
        assert result.overlap is True
        assert result.a_contains_b is True
        assert result.b_contains_a is True

    def test_b_contains_a(self):
        result = core.compare("10.1.0.0/16", "10.0.0.0/8")
        assert result.a_contains_b is False
        assert result.b_contains_a is True

    def test_sizes(self):
        result = core.compare("192.168.1.0/24", "10.0.0.0/8")
        assert result.size_a == 256
        assert result.size_b == 16777216
        assert result.hosts_a == 254
        assert result.hosts_b == 16777214
