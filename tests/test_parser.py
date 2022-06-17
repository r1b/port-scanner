import pytest

from port_scanner.parser import (
    MAX_PORT,
    MIN_PORT,
    load_most_common_ports,
    parse_ports,
)


@pytest.mark.parametrize(
    ("port_spec", "expected_ports"),
    (
        # missing
        (None, load_most_common_ports()),
        # single port
        ("42", [42]),
        # ranges
        ("-", list(range(MIN_PORT, MAX_PORT + 1))),
        ("42-", list(range(42, MAX_PORT + 1))),
        ("-42", list(range(1, 43))),
        ("41-42", [41, 42]),
        ("41-41", [41]),
        # multiple ports
        ("42,41,43", [41, 42, 43]),
        # all together
        (
            "1,22,23,80-81,443,8000-8888",
            [1, 22, 23, 80, 81, 443] + list(range(8000, 8889)),
        ),
    ),
)
def test_parse_ports_ok(port_spec, expected_ports):
    assert parse_ports(port_spec) == expected_ports


@pytest.mark.parametrize(
    "port_spec",
    ("notaport", "--", "23-24-", "5,", "a-b", "42-41", "0-2", f"{MAX_PORT+1}"),
)
def test_parse_ports_error(port_spec):
    with pytest.raises(ValueError):
        parse_ports(port_spec)
