import pytest

from src import reverse_traceroute


def test_build_linux_command_for_public_destination():
    command = reverse_traceroute.build_remote_command("8.8.8.8", "linux", 20, 1500)
    assert command == ["traceroute", "-n", "-m", "20", "-w", "2", "8.8.8.8"]


def test_private_destination_is_rejected():
    with pytest.raises(ValueError, match="public IP"):
        reverse_traceroute.build_remote_command("192.168.1.10", "windows", 30, 2000)


def test_agent_options_are_not_accepted_as_a_destination():
    with pytest.raises(ValueError, match="SSH destination"):
        reverse_traceroute.run("-oProxyCommand=bad", "8.8.8.8")


def test_parse_hops_handles_timeouts_and_addresses():
    hops = reverse_traceroute._parse_hops(" 1  10.0.0.1  1.2 ms\n 2  * * *\n")
    assert hops[0]["address"] == "10.0.0.1"
    assert hops[1]["timed_out"] is True
