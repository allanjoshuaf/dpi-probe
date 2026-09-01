"""Cooperative reverse traceroute through a remote SSH agent."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import time
from typing import Any


def build_remote_command(destination: str, agent_os: str, max_hops: int, timeout_ms: int) -> list[str]:
    """Build a non-interactive traceroute command for a controlled remote host."""
    address = ipaddress.ip_address(destination)
    if not address.is_global:
        raise ValueError("the reverse-trace destination must be a public IP address")
    if not 1 <= max_hops <= 64:
        raise ValueError("max_hops must be between 1 and 64")
    if not 100 <= timeout_ms <= 10_000:
        raise ValueError("timeout_ms must be between 100 and 10000")

    if agent_os == "windows":
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), str(address)]
    return [
        "traceroute", "-n", "-m", str(max_hops), "-w",
        str(max(1, round(timeout_ms / 1000))), str(address),
    ]


def _parse_hops(output: str) -> list[dict[str, Any]]:
    hops: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue
        hop = {"hop": int(match.group(1)), "raw": match.group(2).strip()}
        ip_match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}", hop["raw"])
        hop["address"] = ip_match.group(0) if ip_match else None
        hop["timed_out"] = "*" in hop["raw"] and hop["address"] is None
        hops.append(hop)
    return hops


def run(agent: str, destination: str, agent_os: str = "linux", max_hops: int = 30, timeout_ms: int = 2_000) -> dict[str, Any]:
    """Ask a user-controlled SSH agent to trace its path back to this client."""
    if not agent or agent.startswith("-") or any(character.isspace() for character in agent):
        raise ValueError("agent must be a non-empty SSH destination without whitespace")
    remote_command = build_remote_command(destination, agent_os, max_hops, timeout_ms)
    command = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", agent, *remote_command]
    started = time.monotonic()
    result: dict[str, Any] = {
        "status": "unknown",
        "agent": agent,
        "destination": destination,
        "agent_os": agent_os,
        "command": remote_command,
        "elapsed_ms": None,
        "hops": [],
        "output": "",
        "error": None,
    }
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["output"] = completed.stdout.strip()
        result["hops"] = _parse_hops(result["output"])
        result["status"] = "ok" if completed.returncode == 0 else "agent_error"
        if completed.returncode != 0:
            result["error"] = completed.stderr.strip() or f"ssh exited with {completed.returncode}"
    except FileNotFoundError:
        result["status"] = "ssh_not_found"
        result["error"] = "OpenSSH client was not found in PATH"
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = "remote traceroute exceeded 90 seconds"
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    print("\n[*] Cooperative Reverse Traceroute")
    print(f"    Agent             : {agent}")
    print(f"    Direction         : {agent} -> {destination}")
    print(f"    Status            : {result['status']}")
    print(f"    Hops parsed       : {len(result['hops'])}")
    if result["error"]:
        print(f"    Error             : {result['error']}")
    return result
