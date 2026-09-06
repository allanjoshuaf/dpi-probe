import json
import os
import copy
import ipaddress


def _validate_hostname(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"invalid hostname: {value!r}")
    hostname = value[:-1] if value.endswith(".") else value
    try:
        ascii_name = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {value!r}") from exc
    if len(ascii_name) > 253:
        raise ValueError(f"hostname is too long: {value!r}")
    labels = ascii_name.split(".")
    if any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise ValueError(f"invalid hostname: {value!r}")

DEFAULT_CONFIG = {
    "targets": [
        {"ip": "1.1.1.1", "name": "Cloudflare-operated anycast endpoint", "controlled": False},
        {"ip": "8.8.8.8", "name": "Google-operated anycast endpoint", "controlled": False},
        {"ip": "9.9.9.9", "name": "Quad9-operated anycast endpoint", "controlled": False}
    ],
    "domains": {
        "blocked": ["instagram.com", "facebook.com", "twitter.com", "x.com", "youtube.com"],
        "clean": ["google.com", "github.com", "cloudflare.com", "wikipedia.org", "mozilla.org"]
    },
    "methodology": {
        "controlled_endpoint": False,
        "warning": "Public anycast endpoints are differential probes, not authoritative servers for every hostname."
    }
}

def load(path: str = "targets.json") -> dict:
    if not os.path.exists(path):
        print(f"[*] No config file found at {path} - using defaults")
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        _validate(config)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid probe configuration {path!r}: {exc}") from exc
    print(f"[*] Config loaded from {path}")
    return config


def _validate(config: dict) -> None:
    """Reject malformed configuration before a probe begins issuing traffic."""
    if not isinstance(config, dict):
        raise ValueError("top-level value must be an object")

    targets = config.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets must be a non-empty list")
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("name"), str):
            raise ValueError("every target needs string fields 'name' and 'ip'")
        try:
            address = ipaddress.ip_address(target.get("ip"))
        except ValueError as exc:
            raise ValueError(f"invalid target IP: {target.get('ip')!r}") from exc
        if address.version != 4:
            raise ValueError("only IPv4 targets are currently supported")
        if "controlled" in target and not isinstance(target["controlled"], bool):
            raise ValueError("target.controlled must be a boolean when present")

    domains = config.get("domains")
    if not isinstance(domains, dict):
        raise ValueError("domains must be an object")
    for category in ("clean", "blocked"):
        values = domains.get(category)
        if not isinstance(values, list) or not values or not all(isinstance(value, str) and value for value in values):
            raise ValueError(f"domains.{category} must be a non-empty list of hostnames")
        for value in values:
            _validate_hostname(value)
        if len({value.casefold().rstrip(".") for value in values}) != len(values):
            raise ValueError(f"domains.{category} contains duplicate hostnames")

    overlap = (
        {value.casefold().rstrip(".") for value in domains["clean"]}
        & {value.casefold().rstrip(".") for value in domains["blocked"]}
    )
    if overlap:
        raise ValueError(f"clean and blocked hostname hypotheses overlap: {sorted(overlap)}")
