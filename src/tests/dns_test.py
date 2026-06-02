import time
import ipaddress
import dns.resolver

RESOLVERS = [
    {"name": "system", "ip": None},
    {"name": "cloudflare", "ip": "1.1.1.1"},
    {"name": "google", "ip": "8.8.8.8"},
    {"name": "quad9", "ip": "9.9.9.9"},
]


def query(domain: str, resolver_ip: str = None) -> dict:
    """
    Resolve an A record using either the system resolver
    or a specific DNS resolver.

    Returns:
        {
            "ips": list[str],
            "status": str,
            "rtt_ms": float | None
        }
    """
    result = {
        "ips": [],
        "status": None,
        "rtt_ms": None,
    }

    try:
        resolver = dns.resolver.Resolver()

        if resolver_ip:
            resolver.nameservers = [resolver_ip]

        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        start = time.time()

        answers = resolver.resolve(domain, "A")

        result["rtt_ms"] = round((time.time() - start) * 1000, 2)
        result["ips"] = sorted(str(a) for a in answers)
        result["status"] = "ok"

    except dns.resolver.NXDOMAIN:
        result["status"] = "nxdomain"

    except dns.resolver.NoAnswer:
        result["status"] = "no_answer"

    except dns.resolver.Timeout:
        result["status"] = "timeout"

    except Exception as e:
        result["status"] = "error"
        result["detail"] = str(e)

    return result


def is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)

        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_reserved
        )

    except Exception:
        return False


def classify(system_result: dict, reference_results: list) -> tuple:
    """
    Compare the system resolver response against
    multiple public resolvers and classify the result.

    Possible classifications:

        clean
        suspicious_resolution
        possible_poisoning
        no_response
    """
    system_ips = system_result.get("ips", [])

    reference_ips = set()

    for r in reference_results:
        reference_ips.update(r.get("ips", []))

    # Local resolver returns NXDOMAIN while public resolvers return records
    if (
        system_result["status"] == "nxdomain"
        and len(reference_ips) > 0
    ):
        return (
            "possible_poisoning",
            ["local_nxdomain_public_resolves"]
        )

    # Local resolver returned bogon/private/reserved addresses
    bogons = [ip for ip in system_ips if is_bogon(ip)]

    if bogons:
        return (
            "possible_poisoning",
            [f"bogon_ip:{ip}" for ip in bogons]
        )

    # No response from the local resolver
    if not system_ips:
        return (
            "no_response",
            [system_result["status"]]
        )

    # Local resolver returned addresses that do not overlap
    # with any public resolver results
    if reference_ips and not set(system_ips).intersection(reference_ips):
        return (
            "suspicious_resolution",
            ["ip_mismatch_with_public_resolvers"]
        )

    return (
        "clean",
        []
    )


def run(config: dict) -> list:
    blocked = config["domains"]["blocked"]
    clean = config["domains"]["clean"]

    domains = clean + blocked

    print("\n[*] DNS Poisoning Test")
    print(f"    Testing {len(domains)} domains\n")

    results = []

    for domain in domains:

        resolver_results = {}

        for resolver in RESOLVERS:
            resolver_results[resolver["name"]] = query(
                domain,
                resolver["ip"]
            )

        system_result = resolver_results["system"]

        reference_results = [
            resolver_results["cloudflare"],
            resolver_results["google"],
            resolver_results["quad9"],
        ]

        verdict, flags = classify(
            system_result,
            reference_results
        )

        if verdict == "clean":
            indicator = "✓"
        elif verdict == "possible_poisoning":
            indicator = "✗"
        else:
            indicator = "⚠"

        print(
            f"    [{indicator}] "
            f"{domain:<25} → {verdict}"
        )

        if flags:
            for flag in flags:
                print(f"         flag: {flag}")

        results.append({
            "domain": domain,
            "category": (
                "clean"
                if domain in clean
                else "blocked"
            ),
            "verdict": verdict,
            "flags": flags,
            "system": resolver_results["system"],
            "cloudflare": resolver_results["cloudflare"],
            "google": resolver_results["google"],
            "quad9": resolver_results["quad9"],
        })

    return results