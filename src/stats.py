import statistics

def summarize(samples: list[float]) -> dict:
    """
    Given a list of RTT samples, return statistical summary.
    Filters out None values.
    """
    clean = [s for s in samples if s is not None]

    if not clean:
        return {
            "samples": 0,
            "median_ms": None,
            "mean_ms": None,
            "p95_ms": None,
            "stdev_ms": None,
            "min_ms": None,
            "max_ms": None,
            "timeout_rate": 1.0,
        }

    total = len(samples)
    timeouts = total - len(clean)

    sorted_samples = sorted(clean)
    p95_index = int(len(sorted_samples) * 0.95)
    p95 = sorted_samples[min(p95_index, len(sorted_samples) - 1)]

    return {
        "samples": total,
        "median_ms": round(statistics.median(clean), 2),
        "mean_ms": round(statistics.mean(clean), 2),
        "p95_ms": round(p95, 2),
        "stdev_ms": round(statistics.stdev(clean), 2) if len(clean) > 1 else 0.0,
        "min_ms": round(min(clean), 2),
        "max_ms": round(max(clean), 2),
        "timeout_rate": round(timeouts / total, 2),
    }

def summarize_status(statuses: list[str]) -> dict:
    """
    Given a list of status strings, return frequency breakdown.
    """
    total = len(statuses)
    counts = {}
    for s in statuses:
        counts[s] = counts.get(s, 0) + 1

    return {
        "total": total,
        "breakdown": {k: round(v / total, 2) for k, v in counts.items()},
        "dominant": max(counts, key=counts.get) if counts else None,
    }