#!/usr/bin/env python3
"""
dpi-probe - DPI detection and fingerprinting tool
"""

import sys
import argparse
from src.probe import Probe
from src import autodetect
from src import config as cfg

def main():
    parser = argparse.ArgumentParser(
        description="dpi-probe - detect and fingerprint DPI middleboxes"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="dpi-probe 0.1.0-alpha"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP to probe (omit for auto-detection mode)"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of times to repeat each probe (default: 1)"
    )
    parser.add_argument(
        "--multi",
        action="store_true",
        help="Probe all targets from targets.json in one run"
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Network condition label e.g. no-vpn, adguard, reality, mobile"
    )

    args = parser.parse_args()
    config = cfg.load()

    if args.multi:
        targets = config.get("targets", [])
        print(f"[*] Multi-target mode - {len(targets)} targets")
        if args.samples > 1:
            print(f"[*] Samples per test : {args.samples}\n")
        for t in targets:
            print(f"\n{'='*50}")
            print(f"  Target : {t['name']} - {t['ip']}")
            print(f"{'='*50}")
            probe = Probe(t["ip"], samples=args.samples, config=config, profile=args.profile)
            probe.run()
        sys.exit(0)

    if not args.target:
        print("[*] No target specified - running auto-detection mode")
        autodetect.run()
        sys.exit(0)

    print(f"[*] Starting DPI probe against {args.target}")
    if args.samples > 1:
        print(f"[*] Samples per test : {args.samples}")

    probe = Probe(args.target, samples=args.samples, config=config, profile=args.profile)
    probe.run()

if __name__ == "__main__":
    main()