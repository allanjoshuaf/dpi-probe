#!/usr/bin/env python3
"""
dpi-probe — DPI detection and fingerprinting tool
"""

import sys
import argparse
from src.probe import Probe
from src import autodetect

def main():
    parser = argparse.ArgumentParser(
        description="dpi-probe - detect and fingerprint DPI middleboxes"
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

    args = parser.parse_args()

    if not args.target:
        print("[*] No target specified - running auto-detection mode")
        autodetect.run()
        sys.exit(0)

    print(f"[*] Starting DPI probe against {args.target}")
    if args.samples > 1:
        print(f"[*] Samples per test : {args.samples}")

    probe = Probe(args.target, samples=args.samples)
    probe.run()

if __name__ == "__main__":
    main()