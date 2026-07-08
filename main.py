"""
main.py
--------
Command-line entry point.

Usage:
    python3 main.py --logs sample_logs/*.evtx --output output/report.xlsx
    python3 main.py --logs sample_logs/file1.evtx sample_logs/file2.evtx
"""

import argparse
import glob
import sys
from datetime import datetime

from parser import parse_multiple
from detectors import brute_force, privilege_escalation, persistence, suspicious_process
from report import generate_report


def expand_log_paths(patterns):
    paths = []
    for pattern in patterns:
        matched = glob.glob(pattern)
        paths.extend(matched if matched else [pattern])
    return paths


def run(log_paths, output_path):
    print(f"[+] Parsing {len(log_paths)} log file(s)...")
    events = parse_multiple(log_paths)
    print(f"[+] {len(events)} total events parsed.")

    results = {
        "brute_force": brute_force.detect(events),
        "privilege_escalation": privilege_escalation.detect(events),
        "persistence": persistence.detect(events),
        "suspicious_process": suspicious_process.detect(events),
    }

    total = sum(len(v) for v in results.values())
    print(f"[+] Detection complete. {total} finding(s):")
    for category, findings in results.items():
        print(f"      - {category.replace('_', ' ').title()}: {len(findings)}")

    generate_report(results, output_path)
    print(f"[+] Report written to {output_path}")
    return results


if __name__ == "__main__":
    parser_arg = argparse.ArgumentParser(description="Enterprise Windows Log Analyzer")
    parser_arg.add_argument("--logs", nargs="+", required=True, help="Path(s) or glob pattern(s) to .evtx files")
    parser_arg.add_argument("--output", default=f"output/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
    args = parser_arg.parse_args()

    log_paths = expand_log_paths(args.logs)
    if not log_paths:
        print("No log files matched.", file=sys.stderr)
        sys.exit(1)

    run(log_paths, args.output)
