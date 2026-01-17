#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime
from typing import Dict, Any, List, Optional


FAILED_PATTERNS = [
    # sshd: Failed password for invalid user X from 1.2.3.4 port ...
    re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
    # sshd: Invalid user X from 1.2.3.4
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
]

SUCCESS_PATTERNS = [
    # sshd: Accepted password for user from 1.2.3.4 port ...
    re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
]


def detect_default_log_path() -> Optional[str]:
    candidates = [
        "/var/log/auth.log",   # Ubuntu/Debian
        "/var/log/secure",     # RHEL/CentOS/Fedora
        "/var/log/syslog",     # fallback (may include sshd lines)
    ]
    for path in candidates:
        if os.path.exists(path) and os.path.isfile(path):
            return path
    return None


def parse_lines(lines: List[str]) -> Dict[str, Any]:
    failed_users = Counter()
    failed_ips = Counter()
    success_users = Counter()
    success_ips = Counter()

    failed_samples = []
    success_samples = []

    for line in lines:
        line = line.strip()

        matched = False
        for pat in FAILED_PATTERNS:
            m = pat.search(line)
            if m:
                user = m.group("user")
                ip = m.group("ip")
                failed_users[user] += 1
                failed_ips[ip] += 1
                if len(failed_samples) < 5:
                    failed_samples.append(line)
                matched = True
                break
        if matched:
            continue

        for pat in SUCCESS_PATTERNS:
            m = pat.search(line)
            if m:
                user = m.group("user")
                ip = m.group("ip")
                success_users[user] += 1
                success_ips[ip] += 1
                if len(success_samples) < 5:
                    success_samples.append(line)
                break

    return {
        "failed": {
            "total": sum(failed_users.values()),
            "top_users": failed_users.most_common(10),
            "top_ips": failed_ips.most_common(10),
            "samples": failed_samples,
        },
        "success": {
            "total": sum(success_users.values()),
            "top_users": success_users.most_common(10),
            "top_ips": success_ips.most_common(10),
            "samples": success_samples,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for SSH login successes/failures and summarize results."
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        default=None,
        help="Path to auth log (default: auto-detect /var/log/auth.log, /var/log/secure, or /var/log/syslog).",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Output JSON path (default: reports/auth_report_<timestamp>.json).",
    )
    args = parser.parse_args()

    log_path = args.log_path or detect_default_log_path()
    if not log_path:
        print("❌ Could not find a default log file. Try: --log /path/to/logfile")
        raise SystemExit(1)

    if not os.path.exists(log_path):
        print(f"❌ Log file not found: {log_path}")
        raise SystemExit(1)

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except PermissionError:
        print(f"❌ Permission denied reading {log_path}")
        print("Tip: try running with sudo, e.g. sudo python3 src/analyze_auth_log.py")
        raise SystemExit(1)

    results = parse_lines(lines)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    out_path = args.out_path or f"reports/auth_report_{timestamp}.json"

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "log_path": log_path,
                "summary": results,
            },
            f,
            indent=2,
        )

    # Print a friendly console summary
    print("✅ Auth Log Analyzer Report")
    print(f"Log file: {log_path}")
    print(f"JSON saved: {out_path}")
    print("")
    print(f"Failed logins: {results['failed']['total']}")
    if results["failed"]["top_ips"]:
        print("Top failed IPs:")
        for ip, count in results["failed"]["top_ips"][:5]:
            print(f"  - {ip}: {count}")
    if results["failed"]["top_users"]:
        print("Top targeted users:")
        for user, count in results["failed"]["top_users"][:5]:
            print(f"  - {user}: {count}")
    print("")
    print(f"Successful logins: {results['success']['total']}")
    if results["success"]["top_ips"]:
        print("Top successful IPs:")
        for ip, count in results["success"]["top_ips"][:5]:
            print(f"  - {ip}: {count}")
    if results["success"]["top_users"]:
        print("Top successful users:")
        for user, count in results["success"]["top_users"][:5]:
            print(f"  - {user}: {count}")
    print("")
    print("Done.")


if __name__ == "__main__":
    main()

