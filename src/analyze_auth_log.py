#!/usr/bin/env python3
import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple


FAILED_PATTERNS = [
    re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"),
]


def detect_default_log_path() -> Optional[str]:
    candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"]
    for path in candidates:
        if os.path.exists(path) and os.path.isfile(path):
            return path
    return None


def risk_label(level: str) -> str:
    level = level.upper()
    if level == "HIGH":
        return "[HIGH RISK]"
    if level == "MEDIUM":
        return "[MEDIUM RISK]"
    if level == "LOW":
        return "[LOW RISK]"
    return "[INFO]"


def score_bruteforce(count: int, medium_threshold: int, high_threshold: int) -> str:
    """
    Simple threshold scoring:
      - HIGH if count >= high_threshold
      - MEDIUM if count >= medium_threshold
      - LOW otherwise
    """
    if count >= high_threshold:
        return "HIGH"
    if count >= medium_threshold:
        return "MEDIUM"
    return "LOW"


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
            "raw_counters": {
                "users": dict(failed_users),
                "ips": dict(failed_ips),
            },
        },
        "success": {
            "total": sum(success_users.values()),
            "top_users": success_users.most_common(10),
            "top_ips": success_ips.most_common(10),
            "samples": success_samples,
        },
    }


def build_risk_findings(results: Dict[str, Any],
                        ip_medium: int,
                        ip_high: int,
                        user_medium: int,
                        user_high: int) -> Dict[str, Any]:
    """
    Create risk findings based on failed login counters.
    """
    failed_ip_counts = results["failed"]["raw_counters"]["ips"]
    failed_user_counts = results["failed"]["raw_counters"]["users"]

    ip_findings: List[Dict[str, Any]] = []
    user_findings: List[Dict[str, Any]] = []

    for ip, count in sorted(failed_ip_counts.items(), key=lambda x: x[1], reverse=True):
        level = score_bruteforce(count, ip_medium, ip_high)
        if level != "LOW":
            ip_findings.append({
                "ip": ip,
                "failed_attempts": count,
                "risk": level,
                "label": risk_label(level),
                "reason": f"Failed SSH attempts from IP >= {ip_medium} (MEDIUM) / {ip_high} (HIGH)."
            })

    for user, count in sorted(failed_user_counts.items(), key=lambda x: x[1], reverse=True):
        level = score_bruteforce(count, user_medium, user_high)
        if level != "LOW":
            user_findings.append({
                "user": user,
                "failed_attempts": count,
                "risk": level,
                "label": risk_label(level),
                "reason": f"Failed SSH attempts against user >= {user_medium} (MEDIUM) / {user_high} (HIGH)."
            })

    overall = "LOW"
    if any(f["risk"] == "HIGH" for f in ip_findings + user_findings):
        overall = "HIGH"
    elif any(f["risk"] == "MEDIUM" for f in ip_findings + user_findings):
        overall = "MEDIUM"

    return {
        "thresholds": {
            "ip_medium": ip_medium,
            "ip_high": ip_high,
            "user_medium": user_medium,
            "user_high": user_high
        },
        "overall_risk": overall,
        "overall_label": risk_label(overall),
        "bruteforce_by_ip": ip_findings[:10],
        "bruteforce_by_user": user_findings[:10],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for SSH login successes/failures and summarize results."
    )
    parser.add_argument("--log", dest="log_path", default=None,
                        help="Path to auth log (default: auto-detect /var/log/auth.log, /var/log/secure, or /var/log/syslog).")

    # Thresholds: tuneable, but sane defaults
    parser.add_argument("--ip-medium", type=int, default=5, help="Failed attempts from one IP to trigger MEDIUM risk.")
    parser.add_argument("--ip-high", type=int, default=15, help="Failed attempts from one IP to trigger HIGH risk.")
    parser.add_argument("--user-medium", type=int, default=5, help="Failed attempts against one user to trigger MEDIUM risk.")
    parser.add_argument("--user-high", type=int, default=15, help="Failed attempts against one user to trigger HIGH risk.")

    parser.add_argument("--out", dest="out_path", default=None,
                        help="Output JSON path (default: reports/auth_report_<timestamp>.json).")
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
    findings = build_risk_findings(
        results,
        ip_medium=args.ip_medium,
        ip_high=args.ip_high,
        user_medium=args.user_medium,
        user_high=args.user_high
    )

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    out_path = args.out_path or f"reports/auth_report_{timestamp}.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.now().isoformat(),
                "log_path": log_path,
                "summary": results,
                "risk_findings": findings,
            },
            f,
            indent=2,
        )

    # Console summary
    print("✅ Auth Log Analyzer Report")
    print(f"Log file: {log_path}")
    print(f"JSON saved: {out_path}")
    print("")
    print(f"Failed logins: {results['failed']['total']}")
    print(f"Overall risk: {findings['overall_label']}")
    print("")

    if findings["bruteforce_by_ip"]:
        print("Brute-force indicators by IP (top):")
        for item in findings["bruteforce_by_ip"][:5]:
            print(f"  - {item['ip']}: {item['failed_attempts']} {item['label']}")
        print("")
    if findings["bruteforce_by_user"]:
        print("Brute-force indicators by user (top):")
        for item in findings["bruteforce_by_user"][:5]:
            print(f"  - {item['user']}: {item['failed_attempts']} {item['label']}")
        print("")

    print("Done.")


if __name__ == "__main__":
    main()

