import argparse
import json
import re
import sys
from pathlib import Path

import requests

# Regex for common Apache access log line:
# 198.51.100.77 - - [12/Oct/2025:10:02:01 +0000] "POST /login HTTP/1.1" 401 421 "-" "Mozilla/5.0"
LOG_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'\S+\s+\S+\s+'
    r'\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)\s+'
    r'HTTP/\d\.\d"\s+'
    r'(?P<status>\d{3})\s+'
    r'\S+\s+'
    r'"[^"]*"\s+"[^"]*"'
)

SENSITIVE_PATHS = [
    "/admin",
    "/wp-login",
    "/wp-login.php",
    "/.git",
    "/.git/config",
    "/.env",
    "/phpmyadmin",
]

# thresholds (you can tweak)
MAX_401_403 = 5
MAX_404 = 10


def parse_line(line: str):
    """Parse a single log line, return dict or None on failure."""
    m = LOG_PATTERN.search(line)
    if not m:
        return None
    return {
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": int(m.group("status")),
    }


def is_private_ip(ip: str) -> bool:
    """Simple check to ignore RFC1918 private ranges."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False
    first, second = int(octets[0]), int(octets[1])
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def analyze_log(file_path: Path):
    stats = {}
    lines_processed = 0
    parse_failures = 0

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.lstrip().startswith("#"):
                # skip empty/comment lines but count as processed
                lines_processed += 1
                continue

            lines_processed += 1
            parsed = parse_line(line)
            if not parsed:
                parse_failures += 1
                continue

            ip = parsed["ip"]
            if ip not in stats:
                stats[ip] = {
                    "ip": ip,
                    "status_401": 0,
                    "status_403": 0,
                    "status_404": 0,
                    "sensitive_paths": set(),
                }

            status = parsed["status"]
            path = parsed["path"]

            if status == 401:
                stats[ip]["status_401"] += 1
            elif status == 403:
                stats[ip]["status_403"] += 1
            elif status == 404:
                stats[ip]["status_404"] += 1

            for s in SENSITIVE_PATHS:
                if path.startswith(s):
                    stats[ip]["sensitive_paths"].add(path)
                    break

    return lines_processed, parse_failures, stats


def find_suspicious(stats):
    suspicious = {}
    for ip, data in stats.items():
        if is_private_ip(ip):
            # ignore internal addresses (optional design choice)
            continue

        if (
            data["status_401"] + data["status_403"] >= MAX_401_403
            or data["status_404"] >= MAX_404
            or len(data["sensitive_paths"]) > 0
        ):
            suspicious[ip] = data
    return suspicious


def enrich_ip(ip: str):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        return {"error": str(e)}

    if r.status_code != 200:
        return {"error": f"status_code={r.status_code}"}

    try:
        data = r.json()
    except ValueError as e:
        return {"error": f"json_error={e}"}

    return {
        "country": data.get("country"),
        "org": data.get("org"),
        "city": data.get("city"),
    }


def build_report(lines_processed, parse_failures, suspicious):
    report = {
        "lines_processed": lines_processed,
        "parse_failures": parse_failures,
        "suspicious_ips": [],
    }

    for ip, data in suspicious.items():
        enrichment = enrich_ip(ip)
        report["suspicious_ips"].append(
            {
                "ip": ip,
                "401_count": data["status_401"],
                "403_count": data["status_403"],
                "404_count": data["status_404"],
                "sensitive_paths": sorted(data["sensitive_paths"]),
                "country": enrichment.get("country"),
                "org": enrichment.get("org"),
                "city": enrichment.get("city"),
                "enrichment_error": enrichment.get("error"),
            }
        )

    return report


def print_human_report(report):
    print(f"Lines processed: {report['lines_processed']}")
    print(f"Parse failures: {report['parse_failures']}")
    print("Suspicious IP Report:")

    if not report["suspicious_ips"]:
        print("  (none)")
        return

    for entry in report["suspicious_ips"]:
        print(f"IP: {entry['ip']}")
        print(f"  401 count: {entry['401_count']}")
        print(f"  403 count: {entry['403_count']}")
        print(f"  404 count: {entry['404_count']}")
        if entry["sensitive_paths"]:
            print(f"  Sensitive paths: {', '.join(entry['sensitive_paths'])}")
        else:
            print("  Sensitive paths: -")
        if entry.get("enrichment_error"):
            print(f"  Enrichment error: {entry['enrichment_error']}")
        else:
            print(f"  Country: {entry.get('country')}")
            print(f"  City: {entry.get('city')}")
            print(f"  Org: {entry.get('org')}")
        print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Parse Apache log, detect suspicious IPs, enrich with ipinfo.io"
    )
    parser.add_argument(
        "logfile",
        type=str,
        help="Path to Apache access log file",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        help="Optional path to write JSON report (bonus)",
    )

    args = parser.parse_args(argv)

    log_path = Path(args.logfile)
    if not log_path.is_file():
        print(f"Error: file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    lines_processed, parse_failures, stats = analyze_log(log_path)
    suspicious = find_suspicious(stats)
    report = build_report(lines_processed, parse_failures, suspicious)

    print_human_report(report)

    if args.json_out:
        out_path = Path(args.json_out)
        try:
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        except OSError as e:
            print(f"Failed to write JSON report: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
