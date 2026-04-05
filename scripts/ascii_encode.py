#!/usr/bin/env python3
"""ASCII encoder: print comma-separated decimal codepoints for input strings.

Usage:
    python3 ascii_encode.py                 # interactive (type 'exit' to quit)
    python3 ascii_encode.py "hello world"   # one-shot, encode the argument

Authorized testing only.
"""
import argparse
import sys


def encode(s: str) -> str:
    return ",".join(str(ord(c)) for c in s)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("text", nargs="?", help="String to encode. If omitted, run interactively.")
    args = parser.parse_args()

    if args.text is not None:
        print(encode(args.text))
        return 0

    try:
        while True:
            s = input()
            if s.lower() == "exit":
                return 0
            print(encode(s))
    except (EOFError, KeyboardInterrupt):
        return 0


if __name__ == "__main__":
    sys.exit(main())
