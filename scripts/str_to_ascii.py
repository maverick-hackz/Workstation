#!/usr/bin/env python3
"""Interactive string-to-ASCII printer (similar to ascii_encode.py with verbose framing).

Usage:
    python3 str_to_ascii.py                 # interactive (type 'exit' to quit)
    python3 str_to_ascii.py "hello world"   # one-shot, encode the argument

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
        print("\nASCII text:")
        print(encode(args.text), "\n")
        return 0

    try:
        while True:
            s = input("Enter text:\n")
            if s.lower() == "exit":
                return 0
            print("\nASCII text:")
            print(encode(s), "\n")
    except (EOFError, KeyboardInterrupt):
        return 0


if __name__ == "__main__":
    sys.exit(main())
