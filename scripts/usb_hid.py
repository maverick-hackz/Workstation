#!/usr/bin/env python3
"""USB HID-capture decoder.

Decodes USB HID keyboard scancode captures (one frame per line, hex bytes) into the
plaintext that was typed. Handles non-shift (00), shift (02), and Ctrl (01) modifiers
plus arrow up/down (51/52) and the basic alphanumeric + punctuation keymap.

Usage:
    python3 usb_hid.py --input capture.txt

Authorized testing only.
"""
import argparse
import sys

USB_CODES = {
    "04": "aA", "05": "bB", "06": "cC", "07": "dD", "08": "eE", "09": "fF",
    "0a": "gG", "0b": "hH", "0c": "iI", "0d": "jJ", "0e": "kK", "0f": "lL",
    "10": "mM", "11": "nN", "12": "oO", "13": "pP", "14": "qQ", "15": "rR",
    "16": "sS", "17": "tT", "18": "uU", "19": "vV", "1a": "wW", "1b": "xX",
    "1c": "yY", "1d": "zZ", "1e": "1!", "1f": "2@", "20": "3#", "21": "4$",
    "22": "5%", "23": "6^", "24": "7&", "25": "8*", "26": "9(", "27": "0)",
    "2c": "  ", "2d": "-_", "2e": "=+", "2f": "[{", "30": "]}", "32": "#~",
    "33": ";:", "34": "'\"", "36": ",<", "37": ".>",
}


def decode(lines: list[str]) -> list[str]:
    # Deduplicate consecutive frames; only keep frames with the "no key" zero-fill marker
    filtered = [""]
    for i in lines:
        if i[:2] in ("00", "01", "02") and "0" * 10 in i:
            if filtered[-1] != i:
                filtered.append(i)

    out = ["", "", "", "", "", "", "", "", ""]  # multiple buffer lines for arrow-up/down navigation
    pos = 0
    for frame in filtered[1:]:
        key = frame[4:6]
        if key in ("51", "28"):  # down arrow / enter
            pos += 1
            continue
        if key == "52":  # up arrow
            pos -= 1
            continue
        if "0000000000" not in frame:
            continue
        if key not in USB_CODES:
            continue
        mod = frame[:2]
        if mod == "01":
            # Ctrl-modified: emit the buffers as a checkpoint and continue
            print(out)
        elif mod == "02":
            out[pos] += USB_CODES[key][1]  # shifted character
        elif mod == "00":
            out[pos] += USB_CODES[key][0]  # unshifted character
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", "-i", default="2.txt", help="HID capture text file (default: 2.txt)")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            data = fh.read()
    except FileNotFoundError:
        print(f"[!] file not found: {args.input}", file=sys.stderr)
        return 1

    lines = data.splitlines()
    result = decode(lines)
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
