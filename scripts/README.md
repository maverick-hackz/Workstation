# Scripts

Small Python helpers for AppSec/pentest tasks. Authorized testing only.

## Index

| Script | Purpose | Example |
| --- | --- | --- |
| [ascii_encode.py](./ascii_encode.py) | Print comma-separated decimal codepoints for a string | `python3 ascii_encode.py "hello"` |
| [brute_api.py](./brute_api.py) | Brute-force a numeric `?id=` parameter and grep responses for a marker | `python3 brute_api.py --url http://t:3003 --start 0 --end 10000 --marker position` |
| [hex_encode.py](./hex_encode.py) | Hex-encode a string as `\xHH …` | `python3 hex_encode.py "hello"` |
| [soap_spoof.py](./soap_spoof.py) | Interactive SOAP command injector | `python3 soap_spoof.py --target http://t/wsdl --action '"ExecuteCommand"'` |
| [sqli_websockets.py](./sqli_websockets.py) | HTTP→WebSocket relay so sqlmap/ffuf can target a WS injection point | `python3 sqli_websockets.py --target ws://t:9091/ --listen 0.0.0.0:8081` |
| [str_to_ascii.py](./str_to_ascii.py) | Interactive verbose ASCII encoder (variant of `ascii_encode.py`) | `python3 str_to_ascii.py` |
| [usb_hid.py](./usb_hid.py) | Decode USB HID keyboard scancode captures into typed text | `python3 usb_hid.py --input capture.txt` |
| [web_shell.py](./web_shell.py) | Interactive client for `?cmd=` web shells (with TLS/timeout/proxy controls) | `python3 web_shell.py -t http://t/backdoor.php --interactive` |
| [web_socket_request.py](./web_socket_request.py) | Solve WebSocket arithmetic challenges (safe `ast`-based evaluator, not `eval`) | `python3 web_socket_request.py --target ws://t:16011/ws` |

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Notes

- All scripts share the same skeleton: shebang, module docstring, `argparse`, `main() -> int`, `if __name__ == "__main__": sys.exit(main())`.
- `KeyboardInterrupt` and `requests.exceptions.RequestException` are caught at the boundary so a `^C` returns exit 130 and per-request failures do not crash the loop.
- `web_socket_request.py` historically used `eval(...)` on attacker-controlled bytes (CWE-95); the current version walks an `ast.parse` tree with a whitelist of arithmetic node types. See the `safe_arith_eval` helper.

## Authorized testing only.
