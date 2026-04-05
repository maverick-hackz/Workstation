#!/usr/bin/env python3
"""Middleware HTTP server -> WebSocket relay for WebSocket-based SQL injection testing.

Pipes HTTP GET ?id=PAYLOAD into a WebSocket message {"id": "PAYLOAD"} sent to the
target WS endpoint, then returns the WS response over HTTP. Lets you point sqlmap,
ffuf, or curl at the local HTTP middleware while the actual injection target speaks
WebSocket.

Usage:
    python3 sqli_websockets.py --target ws://example.tld:9091/ --listen 0.0.0.0:8081

Authorized testing only.
"""
import argparse
import sys
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse

from websocket import create_connection


def make_handler(ws_url: str, content_type: str = "text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):  # quieter access log
            sys.stderr.write("[%s] %s\n" % (self.address_string(), format % args))

        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split("=", 1)[1]
            except IndexError:
                payload = None

            if payload:
                content = send_ws(ws_url, payload)
            else:
                content = "No parameters specified!"

            self.send_header("Content-type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())

    return CustomHandler


def send_ws(ws_url: str, payload: str) -> str:
    ws = create_connection(ws_url)
    try:
        message = unquote(payload).replace('"', "'")  # avoid breaking JSON
        data = '{"id":"%s"}' % message
        ws.send(data)
        resp = ws.recv()
    finally:
        ws.close()
    return resp if resp else ""


class _TCPServer(TCPServer):
    allow_reuse_address = True


def parse_listen(spec: str) -> tuple[str, int]:
    host, _, port = spec.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"Invalid --listen spec: {spec!r} (expected host:port)")
    return host, int(port)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Target WebSocket URL, e.g. ws://host:port/")
    parser.add_argument("--listen", default="0.0.0.0:8081", type=parse_listen,
                        help="Listen host:port for the HTTP middleware (default: 0.0.0.0:8081)")
    parser.add_argument("--proxy", default=None,
                        help="Reserved: explicit proxy support requires websocket-client extras; document the env vars HTTPS_PROXY/HTTP_PROXY instead")
    args = parser.parse_args()

    if args.proxy:
        print("[!] --proxy not implemented for websocket-client; set HTTPS_PROXY/HTTP_PROXY env vars instead.", file=sys.stderr)

    handler = make_handler(args.target)
    print(f"[+] Starting middleware server on http://{args.listen[0]}:{args.listen[1]}")
    print(f"[+] Forwarding ?id=* to {args.target}")
    httpd = _TCPServer(args.listen, handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        httpd.server_close()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
