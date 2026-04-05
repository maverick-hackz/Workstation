#!/usr/bin/env python3
"""WebSocket challenge-response client for base64-framed arithmetic prompts.

The target sends frames like "id 1234: 12+34*56" wrapped in base64. This client
decodes each frame, evaluates the arithmetic expression safely (no eval()), and
sends the result back.

Usage:
    python3 web_socket_request.py --target ws://example.tld:16011/ws

Authorized testing only.
"""
import argparse
import ast
import base64
import operator
import sys
from typing import Any

from websocket import create_connection

# Whitelist of AST node types and operators allowed in the math expressions the
# server sends. Anything outside this set raises ValueError -- replaces the
# original eval() call which executed arbitrary Python on attacker-controlled
# bytes (CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code).
_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def safe_arith_eval(expr: str) -> Any:
    """Evaluate a numeric arithmetic expression with no name lookups, no calls."""
    tree = ast.parse(expr, mode="eval")

    def walk(node: ast.AST) -> Any:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
            return _BIN_OPS[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
            return _UNARY_OPS[type(node.op)](walk(node.operand))
        raise ValueError(f"Disallowed expression node: {ast.dump(node)}")

    return walk(tree)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="Target WebSocket URL, e.g. ws://host:port/ws")
    parser.add_argument("--rounds", type=int, default=50, help="Number of challenge frames to process (default: 50)")
    parser.add_argument("--proxy", default=None,
                        help="Reserved: explicit proxy support requires websocket-client extras; set HTTPS_PROXY/HTTP_PROXY env vars instead")
    args = parser.parse_args()

    if args.proxy:
        print("[!] --proxy not implemented for websocket-client; set HTTPS_PROXY/HTTP_PROXY env vars instead.", file=sys.stderr)

    ws = create_connection(args.target)
    try:
        for i in range(args.rounds):
            frame = ws.recv()
            # Frame layout (from original PoC): tokens separated by spaces; the
            # base64 blob is the last token on round 0, second-to-last otherwise.
            b64 = frame.split(" ")[-1] if i == 0 else frame.split(" ")[-2]
            decoded = base64.b64decode(b64).decode()

            # The decoded message is "<noise> <noise> <arith-expression>". Take
            # everything after the second space as the expression text.
            expr = " ".join(decoded.split(" ")[2:])
            try:
                answer = safe_arith_eval(expr)
            except (ValueError, SyntaxError) as exc:
                print(f"[!] refusing to evaluate non-arithmetic input: {exc}", file=sys.stderr)
                return 1
            ws.send(str(answer))

        print(ws.recv())
    finally:
        ws.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
