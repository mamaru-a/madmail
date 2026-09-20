#!/usr/bin/env python3
"""Tier D: drive a real Delta Chat client against :443 from the network under test.

probe.py proves the listener speaks IMAP and SMTP on 443. This proves the actual
client can live there: configure, log in, send, receive, and stay idle — which is
the part a raw handshake cannot tell you.

Needs `deltachat-rpc-client` and `deltachat-rpc-server` on PATH (same dependency
the tests/deltachat-test harness uses):

    pip install deltachat-rpc-client deltachat-rpc-server

Usage:
    ./deltachat_probe.py --domain mail.example.org
    ./deltachat_probe.py --domain mail.example.org --port 993   # control run
    ./deltachat_probe.py --domain mail.example.org --idle-seconds 600

Accounts are created through the open-registration endpoint the relay already
exposes to Delta Chat; nothing else on the server is touched.
"""

from __future__ import annotations

import argparse
import random
import socket
import string
import sys
import tempfile
import time
import urllib.parse

try:
    from deltachat_rpc_client import Rpc, DeltaChat, EventType
except ImportError:  # pragma: no cover - depends on the operator's machine
    print("deltachat-rpc-client is not installed: pip install deltachat-rpc-client deltachat-rpc-server",
          file=sys.stderr)
    raise SystemExit(2)


def rand(n: int = 9) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def login_uri(domain: str, ip: str, port: int) -> str:
    """A dclogin URI pinned to one port for both IMAP and submission.

    Pinning is the whole point: `dcaccount:` would let the client fall back to
    993/465 and we would not learn whether 443 works.
    """
    user, password = rand(), rand(20)
    return (
        f"dclogin:{user}@{domain}/?p={urllib.parse.quote(password, safe='')}&v=1"
        f"&ih={ip}&ip={port}&is=ssl"
        f"&sh={ip}&sp={port}&ss=ssl&ic=3"
    )


def configure(dc: DeltaChat, domain: str, ip: str, port: int, label: str, timeout: int):
    acc = dc.add_account()
    acc.set_config_from_qr(login_uri(domain, ip, port))
    acc.set_config("displayname", f"highdpi-smoke {label}")
    t0 = time.monotonic()
    acc.configure()
    print(f"  {label}: configured in {time.monotonic() - t0:.1f}s as {acc.get_config('addr')}")
    acc.start_io()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ev = acc.wait_for_event()
        if ev and ev.kind == EventType.IMAP_INBOX_IDLE:
            print(f"  {label}: reached IMAP idle after {time.monotonic() - t0:.1f}s")
            return acc
        if ev and ev.kind == EventType.ERROR:
            print(f"  {label}: ERROR {ev.msg}")
    raise SystemExit(f"{label}: never reached IMAP idle on :{port} within {timeout}s")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", required=True)
    ap.add_argument("--ip", help="connect to this IP instead of resolving the domain")
    ap.add_argument("--port", type=int, default=443, help="port for both IMAP and submission (default 443)")
    ap.add_argument("--idle-seconds", type=int, default=300, help="how long to hold IMAP idle after the round trip")
    ap.add_argument("--timeout", type=int, default=120, help="per-account configure timeout")
    args = ap.parse_args()

    ip = args.ip or socket.gethostbyname(args.domain)
    print(f"Delta Chat against {args.domain} ({ip}) on :{args.port}")

    with tempfile.TemporaryDirectory() as tmp, Rpc(accounts_dir=tmp) as rpc:
        dc = DeltaChat(rpc)
        alice = configure(dc, args.domain, ip, args.port, "alice", args.timeout)
        bob = configure(dc, args.domain, ip, args.port, "bob", args.timeout)

        chat = alice.create_chat(bob)
        text = f"highdpi-smoke {rand(6)}"
        t0 = time.monotonic()
        chat.send_text(text)
        print(f"  alice: sent {text!r}")

        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            ev = bob.wait_for_event()
            if ev and ev.kind == EventType.INCOMING_MSG:
                msg = bob.get_message_by_id(ev.msg_id).get_snapshot()
                if msg.text == text:
                    print(f"✓ round trip in {time.monotonic() - t0:.1f}s on :{args.port}")
                    break
        else:
            print(f"✗ message never arrived within {args.timeout}s on :{args.port}")
            return 1

        # The part that breaks on a filtered network even when sending works:
        # holding the connection open so the app gets new mail without polling.
        print(f"  holding idle for {args.idle_seconds}s …")
        held_from = time.monotonic()
        errors = 0
        while time.monotonic() - held_from < args.idle_seconds:
            ev = bob.wait_for_event()
            if ev and ev.kind == EventType.ERROR:
                errors += 1
                print(f"  idle error after {time.monotonic() - held_from:.0f}s: {ev.msg}")
        verdict = "✓" if errors == 0 else "✗"
        print(f"{verdict} idle held {args.idle_seconds}s with {errors} error events on :{args.port}")
        return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
