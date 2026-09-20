#!/usr/bin/env python3
"""Smoke test madmail's shared-port mail from a high-DPI network.

Runs from a client machine on the network under test and reports, per scenario,
*why* a connection failed — a blocked port, a reset mid-handshake, a strict-ALPN
refusal and a working listener all look the same to `nc`.

Python 3.9+, standard library only. Nothing is written on the server except in
tier C (a test message to your own account).

Usage:
    ./probe.py --host mail.example.org                    # tiers A + B
    ./probe.py --host mail.example.org --tier a
    ./probe.py --host mail.example.org --tier b --repeat 20
    MADMAIL_SMOKE_USER=u@x MADMAIL_SMOKE_PASS=… ./probe.py --host x --tier c
    ./probe.py --host mail.example.org --json report.json

Run it twice: once from the network under test, once from an unfiltered network
(the control). The difference between the two reports is the result; a single
report cannot tell a filtered port from a misconfigured server.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# Wire tokens are fixed in the server (chatmail-config): the `alpn_imap` /
# `alpn_smtp` directive values are switches, not tokens.
ALPN_IMAP = "imap"
ALPN_SMTP = "smtp"
BROWSER_ALPN = ["h2", "http/1.1"]

# Ports, overridable so the same script can drive a lab instance on high ports.
PORTS = {"shared": 443, "imap": 993, "submission": 465}
EXTRA_PORTS = [587, 143, 25, 80]  # probed for reachability only
CAFILE: Optional[str] = None  # lab CA for a self-signed instance

# --------------------------------------------------------------------------
# Outcomes. The point of this script is that these stay distinguishable.
# --------------------------------------------------------------------------
DNS_FAIL = "DNS_FAIL"  # name does not resolve (or resolves to a poisoned IP)
TCP_REFUSED = "TCP_REFUSED"  # RST to SYN: something answered, port closed
TCP_TIMEOUT = "TCP_TIMEOUT"  # SYN blackholed: the usual shape of a blocked port
TCP_UNREACH = "TCP_UNREACH"  # ICMP unreachable
TLS_RESET = "TLS_RESET"  # RST *after* ClientHello: the DPI signature
TLS_TIMEOUT = "TLS_TIMEOUT"  # handshake stalled: also consistent with DPI
TLS_ALPN_REFUSED = "TLS_ALPN_REFUSED"  # alert 120, the server's strict ALPN
TLS_CERT_MISMATCH = "TLS_CERT_MISMATCH"  # cert does not cover the name we asked for
TLS_ERROR = "TLS_ERROR"  # any other handshake failure
IMAP_GREETING = "IMAP_GREETING"
SMTP_BANNER = "SMTP_BANNER"
HTTP_RESPONSE = "HTTP_RESPONSE"
NO_DATA = "NO_DATA"  # handshake fine, server said nothing before the deadline
RESET_AFTER_HANDSHAKE = "RESET_AFTER_HANDSHAKE"
UNKNOWN_DATA = "UNKNOWN_DATA"
SKIP = "SKIP"


@dataclass
class Probe:
    """One connection attempt and what came back."""

    outcome: str
    detail: str = ""
    alpn: Optional[str] = None
    tcp_ms: Optional[float] = None
    tls_ms: Optional[float] = None
    first_byte_ms: Optional[float] = None
    payload: str = ""


@dataclass
class Result:
    """One scenario: what we expected, what happened, and whether that is a pass."""

    scenario: str
    what: str
    expected: str
    probe: Probe
    verdict: str  # PASS / FAIL / SKIP / INFO
    note: str = ""


@dataclass
class Report:
    host: str
    ip: str
    started: str
    label: str
    results: list = field(default_factory=list)
    matrix: list = field(default_factory=list)
    cert_sans: list = field(default_factory=list)


def _ctx(alpn: Optional[list], verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CAFILE)
    if not verify:
        # Routing probes must survive a self-signed or mismatched certificate:
        # we are testing which protocol the port speaks, not the PKI. Cert
        # validity is checked separately, by cert_sans().
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn is not None:
        ctx.set_alpn_protocols(alpn)
    return ctx


def _handshake_ok_without_alpn(ip: str, port: int, sni: Optional[str], timeout: float) -> bool:
    """Does the same handshake succeed when we drop the ALPN extension?"""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            ctx = _ctx(None)
            tls = ctx.wrap_socket(sock, server_hostname=sni) if sni else ctx.wrap_socket(sock)
            tls.close()
            return True
    except OSError:
        return False


def _classify_tls_error(
    exc: Exception, ip: str, port: int, sni: Optional[str], alpn: Optional[list], timeout: float
) -> tuple:
    """Name the handshake failure.

    Alert 120 (`no_application_protocol`) is the one we most need to recognise,
    and it is the one OpenSSL is least consistent about: 3.0.11 surfaces it as
    `[SSL] unknown error` with `reason=None`, newer builds as
    `TLSV1_ALERT_NO_APPLICATION_PROTOCOL`. So when a handshake that offered ALPN
    fails, retry once without the extension: if that succeeds, the ALPN offer was
    the reason, whatever the local OpenSSL called it.
    """
    text = str(exc)
    reason = getattr(exc, "reason", "") or ""
    if "NO_APPLICATION_PROTOCOL" in reason or "NO_APPLICATION_PROTOCOL" in text:
        return TLS_ALPN_REFUSED, text
    if isinstance(exc, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text:
        return TLS_CERT_MISMATCH, text
    if alpn and _handshake_ok_without_alpn(ip, port, sni, timeout):
        return TLS_ALPN_REFUSED, f"{text} (confirmed: the same handshake succeeds without ALPN)"
    return TLS_ERROR, text


def probe(
    ip: str,
    port: int,
    *,
    sni: Optional[str],
    alpn: Optional[list],
    send_first: bytes = b"",
    connect_timeout: float = 8.0,
    read_timeout: float = 6.0,
    verify: bool = False,
) -> Probe:
    """One TCP+TLS attempt, classified.

    `sni=None` sends no SNI extension at all (what a client dialling an IP does);
    `alpn=None` sends no ALPN extension (what Thunderbird and Apple Mail do).
    """
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except socket.timeout:
        return Probe(TCP_TIMEOUT, f"no SYN-ACK within {connect_timeout}s")
    except ConnectionRefusedError as exc:
        return Probe(TCP_REFUSED, str(exc))
    except OSError as exc:
        return Probe(TCP_UNREACH, str(exc))
    tcp_ms = (time.monotonic() - t0) * 1000

    ctx = _ctx(alpn, verify=verify)
    t1 = time.monotonic()
    try:
        sock.settimeout(connect_timeout)
        tls = ctx.wrap_socket(sock, server_hostname=sni) if sni else ctx.wrap_socket(sock)
    except ConnectionResetError as exc:
        # The interesting one: the ClientHello left, the connection died. On a
        # filtered network this is the DPI verdict, not the server's.
        sock.close()
        return Probe(TLS_RESET, str(exc), tcp_ms=tcp_ms)
    except socket.timeout:
        sock.close()
        return Probe(TLS_TIMEOUT, f"no ServerHello within {connect_timeout}s", tcp_ms=tcp_ms)
    except ssl.SSLError as exc:
        sock.close()
        outcome, detail = _classify_tls_error(exc, ip, port, sni, alpn, connect_timeout)
        return Probe(outcome, detail, tcp_ms=tcp_ms)
    except OSError as exc:
        sock.close()
        return Probe(TLS_ERROR, str(exc), tcp_ms=tcp_ms)
    tls_ms = (time.monotonic() - t1) * 1000
    negotiated = tls.selected_alpn_protocol()

    try:
        if send_first:
            tls.sendall(send_first)
        tls.settimeout(read_timeout)
        t2 = time.monotonic()
        try:
            data = tls.recv(512)
        except socket.timeout:
            return Probe(NO_DATA, f"silent for {read_timeout}s", negotiated, tcp_ms, tls_ms)
        except ConnectionResetError as exc:
            return Probe(RESET_AFTER_HANDSHAKE, str(exc), negotiated, tcp_ms, tls_ms)
        first_byte_ms = (time.monotonic() - t2) * 1000
    finally:
        try:
            tls.close()
        except OSError:
            pass

    text = data.decode("utf-8", "replace").strip()
    head = text.splitlines()[0][:120] if text else ""
    if not data:
        return Probe(NO_DATA, "server closed without sending", negotiated, tcp_ms, tls_ms)
    if text.startswith("* OK"):
        outcome = IMAP_GREETING
    elif text.startswith("220"):
        outcome = SMTP_BANNER
    elif text.startswith("HTTP/1."):
        outcome = HTTP_RESPONSE
    else:
        outcome = UNKNOWN_DATA
    return Probe(outcome, "", negotiated, tcp_ms, tls_ms, first_byte_ms, head)


def cert_sans(ip: str, port: int, sni: str) -> tuple:
    """Names the served certificate actually covers, via a verifying handshake."""
    ctx = ssl.create_default_context(cafile=CAFILE)
    try:
        with socket.create_connection((ip, port), timeout=8.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                cert = tls.getpeercert() or {}
    except Exception as exc:  # noqa: BLE001 — any failure means "cannot tell"
        return [], str(exc)
    names = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    return names, ""


# --------------------------------------------------------------------------
# Tier A — reachability and the demux
# --------------------------------------------------------------------------
def tier_a(host: str, ip: str, rep: Report, timeout: float) -> None:
    def add(scenario, what, expected, p, ok_outcomes, note=""):
        verdict = "PASS" if p.outcome in ok_outcomes else "FAIL"
        rep.results.append(Result(scenario, what, expected, p, verdict, note))
        return p

    # A1 — which ports are reachable at all. TCP only, no TLS.
    for port in sorted({*PORTS.values(), *EXTRA_PORTS}):
        t0 = time.monotonic()
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            p = Probe("TCP_OPEN", tcp_ms=(time.monotonic() - t0) * 1000)
        except socket.timeout:
            p = Probe(TCP_TIMEOUT, f"no SYN-ACK within {timeout}s")
        except ConnectionRefusedError as exc:
            p = Probe(TCP_REFUSED, str(exc))
        except OSError as exc:
            p = Probe(TCP_UNREACH, str(exc))
        rep.results.append(
            Result(
                f"A1/{port}",
                f"TCP connect to :{port}",
                "reachable or not — record for the control comparison",
                p,
                "INFO",
                "TCP_TIMEOUT here and TCP_OPEN on the control network = the port is filtered",
            )
        )

    # A2 — the feature itself: ALPN imap on the HTTPS port.
    add(
        "A2",
        f"{PORTS['shared']}, ALPN `imap`",
        "IMAP greeting",
        probe(ip, PORTS["shared"], sni=host, alpn=[ALPN_IMAP], connect_timeout=timeout, read_timeout=timeout),
        {IMAP_GREETING},
        "This is what Delta Chat does when 993 is blocked",
    )

    # A3 — submission on the same port.
    add(
        "A3",
        f"{PORTS['shared']}, ALPN `smtp`",
        "SMTP banner",
        probe(ip, PORTS["shared"], sni=host, alpn=[ALPN_SMTP], connect_timeout=timeout, read_timeout=timeout),
        {SMTP_BANNER},
    )

    # A4 — no ALPN must stay HTTPS. Under the first-bytes peek a silent client
    # waits out the peek timeout, so send a request line like a browser would.
    add(
        "A4",
        f"{PORTS['shared']}, no ALPN, HTTP request line",
        "HTTP response (never a mail parser)",
        probe(
            ip,
            PORTS["shared"],
            sni=host,
            alpn=None,
            send_first=f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(),
            connect_timeout=timeout,
            read_timeout=timeout,
        ),
        {HTTP_RESPONSE},
        "Security property: an unidentified connection is served as HTTPS",
    )

    # A5 — strict ALPN: offers that do not intersect must be refused (ALPACA).
    add(
        "A5",
        f"{PORTS['shared']}, ALPN `h2` only",
        "handshake refused (alert 120)",
        probe(ip, PORTS["shared"], sni=host, alpn=["h2"], connect_timeout=timeout, read_timeout=timeout),
        {TLS_ALPN_REFUSED},
        "A reset instead of an alert here means DPI, not the server",
    )

    # A6/A7 — the stock-client paths added on top of ALPN. Both need the
    # certificate to cover the hostname the client dials, so check that first.
    sans, why = cert_sans(ip, PORTS["shared"], host)
    rep.cert_sans = sans
    has_imap_san = any(n in (f"imap.{host}", f"*.{host}") for n in sans)
    if has_imap_san:
        add(
            "A6",
            f"{PORTS['shared']}, no ALPN, SNI imap.{host}",
            "IMAP greeting (SNI path)",
            probe(ip, PORTS["shared"], sni=f"imap.{host}", alpn=None, connect_timeout=timeout, read_timeout=timeout),
            {IMAP_GREETING},
        )
    else:
        rep.results.append(
            Result(
                "A6",
                f"{PORTS['shared']}, no ALPN, SNI imap.{host}",
                "IMAP greeting (SNI path)",
                Probe(SKIP, why or f"certificate covers {sans or 'unknown'}"),
                "SKIP",
                "The served certificate has no imap. name, so a stock client would "
                "reject it before any routing happens. See server-setup.sh.",
            )
        )

    # A7 — first bytes: an early talker on a name that selects nothing.
    add(
        "A7",
        f"{PORTS['shared']}, no ALPN, neutral SNI, early EHLO",
        "SMTP banner (first-bytes path)",
        probe(
            ip,
            PORTS["shared"],
            sni=host,
            alpn=None,
            send_first=b"EHLO highdpi-smoke\r\n",
            connect_timeout=timeout,
            read_timeout=timeout,
        ),
        {SMTP_BANNER},
        "Only fires for clients that speak before being greeted",
    )

    # A8/A9 — the dedicated ports, if they are reachable at all here.
    for port, token, greeting in (
        (PORTS["imap"], ALPN_IMAP, IMAP_GREETING),
        (PORTS["submission"], ALPN_SMTP, SMTP_BANNER),
    ):
        p = probe(ip, port, sni=host, alpn=None, connect_timeout=timeout, read_timeout=timeout)
        if p.outcome in (TCP_TIMEOUT, TCP_REFUSED, TCP_UNREACH):
            rep.results.append(
                Result(
                    f"A8/{port}",
                    f"{port}, no ALPN",
                    "greeting",
                    p,
                    "INFO",
                    "Port unreachable from here — this is the case 443 exists for",
                )
            )
            continue
        add(
            f"A8/{port}",
            f"{port}, no ALPN (Thunderbird, Apple Mail)",
            "greeting: strict ALPN must not lock out ALPN-less clients",
            p,
            {greeting},
        )
        add(
            f"A9/{port}",
            f"{port}, ALPN `{token}`",
            "greeting with the token negotiated",
            probe(ip, port, sni=host, alpn=[token], connect_timeout=timeout, read_timeout=timeout),
            {greeting},
        )
        add(
            f"A10/{port}",
            f"{port}, browser ALPN `h2, http/1.1`",
            "refused (cross-protocol hardening)",
            probe(ip, port, sni=host, alpn=BROWSER_ALPN, connect_timeout=timeout, read_timeout=timeout),
            {TLS_ALPN_REFUSED},
        )


# --------------------------------------------------------------------------
# Tier B — is the ClientHello itself what gets punished?
# --------------------------------------------------------------------------
MATRIX = [
    ("browser-like", BROWSER_ALPN, "host"),
    ("http1-only", ["http/1.1"], "host"),
    ("no-alpn", None, "host"),
    ("alpn-imap", [ALPN_IMAP], "host"),
    ("alpn-smtp", [ALPN_SMTP], "host"),
    ("no-alpn-imap-sni", None, "imap"),
    ("no-sni", None, None),
]


def tier_b(host: str, ip: str, rep: Report, repeat: int, timeout: float) -> None:
    """Repeat each ClientHello shape and count how they die.

    A middlebox that dislikes the `imap` token shows up as a higher TLS_RESET or
    TLS_TIMEOUT rate for that row than for the browser-like row, against the same
    IP and port in the same minute.
    """
    for name, alpn, sni_kind in MATRIX:
        sni = {"host": host, "imap": f"imap.{host}", None: None}[sni_kind]
        outcomes: dict = {}
        handshakes: list = []
        for _ in range(repeat):
            p = probe(ip, PORTS["shared"], sni=sni, alpn=alpn, connect_timeout=timeout, read_timeout=2.0)
            outcomes[p.outcome] = outcomes.get(p.outcome, 0) + 1
            if p.tls_ms is not None:
                handshakes.append(p.tls_ms)
        killed = sum(outcomes.get(o, 0) for o in (TLS_RESET, TLS_TIMEOUT, RESET_AFTER_HANDSHAKE))
        rep.matrix.append(
            {
                "hello": name,
                "alpn": alpn,
                "sni": sni,
                "n": repeat,
                "outcomes": outcomes,
                "killed_pct": round(100.0 * killed / repeat, 1),
                "handshake_ms_median": round(statistics.median(handshakes), 1) if handshakes else None,
            }
        )


# --------------------------------------------------------------------------
# Tier C — a real account: login, IDLE survival, round trip, throughput
# --------------------------------------------------------------------------
def _mail_socket(host: str, port: int, token: str, timeout: float):
    """Verified TLS for tier C — credentials travel on this socket.

    The tier A/B probes deliberately accept any certificate because they measure
    routing, not PKI, and never send anything secret. Here a password is sent, so
    the certificate is verified and the hostname checked; a filtered network that
    intercepts TLS must fail this, loudly, rather than be measured through.
    """
    ctx = ssl.create_default_context(cafile=CAFILE)
    ctx.set_alpn_protocols([token])
    sock = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(sock, server_hostname=host)
    tls.settimeout(timeout)
    return tls


def _imap_cmd(tls, tag: str, cmd: str, timeout: float = 30.0) -> str:
    tls.sendall(f"{tag} {cmd}\r\n".encode())
    tls.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = tls.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        # Done when the tagged completion line arrives.
        if f"\r\n{tag} ".encode() in buf or buf.startswith(f"{tag} ".encode()):
            break
    return buf.decode("utf-8", "replace")


def tier_c(host: str, rep: Report, user: str, password: str, idle_seconds: int, timeout: float) -> None:
    for port, token in ((PORTS["shared"], ALPN_IMAP), (PORTS["imap"], ALPN_IMAP)):
        label = f"C1/{port}"
        try:
            tls = _mail_socket(host, port, token, timeout)
        except Exception as exc:  # noqa: BLE001
            rep.results.append(
                Result(label, f"IMAP LOGIN on :{port}", "authenticated session",
                       Probe(TLS_ERROR, str(exc)), "FAIL" if port == PORTS["shared"] else "INFO")
            )
            continue
        try:
            greeting = tls.recv(512).decode("utf-8", "replace").strip()
            resp = _imap_cmd(tls, "a1", f'LOGIN "{user}" "{password}"')
            ok = " OK " in resp or resp.strip().endswith("OK")
            rep.results.append(
                Result(
                    label,
                    f"IMAP LOGIN on :{port} (ALPN {token})",
                    "a1 OK",
                    Probe(IMAP_GREETING if ok else UNKNOWN_DATA, resp.strip()[:200], payload=greeting[:80]),
                    "PASS" if ok else "FAIL",
                )
            )
            if not ok:
                continue

            # C2 — does a long-held connection survive? Idle mail connections are
            # what a stateful middlebox reaps first, and Delta Chat lives on them.
            _imap_cmd(tls, "a2", "SELECT INBOX")
            t0 = time.monotonic()
            tls.sendall(b"a3 IDLE\r\n")
            tls.settimeout(idle_seconds + 10)
            survived, why = True, ""
            try:
                tls.recv(4096)  # the "+ idling" continuation
                deadline = time.monotonic() + idle_seconds
                while time.monotonic() < deadline:
                    tls.settimeout(min(30.0, max(1.0, deadline - time.monotonic())))
                    try:
                        if tls.recv(4096) == b"":
                            survived, why = False, "server closed the IDLE connection"
                            break
                    except socket.timeout:
                        continue  # silence is what IDLE looks like; keep holding
            except ConnectionResetError as exc:
                survived, why = False, f"reset while idling: {exc}"
            except OSError as exc:
                survived, why = False, f"{exc}"
            held = round(time.monotonic() - t0)
            rep.results.append(
                Result(
                    f"C2/{port}",
                    f"IMAP IDLE held {idle_seconds}s on :{port}",
                    "connection still open at the end",
                    Probe("IDLE_HELD" if survived else "IDLE_DROPPED", f"{why} (held {held}s)"),
                    "PASS" if survived else "FAIL",
                    "A drop here means push notifications and new-mail alerts die on this network",
                )
            )
        finally:
            try:
                tls.close()
            except OSError:
                pass

    # C3 — submission on 443, and the size a filtered network actually lets through.
    for size_kb in (16, 512):
        body = "x" * (size_kb * 1024)
        msg = (
            f"From: {user}\r\nTo: {user}\r\nSubject: highdpi-smoke {size_kb}KB\r\n"
            f"Message-ID: <smoke-{int(time.time())}-{size_kb}@highdpi>\r\n\r\n{body}\r\n"
        )
        t0 = time.monotonic()
        try:
            tls = _mail_socket(host, PORTS["shared"], ALPN_SMTP, timeout)
            tls.recv(512)
            auth = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
            for cmd in (f"EHLO highdpi-smoke", f"AUTH PLAIN {auth}", f"MAIL FROM:<{user}>",
                        f"RCPT TO:<{user}>", "DATA"):
                tls.sendall(f"{cmd}\r\n".encode())
                reply = tls.recv(4096).decode("utf-8", "replace")
                if reply[:1] not in ("2", "3"):
                    raise RuntimeError(f"{cmd} -> {reply.strip()[:120]}")
            tls.sendall(msg.encode() + b".\r\n")
            reply = tls.recv(4096).decode("utf-8", "replace")
            tls.sendall(b"QUIT\r\n")
            tls.close()
            secs = time.monotonic() - t0
            # A chatmail relay rejects cleartext mail with `523 5.7.1 Encryption
            # Needed`, and it does so *after* the body has been uploaded — which
            # is exactly the part we are timing. Both answers mean the upload got
            # through; only a stall or a reset means the network ate it.
            ok = reply.startswith("250") or reply.startswith("523")
            rep.results.append(
                Result(
                    f"C3/{size_kb}KB",
                    f"upload {size_kb} KB through submission on :{PORTS['shared']}",
                    "250 accepted, or 523 (cleartext policy) after the body arrived",
                    Probe(SMTP_BANNER if ok else UNKNOWN_DATA, reply.strip()[:120],
                          first_byte_ms=round(secs * 1000, 1),
                          payload=f"{size_kb / secs:.0f} KB/s"),
                    "PASS" if ok else "FAIL",
                    "Large uploads are where throttling shows up, not the handshake",
                )
            )
        except Exception as exc:  # noqa: BLE001
            rep.results.append(
                Result(f"C3/{size_kb}KB", f"upload {size_kb} KB through submission on :{PORTS['shared']}",
                       "250 accepted, or 523 after the body arrived",
                       Probe(TLS_ERROR, str(exc)[:200]), "FAIL")
            )


# --------------------------------------------------------------------------
def render(rep: Report) -> str:
    out = [
        f"host      {rep.host} ({rep.ip})",
        f"label     {rep.label}",
        f"started   {rep.started}",
        f"cert SANs {', '.join(rep.cert_sans) if rep.cert_sans else '(not verified)'}",
        "",
        f"{'scenario':<12} {'verdict':<7} {'outcome':<24} {'what':<46} detail",
        "-" * 118,
    ]
    for r in rep.results:
        p = r.probe
        timing = ""
        if p.tls_ms is not None:
            timing = f"tls {p.tls_ms:.0f}ms"
        detail = p.detail or p.payload or timing
        out.append(f"{r.scenario:<12} {r.verdict:<7} {p.outcome:<24} {r.what:<46} {detail[:60]}")
    if rep.matrix:
        out += ["", "ClientHello matrix (same IP, same port, same minute):", ""]
        out.append(f"{'hello':<18} {'n':>3} {'killed%':>8} {'median ms':>10}  outcomes")
        out.append("-" * 96)
        for m in rep.matrix:
            out.append(
                f"{m['hello']:<18} {m['n']:>3} {m['killed_pct']:>8} "
                f"{str(m['handshake_ms_median']):>10}  {m['outcomes']}"
            )
    fails = [r for r in rep.results if r.verdict == "FAIL"]
    out += ["", f"{len(fails)} FAIL, "
            f"{sum(1 for r in rep.results if r.verdict == 'PASS')} PASS, "
            f"{sum(1 for r in rep.results if r.verdict == 'SKIP')} SKIP"]
    if fails:
        out.append("A FAIL is only meaningful next to a control run from an unfiltered network.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="mail hostname, e.g. mail.example.org")
    ap.add_argument("--ip", help="connect to this IP instead of resolving (detects DNS poisoning)")
    ap.add_argument("--tier", default="ab", help="which tiers to run: a, b, c or any combination")
    ap.add_argument("--repeat", type=int, default=10, help="tier B repeats per ClientHello shape")
    ap.add_argument("--idle-seconds", type=int, default=300, help="tier C IDLE hold")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--label", default="", help="free text, e.g. 'mobile-lte' or 'control-vps'")
    ap.add_argument("--shared-port", type=int, default=443, help="the HTTPS port that also serves mail")
    ap.add_argument("--imap-port", type=int, default=993)
    ap.add_argument("--submission-port", type=int, default=465)
    ap.add_argument("--cafile", help="CA bundle for a lab instance with its own certificate")
    ap.add_argument("--json", help="also write the report as JSON here")
    args = ap.parse_args()

    global CAFILE
    CAFILE = args.cafile
    PORTS.update(shared=args.shared_port, imap=args.imap_port, submission=args.submission_port)

    try:
        resolved = socket.gethostbyname(args.host)
    except OSError as exc:
        print(f"{args.host}: DNS failed ({exc})", file=sys.stderr)
        if not args.ip:
            return 2
        resolved = ""
    ip = args.ip or resolved
    if resolved and args.ip and resolved != args.ip:
        print(f"note: DNS says {resolved}, probing {args.ip} as asked — possible DNS interference")

    rep = Report(host=args.host, ip=ip, started=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                 label=args.label or socket.gethostname())
    tier = args.tier.lower()
    if "a" in tier:
        tier_a(args.host, ip, rep, args.timeout)
    if "b" in tier:
        tier_b(args.host, ip, rep, args.repeat, args.timeout)
    if "c" in tier:
        user, password = os.environ.get("MADMAIL_SMOKE_USER"), os.environ.get("MADMAIL_SMOKE_PASS")
        if not user or not password:
            print("tier C needs MADMAIL_SMOKE_USER and MADMAIL_SMOKE_PASS", file=sys.stderr)
            return 2
        tier_c(args.host, rep, user, password, args.idle_seconds, args.timeout)

    print(render(rep))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(
                {**asdict(rep), "results": [asdict(r) for r in rep.results]},
                fh, indent=2, default=str,
            )
        print(f"\nJSON written to {args.json}")
    return 1 if any(r.verdict == "FAIL" for r in rep.results) else 0


if __name__ == "__main__":
    sys.exit(main())
