# Smoke test on a high-DPI network

Does madmail's shared port actually reach a user whose network blocks mail ports
and inspects TLS? These scripts answer that with measurements instead of a guess.

The feature under test (PR #173): port 443 serves HTTPS, IMAP and submission on
one listener, chosen by ALPN, then by SNI, then by the client's first bytes.

## What this can and cannot show

- **Can show:** ports 993/465 blocked while 443 works; a middlebox resetting
  connections that advertise the `imap` ALPN token; DNS interference; upload
  throttling; idle connections being reaped.
- **Cannot show:** that mail is undetectable. ALPN tokens travel in the
  cleartext ClientHello, so `imap` on 443 is as visible as port 993. This
  measures port blocking, not traffic analysis.

**Always run twice** — once on the network under test, once on an unfiltered
network as a control. A single report cannot tell a filtered port from a broken
server.

## Files

| File | Runs on | Purpose |
|---|---|---|
| `server-setup.sh` | the mail server | Check/prepare the config, the certificate and DNS; prints a checklist, changes nothing on its own |
| `probe.py` | the client under test | Tiers A, B, C — stdlib Python 3.9+, no pip |
| `deltachat_probe.py` | the client under test | Tier D — a real Delta Chat client pinned to :443 |

## Quick start

```bash
# 1. On the server (once)
./server-setup.sh --domain mail.example.org --with-sni

# 2. On an unfiltered host — the control
./probe.py --host mail.example.org --label control --json control.json

# 3. On the network under test
./probe.py --host mail.example.org --label mobile-lte --json filtered.json
```

Exit code is 1 if any scenario failed, so it drops into a cron or CI step.

## Tier A — reachability and demux

| # | Scenario | Expected |
|---|---|---|
| A0 | Certificate on 443 verifies against system roots | valid chain, matching name — a FAIL here that passes on the control is TLS interception |
| A1 | TCP connect to 443, 993, 465, 587, 143, 25, 80 | recorded, not judged — the control tells you which are filtered |
| A2 | 443, ALPN `imap` | IMAP greeting |
| A3 | 443, ALPN `smtp` | SMTP banner |
| A4 | 443, no ALPN, HTTP request line | HTTP response — an unidentified connection must never reach a mail parser |
| A5 | 443, ALPN `h2` only | handshake refused (alert 120) |
| A6 | 443, no ALPN, SNI `imap.<domain>` | IMAP greeting — SKIP unless the certificate covers that name |
| A7 | 443, no ALPN, neutral SNI, early `EHLO` | SMTP banner (first-bytes path) — SKIP if the host's own first label is `imap.`/`smtp.`, since then no neutral name exists |
| A8 | 993 / 465, no ALPN | greeting — strict ALPN must not lock out Thunderbird or Apple Mail |
| A9 | 993 / 465, matching ALPN | greeting |
| A10 | 993 / 465, browser ALPN | refused (cross-protocol hardening) |

Each result is classified by *why* it failed, which is the point:

| Outcome | Means |
|---|---|
| `TCP_TIMEOUT` | SYN blackholed — the usual shape of a blocked port |
| `TCP_REFUSED` | something answered with RST; the port is closed, not filtered |
| `TLS_RESET` | RST *after* the ClientHello left — the DPI signature |
| `TLS_TIMEOUT` | handshake stalled mid-flight — also consistent with DPI |
| `TLS_ALPN_REFUSED` | the server's own strict-ALPN alert 120; expected in A5/A10 |
| `TLS_CERT_MISMATCH` | the certificate does not cover the name dialled |
| `NO_DATA` | handshake fine, server waiting — correct for an HTTPS-bound connection that sent no request |

`TLS_ALPN_REFUSED` is confirmed by retrying the same handshake without the ALPN
extension, because OpenSSL 3.0.x reports alert 120 as `[SSL] unknown error`.

That inference names the *cause*, not the author: a middlebox that forges TLS
alerts produces the same shape. `TLS_ALPN_REFUSED` on A2 or A3 — where the server
is supposed to accept the token — means the alert came from the network, not the
server. The control run settles it.

## Tier B — is the ClientHello itself punished?

Repeats seven ClientHello shapes (`--repeat N`, default 10) against the same IP,
port and minute, and reports how many died per shape:

```
hello                n  killed%  median ms  outcomes
browser-like        10      0.0        5.7  {'NO_DATA': 10}
alpn-imap           10      0.0        6.0  {'IMAP_GREETING': 10}
no-alpn-imap-sni    10      0.0        3.4  {'IMAP_GREETING': 10}
```

A materially higher `killed%` on the `alpn-imap` row than on `browser-like`, in
the same run, is evidence the token itself draws attention. Equal rates mean the
shared port is indistinguishable from HTTPS to that middlebox — at this layer.

`NO_DATA` on the HTTPS-bound rows is a success: the handshake completed and the
server is waiting for a request.

## Tier C — a real account

Needs credentials, and only ever touches your own account:

```bash
MADMAIL_SMOKE_USER=you@example.org MADMAIL_SMOKE_PASS=… \
  ./probe.py --host mail.example.org --tier c --idle-seconds 600
```

- **C1** IMAP LOGIN on 443 and on 993.
- **C2** holds IMAP IDLE for `--idle-seconds`. A drop here means push and
  new-mail notifications die on this network even though login worked.
- If A0 failed on this network, stop: tier C would carry credentials through
  whatever is terminating TLS.
- **C3** uploads 16 KB and 512 KB through submission on 443 and reports KB/s.
  A chatmail relay answers cleartext mail with `523 5.7.1 Encryption Needed`
  *after* the body is uploaded; that counts as a successful upload, since the
  bytes crossed the network, which is what is being measured.

Tier C verifies the certificate (tiers A and B deliberately do not — they
measure routing, not PKI). A filtered network that intercepts TLS fails tier C
loudly rather than quietly carrying credentials through an interceptor.

## Tier D — a real Delta Chat client

```bash
pip install deltachat-rpc-client deltachat-rpc-server
./deltachat_probe.py --domain mail.example.org            # pinned to :443
./deltachat_probe.py --domain mail.example.org --port 993 # control run
```

Configures two accounts pinned to one port, sends a message between them, then
holds idle. This is the only tier that exercises the client's own retry and
fallback behaviour.

Certificates are verified strictly. `--insecure-lab` (dial the IP, accept invalid
certificates, as the LXC scenarios do) exists for a local instance only — on a
real network it would report a pass straight through an interceptor.

## Lab run without a filtered network

The harness itself was validated this way, and it is how you check a change to
these scripts:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:imap.localhost,DNS:smtp.localhost"

cat > madmail.conf <<'EOF'
hostname localhost
primary_domain localhost
tls file /absolute/path/cert.pem /absolute/path/key.pem
smtp tcp://127.0.0.1:2525 { }
submission tls://127.0.0.1:14465 tcp://127.0.0.1:11587 { }
imap tls://127.0.0.1:14993 tcp://127.0.0.1:11143 { }
chatmail tls://127.0.0.1:14443 {
    alpn_imap imap
    alpn_smtp smtp
}
http tcp://127.0.0.1:18080 { }
EOF

madmail run --config ./madmail.conf --state-dir ./state &
madmail accounts create smoke -p 'lab-pass' --config ./madmail.conf --state-dir ./state
# accounts are loaded at startup, so restart before tier C

./probe.py --host localhost --tier a \
  --shared-port 14443 --imap-port 14993 --submission-port 14465 --cafile ./cert.pem
```

Paths in `tls file` must be absolute. Expected on a correct build: 13 PASS,
0 FAIL in tier A.

## Reading the result

| Control | Filtered network | Conclusion |
|---|---|---|
| A2 PASS, 993 open | A2 PASS, 993 `TCP_TIMEOUT` | The feature works and is doing its job |
| A2 PASS | A2 `TLS_RESET`, browser rows fine | The mail ClientHello is being singled out |
| A0 PASS | A0 FAIL | TLS is being intercepted; stop before tier C |
| A2 PASS | A2 `TLS_ALPN_REFUSED` | The alert is forged by the network — the server accepts that token |
| A2 PASS | everything `TCP_TIMEOUT` incl. 443 | The host is blocked outright; the shared port cannot help |
| A2 PASS | A2 PASS, C2 drops in minutes | Reachable but idle connections are reaped — push is the casualty |
| A2 FAIL on both | — | Server configuration, not the network. See `server-setup.sh` |
