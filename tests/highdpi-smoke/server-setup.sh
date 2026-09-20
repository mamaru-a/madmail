#!/usr/bin/env bash
# Prepare a madmail host so the high-DPI smoke test has something to measure.
#
# Run this ON THE SERVER, as root, once. It only prints what it would change
# unless --apply is given.
#
# Usage:
#   ./server-setup.sh --domain mail.example.org            # check only
#   ./server-setup.sh --domain mail.example.org --apply
#   ./server-setup.sh --domain mail.example.org --apply --with-sni
#
# --with-sni also prepares the stock-client path (SNI routing), which needs a
# certificate covering imap.<domain> / smtp.<domain>. `madmail install` asks
# Let's Encrypt for the bare domain only, so that certificate has to come from
# certbot and be handed to madmail with --tls-mode file.
set -euo pipefail

DOMAIN=""
APPLY=0
WITH_SNI=0
CONF="${MADMAIL_CONF:-/etc/madmail/madmail.conf}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --with-sni) WITH_SNI=1; shift ;;
    --conf) CONF="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DOMAIN" ]] || { echo "--domain is required" >&2; exit 2; }

say() { printf '\n== %s\n' "$*"; }
would() { if [[ $APPLY -eq 1 ]]; then echo "-> $*"; else echo "   would: $*"; fi; }

say "1. Config block"
# The installer has always emitted alpn_imap / alpn_smtp; before #173 they were
# dead config. Everything below is about making sure they are present and live.
if [[ -f "$CONF" ]]; then
  echo "   config: $CONF"
  if grep -qE '^\s*chatmail\s+tls://' "$CONF"; then
    echo "   chatmail block: present"
    grep -nE '^\s*(alpn_imap|alpn_smtp|sni_imap|sni_smtp)\b' "$CONF" || echo "   (no alpn_/sni_ directives)"
  else
    echo "   chatmail block: MISSING — reinstall with --enable-chatmail, or add:"
    cat <<EOF
       chatmail tls://0.0.0.0:443 {
           alpn_imap imap
           alpn_smtp smtp
       }
EOF
  fi
else
  echo "   $CONF not found. Install first, e.g.:"
  echo "     madmail install --domain $DOMAIN --enable-chatmail --obtain-certificate --acme-email you@$DOMAIN"
fi

if [[ $WITH_SNI -eq 1 ]]; then
  say "2. SNI routing for stock clients (Thunderbird, Apple Mail, K-9)"
  echo "   These send no ALPN, so they are identified by the hostname they dial."
  echo "   Required: DNS A/AAAA for imap.$DOMAIN and smtp.$DOMAIN -> this host,"
  echo "   and ONE certificate covering $DOMAIN, imap.$DOMAIN, smtp.$DOMAIN."
  echo
  echo "   madmail install requests the bare domain only (single-name order), so:"
  cat <<EOF
     certbot certonly --standalone \\
       -d $DOMAIN -d imap.$DOMAIN -d smtp.$DOMAIN \\
       --cert-name $DOMAIN
     madmail install --domain $DOMAIN --enable-chatmail \\
       --tls-mode file \\
       --cert-path /etc/letsencrypt/live/$DOMAIN/fullchain.pem \\
       --key-path  /etc/letsencrypt/live/$DOMAIN/privkey.pem
EOF
  echo "   Then add to the chatmail block (optional — unset means the imap./smtp. prefixes):"
  cat <<EOF
       sni_imap imap.$DOMAIN
       sni_smtp smtp.$DOMAIN
EOF
  echo
  echo "   Without those SANs the SNI scenario (A6) reports SKIP, not FAIL: a stock"
  echo "   client would reject the certificate before any routing happened."
fi

say "3. No TLS-terminating CDN in front of 443"
echo "   The demux reads ALPN/SNI from the client's own ClientHello. A proxy that"
echo "   terminates TLS strips both, and every mail connection becomes HTTPS."
RESOLVED="$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1 || true)"
echo "   $DOMAIN resolves to: ${RESOLVED:-<unresolved>}"
echo "   Confirm that address is this host and not a CDN edge."

say "4. Local verification (server side, before testing from the filtered network)"
for probe in "imap:IMAP greeting" "smtp:SMTP banner"; do
  token="${probe%%:*}"; want="${probe##*:}"
  echo "   openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -alpn $token -quiet   # expect $want"
done
echo "   openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -alpn h2 -quiet        # expect alert 120"

say "5. Baseline to compare against"
echo "   Run probe.py from an unfiltered host FIRST and keep the JSON:"
echo "     ./probe.py --host $DOMAIN --label control --json control.json"
echo "   Then run it from the network under test and diff the two."

if [[ $APPLY -eq 1 ]]; then
  say "Apply mode"
  would "restart madmail so config changes take effect: systemctl restart madmail"
  echo "   (Nothing was edited automatically — the config is yours; the commands above are explicit on purpose.)"
fi
