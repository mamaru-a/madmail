"""Transport compatibility for auxiliary servers in Docker scenarios."""
import imaplib
import os
import re
import smtplib
import ssl
import subprocess


def configure_tls(config, directory):
    if not os.environ.get("DELTACHAT_TEST_DOCKER"):
        return config
    cert = os.path.join(directory, "cert.pem")
    key = os.path.join(directory, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-keyout", key, "-out", cert], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    config = config.replace("tls off", f"tls file {cert} {key}")
    return config.replace("submission tcp://", "submission tls://").replace(
        "imap tcp://", "imap tls://")


def smtp_connect(host, port, **kwargs):
    if os.environ.get("DELTACHAT_TEST_DOCKER"):
        return smtplib.SMTP_SSL(host, port, context=ssl._create_unverified_context(), **kwargs)
    return smtplib.SMTP(host, port, **kwargs)


def imap_connect(host, port, **kwargs):
    if os.environ.get("DELTACHAT_TEST_DOCKER"):
        return imaplib.IMAP4_SSL(host, port, ssl_context=ssl._create_unverified_context(), **kwargs)
    return imaplib.IMAP4(host, port, **kwargs)


def search_all(client):
    """Enumerate sequence numbers when the server does not implement SEARCH."""
    try:
        return client.search(None, "ALL")
    except imaplib.IMAP4.error as exc:
        if not os.environ.get("DELTACHAT_TEST_DOCKER") or "BAD" not in str(exc):
            raise
        status, data = client.fetch("1:*", "(UID)")
        ids = [match.group(1) for row in data if isinstance(row, bytes)
               if (match := re.match(rb"(\d+) ", row))]
        return status, [b" ".join(ids)]
