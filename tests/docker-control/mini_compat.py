"""Docker-only compatibility for the cmlxc message-header privacy check."""
import imaplib
import re


def pytest_configure(config):
    import imap_tools

    original = imap_tools.MailBox.uids

    def uids(self, criteria="ALL", charset="US-ASCII", sort=None):
        try:
            return original(self, criteria, charset, sort)
        except imaplib.IMAP4.error as exc:
            criterion = criteria.decode() if isinstance(criteria, bytes) else str(criteria)
            if sort or criterion.strip("() ").upper() != "ALL" or "BAD" not in str(exc):
                raise
            # SEARCH ALL and enumerating all UIDs select the same messages.
            status, data = self.client.uid("FETCH", "1:*", "(UID)")
            if status != "OK":
                raise
            return [match.decode() for row in data if isinstance(row, bytes)
                    for match in re.findall(rb"\bUID (\d+)\b", row)]

    imap_tools.MailBox.uids = uids
