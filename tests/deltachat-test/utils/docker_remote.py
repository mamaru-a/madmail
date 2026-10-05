"""SSH-compatible control of allowlisted, disposable Docker test relays."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time


def run(remote: str, command: str, *, timeout: int = 30, input: str | None = None):
    relays = json.loads(os.environ["DELTACHAT_DOCKER_RELAYS"])
    host = remote.rsplit("@", 1)[-1]
    if host not in relays:
        raise ValueError(f"Docker test relay is not allowlisted: {host}")
    container = relays[host]
    deadline = time.monotonic() + timeout

    def docker(*args, **kwargs):
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            timeout=max(0.1, deadline - time.monotonic()), **kwargs,
        )

    logs = docker("logs", "--timestamps", container)
    # journalctl reads actual Docker log records, refreshed before every command.
    snapshot = json.dumps({"now": time.time(), "logs": logs.stdout + logs.stderr})
    result = docker("exec", "-i", container, "sh", "-c",
                    "cat > /run/docker-test-journal.json", input=snapshot)
    if result.returncode:
        return result
    result = docker("exec", "-i", container, "sh", "-c", command, input=input)
    request = docker("exec", container, "sh", "-c",
                     "cat /run/docker-test-service 2>/dev/null; rm -f /run/docker-test-service")
    for action in request.stdout.splitlines():
        if action not in {"restart", "stop", "start"}:
            raise ValueError(f"Unsupported Docker service action: {action}")
        changed = docker(action, container)
        if changed.returncode:
            return changed
    return result


def main():
    # The existing scenarios use ssh -o KEY=VALUE root@IP 'shell command'.
    args = sys.argv[1:]
    while args and args[0].startswith("-"):
        option = args.pop(0)
        if option in {"-o", "-i", "-F", "-p", "-l"}:
            args.pop(0)
    if len(args) < 2:
        raise SystemExit("Docker SSH adapter requires a relay and command")
    result = run(args[0], " ".join(args[1:]), timeout=600, input=sys.stdin.read())
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
