ARG RELAY_IMAGE=madmail-local:test-docker
FROM ${RELAY_IMAGE} AS relay
RUN apk add --no-cache bash python3 iproute2 iptables nftables conntrack-tools jq coreutils openssl
COPY tests/docker-control/ /usr/local/lib/docker-test-control/
RUN chmod +x /usr/local/lib/docker-test-control/* && \
    ln -s /usr/local/lib/docker-test-control/systemctl /usr/local/bin/systemctl && \
    ln -s /usr/local/lib/docker-test-control/journalctl /usr/local/bin/journalctl

FROM python:3.12-slim AS client
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=relay /bin/madmail /usr/local/bin/madmail
RUN ln -s /usr/local/bin/madmail /usr/local/bin/maddy
WORKDIR /app/tests
COPY tests/pyproject.toml tests/uv.lock ./
RUN uv sync --frozen --no-install-project && \
    uv pip install --python .venv/bin/python deltachat-rpc-server==2.52.0 pytest pytest-xdist imap-tools
COPY tests/deltachat-test/ ./deltachat-test/
COPY tests/cmlxc/src/relay_minitest/ ./relay_minitest/
COPY tests/bin/ssh ./bin/ssh
COPY tests/docker-control/ ./docker-control/
RUN chmod +x bin/ssh
ENV PATH="/app/tests/bin:/app/tests/.venv/bin:$PATH" \
    RPC_SERVER_PATH=/app/tests/.venv/bin/deltachat-rpc-server \
    DELTACHAT_TEST_DOCKER=1 DELTACHAT_TEST_ROOT=/results \
    CHATMAIL_BIN=/usr/local/bin/madmail PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/tests/docker-control
WORKDIR /app/tests/deltachat-test
ENTRYPOINT ["python", "main.py"]
