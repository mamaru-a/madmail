ARG BUILD_IMAGE=madmail-local:test-docker-build
FROM node:24-bookworm-slim AS landing-tests
COPY --from=oven/bun:1 /usr/local/bin/bun /usr/local/bin/bun
WORKDIR /landing
COPY landing/ .
RUN bun install --frozen-lockfile
CMD ["npm", "test"]

FROM ${BUILD_IMAGE} AS workspace-tests
COPY tests/Cargo.toml tests/*.rs ./tests/
COPY tests/support/ ./tests/support/
# Completion tests need Bash; HTTPS upgrade tests need Python and OpenSSL.
RUN apk add --no-cache bash python3 openssl
# Keep the cached runner small; debug symbols are unnecessary for these checks.
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
    CARGO_PROFILE_DEV_INCREMENTAL=false CARGO_PROFILE_TEST_INCREMENTAL=false
# Integration tests locate target/debug/madmail; compile it before testing.
RUN cargo build -p chatmail --locked && cargo test --workspace --locked --no-run
CMD ["cargo", "test", "--workspace", "--locked", "--offline"]
