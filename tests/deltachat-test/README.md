# Delta Chat end-to-end tests

Run the real Delta Chat RPC scenarios with two isolated Docker relays:

```bash
make test-deltachat-docker
```

This also runs the existing cmlxc `relay_minitest` checks first. Use `make test-full-docker` to include the Rust workspace and landing tests, or `make test-mini-docker` for just cmlxc mini-tests.

Scenario selection:

```bash
make test-deltachat-docker DC_TEST_ARGS='--no-mini --test-3 --test-4 --test-6 --test-23 --color'
```

The Docker default runs scenarios 1–9, 11–17, 19, 22–23. Release-key signing, the older Go camouflage contract, and the self-deploying LXC exchanger scenarios are excluded. See [Docker documentation](../../docs/guide/docker.md#extensive-delta-chat-and-cmlxc-tests-in-docker) for details, requirements, cleanup, and logs.

The original Incus harness remains available via `make test-full-cmlxc`.
