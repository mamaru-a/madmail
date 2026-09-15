# `monitor`

Live connection and message-throughput metrics from a running server, one row per sample.


## Synopsis

```bash
madmail monitor [-n|--interval <SECS>] [-c|--count <N>] [--addr <HOST:PORT>]
```

## Global flags

| Flag | Alias | Environment | Default | Description |
|------|-------|-------------|---------|-------------|
| `--config` | — | `CHATMAIL_CONFIG` | `/etc/madmail/madmail.conf` (or `./data/chatmail.toml` when present) | Path to the server config file |
| `--state-dir` | `--libexec` | `CHATMAIL_STATE_DIR` | `/var/lib/madmail` (or `./data` when it contains state) | Persistent state directory (`credentials.db`, maildirs, `admin_token`, …) |


## Options

| Flag | Description |
|------|-------------|
| `-n`, `--interval <SECS>` | Seconds between samples (default `2`) |
| `-c`, `--count <N>` | Stop after `N` samples (default: run until interrupted) |
| `--addr <HOST:PORT>` | Scrape this address instead of the config's `openmetrics` listener |

## Example

```bash
madmail monitor
madmail monitor --interval 1 --count 10
madmail monitor --count 1 --json
```

```
Scraping http://127.0.0.1:9749/metrics every 2s
  imap   smtp submission   total     msg/s aborted/s   queue
     4      2          0       6         -         -       3
     4      2          0       6     19.88      0.00       3
```

Reads the server's `openmetrics` endpoint (`/metrics`), so that endpoint must be enabled. `madmail install` writes it into the generated config:

```
openmetrics tcp://127.0.0.1:9749 {
}
```

Keep it on loopback — the endpoint has no authentication. A wildcard bind address (`0.0.0.0`, `[::]`) is scraped over loopback.

- **Connections** are `maddy_conns_active` per module; `total` sums every module.
- **msg/s** is the change in `maddy_smtp_smtp_completed_transactions` (summed across modules) divided by the wall-clock time between two scrapes. The first row has no previous sample, so it shows `-`.
- A counter that goes backwards means the server restarted; that interval reports `0`.

## JSON output (`--json`)

```bash
madmail monitor --count 1 --json
```

One success envelope per sample, so without `--count` the output is newline-delimited JSON:

```json
{"ok": true, "command": "monitor", "data": { ... }}
```

Schema: [json-output.md](json-output.md#monitor).


---
[← CLI index](README.md) · [Global flags](global-flags.md)

[Source: `crates/chatmail/src/ctl/monitor.rs`](https://github.com/themadorg/madmail/blob/main/crates/chatmail/src/ctl/monitor.rs)
