//! End-to-end: the real `madmail monitor` binary scraping a live openmetrics listener.

use std::process::Command;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;
use chatmail_metrics::run_openmetrics_listener;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

fn reserve_addr() -> String {
    let s = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("addr").to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_reads_a_live_openmetrics_listener() {
    let addr = reserve_addr();
    let cancel = CancellationToken::new();
    let listen = addr.clone();
    let cancel_bg = cancel.clone();
    let server = tokio::spawn(async move {
        run_openmetrics_listener(&listen, cancel_bg)
            .await
            .expect("openmetrics")
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    // An open connection in this process must show up in the separate
    // `madmail` process's scrape: gauge -> exporter -> HTTP -> CLI parser.
    let guard = chatmail_metrics::conn_guard("imap");

    // Point --config at a file that does not exist so the repo's
    // `./data/chatmail.toml` is not picked up (see boot_test.rs).
    let dir = TempDir::new().expect("tempdir");
    let config = dir.path().join("none.toml");
    let (config, state) = (
        config.to_string_lossy().into_owned(),
        dir.path().to_string_lossy().into_owned(),
    );
    let output = tokio::task::spawn_blocking(move || {
        Command::new(cargo_bin("madmail"))
            .args([
                "--json",
                "--config",
                &config,
                "--state-dir",
                &state,
                "monitor",
                "--addr",
                &addr,
                "--count",
                "1",
            ])
            .output()
            .expect("run madmail monitor")
    })
    .await
    .expect("join");
    drop(guard);

    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let line = stdout.lines().next().expect("one JSON line");
    let v: serde_json::Value = serde_json::from_str(line).expect("json envelope");

    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["command"], "monitor", "{v}");
    assert_eq!(v["data"]["conns"]["imap"], 1.0, "{v}");
    // Pre-created by init_metrics, so present and zero rather than absent.
    assert_eq!(v["data"]["conns"]["smtp"], 0.0, "{v}");
    assert_eq!(v["data"]["conns"]["submission"], 0.0, "{v}");
    // The first sample has nothing to measure a rate against.
    assert!(v["data"]["messages_per_second"].is_null(), "{v}");

    cancel.cancel();
    server.await.expect("server task");
}
