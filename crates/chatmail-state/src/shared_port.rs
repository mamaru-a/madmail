// Copyright (C) 2026 themadorg
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime flags: which mail protocols the HTTPS port also serves.
//!
//! The `alpn_imap` / `alpn_smtp` directives are the file default; an admin toggle
//! stores an override in the settings table, exactly as
//! [`crate::inbound_remote_rcpt`] does. Reads happen once per connection, so a
//! toggle takes effect on the next connection without rebinding the socket:
//! `LazyConfigAcceptor` picks the TLS config after the ClientHello arrives, so the
//! advertised ALPN list follows the flags too.

use std::sync::atomic::{AtomicBool, Ordering};

use chatmail_config::{parse_bool_str, AppConfig};
use chatmail_db::{get_setting, settings_keys, DbPool};
use chatmail_types::Result;

/// Effective shared-port state (file defaults + optional admin DB overrides).
#[derive(Debug, Default)]
pub struct SharedPortFlags {
    imap: AtomicBool,
    smtp: AtomicBool,
    /// Whether the HTTPS listener is the demux at all. False when the config has
    /// no `chatmail tls://…` block, in which case flipping a flag changes nothing
    /// until the operator adds the block and restarts — so the admin API can say
    /// so instead of silently doing nothing.
    demux_active: AtomicBool,
}

impl SharedPortFlags {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            imap: AtomicBool::new(config.alpn_imap.is_some()),
            smtp: AtomicBool::new(config.alpn_smtp.is_some()),
            demux_active: AtomicBool::new(false),
        }
    }

    /// Serve IMAP to clients identified on the shared port.
    pub fn imap(&self) -> bool {
        self.imap.load(Ordering::Relaxed)
    }

    /// Serve submission to clients identified on the shared port.
    pub fn smtp(&self) -> bool {
        self.smtp.load(Ordering::Relaxed)
    }

    pub fn set_imap(&self, on: bool) {
        self.imap.store(on, Ordering::Relaxed);
    }

    pub fn set_smtp(&self, on: bool) {
        self.smtp.store(on, Ordering::Relaxed);
    }

    /// Whether either protocol is live — the shared listener skips the
    /// first-bytes peek entirely when neither is.
    pub fn any(&self) -> bool {
        self.imap() || self.smtp()
    }

    pub fn demux_active(&self) -> bool {
        self.demux_active.load(Ordering::Relaxed)
    }

    /// Called by the supervisor when it spawns the demux on the HTTPS port.
    pub fn set_demux_active(&self, active: bool) {
        self.demux_active.store(active, Ordering::Relaxed);
    }

    /// DB overrides when set; otherwise the file directives.
    pub async fn hydrate(&self, pool: &DbPool, config: &AppConfig) -> Result<()> {
        self.set_imap(
            match get_setting(pool, settings_keys::SHARED_PORT_IMAP).await? {
                Some(v) => parse_bool_str(&v),
                None => config.alpn_imap.is_some(),
            },
        );
        self.set_smtp(
            match get_setting(pool, settings_keys::SHARED_PORT_SMTP).await? {
                Some(v) => parse_bool_str(&v),
                None => config.alpn_smtp.is_some(),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chatmail_db::{init_memory_db, set_setting};

    fn cfg(imap: bool, smtp: bool) -> AppConfig {
        AppConfig {
            alpn_imap: imap.then(|| "imap".to_string()),
            alpn_smtp: smtp.then(|| "smtp".to_string()),
            ..Default::default()
        }
    }

    /// P12-UT18: with no admin override stored, the config file decides.
    #[tokio::test]
    async fn hydrate_uses_file_default_when_db_unset() {
        let pool = init_memory_db().await.unwrap();
        let config = cfg(true, false);
        let flags = SharedPortFlags::new(&config);
        flags.hydrate(&pool, &config).await.unwrap();
        assert!(flags.imap());
        assert!(!flags.smtp());
    }

    /// P12-UT19: the admin toggle wins over the directive, in both directions and
    /// per protocol — disabling IMAP must not disable submission.
    #[tokio::test]
    async fn hydrate_db_overrides_file_per_protocol() {
        let pool = init_memory_db().await.unwrap();
        let config = cfg(true, true);
        set_setting(&pool, settings_keys::SHARED_PORT_IMAP, "false")
            .await
            .unwrap();
        let flags = SharedPortFlags::new(&config);
        flags.hydrate(&pool, &config).await.unwrap();
        assert!(!flags.imap(), "DB false must win over the directive");
        assert!(flags.smtp(), "the other protocol is untouched");

        let config = cfg(false, false);
        set_setting(&pool, settings_keys::SHARED_PORT_SMTP, "true")
            .await
            .unwrap();
        let flags = SharedPortFlags::new(&config);
        flags.hydrate(&pool, &config).await.unwrap();
        assert!(flags.smtp(), "DB true must win over a missing directive");
    }

    /// P12-UT20: the live setters take effect without a hydrate, which is what
    /// makes the admin toggle apply to the next connection.
    #[tokio::test]
    async fn set_toggles_live_without_hydrate() {
        let flags = SharedPortFlags::new(&cfg(false, false));
        assert!(!flags.any());
        flags.set_imap(true);
        assert!(flags.imap() && flags.any() && !flags.smtp());
        flags.set_imap(false);
        flags.set_smtp(true);
        assert!(flags.any() && !flags.imap());
    }
}
