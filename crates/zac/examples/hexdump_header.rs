//! Phase 0 debug demo.
//!
//! Emits a 16-byte synthetic ZAC1 header (placeholder layout — Phase 1 will
//! replace it with the real one) and prints a hex dump and a tracing trace
//! at every step.
//!
//! Run with:
//!
//! ```sh
//! RUST_LOG=zac=trace,hexdump_header=trace cargo run --example hexdump_header
//! ```
//!
//! The point of this example is **not** to exercise real ZAC parsing — it is
//! to prove the tracing subscriber, the hex dependency, and the example
//! plumbing all work end-to-end before any real format code lands.

use std::io::Write;
use tracing::{info, trace};

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zac=trace,hexdump_header=trace".into()),
        )
        .with_target(true)
        .init();

    info!("Phase 0 sanity demo — synthetic ZAC1 header");

    let mut buf: Vec<u8> = Vec::with_capacity(16);
    buf.extend_from_slice(b"ZAC1"); // magic (offset 0..4)
    buf.extend_from_slice(&[1, 0, 0, 0]); // version: major=1, minor=0, patch=0, flags=0 (offset 4..8)
    buf.extend_from_slice(&[0u8; 8]); // reserved 8 bytes; Phase 1 fills with file_hash prefix (offset 8..16)

    info!(bytes = buf.len(), "emitted synthetic header");

    for (i, chunk) in buf.chunks(16).enumerate() {
        let offset = i * 16;
        trace!(offset = offset, hex = %hex::encode(chunk), ascii = %ascii_safe(chunk), "row");
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "header hex: {}", hex::encode(&buf))?;
    writeln!(
        stdout,
        "header ascii: {}",
        ascii_safe(&buf).chars().collect::<String>()
    )?;
    Ok(())
}

fn ascii_safe(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}
