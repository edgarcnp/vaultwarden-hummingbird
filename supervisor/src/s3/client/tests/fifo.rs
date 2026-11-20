//! FIFO regression tests for download temp files.

use super::{fake_server, local_client, scratch};
use crate::s3::{Expect, GetError};

/// A vault-created FIFO at the pull temp name must fail the download
/// immediately, not block the boot on `open(2)`.
#[test]
fn get_refuses_a_fifo_partial_without_blocking() {
    let client = local_client(fake_server("200 OK", "", b"ok"));
    let dir = scratch("fifopart");
    let target = dir.join("target.bin");
    let tmp = format!("{}.vw-part", target.display());
    nix::unistd::mkfifo(
        tmp.as_str(),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    let start = std::time::Instant::now();
    let err = client
        .get(
            "state/file",
            target.to_str().unwrap(),
            Expect {
                size: Some(2),
                sha256: None,
                max_bytes: 16,
                mode: 0o600,
            },
            || false,
        )
        .expect_err("a FIFO temp must be refused");
    assert!(matches!(err, GetError::Local(_)), "{err:?}");
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
}
