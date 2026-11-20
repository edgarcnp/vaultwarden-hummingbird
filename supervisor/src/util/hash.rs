//! Streaming SHA-256 for durability checks: sync compares content, not
//! just size, and pulls verify what they wrote. File hashing is bounded
//! memory (one chunk at a time).

use std::io::Read;

use sha2::{Digest, Sha256};

/// 64 KiB chunks: bounded memory, few syscalls per MiB.
const CHUNK: usize = 64 * 1024;

/// Stream `reader` to its lowercase hex SHA-256 with one 64 KiB buffer.
pub fn sha256_reader(reader: &mut impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// The lowercase hex SHA-256 of a file's contents, streamed in bounded memory.
/// A sync source or staged dump may have been swapped for a FIFO after
/// enumeration, so a non-regular file is refused instead of blocking.
pub fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut file = crate::util::fs::open_regular(path)?;
    sha256_reader(&mut file)
}

/// The lowercase hex SHA-256 of an in-memory byte string.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Encode `bytes` as lowercase hex, two characters per byte.
pub(crate) fn hex(bytes: &[u8]) -> String {
    /// Lowercase hex digits, indexed by nibble.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    //! Hash-vector, encoding, and FIFO-refusal tests.

    use super::*;

    /// A clean file path under a per-test temp directory.
    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("vw-sup-hash-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("file").to_string_lossy().into_owned()
    }

    #[test]
    fn known_vectors() {
        let path = scratch("known");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::write(&path, b"").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(sha256_file("/nonexistent/vw-sup-hash").is_err());
        let _ = std::fs::remove_dir_all(
            std::path::Path::new(&path)
                .parent()
                .expect("scratch parent"),
        );
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }

    /// Hashing a FIFO must not block the maintenance thread (the path could
    /// have been swapped after enumeration).
    #[test]
    fn a_fifo_source_is_refused_without_blocking() {
        let path = scratch("fifo");
        let path = std::path::Path::new(&path);
        let _ = std::fs::remove_file(path);
        nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let start = std::time::Instant::now();
        assert!(sha256_file(path.to_str().unwrap()).is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "a FIFO must not block the hash"
        );
        let _ = std::fs::remove_file(path);
    }
}
