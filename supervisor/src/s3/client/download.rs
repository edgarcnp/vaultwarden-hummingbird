//! Descriptor-anchored downloads: temp creation, ranged resume, size and
//! hash checks, atomic rename, and directory fsync, all relative to one opened
//! parent descriptor. A path swap after the caller's check cannot redirect the
//! write outside the target tree.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use rusty_s3::S3Action;

use super::{Client, Expect, GetError, MAX_DOWNLOAD_ATTEMPTS};
use crate::s3::transport::{SIGN_EXPIRE, checked, http_err, retryable};

/// A download target anchored on the directory descriptor, so temp
/// creation, hash, rename, and cleanup cannot be redirected by a path swap
/// in the parent after the check.
struct Download {
    /// Descriptor of the parent directory; every operation is relative to it.
    dir: std::fs::File,
    /// Final file name within `dir`.
    name: String,
    /// Rooted path kept for error messages.
    display: String,
}

impl Download {
    /// Anchor on the parent of `path`, opened without following a symlink.
    fn path(path: &str) -> std::io::Result<Self> {
        let path = Path::new(path);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
            })?;
        Ok(Self {
            dir: crate::util::fs::open_dir(parent)?,
            name: name.to_string(),
            display: path.to_string_lossy().into_owned(),
        })
    }

    /// Anchor on the parent of `rel` below `root`, each component opened
    /// with `openat` and `O_NOFOLLOW`.
    fn under(root: &Path, rel: &str) -> std::io::Result<Self> {
        let path = Path::new(rel);
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
            })?;
        Ok(Self {
            dir: crate::util::fs::open_dir_under(root, parent)?,
            name: name.to_string(),
            display: root.join(path).to_string_lossy().into_owned(),
        })
    }

    /// Temp name beside the target: the final name plus the `.vw-part` suffix.
    fn temp(&self) -> String {
        format!("{}{}", self.name, crate::util::fs::PART_SUFFIX)
    }

    /// Length of an existing temp; 0 when it already covers `expected`, so a
    /// stale or oversized partial restarts.
    fn temp_len(&self, temp: &str, expected: Option<u64>) -> u64 {
        let len = fstatat(&self.dir, temp, AtFlags::AT_SYMLINK_NOFOLLOW)
            .ok()
            .and_then(|stat| u64::try_from(stat.st_size).ok())
            .unwrap_or(0);
        if expected.is_some_and(|expected| len >= expected) {
            0
        } else {
            len
        }
    }

    /// Open the temp at `start`: truncate at 0, append past it; never follow a
    /// symlink and never block on a FIFO.
    fn open_temp(&self, temp: &str, start: u64, mode: u32) -> std::io::Result<std::fs::File> {
        let mut flags = OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC;
        if start == 0 {
            flags |= OFlag::O_TRUNC;
        } else {
            flags |= OFlag::O_APPEND;
        }
        let fd = openat(&self.dir, temp, flags, Mode::from_bits_truncate(mode))?;
        Ok(std::fs::File::from(fd))
    }

    /// Lowercase-hex SHA-256 of the temp, read through the anchored descriptor.
    fn hash_temp(&self, temp: &str) -> std::io::Result<String> {
        let fd = openat(
            &self.dir,
            temp,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let mut file = std::fs::File::from(fd);
        crate::util::hash::sha256_reader(&mut file)
    }

    /// Best-effort removal of the temp; absence is not an error.
    fn remove_temp(&self, temp: &str) {
        let _ = unlinkat(&self.dir, temp, UnlinkatFlags::NoRemoveDir);
    }
}

impl Client {
    /// Download `key` into `path` atomically, through a descriptor anchored on
    /// the parent directory. Publishes only a body that meets every
    /// [`Expect`] check; a failed or mismatched transfer leaves `path` untouched.
    pub fn get(
        &self,
        key: &str,
        path: &str,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        let target = Download::path(path)
            .map_err(|e| GetError::Local(format!("cannot open the parent of {path}: {e}")))?;
        self.get_target(key, target, expect, abort)
    }

    /// [`Self::get`] for `rel` below `root`, anchored with `openat` and
    /// `O_NOFOLLOW` per component. A symlink swapped in after the caller's
    /// directory setup cannot redirect the temp, rename, or cleanup.
    pub fn get_under(
        &self,
        key: &str,
        root: &Path,
        rel: &str,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        let target = Download::under(root, rel).map_err(|e| {
            GetError::Local(format!(
                "cannot open the parent of {}: {e}",
                root.join(rel).display()
            ))
        })?;
        self.get_target(key, target, expect, abort)
    }

    /// Shared download pipeline: resumable ranged attempts into the anchored
    /// temp, then size and hash checks before an atomic rename and directory
    /// fsync. Any failure removes the temp and leaves the target untouched.
    fn get_target(
        &self,
        key: &str,
        target: Download,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        if abort() {
            return Err(GetError::Aborted);
        }
        // The temp lives in the anchored directory so the publish is one
        // atomic same-filesystem rename; a crash leaves the target
        // untouched. A partial transfer is kept and resumed with a Range
        // request, so a slow link makes progress across bounded attempts
        // instead of restarting from zero every time.
        let tmp = target.temp();
        let mut offset = target.temp_len(&tmp, expect.size);
        let mut attempt = 0;
        let staged: Result<u64, GetError> = loop {
            attempt += 1;
            if abort() {
                break Err(GetError::Aborted);
            }
            // Sign per attempt: a retry must not reuse a URL that may have
            // expired while the previous attempt consumed its body budget.
            let url = self
                .bucket
                .get_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            let mut request = self.agent.get(url.as_str());
            if offset > 0 {
                request = request.header("Range", &format!("bytes={offset}-"));
            }
            let response = match request.call() {
                Ok(response) => match checked("download", key, response) {
                    Ok(response) => response,
                    Err(e) => break Err(GetError::Transport(e.to_string())),
                },
                Err(ureq::Error::StatusCode(404)) => break Err(GetError::Missing),
                Err(e) => {
                    if retryable(&e) && attempt < MAX_DOWNLOAD_ATTEMPTS {
                        continue;
                    }
                    break Err(GetError::Transport(format!(
                        "download of {key} failed: {}",
                        http_err(&e)
                    )));
                }
            };
            // A server that ignored the range (or an object that changed)
            // answers 200: restart rather than append a different body.
            if offset > 0 && response.status().as_u16() != 206 {
                offset = 0;
            }
            let declared = response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let start = offset;
            let mut reader = response.into_body().into_reader();
            let streamed = (|| -> Result<u64, GetError> {
                let mut out = target.open_temp(&tmp, start, expect.mode).map_err(|e| {
                    GetError::Local(format!("cannot create {}: {e}", target.display))
                })?;
                // A pre-created FIFO opens without O_NONBLOCK only when a
                // reader is present; never write into anything but a file.
                if !out
                    .metadata()
                    .map_err(|e| {
                        GetError::Local(format!("cannot inspect {}: {e}", target.display))
                    })?
                    .is_file()
                {
                    return Err(GetError::Local(format!(
                        "cannot create {}: not a regular file",
                        target.display
                    )));
                }
                let mut buf = [0u8; 64 * 1024];
                let mut total = start;
                loop {
                    if abort() {
                        return Err(GetError::Aborted);
                    }
                    let n = reader
                        .read(&mut buf)
                        .map_err(|e| GetError::Transport(format!("download of {key}: {e}")))?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    if total > expect.max_bytes {
                        return Err(GetError::Invalid(format!(
                            "download of {key}: exceeds the {}-byte cap",
                            expect.max_bytes
                        )));
                    }
                    if let Some(expected) = expect.size
                        && total > expected
                    {
                        return Err(GetError::Invalid(format!(
                            "download of {key}: larger than the {expected} bytes listed"
                        )));
                    }
                    out.write_all(&buf[..n])
                        .map_err(|e| GetError::Local(format!("download of {key}: {e}")))?;
                }
                // A body that ends short of the declared length is an
                // interrupted transfer, not proof the object is invalid:
                // keep the partial and resume within the attempt budget. A
                // restore then refuses the boot instead of silently
                // downgrading to an older backup.
                if let Some(declared) = declared
                    && total - start != declared
                {
                    return Err(GetError::Transport(format!(
                        "download of {key}: body ended after {} of {declared} bytes",
                        total - start
                    )));
                }
                // The open mode is masked by the umask; the published file
                // must have exactly the caller's mode.
                out.set_permissions(std::fs::Permissions::from_mode(expect.mode))
                    .and_then(|()| out.sync_all())
                    .map_err(|e| GetError::Local(format!("download of {key}: {e}")))?;
                Ok(total)
            })();
            match streamed {
                Ok(total) => break Ok(total),
                Err(e) => {
                    // Only a transport failure is worth another attempt; a
                    // cap/size/hash/local failure is definitive.
                    let retry = matches!(e, GetError::Transport(_));
                    let done = target.temp_len(&tmp, None);
                    if retry
                        && attempt < MAX_DOWNLOAD_ATTEMPTS
                        && !abort()
                        && done < expect.size.unwrap_or(u64::MAX)
                    {
                        offset = done;
                        continue;
                    }
                    break Err(e);
                }
            }
        };
        let result = staged.and_then(|total| {
            if let Some(expected) = expect.size
                && total != expected
            {
                return Err(GetError::Invalid(format!(
                    "download of {key}: got {total} bytes, expected {expected}"
                )));
            }
            if let Some(expected) = expect.sha256 {
                let actual = target.hash_temp(&tmp).map_err(|e| {
                    GetError::Local(format!(
                        "download of {key}: cannot hash {}: {e}",
                        target.display
                    ))
                })?;
                if actual != expected {
                    return Err(GetError::Invalid(format!(
                        "download of {key}: sha256 mismatch (got {actual}, expected {expected})"
                    )));
                }
            }
            renameat(&target.dir, tmp.as_str(), &target.dir, target.name.as_str())
                .map_err(|e| GetError::Local(format!("cannot publish {}: {e}", target.display)))?;
            // The file is complete and published; make the name durable
            // too, or a crash can lose a successful pull.
            target
                .dir
                .sync_all()
                .map_err(|e| GetError::Local(format!("cannot fsync {}: {e}", target.display)))?;
            Ok(())
        });
        if result.is_err() {
            target.remove_temp(&tmp);
        }
        result
    }
}
