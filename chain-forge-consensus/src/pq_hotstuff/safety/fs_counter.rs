//! File-based [`MonotonicCounter`] for devnet testing (Gate B, B3).
//!
//! **This is not a trusted counter.** It is a process-crash-resistant counter
//! for the devnet test harness only. See `safety/mod.rs` for the rollback and
//! power-loss caveats that apply to any file-based counter.
//!
//! # On-disk layout (44 bytes)
//! ```text
//! value:    u64  big-endian  (bytes 0–7)   — the monotonic counter value
//! digest:   [u8; 32]         (bytes 8–39)  — SafetyStore record digest (from advance())
//! checksum: u32  big-endian  (bytes 40–43) — CRC32 of (value_bytes || digest)
//! ```
//! `digest` is the SafetyStore record digest supplied to `advance()`; it is NOT
//! derived from `value`. The checksum is an integrity guard for partial writes only;
//! it carries no semantic meaning to SafetyStore.
//!
//! # Writer fencing
//! The counter file is opened with `GENERIC_WRITE | FILE_SHARE_READ` and no write-share
//! flag. A second process receives `ERROR_SHARING_VIOLATION`. `into_parts()` releases
//! the handle. `TerminateProcess` releases it via OS handle cleanup on process exit.
//!
//! # Partial-write recovery
//! A kill mid-write may leave a truncated or torn record. `read()` checks:
//! 1. Exactly 44 bytes present — otherwise `Err(CounterError("Truncated"))`.
//! 2. CRC32(value_bytes || digest) == stored checksum — otherwise `Err(CounterError("ChecksumMismatch"))`.
//! Both failures are fatal in `SafetyStore::open()`.
#![cfg(feature = "gate-b-harness")]

use super::{CounterBinding, CounterError, CounterState, MonotonicCounter, Session};
use std::path::{Path, PathBuf};

/// 44-byte record: value (8) || digest (32) || crc32 (4).
const RECORD_LEN: usize = 44;

fn encode_record(value: u64, digest: [u8; 32]) -> [u8; RECORD_LEN] {
    let mut buf = [0u8; RECORD_LEN];
    buf[..8].copy_from_slice(&value.to_be_bytes());
    buf[8..40].copy_from_slice(&digest);
    let crc = crc32fast::hash(&buf[..40]);
    buf[40..44].copy_from_slice(&crc.to_be_bytes());
    buf
}

fn decode_record(buf: &[u8]) -> Result<(u64, [u8; 32]), CounterError> {
    if buf.len() != RECORD_LEN {
        return Err(CounterError(format!("Truncated: got {} bytes, expected {RECORD_LEN}", buf.len())));
    }
    let stored_crc = u32::from_be_bytes(buf[40..44].try_into().unwrap());
    let computed_crc = crc32fast::hash(&buf[..40]);
    if stored_crc != computed_crc {
        return Err(CounterError(format!(
            "ChecksumMismatch: stored {stored_crc:#010x} != computed {computed_crc:#010x}"
        )));
    }
    let value = u64::from_be_bytes(buf[..8].try_into().unwrap());
    let digest: [u8; 32] = buf[8..40].try_into().unwrap();
    Ok((value, digest))
}

/// An open file handle on Windows opened with exclusive write access (no write-share).
/// On Unix (CI / sandbox) the file is opened normally; fencing is not tested there.
#[cfg(windows)]
struct ExclusiveFile(std::fs::File);

#[cfg(windows)]
fn open_exclusive(path: &Path) -> Result<ExclusiveFile, CounterError> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ only — no FILE_SHARE_WRITE.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|e| CounterError(format!("open_exclusive: {e}")))?;
    Ok(ExclusiveFile(f))
}

#[cfg(windows)]
fn write_through(f: &ExclusiveFile, buf: &[u8]) -> Result<(), CounterError> {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = &f.0;
    file.seek(SeekFrom::Start(0)).map_err(|e| CounterError(e.to_string()))?;
    file.write_all(buf).map_err(|e| CounterError(e.to_string()))?;
    file.set_len(buf.len() as u64).map_err(|e| CounterError(e.to_string()))?;
    file.sync_all().map_err(|e| CounterError(e.to_string()))
}

#[cfg(windows)]
fn read_file(f: &ExclusiveFile) -> Result<Vec<u8>, CounterError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = &f.0;
    file.seek(SeekFrom::Start(0)).map_err(|e| CounterError(e.to_string()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| CounterError(e.to_string()))?;
    Ok(buf)
}

// --- Unix fallback for sandbox compile ---

#[cfg(not(windows))]
struct ExclusiveFile(std::fs::File);

#[cfg(not(windows))]
fn open_exclusive(path: &Path) -> Result<ExclusiveFile, CounterError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|e| CounterError(format!("open_exclusive: {e}")))?;
    Ok(ExclusiveFile(f))
}

#[cfg(not(windows))]
fn write_through(f: &ExclusiveFile, buf: &[u8]) -> Result<(), CounterError> {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = &f.0;
    file.seek(SeekFrom::Start(0)).map_err(|e| CounterError(e.to_string()))?;
    file.write_all(buf).map_err(|e| CounterError(e.to_string()))?;
    file.set_len(buf.len() as u64).map_err(|e| CounterError(e.to_string()))?;
    file.sync_all().map_err(|e| CounterError(e.to_string()))
}

#[cfg(not(windows))]
fn read_file(f: &ExclusiveFile) -> Result<Vec<u8>, CounterError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = &f.0;
    file.seek(SeekFrom::Start(0)).map_err(|e| CounterError(e.to_string()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| CounterError(e.to_string()))?;
    Ok(buf)
}

/// Reads the counter file without acquiring an exclusive handle. Used by the test
/// harness to inspect file state from a second process after the first is killed.
pub fn read_counter_file(path: &Path) -> Result<(u64, [u8; 32]), CounterError> {
    let buf = std::fs::read(path)
        .map_err(|e| CounterError(format!("read_counter_file: {e}")))?;
    decode_record(&buf)
}

/// A file-backed monotonic counter for devnet Gate B testing.
///
/// # Safety contract
/// - `acquire_session()` opens the counter file with exclusive write access.
/// - Only one live `FsCounter` per file path at a time is safe. A second will fail with
///   `ERROR_SHARING_VIOLATION` on Windows while the first is alive.
/// - On process kill, the OS closes the handle; a new process can then `acquire_session()`.
/// - `into_parts()` closes the handle, releasing the exclusive lock.
pub struct FsCounter {
    path: PathBuf,
    binding: CounterBinding,
    state: CounterState,
    session_token: u64,
    current_token: u64,
    handle: Option<ExclusiveFile>,
}

impl std::fmt::Debug for FsCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsCounter")
            .field("path", &self.path)
            .field("state", &self.state)
            .field("current_token", &self.current_token)
            .field("handle_open", &self.handle.is_some())
            .finish()
    }
}

impl FsCounter {
    /// Open an existing counter file (must already hold a valid 44-byte record).
    /// Does NOT acquire the write lock — call `acquire_session()` for that.
    pub fn open(path: impl Into<PathBuf>, binding: CounterBinding) -> Result<Self, CounterError> {
        let path = path.into();
        let buf = std::fs::read(&path)
            .map_err(|e| CounterError(format!("FsCounter::open: {e}")))?;
        let (value, digest) = decode_record(&buf)?;
        Ok(FsCounter {
            path,
            binding,
            state: CounterState { value, digest },
            session_token: 0,
            current_token: 0,
            handle: None,
        })
    }

    /// Create a new counter file at `path` initialized to `CounterState::INITIAL`.
    /// Fails if the file already exists and is non-empty.
    pub fn create(path: impl Into<PathBuf>, binding: CounterBinding) -> Result<Self, CounterError> {
        let path = path.into();
        let f = open_exclusive(&path)?;
        let buf = encode_record(0, [0u8; 32]);
        write_through(&f, &buf)?;
        Ok(FsCounter {
            path,
            binding,
            state: CounterState::INITIAL,
            session_token: 0,
            current_token: 1, // first session will be token 1
            handle: Some(f),
        })
    }

    /// Release the exclusive handle without consuming self (for explicit drop scenarios).
    pub fn release_handle(&mut self) {
        self.handle = None;
    }

    pub fn path(&self) -> &Path { &self.path }
}

impl MonotonicCounter for FsCounter {
    fn binding(&self) -> &CounterBinding { &self.binding }

    fn read(&self) -> Result<CounterState, CounterError> {
        // If we hold the handle, trust the in-memory state (we're the only writer).
        if self.handle.is_some() {
            return Ok(self.state);
        }
        // No handle: re-read from disk.
        let buf = std::fs::read(&self.path)
            .map_err(|e| CounterError(format!("read: {e}")))?;
        let (value, digest) = decode_record(&buf)?;
        Ok(CounterState { value, digest })
    }

    fn acquire_session(&mut self) -> Result<Session, CounterError> {
        if self.handle.is_none() {
            // No open handle — open the file with exclusive write access.
            // Fails with ERROR_SHARING_VIOLATION on Windows if another process holds it.
            let f = open_exclusive(&self.path)?;
            let buf = read_file(&f)?;
            let (value, digest) = decode_record(&buf)?;
            self.state = CounterState { value, digest };
            self.handle = Some(f);
        } else {
            // Handle already held (e.g. from create()). Re-read state from the open file
            // without attempting a second open — that would hit ERROR_SHARING_VIOLATION
            // on Windows since we already hold the exclusive lock ourselves.
            let buf = read_file(self.handle.as_ref().unwrap())?;
            let (value, digest) = decode_record(&buf)?;
            self.state = CounterState { value, digest };
        }
        self.session_token += 1;
        self.current_token = self.session_token;
        Ok(Session::new(self.current_token))
    }

    fn advance(&mut self, expected: &CounterState, new_digest: [u8; 32], session: &Session) -> Result<(), CounterError> {
        if session.token() != self.current_token {
            return Err(CounterError(format!(
                "stale session: token {} is not the current {}", session.token(), self.current_token
            )));
        }
        if self.state != *expected {
            return Err(CounterError(format!(
                "compare-and-advance failed: counter at {} (digest {:?}), expected {} (digest {:?})",
                self.state.value, &self.state.digest[..4],
                expected.value, &expected.digest[..4],
            )));
        }
        let next_value = self.state.value.checked_add(1)
            .ok_or_else(|| CounterError("counter exhausted: cannot advance past u64::MAX".into()))?;
        let f = self.handle.as_ref()
            .ok_or_else(|| CounterError("advance called without an active session (no open handle)".into()))?;
        let buf = encode_record(next_value, new_digest);
        write_through(f, &buf)?;
        self.state = CounterState { value: next_value, digest: new_digest };
        Ok(())
    }
}

impl Drop for FsCounter {
    fn drop(&mut self) {
        // Closing the handle releases the exclusive write lock.
        self.handle = None;
    }
}
