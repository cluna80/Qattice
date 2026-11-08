//! A directory-tree filesystem abstraction for staged installation. The flat `Storage` trait cannot express directories, `fsync` of directories or renaming a
//! whole directory, all of which the install protocol needs. Paths are relative, `/`-separated, with no empty, `.` or `..` components, no `\` and no NUL.
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("filesystem: {0}")]
pub struct FsError(pub String);

pub fn check_path(p: &str) -> Result<(), FsError> {
    if p.is_empty() { return Ok(()); } // the root
    if p.contains(['\\', '\0']) || p.split('/').any(|c| c.is_empty() || c == "." || c == "..") { return Err(FsError(format!("invalid path {p:?}"))); }
    Ok(())
}
pub fn parent_of(p: &str) -> &str { p.rsplit_once('/').map_or("", |(a, _)| a) }

pub trait TreeFs {
    /// Create `path` and every missing parent as directories.
    fn mkdir_all(&mut self, path: &str) -> Result<(), FsError>;
    /// Create a NEW file (fails if it exists; the parent must exist). Not durable until `sync_file` (content) and `sync_dir` of the parent (name).
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), FsError>;
    fn sync_file(&mut self, path: &str) -> Result<(), FsError>;
    /// Make the entries of directory `dir` durable (creations, renames and removals of its children).
    fn sync_dir(&mut self, dir: &str) -> Result<(), FsError>;
    /// Atomically rename a file (replacing an existing file) or a directory (the target must not exist).
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError>;
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, FsError>;
    /// Names directly inside `dir`, sorted.
    fn list(&self, dir: &str) -> Result<Vec<String>, FsError>;
    fn is_dir(&self, path: &str) -> bool;
    fn exists(&self, path: &str) -> bool;
    /// Remove a file or a whole directory tree; absent is not an error.
    fn remove_all(&mut self, path: &str) -> Result<(), FsError>;
    /// Whether two directories are on the same filesystem (an atomic rename between them is possible).
    fn same_device(&self, _a: &str, _b: &str) -> bool { true }
}

/// The real filesystem under a root directory.
pub struct StdTreeFs { root: PathBuf }

fn io(e: std::io::Error) -> FsError { FsError(e.to_string()) }

#[cfg(unix)]
fn fsync_dir(p: &Path) -> std::io::Result<()> { std::fs::File::open(p)?.sync_all() }
#[cfg(windows)]
fn fsync_dir(p: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new().read(true).write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(p)?.sync_all()
}
#[cfg(not(any(unix, windows)))]
fn fsync_dir(_p: &Path) -> std::io::Result<()> { Ok(()) }

impl StdTreeFs {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, FsError> {
        let root = root.into();
        if !root.is_dir() { return Err(FsError(format!("{} is not a directory", root.display()))); }
        Ok(StdTreeFs { root })
    }
    fn full(&self, p: &str) -> Result<PathBuf, FsError> { check_path(p)?; Ok(if p.is_empty() { self.root.clone() } else { self.root.join(p) }) }
}

impl TreeFs for StdTreeFs {
    fn mkdir_all(&mut self, path: &str) -> Result<(), FsError> { std::fs::create_dir_all(self.full(path)?).map_err(io) }
    fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(self.full(path)?).map_err(io)?;
        f.write_all(data).map_err(io)
    }
    fn sync_file(&mut self, path: &str) -> Result<(), FsError> { std::fs::OpenOptions::new().read(true).write(true).open(self.full(path)?).and_then(|f| f.sync_all()).map_err(io) }
    fn sync_dir(&mut self, dir: &str) -> Result<(), FsError> { fsync_dir(&self.full(dir)?).map_err(io) }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let (f, t) = (self.full(from)?, self.full(to)?);
        if f.is_dir() && t.exists() { return Err(FsError(format!("{to} exists"))); }
        std::fs::rename(f, t).map_err(io)
    }
    fn read(&self, path: &str) -> Result<Option<Vec<u8>>, FsError> {
        match std::fs::read(self.full(path)?) { Ok(b) => Ok(Some(b)), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None), Err(e) => Err(io(e)) }
    }
    fn list(&self, dir: &str) -> Result<Vec<String>, FsError> {
        let mut v = vec![];
        match std::fs::read_dir(self.full(dir)?) {
            Ok(rd) => { for e in rd { let e = e.map_err(io)?; if let Some(n) = e.file_name().to_str() { v.push(n.to_string()); } } }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        v.sort();
        Ok(v)
    }
    fn is_dir(&self, path: &str) -> bool { self.full(path).map_or(false, |p| p.is_dir()) }
    fn exists(&self, path: &str) -> bool { self.full(path).map_or(false, |p| p.exists()) }
    fn remove_all(&mut self, path: &str) -> Result<(), FsError> {
        let p = self.full(path)?;
        if p.is_dir() { std::fs::remove_dir_all(&p).map_err(io) } else if p.exists() { std::fs::remove_file(&p).map_err(io) } else { Ok(()) }
    }
    #[cfg(unix)]
    fn same_device(&self, a: &str, b: &str) -> bool {
        use std::os::unix::fs::MetadataExt;
        match (self.full(a).and_then(|p| std::fs::metadata(p).map_err(io)), self.full(b).and_then(|p| std::fs::metadata(p).map_err(io))) { (Ok(x), Ok(y)) => x.dev() == y.dev(), _ => false }
    }
}
