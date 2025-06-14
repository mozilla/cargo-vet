//! This is an almost-direct port of the `flock.rs` module from cargo, adapted
//! to build within cargo-vet.

// FIXME: Consider moving this to an external library so it's easier to share
// with others in the future. This will require some minor changes to the
// interface to make it less dependent on internal error handling and logging.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Display, Path, PathBuf};

use sys::*;

use crate::errors::FlockError;
use crate::out::indeterminate_spinner;

#[derive(Debug)]
pub struct FileLock {
    f: Option<File>,
    path: PathBuf,
    state: State,
}

#[derive(PartialEq, Debug)]
enum State {
    Unlocked,
    Shared,
    Exclusive,
}

impl FileLock {
    /// Returns the underlying file handle of this lock.
    pub fn file(&self) -> &File {
        self.f.as_ref().unwrap()
    }

    /// Returns the underlying path that this lock points to.
    ///
    /// Note that special care must be taken to ensure that the path is not
    /// referenced outside the lifetime of this lock.
    pub fn path(&self) -> &Path {
        assert_ne!(self.state, State::Unlocked);
        &self.path
    }

    /// Returns the parent path containing this file
    pub fn parent(&self) -> &Path {
        assert_ne!(self.state, State::Unlocked);
        self.path.parent().unwrap()
    }
}

impl Read for FileLock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file().read(buf)
    }
}

impl Seek for FileLock {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.file().seek(to)
    }
}

impl Write for FileLock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file().flush()
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if self.state != State::Unlocked {
            if let Some(f) = self.f.take() {
                let _ = unlock(&f);
            }
        }
    }
}

/// A "filesystem" is intended to be a globally shared, hence locked, resource.
///
/// The `Path` of a filesystem cannot be learned unless it's done in a locked
/// fashion, and otherwise functions on this structure are prepared to handle
/// concurrent invocations across multiple instances.
#[derive(Clone, Debug)]
pub struct Filesystem {
    root: PathBuf,
}

impl Filesystem {
    /// Creates a new filesystem to be rooted at the given path.
    pub fn new(path: PathBuf) -> Filesystem {
        Filesystem { root: path }
    }

    /// Like `Path::join`, creates a new filesystem rooted at this filesystem
    /// joined with the given path.
    pub fn join<T: AsRef<Path>>(&self, other: T) -> Filesystem {
        Filesystem::new(self.root.join(other))
    }

    /// Like `Path::push`, pushes a new path component onto this filesystem.
    pub fn push<T: AsRef<Path>>(&mut self, other: T) {
        self.root.push(other);
    }

    /// Consumes this filesystem and returns the underlying `PathBuf`.
    ///
    /// Note that this is a relatively dangerous operation and should be used
    /// with great caution!.
    pub fn into_path_unlocked(self) -> PathBuf {
        self.root
    }

    /// Returns the underlying `Path`.
    ///
    /// Note that this is a relatively dangerous operation and should be used
    /// with great caution!.
    pub fn as_path_unlocked(&self) -> &Path {
        &self.root
    }

    /// Creates the directory pointed to by this filesystem.
    ///
    /// Handles errors where other processes are also attempting to concurrently
    /// create this directory.
    pub fn create_dir(&self) -> Result<(), std::io::Error> {
        fs::create_dir_all(&self.root)
    }

    /// Returns an adaptor that can be used to print the path of this
    /// filesystem.
    pub fn display(&self) -> Display<'_> {
        self.root.display()
    }

    /// Opens exclusive access to a file, returning the locked version of a
    /// file.
    ///
    /// This function will create a file at `path` if it doesn't already exist
    /// (including intermediate directories), and then it will acquire an
    /// exclusive lock on `path`. If the process must block waiting for the
    /// lock, the `msg` is printed to `config`.
    ///
    /// The returned file can be accessed to look at the path and also has
    /// read/write access to the underlying file.
    pub fn open_rw<P>(&self, path: P, msg: &str) -> Result<FileLock, FlockError>
    where
        P: AsRef<Path>,
    {
        self.open(
            path.as_ref(),
            OpenOptions::new().read(true).write(true).create(true),
            State::Exclusive,
            msg,
        )
    }

    /// Opens shared access to a file, returning the locked version of a file.
    ///
    /// This function will fail if `path` doesn't already exist, but if it does
    /// then it will acquire a shared lock on `path`. If the process must block
    /// waiting for the lock, the `msg` is printed to `config`.
    ///
    /// The returned file can be accessed to look at the path and also has read
    /// access to the underlying file. Any writes to the file will return an
    /// error.
    pub fn open_ro<P>(&self, path: P, msg: &str) -> Result<FileLock, FlockError>
    where
        P: AsRef<Path>,
    {
        self.open(
            path.as_ref(),
            OpenOptions::new().read(true),
            State::Shared,
            msg,
        )
    }

    fn open(
        &self,
        path: &Path,
        opts: &OpenOptions,
        state: State,
        msg: &str,
    ) -> Result<FileLock, FlockError> {
        let path = self.root.join(path);

        // If we want an exclusive lock then if we fail because of NotFound it's
        // likely because an intermediate directory didn't exist, so try to
        // create the directory and then continue.
        let f = opts.open(&path).or_else(|e| {
            if e.kind() == io::ErrorKind::NotFound && state == State::Exclusive {
                let parent = path.parent().unwrap();
                fs::create_dir_all(parent)?;
                Ok(opts.open(&path)?)
            } else {
                Err(e)
            }
        })?;
        match state {
            State::Exclusive => {
                acquire(msg, &path, &|| try_lock_exclusive(&f), &|| {
                    lock_exclusive(&f)
                })?;
            }
            State::Shared => {
                acquire(msg, &path, &|| try_lock_shared(&f), &|| lock_shared(&f))?;
            }
            State::Unlocked => {}
        }
        Ok(FileLock {
            f: Some(f),
            path,
            state,
        })
    }
}

impl PartialEq<Path> for Filesystem {
    fn eq(&self, other: &Path) -> bool {
        self.root == other
    }
}

impl PartialEq<Filesystem> for Path {
    fn eq(&self, other: &Filesystem) -> bool {
        self == other.root
    }
}

/// Acquires a lock on a file in a "nice" manner.
///
/// This function will acquire the lock on a `path`, printing out a message to
/// the console if we have to wait for it. It will first attempt to use `try` to
/// acquire a lock on the crate, and in the case of contention it will emit a
/// status message based on `msg` to `config`'s shell, and then use `block` to
/// block waiting to acquire a lock.
///
/// Returns an error if the lock could not be acquired or if any error other
/// than a contention error happens.
fn acquire(
    msg: &str,
    path: &Path,
    lock_try: &dyn Fn() -> io::Result<()>,
    lock_block: &dyn Fn() -> io::Result<()>,
) -> Result<(), FlockError> {
    // File locking on Unix is currently implemented via `flock`, which is known
    // to be broken on NFS. We could in theory just ignore errors that happen on
    // NFS, but apparently the failure mode [1] for `flock` on NFS is **blocking
    // forever**, even if the "non-blocking" flag is passed!
    //
    // As a result, we just skip all file locks entirely on NFS mounts. That
    // should avoid calling any `flock` functions at all, and it wouldn't work
    // there anyway.
    //
    // [1]: https://github.com/rust-lang/cargo/issues/2615
    if is_on_nfs_mount(path) {
        return Ok(());
    }

    match lock_try() {
        Ok(()) => return Ok(()),

        // In addition to ignoring NFS which is commonly not working we also
        // just ignore locking on filesystems that look like they don't
        // implement file locking.
        Err(e) if error_unsupported(&e) => return Ok(()),

        Err(e) => {
            if !error_contended(&e) {
                return Err(e.into());
            }
        }
    }

    let _spinner = indeterminate_spinner("Blocking", format!("waiting for file lock on {msg}"));

    lock_block()?;
    return Ok(());

    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    fn is_on_nfs_mount(path: &Path) -> bool {
        use std::ffi::CString;
        use std::mem;
        use std::os::unix::prelude::*;

        let path = match CString::new(path.as_os_str().as_bytes()) {
            Ok(path) => path,
            Err(_) => return false,
        };

        unsafe {
            let mut buf: libc::statfs = mem::zeroed();
            let r = libc::statfs(path.as_ptr(), &mut buf);

            r == 0 && buf.f_type as u32 == libc::NFS_SUPER_MAGIC as u32
        }
    }

    #[cfg(any(not(target_os = "linux"), target_env = "musl"))]
    fn is_on_nfs_mount(_path: &Path) -> bool {
        false
    }
}

#[cfg(unix)]
mod sys {
    use std::fs::File;
    use std::io::{Error, Result};
    use std::os::unix::io::AsRawFd;

    pub(super) fn lock_shared(file: &File) -> Result<()> {
        flock(file, libc::LOCK_SH)
    }

    pub(super) fn lock_exclusive(file: &File) -> Result<()> {
        flock(file, libc::LOCK_EX)
    }

    pub(super) fn try_lock_shared(file: &File) -> Result<()> {
        flock(file, libc::LOCK_SH | libc::LOCK_NB)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> Result<()> {
        flock(file, libc::LOCK_EX | libc::LOCK_NB)
    }

    pub(super) fn unlock(file: &File) -> Result<()> {
        flock(file, libc::LOCK_UN)
    }

    pub(super) fn error_contended(err: &Error) -> bool {
        err.raw_os_error() == Some(libc::EWOULDBLOCK)
    }

    pub(super) fn error_unsupported(err: &Error) -> bool {
        match err.raw_os_error() {
            // Unfortunately, depending on the target, these may or may not be the same.
            // For targets in which they are the same, the duplicate pattern causes a warning.
            #[allow(unreachable_patterns)]
            Some(libc::ENOTSUP | libc::EOPNOTSUPP) => true,
            #[cfg(target_os = "linux")]
            Some(libc::ENOSYS) => true,
            _ => false,
        }
    }

    #[cfg(not(target_os = "solaris"))]
    fn flock(file: &File, flag: libc::c_int) -> Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), flag) };
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "solaris")]
    fn flock(file: &File, flag: libc::c_int) -> Result<()> {
        // Solaris lacks flock(), so simply succeed with a no-op
        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    use std::fs::File;
    use std::io::{Error, Result};
    use std::mem;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, UnlockFile, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };

    pub(super) fn lock_shared(file: &File) -> Result<()> {
        lock_file(file, 0)
    }

    pub(super) fn lock_exclusive(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_EXCLUSIVE_LOCK)
    }

    pub(super) fn try_lock_shared(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_FAIL_IMMEDIATELY)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)
    }

    pub(super) fn error_contended(err: &Error) -> bool {
        err.raw_os_error()
            .map_or(false, |x| x == ERROR_LOCK_VIOLATION as i32)
    }

    pub(super) fn error_unsupported(err: &Error) -> bool {
        err.raw_os_error()
            .map_or(false, |x| x == ERROR_INVALID_FUNCTION as i32)
    }

    pub(super) fn unlock(file: &File) -> Result<()> {
        unsafe {
            let ret = UnlockFile(file.as_raw_handle() as HANDLE, 0, 0, !0, !0);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn lock_file(file: &File, flags: u32) -> Result<()> {
        unsafe {
            let mut overlapped = mem::zeroed();
            let ret = LockFileEx(
                file.as_raw_handle() as HANDLE,
                flags,
                0,
                !0,
                !0,
                &mut overlapped,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}
