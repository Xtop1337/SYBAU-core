//! One running core per profile. A second launch detects the first one and
//! leaves it untouched.

use anyhow::Result;

pub enum Acquire {
    /// This process is the only instance; keep the guard alive.
    Acquired(InstanceLock),
    /// Another instance holds the profile (its pid, when known).
    AlreadyRunning(Option<u32>),
}

/// Profile names end up in file, pipe and mutex names.
pub fn valid_profile(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(unix)]
pub struct InstanceLock {
    _file: std::fs::File,
}

#[cfg(unix)]
pub fn acquire(profile: &str) -> Result<Acquire> {
    use anyhow::Context;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let path = sybau_core::control::runtime_dir().join(format!("sybau-core-{profile}.lock"));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("cannot open lock file {}", path.display()))?;
    // SAFETY: `file` owns a valid descriptor for the duration of the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            let mut text = String::new();
            let _ = file.read_to_string(&mut text);
            return Ok(Acquire::AlreadyRunning(text.trim().parse().ok()));
        }
        return Err(err).with_context(|| format!("cannot lock {}", path.display()));
    }
    // The kernel drops the lock when the process dies, however it dies.
    file.set_len(0)?;
    file.rewind()?;
    write!(file, "{}", std::process::id())?;
    file.flush()?;
    Ok(Acquire::Acquired(InstanceLock { _file: file }))
}

#[cfg(windows)]
pub struct InstanceLock {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: a mutex handle may be closed from any thread.
#[cfg(windows)]
unsafe impl Send for InstanceLock {}

#[cfg(windows)]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        // SAFETY: `handle` came from CreateMutexW and is closed exactly once.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(windows)]
pub fn acquire(profile: &str) -> Result<Acquire> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    };
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = format!("Global\\SYBAU-CORE-{profile}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `name` is a valid NUL-terminated UTF-16 string that outlives the call.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    // SAFETY: reads the calling thread's last-error value set by CreateMutexW.
    let err = unsafe { GetLastError() };
    if handle.is_null() {
        // The mutex belongs to an instance of another user.
        if err == ERROR_ACCESS_DENIED {
            return Ok(Acquire::AlreadyRunning(None));
        }
        return Err(std::io::Error::from_raw_os_error(err as i32).into());
    }
    if err == ERROR_ALREADY_EXISTS {
        // SAFETY: `handle` is valid and not used afterwards.
        unsafe { CloseHandle(handle) };
        return Ok(Acquire::AlreadyRunning(None));
    }
    // The system destroys the mutex when the last handle is closed, which
    // also happens when the process is killed.
    Ok(Acquire::Acquired(InstanceLock { handle }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names() {
        assert!(valid_profile("default"));
        assert!(valid_profile("work_2-a"));
        assert!(!valid_profile(""));
        assert!(!valid_profile("../x"));
        assert!(!valid_profile("a b"));
    }
}
