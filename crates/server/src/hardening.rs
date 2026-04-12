//! Process hardening: mlock, disable core dumps, restrict dumpability.
//!
//! Called at server startup to prevent key material from leaking
//! via swap or memory dumps.

/// Apply all available process hardening measures.
/// Errors are logged but do not prevent startup — the server should
/// still work on systems where these aren't available, just with warnings.
pub fn apply() {
    #[cfg(unix)]
    {
        lock_memory();
        disable_core_dumps();
        disable_dumpable();
    }

    #[cfg(not(unix))]
    {
        tracing::warn!("process hardening not implemented for this platform");
    }
}

#[cfg(unix)]
fn lock_memory() {
    // mlockall prevents all current and future pages from being swapped.
    // Requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK.
    let result = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if result == 0 {
        tracing::info!("mlockall succeeded — memory locked against swap");
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "mlockall failed (key material may be swapped to disk): {err}. \
             Consider running with CAP_IPC_LOCK or increasing RLIMIT_MEMLOCK."
        );
    }
}

#[cfg(unix)]
fn disable_core_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if result == 0 {
        tracing::info!("core dumps disabled");
    } else {
        tracing::warn!(
            "failed to disable core dumps: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(unix)]
fn disable_dumpable() {
    // PR_SET_DUMPABLE=0 prevents ptrace attach and /proc/pid/mem access.
    #[cfg(target_os = "linux")]
    {
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if result == 0 {
            tracing::info!("process set to non-dumpable");
        } else {
            tracing::warn!(
                "failed to set PR_SET_DUMPABLE: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::debug!("PR_SET_DUMPABLE not available on this platform");
    }
}
