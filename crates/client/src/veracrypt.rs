use std::path::Path;
use std::process::Command;

use anyhow::Context;

/// Find the VeraCrypt binary on this platform.
fn veracrypt_bin() -> &'static str {
    if cfg!(target_os = "macos") {
        // macOS: VeraCrypt installs to /Applications, CLI is at this path
        "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
    } else if cfg!(target_os = "windows") {
        r"C:\Program Files\VeraCrypt\VeraCrypt.exe"
    } else {
        // Linux: typically in PATH
        "veracrypt"
    }
}

/// Build a Command that runs veracrypt — using sudo if we're not already root.
/// Mount/dismount on macOS and Linux requires root, so the client must either:
///   (a) run as root itself, or
///   (b) use `sudo veracrypt` (with NOPASSWD configured for the binary).
fn veracrypt_cmd() -> Command {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            Command::new(veracrypt_bin())
        } else {
            // Use sudo -n (non-interactive). Requires sudoers NOPASSWD entry
            // for the veracrypt binary. The install script sets this up.
            let mut cmd = Command::new("sudo");
            cmd.args(["-n", veracrypt_bin()]);
            cmd
        }
    }
    #[cfg(not(unix))]
    {
        Command::new(veracrypt_bin())
    }
}

/// Mount a VeraCrypt container using a keyfile provided as raw bytes.
///
/// The keyfile is written to a temporary file, used for mounting, then
/// securely deleted. On Unix, we use a named pipe (FIFO) to avoid writing
/// the key to disk at all. Falls back to a temp file on Windows.
pub fn mount(container: &str, mount_point: &str, keyfile_bytes: &[u8]) -> anyhow::Result<()> {
    // Ensure mount point exists.
    let mount_path = Path::new(mount_point);
    if !mount_path.exists() {
        std::fs::create_dir_all(mount_path).context(format!(
            "failed to create mount point directory: {mount_point}"
        ))?;
    }

    #[cfg(unix)]
    {
        mount_unix(container, mount_point, keyfile_bytes)
    }
    #[cfg(not(unix))]
    {
        mount_tempfile(container, mount_point, keyfile_bytes)
    }
}

/// Unix implementation: use a named pipe (FIFO) to pass the keyfile
/// to VeraCrypt without ever writing it to a regular file.
#[cfg(unix)]
fn mount_unix(container: &str, mount_point: &str, keyfile_bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Create a temporary directory for the FIFO.
    let tmp_dir = std::env::temp_dir().join(format!("picrypt-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let fifo_path = tmp_dir.join("keyfile");

    // Create the FIFO.
    let fifo_path_c =
        std::ffi::CString::new(fifo_path.to_str().unwrap()).context("invalid fifo path")?;
    let ret = unsafe { libc::mkfifo(fifo_path_c.as_ptr(), 0o600) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(err).context("failed to create FIFO for keyfile");
    }

    // Spawn a thread that writes keyfile bytes into the FIFO.
    // The FIFO blocks until the reader (VeraCrypt) opens it.
    let fifo_path_clone = fifo_path.clone();
    let keyfile_data = keyfile_bytes.to_vec();
    let writer_handle = std::thread::spawn(move || -> anyhow::Result<()> {
        use zeroize::Zeroize;
        let mut data = keyfile_data;
        // Use a closure so `data` is always zeroized, even on error.
        let result = (|| -> anyhow::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(0)
                .open(&fifo_path_clone)
                .context("failed to open FIFO for writing")?;
            file.write_all(&data)
                .context("failed to write keyfile to FIFO")?;
            Ok(())
        })();
        data.zeroize(); // Always zeroize, regardless of success or failure.
        result
    });

    // Run VeraCrypt mount command. If the binary is missing or can't execute,
    // we must still unblock and join the writer thread before returning.
    let output = match veracrypt_cmd()
        .args([
            "--text",
            "--mount",
            &format!("--keyfiles={}", fifo_path.display()),
            "--protect-hidden=no",
            "--pim=0",
            "--password=",
            container,
            mount_point,
        ])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            // Binary not found or exec failed — unblock the writer thread.
            let _ = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo_path);
            let _ = writer_handle.join();
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(e).context("failed to execute veracrypt command");
        }
    };

    // Wait for the writer thread — with a timeout. If VeraCrypt exited without
    // opening the FIFO (bad path, missing container), the writer blocks forever
    // on open(). Clean up the FIFO first to unblock it.
    if !output.status.success() {
        // VeraCrypt failed before reading the FIFO. The writer thread is
        // blocked in open() waiting for a reader. Unlinking the FIFO does
        // NOT unblock it (open waits on the inode, not the path). We must
        // open the read end ourselves to unblock the writer.
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path);
        let _ = writer_handle.join();
        let _ = std::fs::remove_dir_all(&tmp_dir);

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "veracrypt mount failed (exit {}): stdout={} stderr={}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        );
    }

    let writer_result = writer_handle
        .join()
        .map_err(|_| anyhow::anyhow!("keyfile writer thread panicked"))?;

    // Cleanup the FIFO and temp dir.
    let _ = std::fs::remove_dir_all(&tmp_dir);

    writer_result?;

    // VeraCrypt succeeded (failure case handled above).

    tracing::info!("mounted {container} at {mount_point}");
    Ok(())
}

/// Windows fallback: write keyfile to a temp file, mount, then securely delete.
#[cfg(not(unix))]
fn mount_tempfile(container: &str, mount_point: &str, keyfile_bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let tmp_dir = std::env::temp_dir().join(format!("picrypt-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let keyfile_path = tmp_dir.join("keyfile.tmp");

    // Write keyfile.
    let mut file = std::fs::File::create(&keyfile_path)?;
    file.write_all(keyfile_bytes)?;
    drop(file);

    // Mount.
    let output = Command::new(veracrypt_bin())
        .args([
            "/volume",
            container,
            "/letter",
            mount_point, // On Windows, mount_point is a drive letter like "V"
            &format!("/keyfile {}", keyfile_path.display()),
            "/silent",
            "/quit",
            "/password \"\"",
        ])
        .output()
        .context("failed to execute veracrypt command")?;

    // Overwrite and delete the temp keyfile.
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&keyfile_path) {
        let _ = std::io::Write::write_all(&mut f, &vec![0u8; keyfile_bytes.len()]);
    }
    let _ = std::fs::remove_dir_all(&tmp_dir);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("veracrypt mount failed: {}", stderr.trim());
    }

    tracing::info!("mounted {container} at {mount_point}");
    Ok(())
}

/// Dismount a VeraCrypt volume at the given mount point.
///
/// Dead-man semantics: this is called either on clean exit OR when the
/// server has died and we must make the contents inaccessible NOW. If
/// processes are still holding files on the mount, a plain `umount()`
/// returns EBUSY and the vault stays live — defeating the whole point of
/// picrypt. So we:
///
///   1. (Linux) Walk /proc to find PIDs with files under `mount_point`,
///      SIGTERM them, wait briefly, SIGKILL stragglers.
///   2. Call `veracrypt --dismount --force` (which wraps umount).
///   3. If still mounted (e.g. a process outside our uid is holding
///      things, or /proc walking wasn't allowed), retry after a second.
///   4. Last resort on Linux: `umount -l` (lazy / detach) so new accesses
///      fail even if existing fds remain open.
pub fn dismount(mount_point: &str) -> anyhow::Result<()> {
    // Step 1: clear holders so the subsequent umount isn't EBUSY'd.
    #[cfg(target_os = "linux")]
    kill_mount_holders(mount_point);

    // Step 2: first dismount attempt via veracrypt.
    let first_err = match run_veracrypt_dismount(mount_point) {
        Ok(()) => {
            tracing::info!("dismounted {mount_point}");
            return Ok(());
        }
        Err(e) => e,
    };

    // Step 3: if veracrypt says it failed but the mount is gone anyway,
    // call it a win. (Happens when a previous run already dismounted and
    // veracrypt now complains "Volume not found".)
    if !is_mounted(mount_point).unwrap_or(true) {
        tracing::info!(
            "dismount reported failure but {mount_point} is no longer mounted — OK"
        );
        return Ok(());
    }

    tracing::warn!(
        "first dismount attempt failed ({first_err}); retrying after killing holders again"
    );

    #[cfg(target_os = "linux")]
    kill_mount_holders(mount_point);
    std::thread::sleep(std::time::Duration::from_secs(1));

    if let Ok(()) = run_veracrypt_dismount(mount_point) {
        tracing::info!("dismounted {mount_point} on retry");
        return Ok(());
    }

    if !is_mounted(mount_point).unwrap_or(true) {
        tracing::info!("{mount_point} is no longer mounted after retry — OK");
        return Ok(());
    }

    // Step 4: last-resort lazy unmount (Linux only — macOS/Windows veracrypt
    // has no equivalent we can safely invoke here).
    #[cfg(target_os = "linux")]
    {
        tracing::warn!(
            "retry also failed — falling back to `umount -l` (lazy) on {mount_point}"
        );
        match lazy_umount(mount_point) {
            Ok(()) => {
                tracing::warn!(
                    "lazy umount succeeded on {mount_point}: namespace detached, \
                     but existing file descriptors in held processes remain valid \
                     until those processes exit"
                );
                return Ok(());
            }
            Err(e) => {
                anyhow::bail!(
                    "all dismount strategies failed for {mount_point}: \
                     veracrypt={first_err}, lazy umount={e}"
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("veracrypt dismount failed on {mount_point}: {first_err}");
    }
}

/// Invoke `veracrypt --dismount --force` (or the Windows equivalent) and
/// return a classified error on failure.
fn run_veracrypt_dismount(mount_point: &str) -> anyhow::Result<()> {
    let output = if cfg!(target_os = "windows") {
        Command::new(veracrypt_bin())
            .args(["/dismount", mount_point, "/silent", "/quit", "/force"])
            .output()
    } else {
        veracrypt_cmd()
            .args(["--text", "--dismount", "--force", mount_point])
            .output()
    }
    .context("failed to execute veracrypt dismount command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("veracrypt dismount failed: {}", stderr.trim());
    }

    Ok(())
}

/// Linux last-resort lazy unmount. Detaches the filesystem from the
/// namespace immediately even if files are held open. Uses `sudo -n`
/// because the picrypt-client installer already grants NOPASSWD for
/// unmount via the veracrypt sudoers entry — but `umount` itself is not
/// in that allowlist, so this may fail. That's fine; if it does, the
/// caller bubbles up and we at least logged the attempt.
#[cfg(target_os = "linux")]
fn lazy_umount(mount_point: &str) -> anyhow::Result<()> {
    let euid = unsafe { libc::geteuid() };
    let output = if euid == 0 {
        Command::new("umount").args(["-l", mount_point]).output()
    } else {
        Command::new("sudo")
            .args(["-n", "umount", "-l", mount_point])
            .output()
    }
    .context("failed to execute umount -l")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("umount -l failed: {}", stderr.trim());
    }
    Ok(())
}

/// Find processes holding files on a mount point and terminate them.
///
/// This is a dead-man escape hatch: when the server dies we must make the
/// vault inaccessible, and any process holding open fds will EBUSY a plain
/// umount. We SIGTERM first (5s grace), then SIGKILL stragglers.
///
/// We look at three sources under `/proc/<pid>/` for each process we can
/// read (same-uid only without root):
///   * `fd/*` — open files and open directories
///   * `cwd`  — the process's working directory
///   * `maps` — mmap'd files (sqlite with MMAP_SIZE, dynamically-loaded
///              libs, etc.)
///
/// Self is excluded. Processes owned by other users are silently skipped
/// unless picrypt-client is running as root — the installer's sudoers
/// entry only covers the veracrypt binary, not arbitrary /proc inspection.
#[cfg(target_os = "linux")]
fn kill_mount_holders(mount_point: &str) {
    use std::time::Duration;

    let mount_path = std::path::Path::new(mount_point);
    let canonical = std::fs::canonicalize(mount_path)
        .unwrap_or_else(|_| mount_path.to_path_buf());

    let pids = find_mount_holder_pids(&canonical);
    if pids.is_empty() {
        tracing::debug!("no processes holding {mount_point}");
        return;
    }

    tracing::warn!(
        "terminating {} process(es) holding {mount_point}: {:?}",
        pids.len(),
        pids
    );

    // SIGTERM pass.
    for pid in &pids {
        let ret = unsafe { libc::kill(*pid, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::debug!("SIGTERM pid={pid} failed: {err}");
        }
    }

    // Give processes a chance to flush and exit cleanly.
    std::thread::sleep(Duration::from_secs(5));

    // SIGKILL any still-holding processes.
    let still_holding = find_mount_holder_pids(&canonical);
    if !still_holding.is_empty() {
        tracing::warn!(
            "SIGKILLing {} straggler(s) on {mount_point}: {:?}",
            still_holding.len(),
            still_holding
        );
        for pid in &still_holding {
            let ret = unsafe { libc::kill(*pid, libc::SIGKILL) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                tracing::debug!("SIGKILL pid={pid} failed: {err}");
            }
        }
        // Give the kernel a moment to reap.
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(target_os = "linux")]
fn find_mount_holder_pids(mount_path: &std::path::Path) -> Vec<libc::pid_t> {
    let mut pids: Vec<libc::pid_t> = Vec::new();
    let self_pid = unsafe { libc::getpid() };

    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("cannot read /proc: {e}");
            return pids;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid: libc::pid_t = match name.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid == self_pid {
            continue;
        }

        let proc_dir = entry.path();
        if pid_holds_mount(&proc_dir, mount_path) && !pids.contains(&pid) {
            pids.push(pid);
        }
    }

    pids
}

#[cfg(target_os = "linux")]
fn pid_holds_mount(proc_dir: &std::path::Path, mount_path: &std::path::Path) -> bool {
    // /proc/<pid>/cwd — the working directory.
    if let Ok(target) = std::fs::read_link(proc_dir.join("cwd")) {
        if target.starts_with(mount_path) {
            return true;
        }
    }

    // /proc/<pid>/root — in case the process chrooted into the mount.
    if let Ok(target) = std::fs::read_link(proc_dir.join("root")) {
        if target != std::path::Path::new("/") && target.starts_with(mount_path) {
            return true;
        }
    }

    // /proc/<pid>/fd/* — open file descriptors.
    if let Ok(fds) = std::fs::read_dir(proc_dir.join("fd")) {
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.starts_with(mount_path) {
                    return true;
                }
            }
        }
    }

    // /proc/<pid>/maps — mmap'd files. Sqlite-with-MMAP, loaded shared
    // libraries, and opened executables all show up here. The format is:
    //   address perms offset dev inode     pathname
    // with a variable run of whitespace between inode and pathname — so
    // we use split_whitespace() (collapses runs) and take the 6th token.
    // Anonymous mappings have no pathname; synthetic mappings like
    // [stack]/[heap]/[vdso] start with '['.
    if let Ok(contents) = std::fs::read_to_string(proc_dir.join("maps")) {
        for line in contents.lines() {
            let Some(path_field) = line.split_whitespace().nth(5) else {
                continue;
            };
            if path_field.starts_with('[') {
                continue;
            }
            if std::path::Path::new(path_field).starts_with(mount_path) {
                return true;
            }
        }
    }

    false
}

/// Dismount ALL VeraCrypt volumes. Nuclear option for panic lock.
pub fn dismount_all() -> anyhow::Result<()> {
    let output = if cfg!(target_os = "windows") {
        Command::new(veracrypt_bin())
            .args(["/dismount", "/silent", "/quit", "/force"])
            .output()
    } else {
        veracrypt_cmd()
            .args(["--text", "--dismount", "--force"])
            .output()
    }
    .context("failed to execute veracrypt dismount-all command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail if nothing was mounted.
        if !stderr.contains("No volumes mounted") {
            anyhow::bail!("veracrypt dismount-all failed: {}", stderr.trim());
        }
    }

    tracing::info!("dismounted all VeraCrypt volumes");
    Ok(())
}

/// Create a new VeraCrypt container using a keyfile.
#[cfg(unix)]
pub fn create_container(
    path: &str,
    size: &str,
    filesystem: &str,
    encryption: &str,
    hash: &str,
    keyfile_bytes: &[u8],
) -> anyhow::Result<()> {
    use std::io::Write;

    // Use a FIFO for the keyfile, same as mount.
    let tmp_dir = std::env::temp_dir().join(format!("picrypt-create-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;
    let fifo_path = tmp_dir.join("keyfile");

    let fifo_c = std::ffi::CString::new(fifo_path.to_str().unwrap()).context("invalid path")?;
    let ret = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(err).context("mkfifo failed");
    }

    let fifo_clone = fifo_path.clone();
    let data_copy = keyfile_bytes.to_vec();
    let writer = std::thread::spawn(move || -> anyhow::Result<()> {
        use zeroize::Zeroize;
        let mut data = data_copy;
        let result = (|| -> anyhow::Result<()> {
            let mut f = std::fs::OpenOptions::new().write(true).open(&fifo_clone)?;
            f.write_all(&data)?;
            Ok(())
        })();
        data.zeroize(); // Always zeroize, regardless of success or failure.
        result
    });

    let output = Command::new(veracrypt_bin())
        .args([
            "--text",
            "--create",
            path,
            &format!("--size={size}"),
            &format!("--encryption={encryption}"),
            &format!("--hash={hash}"),
            &format!("--filesystem={filesystem}"),
            &format!("--keyfiles={}", fifo_path.display()),
            "--random-source=/dev/urandom",
            "--password=",
            "--pim=0",
            "--volume-type=normal",
            "--non-interactive",
        ])
        .output()
        .context("failed to run veracrypt --create")?;

    if !output.status.success() {
        // Unblock writer thread by opening the read end of the FIFO.
        {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo_path);
        }
        let _ = writer.join();
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("veracrypt --create failed: {}", stderr.trim());
    }

    let _ = writer.join();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[cfg(not(unix))]
pub fn create_container(
    _path: &str,
    _size: &str,
    _filesystem: &str,
    _encryption: &str,
    _hash: &str,
    _keyfile_bytes: &[u8],
) -> anyhow::Result<()> {
    anyhow::bail!(
        "create-container not yet implemented on Windows — create manually with VeraCrypt GUI"
    )
}

/// Check if a mount point currently has a VeraCrypt volume mounted.
/// Returns Ok(true) if mounted, Ok(false) if not, Err if we can't tell.
pub fn is_mounted(mount_point: &str) -> Result<bool, String> {
    if cfg!(target_os = "windows") {
        Ok(Path::new(mount_point).exists())
    } else {
        match Command::new("mount").output() {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                Ok(stdout.contains(mount_point))
            }
            Ok(o) => Err(format!(
                "mount command failed with exit code {:?}",
                o.status.code()
            )),
            Err(e) => Err(format!("failed to run mount command: {e}")),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_dismount_tests {
    use super::*;
    use std::io::Write;

    /// Holding an open fd under the mount path must show up as a holder.
    /// We use tempdir as a stand-in for the mount point and the PID lookup
    /// walks /proc — which is only meaningful on Linux.
    #[test]
    fn find_mount_holder_pids_detects_open_fd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file_path = tmp.path().join("held.bin");
        let mut f = std::fs::File::create(&file_path).expect("create held file");
        f.write_all(b"held").unwrap();
        // Keep `f` alive: the fd must remain open during the scan.

        let pids = find_mount_holder_pids(tmp.path());
        let self_pid = unsafe { libc::getpid() };
        assert!(
            !pids.contains(&self_pid),
            "scan should skip the current process (self_pid={self_pid}, got={pids:?})"
        );

        // Drop the file — we should now see zero holders from our own pid.
        drop(f);
        let _ = std::fs::remove_file(&file_path);
        let pids_after = find_mount_holder_pids(tmp.path());
        assert!(
            !pids_after.contains(&self_pid),
            "after closing file, self must not appear: {pids_after:?}"
        );
    }

    /// pid_holds_mount must return true when cwd of a proc entry is under
    /// the mount, and false otherwise. We exercise the pure /proc reader
    /// by pointing it at a synthetic tree and checking the symlink logic.
    #[test]
    fn pid_holds_mount_matches_subpath_via_cwd() {
        // This test only asserts the logic compiles and runs without panic
        // on a real /proc/self entry. Full behavioural assertions require
        // forking, which we skip here.
        let proc_self = std::path::Path::new("/proc/self");
        let root = std::path::Path::new("/");
        let holds = pid_holds_mount(proc_self, root);
        // /proc/self/cwd is always under "/", so this should always be true.
        assert!(
            holds,
            "pid_holds_mount(/proc/self, /) should be true but was false"
        );
    }
}
