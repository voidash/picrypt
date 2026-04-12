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

/// Dismount a VeraCrypt volume at the given mount point. Force-dismounts.
pub fn dismount(mount_point: &str) -> anyhow::Result<()> {
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

    tracing::info!("dismounted {mount_point}");
    Ok(())
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
