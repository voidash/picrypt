//! High-level mount/dismount dispatch for picrypt vaults.
//!
//! Normal volumes go through `crate::veracrypt::{mount, dismount}`. Volumes
//! that set `mount_command` / `dismount_command` in their [`VolumeConfig`]
//! skip picrypt's built-in path entirely and run the user-supplied command.
//!
//! This is the escape hatch for unusual vault layouts that picrypt's default
//! `veracrypt --mount <container> <mount_point>` can't handle — e.g. an
//! APFS filesystem layered on top of a `--filesystem=none` veracrypt volume
//! on macOS (picrypt would try to `mkdir /Volumes/foo`, which non-root can't
//! do, and veracrypt would refuse to mount an absent filesystem).
//!
//! The custom command contract:
//!
//!   argv[0] = mount_command / dismount_command (as written in client.toml)
//!   argv[1] = container path
//!   argv[2] = mount_point
//!   stdin   = raw keyfile bytes (mount only — ~64 bytes, binary)
//!             dismount has no stdin
//!   exit 0  = success
//!   exit !0 = failure, stderr is surfaced in the picrypt log
//!
//! The command must not persist the keyfile to disk; it should pipe
//! stdin through to veracrypt via `--keyfiles=/dev/stdin` or an FIFO.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::config::VolumeConfig;
use crate::veracrypt;

/// Mount a single volume — dispatches to the custom `mount_command` if set,
/// otherwise to [`veracrypt::mount`].
pub fn mount(volume: &VolumeConfig, keyfile_bytes: &[u8]) -> Result<()> {
    if let Some(cmd) = &volume.mount_command {
        run_external_mount(cmd, &volume.container, &volume.mount_point, keyfile_bytes)
    } else {
        veracrypt::mount(&volume.container, &volume.mount_point, keyfile_bytes)
    }
}

/// Dismount a single volume — dispatches to the custom `dismount_command`
/// if set, otherwise to [`veracrypt::dismount`].
pub fn dismount(volume: &VolumeConfig) -> Result<()> {
    if let Some(cmd) = &volume.dismount_command {
        run_external_dismount(cmd, &volume.container, &volume.mount_point)
    } else {
        veracrypt::dismount(&volume.mount_point)
    }
}

/// Spawn the user's mount command with the keyfile on stdin.
fn run_external_mount(
    command: &str,
    container: &str,
    mount_point: &str,
    keyfile_bytes: &[u8],
) -> Result<()> {
    tracing::info!(
        command,
        container,
        mount_point,
        "running custom mount command"
    );

    let mut child = Command::new(command)
        .arg(container)
        .arg(mount_point)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn custom mount command: {command}"))?;

    // Feed the keyfile on stdin, then EXPLICITLY close the write end so the
    // child sees EOF. We must `.take()` the stdin out of `child` and drop it
    // before calling `wait_with_output`, otherwise `child` keeps the pipe
    // open and anything in the script reading from stdin (e.g. `cat > FIFO`)
    // blocks forever waiting for EOF → deadlock.
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to open stdin of mount command"))?;
        stdin
            .write_all(keyfile_bytes)
            .context("failed to write keyfile to custom mount command stdin")?;
        // stdin is dropped here — pipe is closed, child sees EOF.
    }

    let output = child
        .wait_with_output()
        .context("failed to wait for custom mount command")?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "custom mount command failed (exit {}): stdout={} stderr={}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        );
    }

    tracing::info!(container, mount_point, "custom mount command succeeded");
    Ok(())
}

/// Spawn the user's dismount command (no stdin).
fn run_external_dismount(command: &str, container: &str, mount_point: &str) -> Result<()> {
    tracing::info!(
        command,
        container,
        mount_point,
        "running custom dismount command"
    );

    let output = Command::new(command)
        .arg(container)
        .arg(mount_point)
        .output()
        .with_context(|| format!("failed to spawn custom dismount command: {command}"))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "custom dismount command failed (exit {}): stdout={} stderr={}",
            output.status.code().unwrap_or(-1),
            stdout.trim(),
            stderr.trim()
        );
    }

    tracing::info!(container, mount_point, "custom dismount command succeeded");
    Ok(())
}
