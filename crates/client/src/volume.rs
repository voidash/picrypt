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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::config::VolumeConfig;
use crate::veracrypt;

/// Default timeout for `post_mount_command`. Post-mount is not time-critical
/// so 30 seconds is comfortable for things like "start a systemd unit" or
/// "unlock a secondary LUKS container."
pub const POST_MOUNT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for `pre_dismount_command`. Pre-dismount runs in the
/// panic / dead-man path, so it must be short — under 5 seconds. After
/// the timeout the hook is SIGKILL'd and picrypt proceeds with the force
/// dismount, which SIGKILL's anything still holding the vault anyway.
pub const PRE_DISMOUNT_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Run the `post_mount_command` for this volume, if any. Never fails —
/// logs a warning on timeout or non-zero exit. This runs AFTER a
/// successful mount so the vault is already usable; failing the mount
/// because of a post-mount hook bug would make things worse, not better.
pub fn run_post_mount_hook(volume: &VolumeConfig) {
    if let Some(cmd) = &volume.post_mount_command {
        run_hook_bounded(
            "post_mount",
            cmd,
            &volume.container,
            &volume.mount_point,
            POST_MOUNT_TIMEOUT,
        );
    }
}

/// Run the `pre_dismount_command` for this volume, if any. Never fails —
/// logs a warning on timeout or non-zero exit. This runs BEFORE dismount,
/// and the caller always proceeds with the actual dismount regardless of
/// the outcome. Under panic semantics the vault MUST come down even if
/// cleanup fails.
pub fn run_pre_dismount_hook(volume: &VolumeConfig) {
    if let Some(cmd) = &volume.pre_dismount_command {
        run_hook_bounded(
            "pre_dismount",
            cmd,
            &volume.container,
            &volume.mount_point,
            PRE_DISMOUNT_TIMEOUT,
        );
    }
}

/// Shared implementation for post_mount and pre_dismount hooks: shell out
/// via `sh -c`, wait up to `timeout`, kill on timeout, log everything.
fn run_hook_bounded(
    label: &str,
    command: &str,
    container: &str,
    mount_point: &str,
    timeout: Duration,
) {
    tracing::info!(
        hook = label,
        command,
        container,
        mount_point,
        "running volume hook"
    );

    let spawn_result = Command::new("sh")
        .arg("-c")
        .arg(command)
        // Expose container/mount_point to the hook as environment variables
        // so shell snippets can reference them without argv juggling:
        //   post_mount_command = "logger \"vault mounted at $PICRYPT_MOUNT_POINT\""
        .env("PICRYPT_CONTAINER", container)
        .env("PICRYPT_MOUNT_POINT", mount_point)
        .env("PICRYPT_HOOK", label)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match spawn_result {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                hook = label,
                command,
                error = %e,
                "volume hook failed to spawn"
            );
            return;
        }
    };

    // Poll for completion up to `timeout`. This avoids pulling in
    // tokio for what is otherwise a sync code path.
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut s) = child.stdout.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stdout);
                }
                if let Some(mut s) = child.stderr.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut stderr);
                }
                if status.success() {
                    tracing::info!(
                        hook = label,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "volume hook succeeded"
                    );
                    if !stdout.trim().is_empty() {
                        tracing::debug!(hook = label, stdout = %stdout.trim(), "hook stdout");
                    }
                } else {
                    tracing::warn!(
                        hook = label,
                        exit = status.code().unwrap_or(-1),
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        stdout = %stdout.trim(),
                        stderr = %stderr.trim(),
                        "volume hook returned non-zero — ignored, proceeding"
                    );
                }
                return;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    tracing::warn!(
                        hook = label,
                        command,
                        timeout_secs = timeout.as_secs(),
                        "volume hook timed out — sending SIGKILL and proceeding"
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                // Short sleep so we don't burn CPU. 50ms is fine-grained
                // enough for a 5-second timeout and low-cost.
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                tracing::warn!(
                    hook = label,
                    error = %e,
                    "volume hook wait failed — proceeding"
                );
                return;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn vol_with_hooks(post: Option<&str>, pre: Option<&str>) -> VolumeConfig {
        VolumeConfig {
            container: "/tmp/fake.hc".to_string(),
            mount_point: "/tmp/fake-mp".to_string(),
            mount_command: None,
            dismount_command: None,
            post_mount_command: post.map(String::from),
            pre_dismount_command: pre.map(String::from),
        }
    }

    #[test]
    fn no_hook_is_a_noop() {
        // None hook -> function returns without spawning anything. Hard
        // to assert directly; the test exists to catch panics.
        run_post_mount_hook(&vol_with_hooks(None, None));
        run_pre_dismount_hook(&vol_with_hooks(None, None));
    }

    #[test]
    fn post_mount_hook_runs_and_sees_env() {
        // Use a temp file to prove the hook actually executed AND
        // received the env vars.
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_str().unwrap().to_string();
        let cmd = format!(
            "printf '%s %s %s' \"$PICRYPT_HOOK\" \"$PICRYPT_CONTAINER\" \"$PICRYPT_MOUNT_POINT\" > {path}"
        );
        run_post_mount_hook(&vol_with_hooks(Some(&cmd), None));
        let wrote = std::fs::read_to_string(&path).expect("hook didn't write output file");
        assert_eq!(wrote, "post_mount /tmp/fake.hc /tmp/fake-mp");
    }

    #[test]
    fn pre_dismount_hook_runs() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let path = tmp.path().to_str().unwrap().to_string();
        let cmd = format!("echo ran > {path}");
        run_pre_dismount_hook(&vol_with_hooks(None, Some(&cmd)));
        let wrote = std::fs::read_to_string(&path).expect("hook didn't write output file");
        assert_eq!(wrote.trim(), "ran");
    }

    #[test]
    fn failing_hook_does_not_panic() {
        // Non-zero exit — hook runner must log and return cleanly.
        run_post_mount_hook(&vol_with_hooks(Some("exit 7"), None));
        run_pre_dismount_hook(&vol_with_hooks(None, Some("exit 7")));
    }

    #[test]
    fn missing_shell_command_does_not_panic() {
        // A command that nonexist should fail to exec via sh -c; sh returns
        // 127 and we log + continue.
        run_post_mount_hook(&vol_with_hooks(
            Some("/nonexistent/binary/definitely/not/here"),
            None,
        ));
    }

    #[test]
    fn pre_dismount_hook_times_out_and_kills() {
        // Spawn a hook that sleeps longer than PRE_DISMOUNT_TIMEOUT (5s).
        // We can't easily verify the child was killed within the test,
        // but we DO verify the function returns before the full sleep
        // elapses — i.e., the timeout path fires.
        let start = Instant::now();
        run_pre_dismount_hook(&vol_with_hooks(None, Some("sleep 20")));
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "pre_dismount hook timeout didn't fire: elapsed={elapsed:?}"
        );
    }
}
