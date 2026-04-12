//! Linux sleep detection via D-Bus `PrepareForSleep` signal.
//!
//! Monitors `org.freedesktop.login1.Manager.PrepareForSleep` by spawning
//! `gdbus monitor` as a subprocess and parsing its output. This avoids
//! pulling in a full D-Bus client library.

use tokio::sync::mpsc;

use super::PlatformEvent;

pub fn start(tx: mpsc::Sender<PlatformEvent>) {
    std::thread::Builder::new()
        .name("picrypt-sleep-monitor".into())
        .spawn(move || {
            tracing::info!("Linux sleep monitor starting (D-Bus)");
            if let Err(e) = run_dbus_monitor(tx) {
                tracing::error!("Linux sleep monitor failed: {e}");
            }
        })
        .expect("failed to spawn sleep monitor thread");
}

fn run_dbus_monitor(tx: mpsc::Sender<PlatformEvent>) -> anyhow::Result<()> {
    use std::io::BufRead;
    use std::process::{Command, Stdio};

    let mut child = Command::new("gdbus")
        .args([
            "monitor",
            "--system",
            "--dest",
            "org.freedesktop.login1",
            "--object-path",
            "/org/freedesktop/login1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn gdbus monitor — is gdbus installed? {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture gdbus stdout"))?;

    let reader = std::io::BufReader::new(stdout);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("error reading gdbus output: {e}");
                continue;
            }
        };

        // PrepareForSleep signal looks like:
        // /org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true)
        // true = going to sleep, false = waking up
        if line.contains("PrepareForSleep") {
            if line.contains("true") {
                tracing::info!("Linux: system preparing to sleep");
                if let Err(e) = tx.blocking_send(PlatformEvent::SleepImminent) {
                    tracing::error!("CRITICAL: failed to send SleepImminent: {e}");
                }
            } else if line.contains("false") {
                tracing::info!("Linux: system woke from sleep");
                if let Err(e) = tx.blocking_send(PlatformEvent::WokeFromSleep) {
                    tracing::error!("failed to send WokeFromSleep: {e}");
                }
            }
        }
    }

    // If we get here, gdbus exited.
    tracing::warn!("gdbus monitor exited — sleep detection stopped");
    Ok(())
}
