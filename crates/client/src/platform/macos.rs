//! macOS sleep detection via IOKit power management notifications.
//!
//! Uses `IORegisterForSystemPower` to receive pre-sleep and post-wake
//! notifications from the kernel. Runs a CoreFoundation run loop in a
//! dedicated thread.

use std::ffi::c_void;

use tokio::sync::mpsc;

use super::PlatformEvent;

// ---------------------------------------------------------------------------
// IOKit FFI declarations
// ---------------------------------------------------------------------------

// IOKit message types for system power events.
const IOKIT_MSG_SYSTEM_WILL_SLEEP: u32 = 0xe0000280;
const IOKIT_MSG_SYSTEM_HAS_POWERED_ON: u32 = 0xe0000300;
const IOKIT_MSG_CAN_SYSTEM_SLEEP: u32 = 0xe0000270;

// CoreFoundation opaque types.
type CFRunLoopSourceRef = *mut c_void;
type CFRunLoopRef = *mut c_void;
type CFStringRef = *const c_void;

extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        thePortRef: *mut *mut c_void,
        callback: extern "C" fn(*mut c_void, u32, u32, *mut c_void),
        notifier: *mut u32,
    ) -> u32;

    fn IODeregisterForSystemPower(notifier: *mut u32) -> i32;
    fn IOAllowPowerChange(kernelPort: u32, notification_id: isize) -> i32;
    fn IONotificationPortGetRunLoopSource(notify: *mut c_void) -> CFRunLoopSourceRef;

    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
    fn CFRunLoopRun();

    static kCFRunLoopDefaultMode: CFStringRef;
}

// ---------------------------------------------------------------------------
// Combined context (sender + root_port) for the IOKit callback.
// ---------------------------------------------------------------------------

#[repr(C)]
struct PowerCallbackContext {
    tx: mpsc::Sender<PlatformEvent>,
    root_port: u32,
}

extern "C" fn power_callback(
    refcon: *mut c_void,
    _service: u32,
    message_type: u32,
    message_argument: *mut c_void,
) {
    let ctx = unsafe { &*(refcon as *const PowerCallbackContext) };
    let notification_id = message_argument as isize;

    match message_type {
        IOKIT_MSG_SYSTEM_WILL_SLEEP => {
            tracing::info!("macOS: system will sleep — sending SleepImminent");
            // blocking_send is safe here — we're in a dedicated OS thread, not a Tokio task.
            // MUST NOT use try_send: if the buffer is full, dropping SleepImminent
            // means volumes stay mounted while the machine sleeps.
            if let Err(e) = ctx.tx.blocking_send(PlatformEvent::SleepImminent) {
                tracing::error!("CRITICAL: failed to send SleepImminent event: {e}");
            }
            // Brief delay for daemon to initiate dismount, then allow sleep.
            std::thread::sleep(std::time::Duration::from_millis(500));
            unsafe {
                IOAllowPowerChange(ctx.root_port, notification_id);
            }
        }
        IOKIT_MSG_SYSTEM_HAS_POWERED_ON => {
            tracing::info!("macOS: system woke from sleep");
            if let Err(e) = ctx.tx.blocking_send(PlatformEvent::WokeFromSleep) {
                tracing::error!("failed to send WokeFromSleep event: {e}");
            }
        }
        IOKIT_MSG_CAN_SYSTEM_SLEEP => {
            // We don't object to sleep — allow it immediately.
            unsafe {
                IOAllowPowerChange(ctx.root_port, notification_id);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn start(tx: mpsc::Sender<PlatformEvent>) {
    std::thread::Builder::new()
        .name("picrypt-sleep-monitor".into())
        .spawn(move || {
            tracing::info!("macOS sleep monitor starting");
            unsafe {
                run_iokit_loop(tx);
            }
        })
        .expect("failed to spawn sleep monitor thread");
}

unsafe fn run_iokit_loop(tx: mpsc::Sender<PlatformEvent>) {
    let mut notification_port: *mut c_void = std::ptr::null_mut();
    let mut notifier: u32 = 0;

    // Allocate context on the heap — it must outlive the callback.
    let ctx = Box::new(PowerCallbackContext {
        tx,
        root_port: 0, // Set after IORegisterForSystemPower returns.
    });
    let ctx_ptr = Box::into_raw(ctx);

    let root_port = IORegisterForSystemPower(
        ctx_ptr as *mut c_void,
        &mut notification_port,
        power_callback,
        &mut notifier,
    );

    if root_port == 0 {
        tracing::error!("IORegisterForSystemPower failed — sleep detection disabled");
        let _ = Box::from_raw(ctx_ptr);
        return;
    }

    // Store the root_port so the callback can use it for IOAllowPowerChange.
    (*ctx_ptr).root_port = root_port;

    let run_loop_source = IONotificationPortGetRunLoopSource(notification_port);
    if run_loop_source.is_null() {
        tracing::error!("IONotificationPortGetRunLoopSource returned null");
        IODeregisterForSystemPower(&mut notifier);
        let _ = Box::from_raw(ctx_ptr);
        return;
    }

    let run_loop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(run_loop, run_loop_source, kCFRunLoopDefaultMode);

    tracing::info!("macOS sleep monitor active — listening for power events");

    // Blocks forever (or until the run loop is stopped).
    CFRunLoopRun();

    // Cleanup (unreachable in normal operation).
    IODeregisterForSystemPower(&mut notifier);
    let _ = Box::from_raw(ctx_ptr);
}
