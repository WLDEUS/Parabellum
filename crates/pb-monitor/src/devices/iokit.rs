//! macOS IOKit: arrival / removal notifications for USB (`IOUSBHostDevice`), HID (`IOHIDDevice`)
//! and Thunderbolt (`IOThunderboltSwitch`) services, on a dedicated thread running a CFRunLoop.
//!
//! Contract followed (IOKitLib): `IOServiceMatching` returns a +1 dictionary that
//! `IOServiceAddMatchingNotification` consumes (one per call); each notification iterator must be
//! drained completely to arm it (initial drain = devices already present); every `io_object_t`
//! obtained from an iterator is released with `IOObjectRelease`; iterators are released and the
//! notification port destroyed when the thread stops. Registry properties are converted into a
//! `plist::Dictionary` so the same pure parsers serve IOKit and the `ioreg -a` fallback.

use std::ffi::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use core_foundation::array::{
    CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFArrayRef,
};
use core_foundation::base::{kCFAllocatorDefault, CFGetTypeID, CFRelease, CFTypeRef, TCFType};
use core_foundation::data::{CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID, CFDataRef};
use core_foundation::dictionary::{
    CFDictionaryGetCount, CFDictionaryGetKeysAndValues, CFDictionaryGetTypeID, CFDictionaryRef,
    CFMutableDictionaryRef,
};
use core_foundation::number::{
    kCFNumberFloat64Type, kCFNumberSInt64Type, CFBooleanGetTypeID, CFBooleanGetValue, CFBooleanRef,
    CFNumberGetTypeID, CFNumberGetValue, CFNumberIsFloatType, CFNumberRef,
};
use core_foundation::runloop::{
    kCFRunLoopDefaultMode, CFRunLoop, CFRunLoopAddSource, CFRunLoopGetCurrent, CFRunLoopRunResult,
};
use core_foundation::string::{CFString, CFStringGetTypeID, CFStringRef};
use io_kit_sys::keys::{kIOFirstMatchNotification, kIOServicePlane, kIOTerminatedNotification};
use io_kit_sys::types::{io_iterator_t, io_object_t, IO_OBJECT_NULL};
use io_kit_sys::{
    IOIteratorNext, IONotificationPortCreate, IONotificationPortDestroy,
    IONotificationPortGetRunLoopSource, IOObjectRelease, IORegistryEntryCreateCFProperties,
    IORegistryEntryGetChildIterator, IORegistryEntryGetRegistryEntryID,
    IOServiceAddMatchingNotification, IOServiceMatching,
};
use plist::{Dictionary, Value};
use tokio::sync::mpsc;

use super::IoClass;
use crate::util::clip;
use crate::MonitorError;

/// `kIOMainPortDefault` / `MACH_PORT_NULL`: "use the default main port".
const MAIN_PORT_DEFAULT: u32 = 0;

/// One arrival (`props` set) or removal (`props` = `None`) notification.
#[derive(Debug)]
pub(crate) struct IoKitEvent {
    pub class: IoClass,
    pub arrived: bool,
    pub entry_id: u64,
    pub props: Option<Dictionary>,
}

struct CallbackCtx {
    class: IoClass,
    arrived: bool,
    tx: mpsc::Sender<IoKitEvent>,
}

/// Handle on the notification thread; stops it on drop.
pub(crate) struct IoKitMonitor {
    run_loop: CFRunLoop,
    stop: Arc<AtomicBool>,
}

impl IoKitMonitor {
    /// Starts the thread. Blocking (waits up to 10 s for the registrations): call it from
    /// `spawn_blocking`. Events (including one arrival per device already present) are delivered
    /// on `tx` after this returns.
    pub(crate) fn start(tx: mpsc::Sender<IoKitEvent>) -> Result<Self, MonitorError> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<CFRunLoop, String>>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        std::thread::Builder::new()
            .name("pb-iokit".into())
            .spawn(move || thread_main(tx, ready_tx, stop_thread))
            .map_err(MonitorError::Io)?;
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(run_loop)) => Ok(Self { run_loop, stop }),
            Ok(Err(e)) => Err(MonitorError::IoKit(e)),
            Err(_) => {
                stop.store(true, Ordering::Release);
                Err(MonitorError::IoKit("IOKit thread did not start".into()))
            }
        }
    }
}

impl Drop for IoKitMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // CFRunLoopStop is thread-safe; if the loop is not running yet, the stop flag is seen on
        // its next run.
        self.run_loop.stop();
    }
}

fn thread_main(
    tx: mpsc::Sender<IoKitEvent>,
    ready: std::sync::mpsc::Sender<Result<CFRunLoop, String>>,
    stop: Arc<AtomicBool>,
) {
    // SAFETY: plain IOKit call; returns null on failure.
    let port = unsafe { IONotificationPortCreate(MAIN_PORT_DEFAULT) };
    if port.is_null() {
        let _ = ready.send(Err("IONotificationPortCreate a échoué".into()));
        return;
    }
    // SAFETY: `port` is a valid notification port; the source is owned by the port.
    let source = unsafe { IONotificationPortGetRunLoopSource(port) };
    if source.is_null() {
        // SAFETY: port created above, destroyed once.
        unsafe { IONotificationPortDestroy(port) };
        let _ = ready.send(Err("IONotificationPortGetRunLoopSource a échoué".into()));
        return;
    }
    // SAFETY: current thread's run loop; kCFRunLoopDefaultMode is an immutable CF constant.
    unsafe { CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode) };

    let mut registrations: Vec<(*mut CallbackCtx, io_iterator_t)> = Vec::new();
    for class in IoClass::ALL {
        for arrived in [true, false] {
            // SAFETY: NUL-terminated class name; returns a +1 dictionary (or null).
            let matching: CFMutableDictionaryRef =
                unsafe { IOServiceMatching(class.class_name().as_ptr()) };
            if matching.is_null() {
                continue;
            }
            let ctx = Box::into_raw(Box::new(CallbackCtx {
                class,
                arrived,
                tx: tx.clone(),
            }));
            let mut iter: io_iterator_t = IO_OBJECT_NULL;
            let ntype = if arrived {
                kIOFirstMatchNotification
            } else {
                kIOTerminatedNotification
            };
            // SAFETY: valid port; `matching` is consumed by the call (even on failure); `ctx`
            // stays alive until the iterator is released at thread exit.
            let kr = unsafe {
                IOServiceAddMatchingNotification(
                    port,
                    ntype as *mut c_char,
                    matching as CFDictionaryRef,
                    on_notification,
                    ctx as *mut c_void,
                    &mut iter,
                )
            };
            if kr != 0 {
                tracing::warn!(class = ?class, arrived, kr, "IOServiceAddMatchingNotification failed");
                // SAFETY: ctx came from Box::into_raw above and was not registered.
                drop(unsafe { Box::from_raw(ctx) });
                continue;
            }
            registrations.push((ctx, iter));
        }
    }
    if registrations.is_empty() {
        // SAFETY: destroyed once; no registration references it.
        unsafe { IONotificationPortDestroy(port) };
        let _ = ready.send(Err("aucune notification IOKit enregistrée".into()));
        return;
    }
    let _ = ready.send(Ok(CFRunLoop::get_current()));

    // Arm every iterator (and report devices already present for first-match ones).
    for (ctx, iter) in &registrations {
        // SAFETY: same contract as an IOKit callback invocation.
        unsafe { on_notification(*ctx as *mut c_void, *iter) };
    }

    while !stop.load(Ordering::Acquire) {
        // SAFETY: reading an immutable CF constant.
        let mode = unsafe { kCFRunLoopDefaultMode };
        if CFRunLoop::run_in_mode(mode, Duration::from_secs(300), false)
            == CFRunLoopRunResult::Finished
        {
            // No source left (should not happen): avoid spinning.
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    for (_, iter) in &registrations {
        // SAFETY: each notification iterator is released exactly once (this also cancels it).
        unsafe { IOObjectRelease(*iter) };
    }
    // SAFETY: destroyed once, after its notifications were cancelled; also removes the source.
    unsafe { IONotificationPortDestroy(port) };
    for (ctx, _) in registrations {
        // SAFETY: no callback can run any more (we are the run loop thread and left the loop).
        drop(unsafe { Box::from_raw(ctx) });
    }
}

/// `IOServiceMatchingCallback`: drains the iterator (required to re-arm it).
unsafe extern "C" fn on_notification(refcon: *mut c_void, iterator: io_iterator_t) {
    if refcon.is_null() {
        return;
    }
    // SAFETY: refcon is the CallbackCtx registered with this notification, alive until thread exit.
    let ctx = unsafe { &*(refcon as *const CallbackCtx) };
    // Never unwind into IOKit.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drain(ctx, iterator)));
}

fn drain(ctx: &CallbackCtx, iterator: io_iterator_t) {
    loop {
        // SAFETY: valid notification iterator.
        let service = unsafe { IOIteratorNext(iterator) };
        if service == IO_OBJECT_NULL {
            break;
        }
        let entry_id = registry_entry_id(service);
        let props = if ctx.arrived {
            read_properties(service, ctx.class == IoClass::Usb)
        } else {
            None
        };
        // SAFETY: objects returned by IOIteratorNext are owned by us.
        unsafe { IOObjectRelease(service) };
        // The receiver may be gone (watcher stopping): keep draining anyway.
        let _ = ctx.tx.blocking_send(IoKitEvent {
            class: ctx.class,
            arrived: ctx.arrived,
            entry_id,
            props,
        });
    }
}

pub(crate) fn registry_entry_id(entry: io_object_t) -> u64 {
    let mut id: u64 = 0;
    // SAFETY: valid registry entry, out-pointer to a u64.
    let kr = unsafe { IORegistryEntryGetRegistryEntryID(entry, &mut id) };
    if kr == 0 {
        id
    } else {
        0
    }
}

/// All registry properties of `entry` as a plist dictionary (plus `IORegistryEntryID`, and for
/// USB devices `IORegistryEntryChildren` with the interfaces' `bInterfaceClass`).
pub(crate) fn read_properties(entry: io_object_t, with_children: bool) -> Option<Dictionary> {
    let mut dict: CFMutableDictionaryRef = std::ptr::null_mut();
    // SAFETY: valid entry, out-pointer; on success we own `dict` (+1) and release it below.
    let kr = unsafe { IORegistryEntryCreateCFProperties(entry, &mut dict, kCFAllocatorDefault, 0) };
    if kr != 0 || dict.is_null() {
        return None;
    }
    // SAFETY: `dict` is a valid CFDictionary.
    let value = unsafe { cf_to_plist(dict as CFTypeRef, 0) };
    // SAFETY: balanced with the create above.
    unsafe { CFRelease(dict as CFTypeRef) };
    let mut d = value?.into_dictionary()?;
    d.insert(
        "IORegistryEntryID".into(),
        Value::Integer(registry_entry_id(entry).into()),
    );
    if with_children {
        let children = child_interface_props(entry);
        if !children.is_empty() {
            d.insert("IORegistryEntryChildren".into(), Value::Array(children));
        }
    }
    Some(d)
}

/// `bInterfaceClass` of direct children (USB interfaces), best effort (they may not be matched yet).
fn child_interface_props(entry: io_object_t) -> Vec<Value> {
    let mut out = Vec::new();
    let mut iter: io_iterator_t = IO_OBJECT_NULL;
    // SAFETY: valid entry; plane name is a NUL-terminated constant; iterator released below.
    let kr = unsafe {
        IORegistryEntryGetChildIterator(entry, kIOServicePlane as *mut c_char, &mut iter)
    };
    if kr != 0 {
        return out;
    }
    let mut n = 0;
    loop {
        // SAFETY: valid iterator.
        let child = unsafe { IOIteratorNext(iter) };
        if child == IO_OBJECT_NULL {
            break;
        }
        n += 1;
        if n <= 32 {
            let mut cd: CFMutableDictionaryRef = std::ptr::null_mut();
            // SAFETY: as in read_properties.
            let kr = unsafe {
                IORegistryEntryCreateCFProperties(child, &mut cd, kCFAllocatorDefault, 0)
            };
            if kr == 0 && !cd.is_null() {
                // SAFETY: valid dictionary, released right after.
                let v = unsafe { cf_to_plist(cd as CFTypeRef, 0) };
                // SAFETY: balanced with the create above.
                unsafe { CFRelease(cd as CFTypeRef) };
                if let Some(cls) = v
                    .as_ref()
                    .and_then(Value::as_dictionary)
                    .and_then(|d| d.get("bInterfaceClass"))
                    .cloned()
                {
                    let mut m = Dictionary::new();
                    m.insert("bInterfaceClass".into(), cls);
                    out.push(Value::Dictionary(m));
                }
            }
        }
        // SAFETY: owned child object.
        unsafe { IOObjectRelease(child) };
    }
    // SAFETY: owned iterator.
    unsafe { IOObjectRelease(iter) };
    out
}

/// Converts a CF property-list object (string, number, boolean, data, array, dictionary) into a
/// `plist::Value`, bounded (depth 6, 256 array items, 1024 dictionary keys, data <= 4 KiB, strings
/// <= 4096 chars). Unsupported types (e.g. CFSet) are skipped.
///
/// # Safety
/// `v` must be null or a valid CF object for the duration of the call.
pub(crate) unsafe fn cf_to_plist(v: CFTypeRef, depth: usize) -> Option<Value> {
    if v.is_null() || depth > 6 {
        return None;
    }
    // SAFETY: `v` is a valid CF object (caller contract); type-id functions have no preconditions.
    let t = unsafe { CFGetTypeID(v) };
    // SAFETY: (all blocks below) `v` was checked to be of the matching CF type before the cast.
    unsafe {
        if t == CFStringGetTypeID() {
            let s = CFString::wrap_under_get_rule(v as CFStringRef).to_string();
            return Some(Value::String(clip(&s, 4096)));
        }
        if t == CFNumberGetTypeID() {
            let n = v as CFNumberRef;
            if CFNumberIsFloatType(n) != 0 {
                let mut f: f64 = 0.0;
                CFNumberGetValue(n, kCFNumberFloat64Type, &mut f as *mut f64 as *mut c_void);
                return f.is_finite().then_some(Value::Real(f));
            }
            let mut i: i64 = 0;
            // A lossy conversion still stores the (bit-preserved) 64-bit value.
            CFNumberGetValue(n, kCFNumberSInt64Type, &mut i as *mut i64 as *mut c_void);
            return Some(Value::Integer(i.into()));
        }
        if t == CFBooleanGetTypeID() {
            return Some(Value::Boolean(CFBooleanGetValue(v as CFBooleanRef)));
        }
        if t == CFDataGetTypeID() {
            let d = v as CFDataRef;
            let len = CFDataGetLength(d);
            if !(0..=4096).contains(&len) {
                return None;
            }
            let ptr = CFDataGetBytePtr(d);
            if ptr.is_null() {
                return Some(Value::Data(Vec::new()));
            }
            return Some(Value::Data(
                std::slice::from_raw_parts(ptr, len as usize).to_vec(),
            ));
        }
        if t == CFArrayGetTypeID() {
            let a = v as CFArrayRef;
            let count = CFArrayGetCount(a).clamp(0, 256);
            let mut out = Vec::with_capacity(count as usize);
            for i in 0..count {
                if let Some(x) = cf_to_plist(CFArrayGetValueAtIndex(a, i), depth + 1) {
                    out.push(x);
                }
            }
            return Some(Value::Array(out));
        }
        if t == CFDictionaryGetTypeID() {
            let d = v as CFDictionaryRef;
            let count = CFDictionaryGetCount(d);
            if !(0..=4096).contains(&count) {
                return None;
            }
            let mut keys: Vec<*const c_void> = vec![std::ptr::null(); count as usize];
            let mut values: Vec<*const c_void> = vec![std::ptr::null(); count as usize];
            CFDictionaryGetKeysAndValues(d, keys.as_mut_ptr(), values.as_mut_ptr());
            let mut out = Dictionary::new();
            for (k, val) in keys.iter().zip(values.iter()).take(1024) {
                if k.is_null() || CFGetTypeID(*k) != CFStringGetTypeID() {
                    continue;
                }
                let key = CFString::wrap_under_get_rule(*k as CFStringRef).to_string();
                if let Some(x) = cf_to_plist(*val, depth + 1) {
                    out.insert(key, x);
                }
            }
            return Some(Value::Dictionary(out));
        }
    }
    None
}
