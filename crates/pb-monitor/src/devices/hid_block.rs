//! [`HidBlocker`]: opt-in, best-effort blocking of a HID device's input by *seizing* it
//! (`IOHIDDeviceOpen(dev, kIOHIDOptionsTypeSeizeDevice)`): while Parabellum holds the device
//! exclusively, its reports (keystrokes) no longer reach the rest of the system.
//!
//! Caveats (documented, **untested on real hardware**):
//! - opening keyboards may require the Input Monitoring permission (TCC `ListenEvent`) for
//!   `parabellumd`; without it `IOHIDDeviceOpen` fails with `kIOReturnNotPermitted`,
//! - a BadUSB device can type before the daemon reacts (tens to hundreds of ms),
//! - devices whose transport is SPI / FIFO or that carry the `Built-In` flag are **never** seized.
//!
//! Devices are located with `IOServiceGetMatchingServices(IOServiceMatching("IOHIDDevice"))`,
//! matched on the same id as [`crate::devices::parse::hid_from_props`] and wrapped with
//! `IOHIDDeviceCreate`; every interface of the device that matches is seized. They stay seized
//! until [`HidBlocker::unblock`] or drop (unplugging the device ends the seizure too).

use crate::MonitorError;

#[cfg(target_os = "macos")]
mod imp {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use core_foundation::base::{kCFAllocatorDefault, CFRelease, CFTypeRef};
    use core_foundation::dictionary::CFDictionaryRef;
    use io_kit_sys::hid::base::IOHIDDeviceRef;
    use io_kit_sys::hid::device::{IOHIDDeviceClose, IOHIDDeviceCreate, IOHIDDeviceOpen};
    use io_kit_sys::hid::keys::{kIOHIDOptionsTypeNone, kIOHIDOptionsTypeSeizeDevice};
    use io_kit_sys::types::{io_iterator_t, IO_OBJECT_NULL};
    use io_kit_sys::{
        IOIteratorNext, IOObjectRelease, IOServiceGetMatchingServices, IOServiceMatching,
    };

    use crate::devices::iokit::read_properties;
    use crate::devices::parse::hid_from_props;
    use crate::MonitorError;

    struct Seized(IOHIDDeviceRef);
    // SAFETY: IOHIDDeviceRef is a CF object; open/close/release are thread-safe and we only touch
    // it under the blocker's mutex.
    unsafe impl Send for Seized {}

    impl Seized {
        fn release(self) {
            // SAFETY: we opened (seized) and own one reference to this device.
            unsafe {
                IOHIDDeviceClose(self.0, kIOHIDOptionsTypeNone);
                CFRelease(self.0 as CFTypeRef);
            }
        }
    }

    #[derive(Default)]
    pub struct Inner {
        seized: Mutex<HashMap<String, Vec<Seized>>>,
    }

    impl Inner {
        pub fn block(&self, device_id: &str) -> Result<usize, MonitorError> {
            if !device_id.starts_with("hid:") {
                return Err(MonitorError::Refused(format!(
                    "{device_id} n'est pas un périphérique HID"
                )));
            }
            let mut map = self.seized.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(v) = map.get(device_id) {
                return Ok(v.len());
            }
            // SAFETY: NUL-terminated class name; the +1 dictionary is consumed below.
            let matching = unsafe { IOServiceMatching(c"IOHIDDevice".as_ptr()) };
            if matching.is_null() {
                return Err(MonitorError::IoKit(
                    "IOServiceMatching(IOHIDDevice) a échoué".into(),
                ));
            }
            let mut iter: io_iterator_t = IO_OBJECT_NULL;
            // SAFETY: consumes `matching`; on success we own `iter`.
            let kr =
                unsafe { IOServiceGetMatchingServices(0, matching as CFDictionaryRef, &mut iter) };
            if kr != 0 {
                return Err(MonitorError::IoKit(format!(
                    "IOServiceGetMatchingServices: 0x{kr:08x}"
                )));
            }
            let mut seized = Vec::new();
            let mut refused_builtin = false;
            let mut last_err: Option<i32> = None;
            loop {
                // SAFETY: valid iterator.
                let service = unsafe { IOIteratorNext(iter) };
                if service == IO_OBJECT_NULL {
                    break;
                }
                let dev = read_properties(service, false).and_then(|p| hid_from_props(&p));
                if let Some(dev) = dev.filter(|d| d.id == device_id) {
                    if dev
                        .details
                        .get("built_in")
                        .map(|b| b == "true")
                        .unwrap_or(true)
                    {
                        refused_builtin = true;
                    } else {
                        // SAFETY: valid service; returns a +1 IOHIDDeviceRef or null.
                        let hid = unsafe { IOHIDDeviceCreate(kCFAllocatorDefault, service) };
                        if !hid.is_null() {
                            // SAFETY: valid device reference.
                            let r = unsafe { IOHIDDeviceOpen(hid, kIOHIDOptionsTypeSeizeDevice) };
                            if r == 0 {
                                seized.push(Seized(hid));
                            } else {
                                last_err = Some(r);
                                // SAFETY: balanced with IOHIDDeviceCreate.
                                unsafe { CFRelease(hid as CFTypeRef) };
                            }
                        }
                    }
                }
                // SAFETY: owned object from the iterator.
                unsafe { IOObjectRelease(service) };
            }
            // SAFETY: owned iterator.
            unsafe { IOObjectRelease(iter) };
            if seized.is_empty() {
                return Err(if refused_builtin {
                    MonitorError::Refused("périphérique intégré : jamais bloqué".into())
                } else if let Some(r) = last_err {
                    MonitorError::IoKit(format!(
                        "IOHIDDeviceOpen(seize) a échoué : 0x{r:08x} (autorisation « Surveillance de l'entrée » requise ?)"
                    ))
                } else {
                    MonitorError::NotFound(device_id.to_string())
                });
            }
            let n = seized.len();
            map.insert(device_id.to_string(), seized);
            Ok(n)
        }

        pub fn unblock(&self, device_id: &str) -> bool {
            let mut map = self.seized.lock().unwrap_or_else(|e| e.into_inner());
            match map.remove(device_id) {
                Some(v) => {
                    v.into_iter().for_each(Seized::release);
                    true
                }
                None => false,
            }
        }

        pub fn blocked(&self) -> Vec<String> {
            let map = self.seized.lock().unwrap_or_else(|e| e.into_inner());
            let mut v: Vec<String> = map.keys().cloned().collect();
            v.sort();
            v
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            let mut map = self.seized.lock().unwrap_or_else(|e| e.into_inner());
            for (_, v) in map.drain() {
                v.into_iter().for_each(Seized::release);
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use crate::MonitorError;

    #[derive(Default)]
    pub struct Inner;

    impl Inner {
        pub fn block(&self, _device_id: &str) -> Result<usize, MonitorError> {
            Err(MonitorError::Unsupported("blocage HID (macOS uniquement)"))
        }
        pub fn unblock(&self, _device_id: &str) -> bool {
            false
        }
        pub fn blocked(&self) -> Vec<String> {
            Vec::new()
        }
    }
}

/// Seizes HID devices to block their input (see module docs). Thread-safe; share it with `Arc`.
#[derive(Default)]
pub struct HidBlocker {
    inner: imp::Inner,
}

impl std::fmt::Debug for HidBlocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HidBlocker")
            .field("blocked", &self.inner.blocked())
            .finish()
    }
}

impl HidBlocker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seizes every interface of the HID device `device_id` (`hid:<vid>:<pid>:<serial|loc-…>`).
    /// Returns the number of interfaces seized. Errors: not found, built-in device (refused),
    /// permission (`IOHIDDeviceOpen` failure), unsupported platform. Blocking IOKit calls: run it in
    /// `spawn_blocking`.
    pub fn block(&self, device_id: &str) -> Result<usize, MonitorError> {
        self.inner.block(device_id)
    }

    /// Releases a seized device. Returns `false` if it was not blocked.
    pub fn unblock(&self, device_id: &str) -> bool {
        self.inner.unblock(device_id)
    }

    /// Ids currently blocked.
    pub fn blocked(&self) -> Vec<String> {
        self.inner.blocked()
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn unsupported_off_macos() {
        let b = HidBlocker::new();
        assert!(matches!(
            b.block("hid:05ac:0221:loc-1"),
            Err(MonitorError::Unsupported(_))
        ));
        assert!(!b.unblock("hid:05ac:0221:loc-1"));
        assert!(b.blocked().is_empty());
    }
}
