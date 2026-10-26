//! Administrator approval for protection-weakening commands ([`Request::requires_admin`]).
//!
//! macOS: the daemon registers [`ADMIN_RIGHT`] in the authorization database (rule `authenticate-admin`)
//! at startup. The app obtains the right with a password / Touch ID prompt drawn by SecurityAgent and sends
//! the 32-byte `AuthorizationExternalForm` (base64) in `RequestEnvelope.auth`; the daemon recreates the
//! reference and checks the right **without interaction**. Root peers (`sudo parabellum …`) need nothing.
//! Other platforms: no Authorization Services, so `auth` is never valid (root or dev mode only).
//!
//! [`Request::requires_admin`]: pb_core::ipc::Request::requires_admin

use pb_core::ipc::ADMIN_RIGHT;

/// Message of the `auth_required` error.
pub const AUTH_REQUIRED_MESSAGE: &str = "Cette action réduit la protection : approbation d'un administrateur requise \
     (mot de passe ou Touch ID dans l'app Parabellum, ou sudo parabellum …)";

/// Length of an `AuthorizationExternalForm` (`kAuthorizationExternalFormLength`).
pub const EXTERNAL_FORM_LEN: usize = 32;

/// Decode the base64 external form (exactly 32 bytes).
pub fn decode_external_form(b64: &str) -> Option<[u8; EXTERNAL_FORM_LEN]> {
    use base64::Engine;
    let s = b64.trim();
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    let v = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    v.try_into().ok()
}

/// Register (or repair) [`ADMIN_RIGHT`] so that it delegates to `authenticate-admin`. Idempotent.
/// Returns `Ok(true)` when the database was changed. No-op elsewhere than macOS.
pub fn register_admin_right() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        mac::register()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

/// Does this external form hold [`ADMIN_RIGHT`] right now (checked without user interaction)?
/// Blocking (talks to `authd`): call from `spawn_blocking`.
pub fn verify_admin_auth(external_form_b64: &str) -> bool {
    let Some(bytes) = decode_external_form(external_form_b64) else {
        return false;
    };
    #[cfg(target_os = "macos")]
    {
        mac::verify(&bytes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bytes;
        false
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use super::{ADMIN_RIGHT, EXTERNAL_FORM_LEN};
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::bundle::CFBundleRef;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::{CFString, CFStringRef};
    use std::ffi::{c_char, c_void, CString};

    type OSStatus = i32;
    #[repr(C)]
    struct AuthorizationOpaqueRef {
        _private: [u8; 0],
    }
    /// `typedef const struct AuthorizationOpaqueRef *AuthorizationRef;`
    type AuthorizationRef = *const AuthorizationOpaqueRef;
    type AuthorizationFlags = u32;
    const FLAG_DEFAULTS: AuthorizationFlags = 0;
    /// `kAuthorizationFlagExtendRights` (no `kAuthorizationFlagInteractionAllowed`: never prompt from root).
    const FLAG_EXTEND_RIGHTS: AuthorizationFlags = 1 << 1;
    const ERR_AUTHORIZATION_SUCCESS: OSStatus = 0;
    /// `errAuthorizationDenied`, also "no such right" for `AuthorizationRightGet`.
    const ERR_AUTHORIZATION_DENIED: OSStatus = -60005;
    /// `kAuthorizationRuleAuthenticateAsAdmin`.
    const RULE_AUTHENTICATE_ADMIN: &str = "authenticate-admin";

    #[repr(C)]
    struct AuthorizationItem {
        name: *const c_char,
        value_length: usize,
        value: *mut c_void,
        flags: u32,
    }
    #[repr(C)]
    struct AuthorizationItemSet {
        count: u32,
        items: *mut AuthorizationItem,
    }
    #[repr(C)]
    struct AuthorizationExternalForm {
        bytes: [c_char; EXTERNAL_FORM_LEN],
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn AuthorizationCreate(
            rights: *const AuthorizationItemSet,
            environment: *const AuthorizationItemSet,
            flags: AuthorizationFlags,
            authorization: *mut AuthorizationRef,
        ) -> OSStatus;
        fn AuthorizationFree(authorization: AuthorizationRef, flags: AuthorizationFlags) -> OSStatus;
        fn AuthorizationCopyRights(
            authorization: AuthorizationRef,
            rights: *const AuthorizationItemSet,
            environment: *const AuthorizationItemSet,
            flags: AuthorizationFlags,
            authorized_rights: *mut *mut AuthorizationItemSet,
        ) -> OSStatus;
        fn AuthorizationCreateFromExternalForm(
            ext_form: *const AuthorizationExternalForm,
            authorization: *mut AuthorizationRef,
        ) -> OSStatus;
        fn AuthorizationRightGet(right_name: *const c_char, right_definition: *mut CFDictionaryRef) -> OSStatus;
        fn AuthorizationRightSet(
            auth_ref: AuthorizationRef,
            right_name: *const c_char,
            right_definition: CFTypeRef,
            description_key: CFStringRef,
            bundle: CFBundleRef,
            locale_table_name: CFStringRef,
        ) -> OSStatus;
    }

    fn is_admin_rule_name(v: &CFType) -> bool {
        v.downcast::<CFString>().map(|s| s.to_string() == RULE_AUTHENTICATE_ADMIN).unwrap_or(false)
    }

    /// The stored definition delegates to `authenticate-admin` (class `rule`, rule = name or [name]).
    fn delegates_to_admin(def: &CFDictionary<CFString, CFType>) -> bool {
        let class_ok = def
            .find(CFString::from_static_string("class"))
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string() == "rule")
            .unwrap_or(false);
        let rule_ok = match def.find(CFString::from_static_string("rule")) {
            None => false,
            Some(v) if is_admin_rule_name(&v) => true,
            Some(v) => match v.downcast::<CFArray<*const c_void>>() {
                Some(arr) => {
                    arr.len() == 1
                        && arr.iter().all(|p| {
                            // SAFETY: elements of a CFArray from the authorization DB are CF objects.
                            let item = unsafe { CFType::wrap_under_get_rule(*p as CFTypeRef) };
                            is_admin_rule_name(&item)
                        })
                }
                None => false,
            },
        };
        class_ok && rule_ok
    }

    pub(super) fn register() -> Result<bool, String> {
        let name = CString::new(ADMIN_RIGHT).map_err(|e| e.to_string())?;
        let mut def: CFDictionaryRef = std::ptr::null();
        // SAFETY: valid C string and out-pointer; a returned dictionary follows the create rule.
        let st = unsafe { AuthorizationRightGet(name.as_ptr(), &mut def) };
        if st == ERR_AUTHORIZATION_SUCCESS && !def.is_null() {
            // SAFETY: `def` was returned +1 by AuthorizationRightGet.
            let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(def) };
            if delegates_to_admin(&dict) {
                return Ok(false);
            }
            tracing::warn!(right = ADMIN_RIGHT, "authorization right has an unexpected definition, repairing");
        } else if st != ERR_AUTHORIZATION_DENIED && st != ERR_AUTHORIZATION_SUCCESS {
            return Err(format!("AuthorizationRightGet: OSStatus {st}"));
        }
        let mut auth: AuthorizationRef = std::ptr::null();
        // SAFETY: null rights/environment are allowed; out-pointer is valid.
        let st = unsafe { AuthorizationCreate(std::ptr::null(), std::ptr::null(), FLAG_DEFAULTS, &mut auth) };
        if st != ERR_AUTHORIZATION_SUCCESS || auth.is_null() {
            return Err(format!("AuthorizationCreate: OSStatus {st}"));
        }
        let rule = CFString::from_static_string(RULE_AUTHENTICATE_ADMIN);
        let description = CFString::new("Parabellum veut effectuer une action qui réduit la protection de ce Mac.");
        // SAFETY: all CF objects outlive the call; bundle / locale table may be NULL.
        let st = unsafe {
            AuthorizationRightSet(
                auth,
                name.as_ptr(),
                rule.as_CFTypeRef(),
                description.as_concrete_TypeRef(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        // SAFETY: `auth` came from AuthorizationCreate.
        unsafe {
            AuthorizationFree(auth, FLAG_DEFAULTS);
        }
        if st == ERR_AUTHORIZATION_SUCCESS {
            Ok(true)
        } else {
            Err(format!("AuthorizationRightSet: OSStatus {st}"))
        }
    }

    pub(super) fn verify(bytes: &[u8; EXTERNAL_FORM_LEN]) -> bool {
        let ext = AuthorizationExternalForm { bytes: bytes.map(|b| b as c_char) };
        let mut auth: AuthorizationRef = std::ptr::null();
        // SAFETY: `ext` is a valid external form buffer; out-pointer is valid.
        let st = unsafe { AuthorizationCreateFromExternalForm(&ext, &mut auth) };
        if st != ERR_AUTHORIZATION_SUCCESS || auth.is_null() {
            return false;
        }
        let Ok(name) = CString::new(ADMIN_RIGHT) else {
            // SAFETY: `auth` came from AuthorizationCreateFromExternalForm.
            unsafe { AuthorizationFree(auth, FLAG_DEFAULTS) };
            return false;
        };
        let mut item = AuthorizationItem { name: name.as_ptr(), value_length: 0, value: std::ptr::null_mut(), flags: 0 };
        let rights = AuthorizationItemSet { count: 1, items: &mut item };
        // SAFETY: rights point to live stack data; no environment, no output set requested.
        let st = unsafe {
            AuthorizationCopyRights(auth, &rights, std::ptr::null(), FLAG_EXTEND_RIGHTS, std::ptr::null_mut())
        };
        // Plain free: destroying rights would revoke the app's own authorization.
        // SAFETY: `auth` came from AuthorizationCreateFromExternalForm.
        unsafe {
            AuthorizationFree(auth, FLAG_DEFAULTS);
        }
        st == ERR_AUTHORIZATION_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn external_form_decoding() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(decode_external_form(&b64), Some([7u8; 32]));
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 31]);
        assert_eq!(decode_external_form(&short), None);
        assert_eq!(decode_external_form("!!!"), None);
        assert_eq!(decode_external_form(""), None);
        assert_eq!(decode_external_form(&"A".repeat(200)), None);
    }

    #[test]
    fn never_valid_without_authorization_services() {
        if !cfg!(target_os = "macos") {
            let b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
            assert!(!verify_admin_auth(&b64));
            assert_eq!(register_admin_right(), Ok(false));
        }
    }
}
