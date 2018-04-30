use std::ffi::{CStr, CString};
use libc::{c_char, c_void, free};

/// Clones the c_string into a owned String. Destroys the original.
pub fn borrow_c_string(char_ptr: *mut c_char) -> String {
    let str = c_string_to_string(char_ptr);
    unsafe { free(char_ptr as *mut c_void) };
    str
}

/// Clones the c_string into a owned String. Does not destroy the original.
pub fn c_string_to_string(char_ptr: *const c_char) -> String {
    let c_str = unsafe { CStr::from_ptr(char_ptr) };
    let r_str = c_str.to_str().unwrap_or("");
    r_str.to_string()
}

/// This string must be de-allocated later by taking its ownership back with CString::from_raw.
pub fn string_to_c_char<T>(r_string: T) -> *mut c_char where T: Into<String> {
    CString::new(r_string.into()).unwrap().into_raw()
}