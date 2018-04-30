extern crate cjose_sys;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate serde_json;

pub mod error;
mod util;

use cjose_sys::*;
use error::*;
use libc::{free, c_void};
use std::slice;
use util::*;

pub enum JWKECCurve {
    P256,
    P384,
    P521
}

impl From<JWKECCurve> for i32 {
    fn from(curve: JWKECCurve) -> Self {
        match curve {
            JWKECCurve::P256 => CJOSE_JWK_EC_P_256,
            JWKECCurve::P384 => CJOSE_JWK_EC_P_384,
            JWKECCurve::P521 => CJOSE_JWK_EC_P_521,
        }
    }
}

fn out_error() -> *mut cjose_err {
    Box::into_raw(Box::new(cjose_err {
        code: CJOSE_ERR_NONE,
        message: std::ptr::null(),
        function: std::ptr::null(),
        file: std::ptr::null(),
        line: 0
    }))
}

fn bail_on_err<T>(ptr: *mut T, err_ptr: *mut cjose_err) -> Result<*mut T> {
    if ptr.is_null() {
        let err = unsafe { Box::from_raw(err_ptr) };
        let err = ErrorKind::CJoseError(
            err.code,
            c_string_to_string(err.message),
            c_string_to_string(err.function),
            c_string_to_string(err.file),
            err.line.into()
        );
        bail!(err)
    }
    Ok(ptr)
}

// No parametrized mutability in Rust :(
fn bail_on_err_const<T>(ptr: *const T, err_ptr: *mut cjose_err) -> Result<*const T> {
    if ptr.is_null() {
        let err = unsafe { Box::from_raw(err_ptr) };
        let err = ErrorKind::CJoseError(
            err.code,
            c_string_to_string(err.message),
            c_string_to_string(err.function),
            c_string_to_string(err.file),
            err.line.into()
        );
        bail!(err)
    }
    Ok(ptr)
}

pub struct JWK {
    jwk: *mut cjose_jwk_t
}

impl JWK {
    /// Creates a new Elliptic-Curve JWK, using a secure random number generator.
    pub fn from_random_ec(curve: JWKECCurve) -> Result<JWK> {
        let err = out_error();
        let jwk = bail_on_err(unsafe {
            cjose_jwk_create_EC_random(curve.into(), err)
        }, err)?;
        Ok(JWK {
            jwk
        })
    }

    pub fn to_json(&self, include_private: bool) -> Result<serde_json::Value> {
        let err = out_error();
        let json_str = bail_on_err(unsafe {
            cjose_jwk_to_json(self.jwk, include_private, err)
        }, err)?;
        let json_str = borrow_c_string(json_str);
        Ok(serde_json::from_str(&json_str)?)
    }

    pub fn decrypt(&self, jwe: &JWE) -> Result<String> {
        let mut content_len: usize = 0;
        let out_content_len: *mut usize = &mut content_len;
        let err = out_error();
        let plaintext_ptr = bail_on_err(unsafe {
            cjose_jwe_decrypt(jwe.jwe, self.jwk, out_content_len, err)
        }, err)?;
        let plaintext_slice = unsafe { slice::from_raw_parts(plaintext_ptr, content_len) };
        let plaintext = String::from_utf8(plaintext_slice.to_vec())
            .chain_err(|| "Invalid UTF-8!")?;
        unsafe { free(plaintext_ptr as *mut c_void) };
        Ok(plaintext)
    }
}

impl Drop for JWK {
    fn drop(&mut self) {
        unsafe { cjose_jwk_release(self.jwk) };
    }
}

pub struct JWE {
    jwe: *mut cjose_jwe_t
}

impl JWE {
    /// Creates a new JWE object from the given JWE compact serialization.
    pub fn import(input: &str) -> Result<JWE> {
        let compact = string_to_c_char(input);
        let compact_len = input.len(); // Should we +1 it?
        let err = out_error();
        let jwe = bail_on_err(unsafe {
            cjose_jwe_import(compact, compact_len, err)
        }, err)?;
        Ok(JWE {
            jwe
        })
    }
}

impl Drop for JWE {
    fn drop(&mut self) {
        unsafe { cjose_jwe_release(self.jwe) };
    }
}
