//! A stable C ABI over the sans-I/O engine (`rtc`).
//!
//! The sans-I/O layer (`rtc_pc_*`) is the Rust API one to one: an opaque peer connection
//! handle, configuration and settings as JSON, descriptions and candidates as the W3C JSON
//! shapes, transceivers, senders, receivers and data channels by numeric id, and the event loop
//! (`rtc_pc_handle_read`, `rtc_pc_poll_write`, `rtc_pc_poll_read`, `rtc_pc_poll_event`,
//! `rtc_pc_poll_timeout`, `rtc_pc_handle_timeout`) with buffers the caller owns. The caller
//! drives the clock: every call that needs the time takes it as monotonic nanoseconds on an
//! origin of the caller's choosing (see [`clock`]).
//!
//! # The rules of the boundary
//!
//! * Every function returns an `int32_t` status: [`RTC_OK`] (0), [`RTC_EMPTY`] (1, nothing to
//!   poll), or a negative error code. After an error, [`rtc_last_error`] gives a description;
//!   it is kept per thread until the next error on that thread.
//! * No panic crosses the boundary: every entry point catches unwinding and returns
//!   [`RTC_ERR_PANIC`]. A handle whose call panicked is poisoned and refuses every later call
//!   except its free.
//! * Every allocation the library hands out is freed by its matching function: a handle by its
//!   `_free`, a string (`char **out`) by [`rtc_string_free`]. Strings going in are borrowed for
//!   the call only. Buffers given to `poll_*` are the caller's; when one is too small the call
//!   returns [`RTC_ERR_BUFFER_TOO_SMALL`] with the size needed and keeps the item for the next
//!   call.
//! * A `rtc_pc` handle is not thread-safe: calls on one handle must not overlap. It may be used
//!   from different threads one after another. Different handles are independent.
//! * Every exported symbol starts with `rtc_`. [`rtc_abi_version`] is the version of this
//!   interface; it changes when a signature or a struct layout does.

#![warn(missing_docs)]
#![allow(clippy::missing_safety_doc)]

pub mod clock;
mod json;
pub mod pc;

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicI64, Ordering};

/// The version of this C interface. It changes whenever a function signature, a struct layout
/// or the meaning of a status code changes; a binding checks it at load time.
pub const RTC_ABI_VERSION: u32 = 1;

/// Success.
pub const RTC_OK: i32 = 0;
/// Success, nothing to return: a poll found its queue empty, a lookup found no value.
pub const RTC_EMPTY: i32 = 1;
/// An argument is null, out of range, not UTF-8, or names no such object.
pub const RTC_ERR_INVALID_ARGUMENT: i32 = -1;
/// The caller's buffer is too small; the size needed was written and the item kept.
pub const RTC_ERR_BUFFER_TOO_SMALL: i32 = -2;
/// The engine refused the call (W3C errors such as `InvalidStateError`, malformed SDP, ...).
pub const RTC_ERR_ENGINE: i32 = -3;
/// A JSON argument did not parse or did not match its schema.
pub const RTC_ERR_JSON: i32 = -4;
/// The call panicked inside the library; the handle is poisoned.
pub const RTC_ERR_PANIC: i32 = -5;
/// No object with this id (data channel, sender, receiver, transceiver).
pub const RTC_ERR_NOT_FOUND: i32 = -6;
/// A socket or thread operation failed (driven layer).
pub const RTC_ERR_IO: i32 = -7;
/// The handle is closed or poisoned.
pub const RTC_ERR_CLOSED: i32 = -8;

/// An error on its way out: a status code and a description for [`rtc_last_error`].
#[derive(Debug)]
pub(crate) struct FfiError {
    pub(crate) code: i32,
    pub(crate) message: String,
}

impl FfiError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(RTC_ERR_INVALID_ARGUMENT, message)
    }

    pub(crate) fn not_found(what: &str, id: u64) -> Self {
        Self::new(RTC_ERR_NOT_FOUND, format!("no {what} with id {id}"))
    }
}

impl From<rtc::shared::error::Error> for FfiError {
    fn from(e: rtc::shared::error::Error) -> Self {
        Self::new(RTC_ERR_ENGINE, e.to_string())
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(RTC_ERR_JSON, e.to_string())
    }
}

pub(crate) type FfiResult<T = i32> = Result<T, FfiError>;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|last| *last.borrow_mut() = message);
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "a panic without a message".to_owned()
    }
}

/// Runs an entry point: no unwinding past it, errors recorded for [`rtc_last_error`].
pub(crate) fn guard(f: impl FnOnce() -> FfiResult) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => {
            set_last_error(e.message);
            e.code
        }
        Err(payload) => {
            set_last_error(format!("panic: {}", panic_message(payload.as_ref())));
            RTC_ERR_PANIC
        }
    }
}

/// Objects the library handed out and that were not freed yet (handles and strings), for the
/// tests' leak checks.
static LIVE_OBJECTS: AtomicI64 = AtomicI64::new(0);

pub(crate) fn object_created() {
    LIVE_OBJECTS.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn object_freed() {
    LIVE_OBJECTS.fetch_sub(1, Ordering::SeqCst);
}

/// Borrows a C string argument as UTF-8; `None` for a null pointer.
pub(crate) unsafe fn opt_str<'a>(ptr: *const c_char) -> FfiResult<Option<&'a str>> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller passes a NUL-terminated string that outlives the call.
    let s = unsafe { CStr::from_ptr(ptr) };
    s.to_str()
        .map(Some)
        .map_err(|_| FfiError::invalid("a string argument is not UTF-8"))
}

/// Borrows a required C string argument.
pub(crate) unsafe fn req_str<'a>(ptr: *const c_char, what: &str) -> FfiResult<&'a str> {
    // SAFETY: as `opt_str`.
    unsafe { opt_str(ptr) }?.ok_or_else(|| FfiError::invalid(format!("{what} is null")))
}

/// Borrows a byte argument; a null pointer is only accepted with length 0.
pub(crate) unsafe fn bytes_arg<'a>(ptr: *const u8, len: usize) -> FfiResult<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FfiError::invalid("a null buffer with a non-zero length"));
    }
    // SAFETY: the caller passes `len` readable bytes that outlive the call.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Hands a string to the caller through `out`, to be freed with [`rtc_string_free`].
pub(crate) unsafe fn give_string(out: *mut *mut c_char, s: String) -> FfiResult {
    if out.is_null() {
        return Err(FfiError::invalid("the output pointer is null"));
    }
    let c = CString::new(s).map_err(|_| FfiError::invalid("a string with a NUL byte"))?;
    object_created();
    // SAFETY: `out` is a valid pointer to a `char *` (checked non-null above).
    unsafe { *out = c.into_raw() };
    Ok(RTC_OK)
}

/// Copies `data` into the caller's buffer `buf` of `cap` bytes and writes its length to
/// `out_len`. `RTC_ERR_BUFFER_TOO_SMALL` (with the length needed) when it does not fit.
pub(crate) unsafe fn copy_out(data: &[u8], buf: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    if !out_len.is_null() {
        // SAFETY: a valid `size_t *` (checked non-null).
        unsafe { *out_len = data.len() };
    }
    if data.len() > cap || (!data.is_empty() && buf.is_null()) {
        return RTC_ERR_BUFFER_TOO_SMALL;
    }
    if !data.is_empty() {
        // SAFETY: `buf` has room for `cap >= data.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf, data.len()) };
    }
    RTC_OK
}

/// The version of this C interface ([`RTC_ABI_VERSION`]).
#[unsafe(no_mangle)]
pub extern "C" fn rtc_abi_version() -> u32 {
    RTC_ABI_VERSION
}

/// The library's version, a static NUL-terminated string (not to be freed).
#[unsafe(no_mangle)]
pub extern "C" fn rtc_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Copies the description of this thread's last error into `buf` (NUL-terminated, truncated to
/// `cap`) and returns its full length without the NUL. 0 when there was none. `buf` may be null
/// with `cap` 0 to ask for the length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_last_error(buf: *mut c_char, cap: usize) -> usize {
    catch_unwind(|| {
        LAST_ERROR.with(|last| {
            let last = last.borrow();
            let bytes = last.as_bytes();
            if !buf.is_null() && cap > 0 {
                let n = bytes.len().min(cap - 1);
                // SAFETY: `buf` has room for `cap` bytes; `n + 1 <= cap`.
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), n);
                    *buf.add(n) = 0;
                }
            }
            bytes.len()
        })
    })
    .unwrap_or(0)
}

/// Frees a string the library returned through a `char **out` argument. Null is ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtc_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `s` came from `CString::into_raw` in `give_string` and is freed once.
        drop(unsafe { CString::from_raw(s) });
        object_freed();
    }));
}

/// The number of objects (handles and strings) the library handed out that were not freed yet.
/// For leak checks in tests; 0 when everything was freed.
#[unsafe(no_mangle)]
pub extern "C" fn rtc_debug_live_objects() -> i64 {
    LIVE_OBJECTS.load(Ordering::SeqCst)
}
