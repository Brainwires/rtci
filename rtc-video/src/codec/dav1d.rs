//! AV1 decode with libdav1d (feature `dav1d`), the decoder the browsers ship: C and assembly,
//! BSD-2-Clause, **loaded at run time** (`dlopen`), so building this feature needs no library
//! and no C toolchain; running it needs libdav1d installed (Debian / Ubuntu: `libdav1d7`;
//! macOS: Homebrew `dav1d`; Windows: `dav1d.dll` beside the application).
//!
//! The binding is written here from dav1d's public headers at API version 7 (dav1d 1.x; checked
//! against 1.5.3): [`Dav1dDecoder`] refuses a library whose `dav1d_version_api()` has another
//! major version, so a layout change cannot be read as garbage. docs/video-pipeline.md 4.9 has
//! the measurements (identity with rav1d, speed, hostile input).
//!
//! A C decoder can crash outright on input its authors did not foresee; `codec::isolated`
//! (feature `isolation`) contains that, as it contains rav1d's abort.

use std::ffi::{OsStr, c_char, c_int, c_uint, c_void};
use std::ptr::NonNull;
use std::sync::Arc;

use libloading::Library;

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::frame::EncodedFrame;
use crate::picture::{I420, I420Buffer};

/// The API major version this binding is written for (`DAV1D_API_VERSION_MAJOR`).
pub const API_MAJOR: u32 = 7;

/// The largest picture the decoder accepts by default (`frame_size_limit`): 1920x1088.
pub const DEFAULT_MAX_PIXELS: u32 = 1920 * 1088;

/// The library names tried by [`Dav1dDecoder::new`], in order.
#[cfg(target_os = "macos")]
pub const LIBRARY_NAMES: &[&str] = &[
    "libdav1d.7.dylib",
    "/opt/homebrew/lib/libdav1d.7.dylib",
    "/usr/local/lib/libdav1d.7.dylib",
];
/// The library names tried by [`Dav1dDecoder::new`], in order.
#[cfg(target_os = "windows")]
pub const LIBRARY_NAMES: &[&str] = &["dav1d.dll", "libdav1d.dll"];
/// The library names tried by [`Dav1dDecoder::new`], in order.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub const LIBRARY_NAMES: &[&str] = &["libdav1d.so.7"];

// The structures of dav1d.h, data.h, picture.h and common.h at API version 7.

#[repr(C)]
#[derive(Clone, Copy)]
struct UserData {
    data: *const u8,
    r#ref: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DataProps {
    timestamp: i64,
    duration: i64,
    offset: i64,
    size: usize,
    user_data: UserData,
}

#[repr(C)]
struct Data {
    data: *const u8,
    sz: usize,
    r#ref: *mut c_void,
    m: DataProps,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PictureParameters {
    w: c_int,
    h: c_int,
    layout: c_int,
    bpc: c_int,
}

#[repr(C)]
struct Picture {
    seq_hdr: *mut c_void,
    frame_hdr: *mut c_void,
    data: [*mut c_void; 3],
    stride: [isize; 2],
    p: PictureParameters,
    m: DataProps,
    content_light: *mut c_void,
    mastering_display: *mut c_void,
    itut_t35: *mut c_void,
    n_itut_t35: usize,
    reserved: [usize; 4],
    frame_hdr_ref: *mut c_void,
    seq_hdr_ref: *mut c_void,
    content_light_ref: *mut c_void,
    mastering_display_ref: *mut c_void,
    itut_t35_ref: *mut c_void,
    reserved_ref: [usize; 4],
    r#ref: *mut c_void,
    allocator_data: *mut c_void,
}

#[repr(C)]
struct PicAllocator {
    cookie: *mut c_void,
    alloc: *mut c_void,
    release: *mut c_void,
}

#[repr(C)]
struct Logger {
    cookie: *mut c_void,
    callback: *mut c_void,
}

#[repr(C)]
struct Settings {
    n_threads: c_int,
    max_frame_delay: c_int,
    apply_grain: c_int,
    operating_point: c_int,
    all_layers: c_int,
    frame_size_limit: c_uint,
    allocator: PicAllocator,
    logger: Logger,
    strict_std_compliance: c_int,
    output_invisible_frames: c_int,
    inloop_filters: c_int,
    decode_frame_type: c_int,
    reserved: [u8; 16],
}

/// `DAV1D_PIXEL_LAYOUT_I420` (headers.h).
const LAYOUT_I420: c_int = 1;

type Context = c_void;

/// The library and the functions this binding uses, resolved once.
struct Api {
    version: unsafe extern "C" fn() -> *const c_char,
    default_settings: unsafe extern "C" fn(*mut Settings),
    open: unsafe extern "C" fn(*mut *mut Context, *const Settings) -> c_int,
    send_data: unsafe extern "C" fn(*mut Context, *mut Data) -> c_int,
    get_picture: unsafe extern "C" fn(*mut Context, *mut Picture) -> c_int,
    picture_unref: unsafe extern "C" fn(*mut Picture),
    data_create: unsafe extern "C" fn(*mut Data, usize) -> *mut u8,
    data_unref: unsafe extern "C" fn(*mut Data),
    close: unsafe extern "C" fn(*mut *mut Context),
    // Last: the functions above point into it.
    _lib: Library,
}

/// Resolves `name` as a function pointer of type `T`.
///
/// # Safety
///
/// `T` must be the function's true type.
unsafe fn symbol<T: Copy>(lib: &Library, name: &[u8]) -> Result<T, DecodeError> {
    // SAFETY: the caller states the type.
    unsafe { lib.get::<T>(name) }
        .map(|s| *s)
        .map_err(|e| DecodeError::Corrupt(format!("libdav1d: {e}")))
}

impl Api {
    fn load(path: &OsStr) -> Result<Self, DecodeError> {
        // SAFETY: loading a library runs its initialisers; libdav1d's are dav1d's own.
        let lib = unsafe { Library::new(path) }
            .map_err(|e| DecodeError::Corrupt(format!("libdav1d: {e}")))?;
        // SAFETY: the declaration in dav1d.h.
        let version_api: unsafe extern "C" fn() -> c_uint =
            unsafe { symbol(&lib, b"dav1d_version_api\0")? };
        // SAFETY: no arguments, returns a number.
        let v = unsafe { version_api() };
        if (v >> 16) & 0xff != API_MAJOR {
            return Err(DecodeError::Corrupt(format!(
                "libdav1d API version {}.{}.{}, this binding needs {API_MAJOR}.x",
                (v >> 16) & 0xff,
                (v >> 8) & 0xff,
                v & 0xff
            )));
        }
        // SAFETY: each type below is the declaration in dav1d.h, data.h or picture.h at API 7.
        unsafe {
            Ok(Self {
                version: symbol(&lib, b"dav1d_version\0")?,
                default_settings: symbol(&lib, b"dav1d_default_settings\0")?,
                open: symbol(&lib, b"dav1d_open\0")?,
                send_data: symbol(&lib, b"dav1d_send_data\0")?,
                get_picture: symbol(&lib, b"dav1d_get_picture\0")?,
                picture_unref: symbol(&lib, b"dav1d_picture_unref\0")?,
                data_create: symbol(&lib, b"dav1d_data_create\0")?,
                data_unref: symbol(&lib, b"dav1d_data_unref\0")?,
                close: symbol(&lib, b"dav1d_close\0")?,
                _lib: lib,
            })
        }
    }
}

/// The AV1 decoder on libdav1d: one thread, no frame delay (each temporal unit's picture comes
/// out of the call that took it), the highest spatial layer only, 8-bit 4:2:0 output.
pub struct Dav1dDecoder {
    api: Arc<Api>,
    ctx: NonNull<Context>,
    name: String,
    last: I420Buffer,
    has_picture: bool,
    need_key_frame: bool,
}

// SAFETY: the context is used through `&mut self` only; dav1d allows a context to move between
// threads.
unsafe impl Send for Dav1dDecoder {}

impl Dav1dDecoder {
    /// A decoder on the first of [`LIBRARY_NAMES`] that loads, accepting pictures up to
    /// [`DEFAULT_MAX_PIXELS`].
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] when no libdav1d with API version 7 loads, or the decoder does
    /// not open.
    pub fn new() -> Result<Self, DecodeError> {
        let mut last = DecodeError::Corrupt("libdav1d: no library name".into());
        for name in LIBRARY_NAMES {
            match Self::with_library(name, DEFAULT_MAX_PIXELS) {
                Ok(d) => return Ok(d),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// A decoder on the library at `path` (a file name the platform's loader searches, or a
    /// path), accepting pictures up to `max_pixels`.
    ///
    /// # Errors
    ///
    /// As [`Dav1dDecoder::new`].
    pub fn with_library(path: impl AsRef<OsStr>, max_pixels: u32) -> Result<Self, DecodeError> {
        let api = Arc::new(Api::load(path.as_ref())?);
        let mut s = std::mem::MaybeUninit::<Settings>::zeroed();
        // SAFETY: `s` is valid to write a `Dav1dSettings` to.
        unsafe { (api.default_settings)(s.as_mut_ptr()) };
        // SAFETY: initialised by dav1d_default_settings.
        let mut s = unsafe { s.assume_init() };
        s.n_threads = 1;
        s.max_frame_delay = 1;
        s.frame_size_limit = max_pixels;
        s.all_layers = 0;
        let mut ctx: *mut Context = std::ptr::null_mut();
        // SAFETY: both pointers are valid.
        let r = unsafe { (api.open)(&mut ctx, &s) };
        let ctx = NonNull::new(ctx)
            .filter(|_| r == 0)
            .ok_or_else(|| DecodeError::Corrupt(format!("dav1d_open failed: {r}")))?;
        // SAFETY: returns a static NUL-terminated string.
        let version = unsafe { std::ffi::CStr::from_ptr((api.version)()) }
            .to_string_lossy()
            .into_owned();
        Ok(Self {
            api,
            ctx,
            name: format!("libdav1d {version}"),
            last: I420Buffer::default(),
            has_picture: false,
            need_key_frame: true,
        })
    }

    /// Decodes one temporal unit (its OBUs, low-overhead format).
    ///
    /// # Errors
    ///
    /// [`DecodeError::NeedKeyFrame`] for a delta frame before a key frame or after an error;
    /// [`DecodeError::Corrupt`] for data that does not decode.
    pub fn decode_bytes(
        &mut self,
        data: &[u8],
        keyframe: bool,
    ) -> Result<Option<DecodedPicture>, DecodeError> {
        if self.need_key_frame && !keyframe {
            return Err(DecodeError::NeedKeyFrame);
        }
        let result = self.decode_inner(data);
        match &result {
            Ok(_) => self.need_key_frame = false,
            Err(_) => {
                self.need_key_frame = true;
                self.has_picture = false;
            }
        }
        result
    }

    fn eagain() -> c_int {
        -libc::EAGAIN
    }

    fn decode_inner(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::Corrupt("empty temporal unit".into()));
        }
        let api = Arc::clone(&self.api);
        let mut buf = OwnedData::new(&api, data)?;
        let mut picture = None;
        let mut status = 0;
        for _ in 0..4 {
            // SAFETY: the context is open; `buf.data` is valid.
            status = unsafe { (api.send_data)(self.ctx.as_ptr(), &mut buf.data) };
            if status != Self::eagain() {
                break;
            }
            // A picture waiting here belongs to an earlier temporal unit; if it fails to
            // decode (dav1d reports a frame's error when it is taken out), that is the earlier
            // unit's error, not this one's: keep sending this unit.
            match self.take_picture() {
                Ok(Some(p)) => picture = Some(p),
                Ok(None) => {}
                Err(e) => log::debug!("an earlier temporal unit did not decode: {e}"),
            }
        }
        drop(buf);
        if status != 0 && status != Self::eagain() {
            return Err(DecodeError::Corrupt(format!("dav1d_send_data: {status}")));
        }
        if let Some(p) = self.take_picture()? {
            picture = Some(p);
        }
        Ok(picture)
    }

    fn take_picture(&mut self) -> Result<Option<DecodedPicture>, DecodeError> {
        // SAFETY: an all-zero Dav1dPicture is the empty picture dav1d expects to fill.
        let mut p: Picture = unsafe { std::mem::zeroed() };
        // SAFETY: the context is open; `p` is valid to write to.
        let r = unsafe { (self.api.get_picture)(self.ctx.as_ptr(), &mut p) };
        if r == Self::eagain() {
            return Ok(None);
        }
        if r != 0 {
            return Err(DecodeError::Corrupt(format!("dav1d_get_picture: {r}")));
        }
        let out = self.copy_picture(&p);
        // SAFETY: `p` holds a picture from dav1d_get_picture, released once.
        unsafe { (self.api.picture_unref)(&mut p) };
        out.map(Some)
    }

    fn copy_picture(&mut self, p: &Picture) -> Result<DecodedPicture, DecodeError> {
        if p.p.bpc != 8 || p.p.layout != LAYOUT_I420 {
            return Err(DecodeError::Corrupt(format!(
                "unsupported picture format: {} bits, layout {}",
                p.p.bpc, p.p.layout
            )));
        }
        let (w, h) = (p.p.w.max(0) as usize, p.p.h.max(0) as usize);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let (ys, uvs) = (p.stride[0], p.stride[1]);
        if w == 0 || h == 0 || p.data.iter().any(|d| d.is_null()) {
            return Err(DecodeError::Corrupt("picture without planes".into()));
        }
        if ys < w as isize || uvs < cw as isize {
            return Err(DecodeError::Corrupt("picture strides too small".into()));
        }
        let (ys, uvs) = (ys as usize, uvs as usize);
        // SAFETY: an 8-bit 4:2:0 dav1d picture has `h` luma rows of `ys` bytes and `ch` rows of
        // `uvs` bytes per chroma plane (strides checked above), valid until it is unreferenced,
        // which happens after this copy.
        let (y, u, v) = unsafe {
            (
                std::slice::from_raw_parts(p.data[0].cast::<u8>(), (h - 1) * ys + w),
                std::slice::from_raw_parts(p.data[1].cast::<u8>(), (ch - 1) * uvs + cw),
                std::slice::from_raw_parts(p.data[2].cast::<u8>(), (ch - 1) * uvs + cw),
            )
        };
        self.last.copy_from(&I420 {
            width: w as u32,
            height: h as u32,
            y,
            u,
            v,
            y_stride: ys,
            uv_stride: uvs,
        });
        self.has_picture = true;
        Ok(DecodedPicture {
            width: w as u32,
            height: h as u32,
            qp: None,
        })
    }
}

/// One temporal unit's data in a dav1d buffer, released on drop unless the decoder took it.
struct OwnedData<'a> {
    api: &'a Api,
    data: Data,
}

impl<'a> OwnedData<'a> {
    fn new(api: &'a Api, bytes: &[u8]) -> Result<Self, DecodeError> {
        // SAFETY: an all-zero Dav1dData is the empty buffer dav1d_data_create fills.
        let mut data: Data = unsafe { std::mem::zeroed() };
        // SAFETY: `data` is valid to write to.
        let ptr = unsafe { (api.data_create)(&mut data, bytes.len()) };
        if ptr.is_null() {
            return Err(DecodeError::Corrupt("dav1d_data_create failed".into()));
        }
        // SAFETY: `ptr` points to `bytes.len()` fresh bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
        Ok(Self { api, data })
    }
}

impl Drop for OwnedData<'_> {
    fn drop(&mut self) {
        if self.data.sz > 0 {
            // SAFETY: the buffer came from dav1d_data_create and still holds its data.
            unsafe { (self.api.data_unref)(&mut self.data) };
        }
    }
}

impl Drop for Dav1dDecoder {
    fn drop(&mut self) {
        let mut ctx = self.ctx.as_ptr();
        // SAFETY: the context came from dav1d_open and is closed once.
        unsafe { (self.api.close)(&mut ctx) };
    }
}

impl VideoDecoder for Dav1dDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        self.decode_bytes(frame.data(), frame.is_keyframe())
    }

    fn picture(&self) -> Option<I420<'_>> {
        self.has_picture.then(|| self.last.view())
    }

    fn implementation_name(&self) -> &str {
        &self.name
    }
}
