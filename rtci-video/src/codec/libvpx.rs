//! VP8 and VP9 decode and encode with libvpx (feature `libvpx`), the reference implementation:
//! C and assembly, BSD-3-Clause, **loaded at run time** (`dlopen`), so building this feature
//! needs no library and no C toolchain; running it needs libvpx 1.12.0 to 1.17.0 installed
//! (Ubuntu 24.04: `libvpx9`, 1.14.0; Ubuntu 26.04: `libvpx12`, 1.16.0; macOS: Homebrew
//! `libvpx`; Windows: `vpx.dll`).
//!
//! The binding is written here from libvpx's public headers. Every context is created through
//! `vpx_codec_dec_init_ver` / `vpx_codec_enc_init_ver` with an ABI version, which libvpx
//! compares with its own and refuses (`VPX_CODEC_ABI_MISMATCH`) when they differ. libvpx raises
//! its encoder ABI version in nearly every release (30 in 1.13, 34 in 1.14, 36 / 37 in 1.15, 39
//! in 1.16 and 1.17), mostly for structures this binding never touches (the external rate
//! control and TPL interfaces), so one number works with one release only. The binding
//! therefore passes the encoder ABI version of the release that loaded, from
//! [`ENCODER_ABI_VERSIONS`], and only for releases whose headers were compared with this
//! binding: every structure, enumeration, constant and function type it uses is the same in
//! libvpx 1.12.0 to 1.17.0 (the one difference, a field added to the PSNR packet in 1.16.0,
//! is inside a union of fixed size the binding does not read). Any other release is refused
//! before a structure is handed to it, with the release named. The decoder's ABI version is 12
//! in all of them ([`DECODER_ABI_VERSION`]); libvpx's own check guards it on any release. The encoder runs libvpx's real-time path (one pass, CBR, no look-ahead,
//! error resilient, key frames on request only), with libwebrtc's buffer and quantizer settings
//! (`modules/video_coding/codecs/vp8/libvpx_vp8_encoder.cc @ a222406d`).
//!
//! A C decoder can crash outright on hostile input; `codec::isolated` (feature `isolation`)
//! contains that.

use std::ffi::{CStr, OsStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::sync::Arc;

use libloading::Library;

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::encoder::{EncodeError, EncodedPicture, VideoEncoder};
use crate::frame::EncodedFrame;
use crate::picture::{I420, I420Buffer};

/// `VPX_DECODER_ABI_VERSION` of the headers this binding follows (3 + 4 + 5).
pub const DECODER_ABI_VERSION: c_int = 12;
/// `VPX_ENCODER_ABI_VERSION` of libvpx 1.16.0's headers (18 + 9 + 7 + 5).
pub const ENCODER_ABI_VERSION: c_int = 39;

/// `VPX_ENCODER_ABI_VERSION` of each libvpx release whose headers were compared with this
/// binding (`vpx/vpx_encoder.h`, `vpx_codec.h`, `vpx_ext_ratectrl.h`, `vpx_tpl.h` at the
/// release's tag): (major, minor, patch) and the number. The encoder refuses any other release.
/// 15 + 9 + 1 (1.12); 15 + 9 + 6 (1.13); 16 + 9 + 7 + 2 (1.14); 18 + 9 + (5 + 4) (1.15.0);
/// 18 + 9 + (6 + 4) (1.15.1, 1.15.2); 18 + 9 + (7 + 5) (1.16.0, 1.17.0).
pub const ENCODER_ABI_VERSIONS: &[((u8, u8, u8), c_int)] = &[
    ((1, 12, 0), 25),
    ((1, 13, 0), 30),
    ((1, 13, 1), 30),
    ((1, 14, 0), 34),
    ((1, 14, 1), 34),
    ((1, 15, 0), 36),
    ((1, 15, 1), 37),
    ((1, 15, 2), 37),
    ((1, 16, 0), 39),
    ((1, 17, 0), 39),
];

/// The encoder ABI version of libvpx `release` (major, minor, patch), if the binding was
/// checked against it.
#[must_use]
pub fn encoder_abi_version(release: (u8, u8, u8)) -> Option<c_int> {
    ENCODER_ABI_VERSIONS
        .iter()
        .find(|(r, _)| *r == release)
        .map(|(_, abi)| *abi)
}

/// The library names tried by [`VpxDecoder::new`] and [`VpxEncoder::new`], in order.
#[cfg(target_os = "macos")]
pub const LIBRARY_NAMES: &[&str] = &[
    "libvpx.dylib",
    "/opt/homebrew/lib/libvpx.dylib",
    "/usr/local/lib/libvpx.dylib",
];
/// The library names tried by [`VpxDecoder::new`] and [`VpxEncoder::new`], in order.
#[cfg(target_os = "windows")]
pub const LIBRARY_NAMES: &[&str] = &["vpx.dll", "libvpx.dll", "libvpx-1.dll"];
/// The library names tried by [`VpxDecoder::new`] and [`VpxEncoder::new`], in order.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub const LIBRARY_NAMES: &[&str] = &[
    "libvpx.so.12",
    "libvpx.so.11",
    "libvpx.so.10",
    "libvpx.so.9",
    "libvpx.so",
];

/// The codec of a libvpx context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpxCodec {
    /// VP8 (RFC 6386).
    Vp8,
    /// VP9.
    Vp9,
}

// vpx_image.h, vpx_codec.h, vpx_decoder.h, vpx_encoder.h (libvpx 1.16.0).

const IMG_FMT_I420: c_int = 0x100 | 2;
const SS_MAX_LAYERS: usize = 5;
const TS_MAX_LAYERS: usize = 5;
const TS_MAX_PERIODICITY: usize = 16;
const MAX_LAYERS: usize = 12;
const CX_FRAME_PKT: c_int = 0;
const FRAME_IS_KEY: u32 = 1;
const EFLAG_FORCE_KF: c_long = 1;
const DL_REALTIME: c_ulong = 1;
const RC_ONE_PASS: c_int = 0;
const CBR: c_int = 1;
const KF_DISABLED: c_int = 0;
const ERROR_RESILIENT_DEFAULT: u32 = 1;
const VP8E_SET_CPUUSED: c_int = 13;
const VP8E_SET_NOISE_SENSITIVITY: c_int = 15;
const VP8E_SET_STATIC_THRESHOLD: c_int = 17;
const VP9E_SET_ROW_MT: c_int = 55;

#[repr(C)]
struct Image {
    fmt: c_int,
    cs: c_int,
    range: c_int,
    w: c_uint,
    h: c_uint,
    bit_depth: c_uint,
    d_w: c_uint,
    d_h: c_uint,
    r_w: c_uint,
    r_h: c_uint,
    x_chroma_shift: c_uint,
    y_chroma_shift: c_uint,
    planes: [*mut u8; 4],
    stride: [c_int; 4],
    bps: c_int,
    user_priv: *mut c_void,
    img_data: *mut u8,
    img_data_owner: c_int,
    self_allocd: c_int,
    fb_priv: *mut c_void,
}

#[repr(C)]
struct CodecCtx {
    name: *const c_char,
    iface: *const c_void,
    err: c_int,
    err_detail: *const c_char,
    init_flags: c_long,
    config: *const c_void,
    private: *mut c_void,
}

#[repr(C)]
struct DecCfg {
    threads: c_uint,
    w: c_uint,
    h: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FixedBuf {
    buf: *mut c_void,
    sz: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rational {
    num: c_int,
    den: c_int,
}

#[repr(C)]
struct EncCfg {
    g_usage: c_uint,
    g_threads: c_uint,
    g_profile: c_uint,
    g_w: c_uint,
    g_h: c_uint,
    g_bit_depth: c_int,
    g_input_bit_depth: c_uint,
    g_timebase: Rational,
    g_error_resilient: u32,
    g_pass: c_int,
    g_lag_in_frames: c_uint,
    rc_dropframe_thresh: c_uint,
    rc_resize_allowed: c_uint,
    rc_scaled_width: c_uint,
    rc_scaled_height: c_uint,
    rc_resize_up_thresh: c_uint,
    rc_resize_down_thresh: c_uint,
    rc_end_usage: c_int,
    rc_twopass_stats_in: FixedBuf,
    rc_firstpass_mb_stats_in: FixedBuf,
    rc_target_bitrate: c_uint,
    rc_min_quantizer: c_uint,
    rc_max_quantizer: c_uint,
    rc_undershoot_pct: c_uint,
    rc_overshoot_pct: c_uint,
    rc_buf_sz: c_uint,
    rc_buf_initial_sz: c_uint,
    rc_buf_optimal_sz: c_uint,
    rc_2pass_vbr_bias_pct: c_uint,
    rc_2pass_vbr_minsection_pct: c_uint,
    rc_2pass_vbr_maxsection_pct: c_uint,
    rc_2pass_vbr_corpus_complexity: c_uint,
    kf_mode: c_int,
    kf_min_dist: c_uint,
    kf_max_dist: c_uint,
    ss_number_layers: c_uint,
    ss_enable_auto_alt_ref: [c_int; SS_MAX_LAYERS],
    ss_target_bitrate: [c_uint; SS_MAX_LAYERS],
    ts_number_layers: c_uint,
    ts_target_bitrate: [c_uint; TS_MAX_LAYERS],
    ts_rate_decimator: [c_uint; TS_MAX_LAYERS],
    ts_periodicity: c_uint,
    ts_layer_id: [c_uint; TS_MAX_PERIODICITY],
    layer_target_bitrate: [c_uint; MAX_LAYERS],
    temporal_layering_mode: c_int,
    use_vizier_rc_params: c_int,
    vizier: [Rational; 15],
}

#[repr(C)]
struct CxPktFrame {
    buf: *mut c_void,
    sz: usize,
    pts: i64,
    duration: c_ulong,
    flags: u32,
    partition_id: c_int,
}

#[repr(C)]
struct CxPkt {
    kind: c_int,
    // The union `data`: 8-byte aligned, the frame member first.
    frame: CxPktFrame,
}

type Iface = unsafe extern "C" fn() -> *const c_void;

/// A structure libvpx writes whole (`vpx_codec_enc_config_default`, `vpx_img_wrap`, the codec
/// context) with room after it: those writes happen before `*_init_ver` checks the ABI, so a
/// library whose structure grew must not write past the end of ours.
#[repr(C)]
struct Slack<T> {
    v: T,
    _pad: [u8; 1024],
}

impl<T> Slack<T> {
    fn zeroed() -> Box<Self> {
        // SAFETY: every type used here (C structures of integers and pointers) is valid all
        // zero.
        Box::new(unsafe { std::mem::zeroed() })
    }
}

struct Api {
    version_num: unsafe extern "C" fn() -> c_int,
    version_str: unsafe extern "C" fn() -> *const c_char,
    vp8_dx: Iface,
    vp9_dx: Iface,
    vp8_cx: Iface,
    vp9_cx: Iface,
    dec_init_ver:
        unsafe extern "C" fn(*mut CodecCtx, *const c_void, *const DecCfg, c_long, c_int) -> c_int,
    decode: unsafe extern "C" fn(*mut CodecCtx, *const u8, c_uint, *mut c_void, c_long) -> c_int,
    get_frame: unsafe extern "C" fn(*mut CodecCtx, *mut *const c_void) -> *const Image,
    enc_config_default: unsafe extern "C" fn(*const c_void, *mut EncCfg, c_uint) -> c_int,
    enc_init_ver:
        unsafe extern "C" fn(*mut CodecCtx, *const c_void, *const EncCfg, c_long, c_int) -> c_int,
    enc_config_set: unsafe extern "C" fn(*mut CodecCtx, *const EncCfg) -> c_int,
    encode:
        unsafe extern "C" fn(*mut CodecCtx, *const Image, i64, c_ulong, c_long, c_ulong) -> c_int,
    get_cx_data: unsafe extern "C" fn(*mut CodecCtx, *mut *const c_void) -> *const CxPkt,
    control: unsafe extern "C" fn(*mut CodecCtx, c_int, ...) -> c_int,
    img_wrap:
        unsafe extern "C" fn(*mut Image, c_int, c_uint, c_uint, c_uint, *mut u8) -> *mut Image,
    destroy: unsafe extern "C" fn(*mut CodecCtx) -> c_int,
    error: unsafe extern "C" fn(*const CodecCtx) -> *const c_char,
    _lib: Library,
}

/// # Safety
///
/// `T` must be the function's true type.
unsafe fn symbol<T: Copy>(lib: &Library, name: &[u8]) -> Result<T, String> {
    // SAFETY: the caller states the type.
    unsafe { lib.get::<T>(name) }
        .map(|s| *s)
        .map_err(|e| format!("libvpx: {e}"))
}

impl Api {
    fn load(path: &OsStr) -> Result<Self, String> {
        // SAFETY: loading a library runs its initialisers; libvpx's are libvpx's own.
        let lib = unsafe { Library::new(path) }.map_err(|e| format!("libvpx: {e}"))?;
        // SAFETY: each type is the declaration in libvpx 1.12.0 to 1.17.0's headers.
        unsafe {
            Ok(Self {
                version_num: symbol(&lib, b"vpx_codec_version\0")?,
                version_str: symbol(&lib, b"vpx_codec_version_str\0")?,
                vp8_dx: symbol(&lib, b"vpx_codec_vp8_dx\0")?,
                vp9_dx: symbol(&lib, b"vpx_codec_vp9_dx\0")?,
                vp8_cx: symbol(&lib, b"vpx_codec_vp8_cx\0")?,
                vp9_cx: symbol(&lib, b"vpx_codec_vp9_cx\0")?,
                dec_init_ver: symbol(&lib, b"vpx_codec_dec_init_ver\0")?,
                decode: symbol(&lib, b"vpx_codec_decode\0")?,
                get_frame: symbol(&lib, b"vpx_codec_get_frame\0")?,
                enc_config_default: symbol(&lib, b"vpx_codec_enc_config_default\0")?,
                enc_init_ver: symbol(&lib, b"vpx_codec_enc_init_ver\0")?,
                enc_config_set: symbol(&lib, b"vpx_codec_enc_config_set\0")?,
                encode: symbol(&lib, b"vpx_codec_encode\0")?,
                get_cx_data: symbol(&lib, b"vpx_codec_get_cx_data\0")?,
                control: symbol(&lib, b"vpx_codec_control_\0")?,
                img_wrap: symbol(&lib, b"vpx_img_wrap\0")?,
                destroy: symbol(&lib, b"vpx_codec_destroy\0")?,
                error: symbol(&lib, b"vpx_codec_error\0")?,
                _lib: lib,
            })
        }
    }

    fn load_any() -> Result<Self, String> {
        let mut last = String::from("libvpx: no library name");
        for name in LIBRARY_NAMES {
            match Self::load(OsStr::new(name)) {
                Ok(a) => return Ok(a),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The release that loaded: (major, minor, patch) of `vpx_codec_version()`.
    fn release(&self) -> (u8, u8, u8) {
        // SAFETY: takes nothing, returns an int.
        let v = unsafe { (self.version_num)() };
        (
            ((v >> 16) & 0xff) as u8,
            ((v >> 8) & 0xff) as u8,
            (v & 0xff) as u8,
        )
    }

    /// The encoder ABI version to pass this release, or why there is none.
    fn encoder_abi(&self) -> Result<c_int, String> {
        let release = self.release();
        encoder_abi_version(release).ok_or_else(|| {
            let (major, minor, patch) = release;
            format!(
                "libvpx {major}.{minor}.{patch} ({}): this binding's encoder structures were \
                 checked against libvpx 1.12.0 to 1.17.0 only, and libvpx changes its encoder ABI \
                 in nearly every release; refused rather than handed a layout it may not have",
                self.version()
            )
        })
    }

    fn version(&self) -> String {
        // SAFETY: returns a static NUL-terminated string.
        unsafe { CStr::from_ptr((self.version_str)()) }
            .to_string_lossy()
            .into_owned()
    }

    fn error_of(&self, ctx: &CodecCtx) -> String {
        // SAFETY: `ctx` is a context libvpx initialised (or tried to); returns a static string.
        let p = unsafe { (self.error)(ctx) };
        if p.is_null() {
            return "unknown error".into();
        }
        // SAFETY: non-null, NUL-terminated.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

fn zeroed_ctx() -> Box<Slack<CodecCtx>> {
    Slack::zeroed()
}

/// The VP8 or VP9 decoder on libvpx (one thread).
pub struct VpxDecoder {
    api: Arc<Api>,
    ctx: Box<Slack<CodecCtx>>,
    name: String,
    last: I420Buffer,
    has_picture: bool,
}

// SAFETY: the context is used through `&mut self` only; libvpx contexts may move between
// threads.
unsafe impl Send for VpxDecoder {}

impl VpxDecoder {
    /// A decoder for `codec` on the first of [`LIBRARY_NAMES`] that loads.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] when no libvpx loads or its ABI differs.
    pub fn new(codec: VpxCodec) -> Result<Self, DecodeError> {
        let api = Api::load_any().map_err(DecodeError::Corrupt)?;
        Self::with_api(Arc::new(api), codec)
    }

    /// A decoder for `codec` on the libvpx at `path`.
    ///
    /// # Errors
    ///
    /// As [`VpxDecoder::new`].
    pub fn with_library(path: impl AsRef<OsStr>, codec: VpxCodec) -> Result<Self, DecodeError> {
        let api = Api::load(path.as_ref()).map_err(DecodeError::Corrupt)?;
        Self::with_api(Arc::new(api), codec)
    }

    fn with_api(api: Arc<Api>, codec: VpxCodec) -> Result<Self, DecodeError> {
        let mut ctx = zeroed_ctx();
        let cfg = DecCfg {
            threads: 1,
            w: 0,
            h: 0,
        };
        // SAFETY: the interface functions take no arguments and return a static interface.
        let iface = unsafe {
            match codec {
                VpxCodec::Vp8 => (api.vp8_dx)(),
                VpxCodec::Vp9 => (api.vp9_dx)(),
            }
        };
        // SAFETY: `ctx` and `cfg` are valid; the ABI version is the headers'.
        let r = unsafe { (api.dec_init_ver)(&mut ctx.v, iface, &cfg, 0, DECODER_ABI_VERSION) };
        if r != 0 {
            return Err(DecodeError::Corrupt(format!(
                "vpx_codec_dec_init: {r} ({})",
                api.error_of(&ctx.v)
            )));
        }
        let name = format!(
            "libvpx {} ({})",
            api.version(),
            if codec == VpxCodec::Vp8 { "VP8" } else { "VP9" }
        );
        Ok(Self {
            api,
            ctx,
            name,
            last: I420Buffer::default(),
            has_picture: false,
        })
    }

    /// Decodes one frame (VP9: a superframe included).
    ///
    /// # Errors
    ///
    /// [`DecodeError::Corrupt`] for a frame libvpx refuses (libvpx asks for no key frame itself:
    /// a delta frame without its reference fails as corrupt).
    pub fn decode_bytes(&mut self, data: &[u8]) -> Result<Option<DecodedPicture>, DecodeError> {
        let len = c_uint::try_from(data.len())
            .map_err(|_| DecodeError::Corrupt("frame too large".into()))?;
        // SAFETY: the context is initialised; `data` is valid for `len` bytes.
        let r = unsafe {
            (self.api.decode)(&mut self.ctx.v, data.as_ptr(), len, std::ptr::null_mut(), 0)
        };
        if r != 0 {
            self.has_picture = false;
            return Err(DecodeError::Corrupt(format!(
                "vpx_codec_decode: {r} ({})",
                self.api.error_of(&self.ctx.v)
            )));
        }
        let mut iter: *const c_void = std::ptr::null();
        let mut out = None;
        loop {
            // SAFETY: the context is initialised; `iter` is the iteration state libvpx expects.
            let img = unsafe { (self.api.get_frame)(&mut self.ctx.v, &mut iter) };
            if img.is_null() {
                break;
            }
            // SAFETY: a non-null image from vpx_codec_get_frame is valid until the next call
            // into this context.
            let img = unsafe { &*img };
            out = Some(self.copy_image(img)?);
        }
        Ok(out)
    }

    fn copy_image(&mut self, img: &Image) -> Result<DecodedPicture, DecodeError> {
        if img.fmt != IMG_FMT_I420 || img.bit_depth != 8 {
            return Err(DecodeError::Corrupt(format!(
                "unsupported picture format {:#x}, {} bits",
                img.fmt, img.bit_depth
            )));
        }
        let (w, h) = (img.d_w as usize, img.d_h as usize);
        let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
        let (ys, us, vs) = (img.stride[0], img.stride[1], img.stride[2]);
        if w == 0 || h == 0 || img.planes[..3].iter().any(|p| p.is_null()) {
            return Err(DecodeError::Corrupt("picture without planes".into()));
        }
        if ys < w as c_int || us < cw as c_int || vs != us {
            return Err(DecodeError::Corrupt("picture strides".into()));
        }
        let (ys, uvs) = (ys as usize, us as usize);
        // SAFETY: an 8-bit I420 vpx_image_t has `d_h` luma rows of `stride[0]` bytes and
        // `(d_h + 1) / 2` rows of `stride[1]` bytes per chroma plane, valid until the next call
        // into the context (the copy happens first).
        let (y, u, v) = unsafe {
            (
                std::slice::from_raw_parts(img.planes[0], (h - 1) * ys + w),
                std::slice::from_raw_parts(img.planes[1], (ch - 1) * uvs + cw),
                std::slice::from_raw_parts(img.planes[2], (ch - 1) * uvs + cw),
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

impl Drop for VpxDecoder {
    fn drop(&mut self) {
        // SAFETY: the context was initialised and is destroyed once.
        unsafe { (self.api.destroy)(&mut self.ctx.v) };
    }
}

impl VideoDecoder for VpxDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError> {
        self.decode_bytes(frame.data())
    }

    fn picture(&self) -> Option<I420<'_>> {
        self.has_picture.then(|| self.last.view())
    }

    fn implementation_name(&self) -> &str {
        &self.name
    }
}

/// The VP8 or VP9 encoder on libvpx, real time: one pass, CBR, no look-ahead (each picture's
/// frame comes out of the call that took it), error resilient, key frames on request only, one
/// thread.
pub struct VpxEncoder {
    api: Arc<Api>,
    ctx: Box<Slack<CodecCtx>>,
    cfg: Box<Slack<EncCfg>>,
    name: String,
    frames_in: u64,
    /// One frame interval on the 90 kHz time base.
    pts_step: u64,
    /// The packed copy of the input picture libvpx reads (`vpx_img_wrap`).
    input: Vec<u8>,
}

// SAFETY: as `VpxDecoder`.
unsafe impl Send for VpxEncoder {}

impl VpxEncoder {
    /// An encoder for `codec` at `width` x `height`, `fps`, aiming at `bitrate_bps`, on the
    /// first of [`LIBRARY_NAMES`] that loads.
    ///
    /// # Errors
    ///
    /// [`EncodeError::InvalidConfig`] when no libvpx loads, it is a release the binding was not
    /// checked against ([`ENCODER_ABI_VERSIONS`]), or it refuses the settings.
    pub fn new(
        codec: VpxCodec,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
    ) -> Result<Self, EncodeError> {
        let api = Api::load_any().map_err(EncodeError::InvalidConfig)?;
        // Before any structure reaches the library: `vpx_codec_enc_config_default` writes one.
        let abi = api.encoder_abi().map_err(EncodeError::InvalidConfig)?;
        let api = Arc::new(api);
        // SAFETY: the interface functions take no arguments and return a static interface.
        let iface = unsafe {
            match codec {
                VpxCodec::Vp8 => (api.vp8_cx)(),
                VpxCodec::Vp9 => (api.vp9_cx)(),
            }
        };
        let mut slack = Slack::<EncCfg>::zeroed();
        // SAFETY: `slack` is valid to write a configuration to, with room to spare.
        let r = unsafe { (api.enc_config_default)(iface, &mut slack.v, 0) };
        if r != 0 {
            return Err(EncodeError::InvalidConfig(format!(
                "vpx_codec_enc_config_default: {r}"
            )));
        }
        let cfg = &mut slack.v;
        cfg.g_w = width;
        cfg.g_h = height;
        cfg.g_threads = 1;
        cfg.g_timebase = Rational {
            num: 1,
            den: 90_000,
        };
        cfg.g_pass = RC_ONE_PASS;
        cfg.g_lag_in_frames = 0;
        cfg.g_error_resilient = ERROR_RESILIENT_DEFAULT;
        cfg.rc_end_usage = CBR;
        cfg.rc_target_bitrate = (bitrate_bps / 1000).max(1);
        cfg.rc_dropframe_thresh = 0;
        cfg.rc_resize_allowed = 0;
        // libvpx_vp8_encoder.cc: min / max QP 2 / 56, undershoot 100 %, overshoot 15 %, buffer
        // 1000 ms, initial 500 ms, optimal 600 ms.
        cfg.rc_min_quantizer = 2;
        cfg.rc_max_quantizer = 56;
        cfg.rc_undershoot_pct = 100;
        cfg.rc_overshoot_pct = 15;
        cfg.rc_buf_sz = 1000;
        cfg.rc_buf_initial_sz = 500;
        cfg.rc_buf_optimal_sz = 600;
        cfg.kf_mode = KF_DISABLED;
        let mut ctx = zeroed_ctx();
        // SAFETY: `ctx` and `cfg` are valid; `abi` is the loaded release's, whose structures are
        // this binding's (`ENCODER_ABI_VERSIONS`).
        let r = unsafe { (api.enc_init_ver)(&mut ctx.v, iface, &slack.v, 0, abi) };
        if r != 0 {
            return Err(EncodeError::InvalidConfig(format!(
                "vpx_codec_enc_init: {r} ({})",
                api.error_of(&ctx.v)
            )));
        }
        // SAFETY: the context is initialised; each control takes an int.
        unsafe {
            match codec {
                VpxCodec::Vp8 => {
                    (api.control)(&mut ctx.v, VP8E_SET_CPUUSED, -6 as c_int);
                    (api.control)(&mut ctx.v, VP8E_SET_NOISE_SENSITIVITY, 0 as c_uint);
                    (api.control)(&mut ctx.v, VP8E_SET_STATIC_THRESHOLD, 1 as c_uint);
                }
                VpxCodec::Vp9 => {
                    (api.control)(&mut ctx.v, VP8E_SET_CPUUSED, 7 as c_int);
                    (api.control)(&mut ctx.v, VP9E_SET_ROW_MT, 0 as c_uint);
                }
            }
        }
        let name = format!(
            "libvpx {} ({})",
            api.version(),
            if codec == VpxCodec::Vp8 { "VP8" } else { "VP9" }
        );
        Ok(Self {
            api,
            ctx,
            cfg: slack,
            name,
            frames_in: 0,
            pts_step: u64::from(90_000 / fps.max(1)),
            input: Vec::new(),
        })
    }
}

impl Drop for VpxEncoder {
    fn drop(&mut self) {
        // SAFETY: the context was initialised and is destroyed once.
        unsafe { (self.api.destroy)(&mut self.ctx.v) };
    }
}

impl VideoEncoder for VpxEncoder {
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError> {
        if picture.width != self.cfg.v.g_w
            || picture.height != self.cfg.v.g_h
            || !picture.is_valid()
        {
            return Err(EncodeError::InvalidPicture(format!(
                "{}x{} for a {}x{} encoder",
                picture.width, picture.height, self.cfg.v.g_w, self.cfg.v.g_h
            )));
        }
        self.input.clear();
        for row in picture.rows() {
            self.input.extend_from_slice(row);
        }
        let mut img = Slack::<Image>::zeroed();
        // SAFETY: `input` holds a packed I420 picture of the encoder's size (stride alignment
        // 1), alive until vpx_codec_encode returns.
        let wrapped = unsafe {
            (self.api.img_wrap)(
                &mut img.v,
                IMG_FMT_I420,
                picture.width,
                picture.height,
                1,
                self.input.as_mut_ptr(),
            )
        };
        if wrapped.is_null() {
            return Err(EncodeError::Failed("vpx_img_wrap failed".into()));
        }
        let source_index = self.frames_in;
        self.frames_in += 1;
        let pts = (source_index * self.pts_step) as i64;
        let flags = if keyframe || source_index == 0 {
            EFLAG_FORCE_KF
        } else {
            0
        };
        // SAFETY: the context is initialised; `img` describes `input`.
        let r = unsafe {
            (self.api.encode)(
                &mut self.ctx.v,
                &img.v,
                pts,
                self.pts_step as c_ulong,
                flags,
                DL_REALTIME,
            )
        };
        if r != 0 {
            return Err(EncodeError::Failed(format!(
                "vpx_codec_encode: {r} ({})",
                self.api.error_of(&self.ctx.v)
            )));
        }
        let mut iter: *const c_void = std::ptr::null();
        let mut out: Option<EncodedPicture> = None;
        loop {
            // SAFETY: the context is initialised; `iter` is the iteration state.
            let pkt = unsafe { (self.api.get_cx_data)(&mut self.ctx.v, &mut iter) };
            if pkt.is_null() {
                break;
            }
            // SAFETY: a packet is valid until the next call into the context.
            let pkt = unsafe { &*pkt };
            if pkt.kind != CX_FRAME_PKT {
                continue;
            }
            // SAFETY: a frame packet's buffer holds `sz` bytes.
            let bytes =
                unsafe { std::slice::from_raw_parts(pkt.frame.buf.cast::<u8>(), pkt.frame.sz) };
            let key = pkt.frame.flags & FRAME_IS_KEY != 0;
            match &mut out {
                Some(o) => {
                    o.data.extend_from_slice(bytes);
                    o.keyframe |= key;
                }
                None => {
                    out = Some(EncodedPicture {
                        source_index,
                        keyframe: key,
                        temporal_id: 0,
                        qp: None,
                        data: bytes.to_vec(),
                    })
                }
            }
        }
        Ok(out)
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) {
        let kbps = (bitrate_bps / 1000).max(1);
        if kbps == self.cfg.v.rc_target_bitrate {
            return;
        }
        self.cfg.v.rc_target_bitrate = kbps;
        // SAFETY: the context is initialised; `cfg` is the configuration it was made with.
        let _ = unsafe { (self.api.enc_config_set)(&mut self.ctx.v, &self.cfg.v) };
    }

    fn implementation_name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_encoder_abi_version_is_the_loaded_releases() {
        // libvpx 1.14.0 (Ubuntu 24.04) is 34: passing 1.16's 39 there failed every encoder
        // with VPX_CODEC_ABI_MISMATCH (cargo run 46148529023).
        assert_eq!(encoder_abi_version((1, 14, 0)), Some(34));
        assert_eq!(encoder_abi_version((1, 16, 0)), Some(ENCODER_ABI_VERSION));
        assert_eq!(encoder_abi_version((1, 17, 0)), Some(39));
        assert_eq!(encoder_abi_version((1, 15, 0)), Some(36));
        assert_eq!(encoder_abi_version((1, 15, 2)), Some(37));
    }

    #[test]
    fn a_release_the_binding_was_not_checked_against_has_no_encoder_abi_version() {
        assert_eq!(encoder_abi_version((1, 11, 0)), None);
        assert_eq!(encoder_abi_version((1, 16, 1)), None);
        assert_eq!(encoder_abi_version((1, 18, 0)), None);
    }
}
