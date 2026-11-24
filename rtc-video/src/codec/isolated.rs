//! A decoder in a child process (feature `isolation`): when the decoder crashes, aborts or
//! hangs on a hostile frame, the child dies and the application gets a [`DecodeError`] for that
//! frame instead of dying with it.
//!
//! This is the containment for decoders whose failures cannot be caught in process: rav1d 1.1.0
//! aborts the process on a malformed frame (a panic inside its `extern "C"` API, which cannot
//! unwind), and a C decoder (libvpx, dav1d, OpenH264) can crash outright. A pure-Rust decoder
//! that panics normally needs none of this (`codec::vp8` catches its panics).
//!
//! The application decides which program runs the decoder: usually its own executable,
//! started with an argument or environment variable that makes `main` call [`serve`] with the
//! decoder for the codec, so no extra binary ships:
//!
//! ```no_run
//! # #[cfg(feature = "av1")] {
//! use rtc_video::codec::av1::Av1Decoder;
//! use rtc_video::codec::isolated::{IsolatedDecoder, serve};
//! use rtc_video::frame::Codec;
//!
//! // In main(), first thing:
//! if std::env::var_os("MYAPP_AV1_DECODER").is_some() {
//!     let mut decoder = Av1Decoder::new().expect("decoder");
//!     let (stdin, stdout) = (std::io::stdin().lock(), std::io::stdout().lock());
//!     let _ = serve(&mut decoder, Codec::Av1, stdin, stdout, std::time::Instant::now());
//!     std::process::exit(0);
//! }
//! // Where the pipeline needs an AV1 decoder:
//! let mut command = std::process::Command::new(std::env::current_exe().unwrap());
//! command.env("MYAPP_AV1_DECODER", "1");
//! let decoder = IsolatedDecoder::new(command, "rav1d (isolated)");
//! # }
//! ```
//!
//! The child starts on the first frame and again on the frame after it died; a new child needs
//! a key frame (its decoder answers [`DecodeError::NeedKeyFrame`] until one comes, which the
//! pipeline turns into a key-frame request). Each frame costs two copies through a pipe and a
//! context switch, small next to decoding it. This module spawns a process and a reader thread:
//! it is the one part of the crate that does I/O, and only when the application creates an
//! [`IsolatedDecoder`].
//!
//! Protocol (little-endian), on the child's standard input and output: the child first writes
//! [`MAGIC`] (anything the child printed before it is skipped); a request is `u32` length, `u8`
//! flags (bit 0: key frame), the bitstream; a reply is a `u8` kind (0: no picture, 1: picture,
//! 2: key frame needed, 3: corrupt) followed, for 1, by width, height, QP + 1 (0 when unknown),
//! and the packed I420 picture as `u32` width, `u32` height, `u32` length, bytes (length 0 when
//! the decoder keeps no pixels); for 3, by `u32` length and the message.

use std::ffi::OsString;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::decoder::{DecodeError, DecodedPicture, VideoDecoder};
use crate::frame::{AssembledFrame, Codec, CodecHeader, EncodedFrame};
use crate::picture::{I420, I420Buffer};

/// What a child writes first on its standard output.
pub const MAGIC: &[u8; 8] = b"RTCVDEC1";

/// How long a frame may take in the child by default before it is taken as hung and killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// The largest frame or picture the protocol carries (a guard against a garbled stream).
const MAX_MESSAGE: usize = 64 << 20;

/// One reply from the child.
enum Reply {
    Picture(DecodedPicture, Option<I420Buffer>),
    NoPicture,
    NeedKeyFrame,
    Corrupt(String),
}

struct Running {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    replies: Receiver<io::Result<Reply>>,
}

/// A [`VideoDecoder`] that runs another decoder in a child process (see the module
/// documentation).
pub struct IsolatedDecoder {
    program: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(OsString, Option<OsString>)>,
    current_dir: Option<PathBuf>,
    name: String,
    timeout: Duration,
    running: Option<Running>,
    last: I420Buffer,
    has_picture: bool,
    restarts: u64,
}

impl IsolatedDecoder {
    /// A decoder that runs `command` (whose program calls [`serve`]) for its child, named
    /// `name` (W3C `decoderImplementation`). Nothing starts until the first frame. The child's
    /// standard input and output are the protocol's; its standard error is inherited.
    pub fn new(command: Command, name: &str) -> Self {
        Self {
            program: PathBuf::from(command.get_program()),
            args: command.get_args().map(OsString::from).collect(),
            envs: command
                .get_envs()
                .map(|(k, v)| (k.to_owned(), v.map(OsString::from)))
                .collect(),
            current_dir: command.get_current_dir().map(PathBuf::from),
            name: name.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            running: None,
            last: I420Buffer::default(),
            has_picture: false,
            restarts: 0,
        }
    }

    /// How long one frame may take in the child before it is killed (default
    /// [`DEFAULT_TIMEOUT`]).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// How many times a child died (crashed, aborted, hung or broke the protocol) and was
    /// replaced.
    pub fn restarts(&self) -> u64 {
        self.restarts
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args);
        for (k, v) in &self.envs {
            match v {
                Some(v) => c.env(k, v),
                None => c.env_remove(k),
            };
        }
        if let Some(d) = &self.current_dir {
            c.current_dir(d);
        }
        c.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        c
    }

    fn start(&mut self) -> io::Result<()> {
        let mut child = self.command().spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("rtc-video-isolated-reader".into())
            .spawn(move || {
                let mut r = BufReader::new(stdout);
                if let Err(e) = skip_to_magic(&mut r) {
                    let _ = tx.send(Err(e));
                    return;
                }
                loop {
                    let reply = read_reply(&mut r);
                    let failed = reply.is_err();
                    if tx.send(reply).is_err() || failed {
                        return;
                    }
                }
            })?;
        self.running = Some(Running {
            child,
            stdin: BufWriter::new(stdin),
            replies: rx,
        });
        Ok(())
    }

    /// Ends the child (killed if still running) after a failure.
    fn fail(&mut self, what: &str) -> DecodeError {
        let mut status = String::new();
        if let Some(mut r) = self.running.take() {
            let _ = r.child.kill();
            if let Ok(s) = r.child.wait() {
                status = format!(" ({s})");
            }
            self.restarts += 1;
        }
        self.has_picture = false;
        DecodeError::Corrupt(format!("decoder process {what}{status}"))
    }

    /// Decodes one temporal unit in the child.
    ///
    /// # Errors
    ///
    /// The child decoder's own errors; [`DecodeError::Corrupt`] when the child cannot start,
    /// dies on the frame, hangs past the timeout or breaks the protocol (it is replaced on the
    /// next call, and then needs a key frame).
    pub fn decode_bytes(
        &mut self,
        data: &[u8],
        keyframe: bool,
    ) -> Result<Option<DecodedPicture>, DecodeError> {
        if data.len() > MAX_MESSAGE {
            return Err(DecodeError::Corrupt("frame too large".into()));
        }
        if self.running.is_none()
            && let Err(e) = self.start()
        {
            return Err(DecodeError::Corrupt(format!("decoder process: {e}")));
        }
        let timeout = self.timeout;
        let r = self.running.as_mut().expect("started above");
        let sent = r
            .stdin
            .write_all(&(data.len() as u32).to_le_bytes())
            .and_then(|()| r.stdin.write_all(&[u8::from(keyframe)]))
            .and_then(|()| r.stdin.write_all(data))
            .and_then(|()| r.stdin.flush());
        if sent.is_err() {
            return Err(self.fail("ended"));
        }
        match r.replies.recv_timeout(timeout) {
            Ok(Ok(Reply::Picture(p, pixels))) => {
                match pixels {
                    Some(b) => {
                        self.last = b;
                        self.has_picture = true;
                    }
                    None => self.has_picture = false,
                }
                Ok(Some(p))
            }
            Ok(Ok(Reply::NoPicture)) => Ok(None),
            Ok(Ok(Reply::NeedKeyFrame)) => {
                self.has_picture = false;
                Err(DecodeError::NeedKeyFrame)
            }
            Ok(Ok(Reply::Corrupt(m))) => {
                self.has_picture = false;
                Err(DecodeError::Corrupt(m))
            }
            Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => Err(self.fail("ended")),
            Err(RecvTimeoutError::Timeout) => Err(self.fail("timed out")),
        }
    }
}

impl Drop for IsolatedDecoder {
    fn drop(&mut self) {
        if let Some(mut r) = self.running.take() {
            let _ = r.child.kill();
            let _ = r.child.wait();
        }
    }
}

impl VideoDecoder for IsolatedDecoder {
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

fn skip_to_magic(r: &mut impl Read) -> io::Result<()> {
    let mut window = [0u8; 8];
    let mut seen = 0usize;
    let mut b = [0u8; 1];
    // Whatever the child printed before the protocol starts (at most 64 KiB) is skipped.
    for _ in 0..(64 << 10) {
        r.read_exact(&mut b)?;
        window.copy_within(1.., 0);
        window[7] = b[0];
        seen += 1;
        if seen >= 8 && &window == MAGIC {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no protocol header from the decoder process",
    ))
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let n = read_u32(r)? as usize;
    if n > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn read_reply(r: &mut impl Read) -> io::Result<Reply> {
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind)?;
    Ok(match kind[0] {
        0 => Reply::NoPicture,
        1 => {
            let (width, height, qp) = (read_u32(r)?, read_u32(r)?, read_u32(r)?);
            let (pw, ph) = (read_u32(r)?, read_u32(r)?);
            let data = read_bytes(r)?;
            let pixels = if data.is_empty() {
                None
            } else {
                let (cw, ch) = (pw.div_ceil(2) as usize, ph.div_ceil(2) as usize);
                if data.len() != pw as usize * ph as usize + 2 * cw * ch {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "picture size"));
                }
                Some(I420Buffer {
                    width: pw,
                    height: ph,
                    data,
                })
            };
            let p = DecodedPicture {
                width,
                height,
                qp: qp.checked_sub(1),
            };
            Reply::Picture(p, pixels)
        }
        2 => Reply::NeedKeyFrame,
        3 => Reply::Corrupt(String::from_utf8_lossy(&read_bytes(r)?).into_owned()),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "reply kind")),
    })
}

/// The child's side: writes [`MAGIC`], then decodes every request from `input` with `decoder`
/// and writes the reply to `output`, until `input` ends. `now` is stamped on every frame as its
/// arrival (the decoder backends do not look at it; this module reads no clock).
///
/// # Errors
///
/// An I/O error on `input` or `output` (the parent went away).
pub fn serve(
    decoder: &mut dyn VideoDecoder,
    codec: Codec,
    input: impl Read,
    output: impl Write,
    now: Instant,
) -> io::Result<()> {
    let mut input = BufReader::new(input);
    let mut out = BufWriter::new(output);
    out.write_all(MAGIC)?;
    out.flush()?;
    let mut id = 0i64;
    loop {
        let mut len = [0u8; 4];
        match input.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let n = u32::from_le_bytes(len) as usize;
        if n > MAX_MESSAGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut flags = [0u8; 1];
        input.read_exact(&mut flags)?;
        let mut data = vec![0u8; n];
        input.read_exact(&mut data)?;
        let keyframe = flags[0] & 1 == 1;
        let frame = EncodedFrame {
            frame: AssembledFrame {
                codec,
                payload_type: 0,
                ssrc: 0,
                rtp_timestamp: 0,
                first_sequence: id,
                last_sequence: id,
                packet_count: 1,
                first_arrival: now,
                last_arrival: now,
                retransmitted: false,
                end_of_picture: true,
                keyframe,
                resolution: None,
                header: CodecHeader::None,
                playout_delay_ms: None,
                data: Bytes::from(data),
            },
            id,
            references: if keyframe || id == 0 {
                vec![]
            } else {
                vec![id - 1]
            },
            spatial_id: 0,
            temporal_id: 0,
            unwrapped_timestamp: id,
            layer_ids: vec![],
        };
        id += 1;
        match decoder.decode(&frame) {
            Ok(Some(p)) => {
                out.write_all(&[1])?;
                for v in [p.width, p.height, p.qp.map_or(0, |q| q.saturating_add(1))] {
                    out.write_all(&v.to_le_bytes())?;
                }
                match decoder.picture() {
                    Some(pic) => {
                        out.write_all(&pic.width.to_le_bytes())?;
                        out.write_all(&pic.height.to_le_bytes())?;
                        let n: usize = pic.rows().map(<[u8]>::len).sum();
                        out.write_all(&(n as u32).to_le_bytes())?;
                        for row in pic.rows() {
                            out.write_all(row)?;
                        }
                    }
                    None => out.write_all(&[0u8; 12])?,
                }
            }
            Ok(None) => out.write_all(&[0])?,
            Err(DecodeError::NeedKeyFrame) => out.write_all(&[2])?,
            Err(DecodeError::Corrupt(m)) => {
                out.write_all(&[3])?;
                out.write_all(&(m.len() as u32).to_le_bytes())?;
                out.write_all(m.as_bytes())?;
            }
        }
        out.flush()?;
    }
}
