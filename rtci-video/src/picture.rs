//! Decoded and raw pictures: an I420 view, an owned I420 buffer, PSNR, and a synthetic source.
//!
//! Every codec backend takes and gives 8-bit I420 (4:2:0, chroma planes `(width + 1) / 2` by
//! `(height + 1) / 2`), the format WebRTC's encoders and decoders use.

/// A borrowed 8-bit I420 picture.
#[derive(Debug, Clone, Copy)]
pub struct I420<'a> {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The luma plane; row `r` starts at `r * y_stride`.
    pub y: &'a [u8],
    /// The Cb plane; row `r` starts at `r * uv_stride`.
    pub u: &'a [u8],
    /// The Cr plane; row `r` starts at `r * uv_stride`.
    pub v: &'a [u8],
    /// Bytes between luma rows.
    pub y_stride: usize,
    /// Bytes between chroma rows.
    pub uv_stride: usize,
}

impl I420<'_> {
    /// Width of the chroma planes.
    pub fn chroma_width(&self) -> u32 {
        self.width.div_ceil(2)
    }

    /// Height of the chroma planes.
    pub fn chroma_height(&self) -> u32 {
        self.height.div_ceil(2)
    }

    /// Whether the planes hold what the size and strides say.
    pub fn is_valid(&self) -> bool {
        let (w, h) = (self.width as usize, self.height as usize);
        let (cw, ch) = (self.chroma_width() as usize, self.chroma_height() as usize);
        let fits = |plane: &[u8], stride: usize, w: usize, h: usize| {
            h == 0 || (stride >= w && plane.len() >= (h - 1) * stride + w)
        };
        fits(self.y, self.y_stride, w, h)
            && fits(self.u, self.uv_stride, cw, ch)
            && fits(self.v, self.uv_stride, cw, ch)
    }

    /// The rows of each plane in order (Y, then U, then V), without stride padding: what the
    /// libvpx tools write for `--i420` and what the WebM test vectors' MD5s are taken over.
    pub fn rows(&self) -> impl Iterator<Item = &[u8]> + '_ {
        let (w, h) = (self.width as usize, self.height as usize);
        let (cw, ch) = (self.chroma_width() as usize, self.chroma_height() as usize);
        let y = (0..h).map(move |r| &self.y[r * self.y_stride..r * self.y_stride + w]);
        let u = (0..ch).map(move |r| &self.u[r * self.uv_stride..r * self.uv_stride + cw]);
        let v = (0..ch).map(move |r| &self.v[r * self.uv_stride..r * self.uv_stride + cw]);
        y.chain(u).chain(v)
    }

    /// A packed copy (no stride padding).
    pub fn to_buffer(&self) -> I420Buffer {
        let mut b = I420Buffer::default();
        b.copy_from(self);
        b
    }
}

/// An owned, packed 8-bit I420 picture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct I420Buffer {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Y, then U, then V, each packed (stride = plane width).
    pub data: Vec<u8>,
}

impl I420Buffer {
    /// A mid-grey picture of `width` x `height`.
    pub fn new(width: u32, height: u32) -> Self {
        let (cw, ch) = (width.div_ceil(2) as usize, height.div_ceil(2) as usize);
        Self {
            width,
            height,
            data: vec![128; width as usize * height as usize + 2 * cw * ch],
        }
    }

    /// Replaces the contents with a packed copy of `picture` (reusing the allocation).
    pub fn copy_from(&mut self, picture: &I420<'_>) {
        self.width = picture.width;
        self.height = picture.height;
        self.data.clear();
        for row in picture.rows() {
            self.data.extend_from_slice(row);
        }
    }

    /// The view of this buffer.
    pub fn view(&self) -> I420<'_> {
        let (w, h) = (self.width as usize, self.height as usize);
        let (cw, ch) = (
            self.width.div_ceil(2) as usize,
            self.height.div_ceil(2) as usize,
        );
        let (y, rest) = self.data.split_at(w * h);
        let (u, v) = rest.split_at(cw * ch);
        I420 {
            width: self.width,
            height: self.height,
            y,
            u,
            v,
            y_stride: w,
            uv_stride: cw,
        }
    }
}

/// Scales `src` to `width` x `height` into `out` (reusing its allocation): each output sample
/// is the mean of the source samples its area covers (a box filter, exact for the integer
/// ratios and good enough for the send pipeline's resolution steps), nearest sample when
/// enlarging. The send pipeline's resolution degradation uses it.
pub fn scale_into(src: &I420<'_>, width: u32, height: u32, out: &mut I420Buffer) {
    let (cw, ch) = (width.div_ceil(2) as usize, height.div_ceil(2) as usize);
    let (w, h) = (width as usize, height as usize);
    out.width = width;
    out.height = height;
    out.data.clear();
    out.data.resize(w * h + 2 * cw * ch, 0);
    let (y, rest) = out.data.split_at_mut(w * h);
    let (u, v) = rest.split_at_mut(cw * ch);
    let (sw, sh) = (src.width as usize, src.height as usize);
    let (scw, sch) = (src.chroma_width() as usize, src.chroma_height() as usize);
    scale_plane(src.y, src.y_stride, sw, sh, y, w, h);
    scale_plane(src.u, src.uv_stride, scw, sch, u, cw, ch);
    scale_plane(src.v, src.uv_stride, scw, sch, v, cw, ch);
}

fn scale_plane(
    src: &[u8],
    stride: usize,
    sw: usize,
    sh: usize,
    dst: &mut [u8],
    dw: usize,
    dh: usize,
) {
    if sw == 0 || sh == 0 || dw == 0 || dh == 0 {
        return;
    }
    for oy in 0..dh {
        let y0 = oy * sh / dh;
        let y1 = ((oy + 1) * sh / dh).max(y0 + 1).min(sh);
        for ox in 0..dw {
            let x0 = ox * sw / dw;
            let x1 = ((ox + 1) * sw / dw).max(x0 + 1).min(sw);
            let mut sum = 0u32;
            for r in y0..y1 {
                let row = &src[r * stride + x0..r * stride + x1];
                sum += row.iter().map(|&p| u32::from(p)).sum::<u32>();
            }
            let n = ((y1 - y0) * (x1 - x0)) as u32;
            dst[oy * dw + ox] = ((sum + n / 2) / n) as u8;
        }
    }
}

/// The PSNR of `b` against `a` over all three planes (the libvpx / WebRTC convention: the
/// mean squared error of every sample of Y, U and V together), in dB; `None` when the sizes
/// differ. Identical pictures give 100 dB.
pub fn psnr(a: &I420<'_>, b: &I420<'_>) -> Option<f64> {
    if a.width != b.width || a.height != b.height {
        return None;
    }
    let (mut sse, mut n) = (0u64, 0u64);
    for (ra, rb) in a.rows().zip(b.rows()) {
        for (&x, &y) in ra.iter().zip(rb) {
            let d = i64::from(x) - i64::from(y);
            sse += (d * d) as u64;
        }
        n += ra.len() as u64;
    }
    if sse == 0 {
        return Some(100.0);
    }
    let mse = sse as f64 / n as f64;
    Some(10.0 * (255.0 * 255.0 / mse).log10())
}

/// A deterministic synthetic camera-like source: a textured background that pans, a few
/// moving shapes, and a little temporal noise, so that encoders meet motion, detail and
/// noise as they do with a camera. Every test that encodes uses it (no camera runs in CI).
#[derive(Debug, Clone)]
pub struct TestSource {
    width: u32,
    height: u32,
    frame: u32,
    noise: u64,
}

impl TestSource {
    /// A source of `width` x `height`.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            frame: 0,
            noise: 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next_noise(&mut self) -> u8 {
        self.noise ^= self.noise << 13;
        self.noise ^= self.noise >> 7;
        self.noise ^= self.noise << 17;
        (self.noise & 7) as u8
    }

    /// The next picture.
    pub fn next_picture(&mut self) -> I420Buffer {
        let (w, h) = (self.width as usize, self.height as usize);
        let (cw, ch) = (
            self.width.div_ceil(2) as usize,
            self.height.div_ceil(2) as usize,
        );
        let t = self.frame as usize;
        let mut b = I420Buffer::new(self.width, self.height);
        let pan = t * 2;
        // Shapes: (x speed, y speed, size, luma).
        let shapes = [
            (3usize, 1usize, h / 4, 230u8),
            (2, 3, h / 6, 30),
            (5, 2, h / 8, 180),
        ];
        for y in 0..h {
            for x in 0..w {
                let (px, py) = (x + pan, y + t / 2);
                // A texture of soft stripes and a checker, panning.
                let stripe = ((px / 3 + py / 5) % 32) as u8 * 3;
                let checker = if ((px / 24) + (py / 24)) % 2 == 0 {
                    40
                } else {
                    0
                };
                let mut l = 60u8.saturating_add(stripe).saturating_add(checker);
                for (i, &(sx, sy, size, luma)) in shapes.iter().enumerate() {
                    let cx = (t * sx + i * w / 3) % (w + size);
                    let cy = (t * sy + i * h / 3) % (h + size);
                    if x + size >= cx && x < cx && y + size >= cy && y < cy {
                        l = luma;
                    }
                }
                b.data[y * w + x] = l.saturating_add(self.next_noise());
            }
        }
        let (u, v) = b.data[w * h..].split_at_mut(cw * ch);
        for y in 0..ch {
            for x in 0..cw {
                u[y * cw + x] = (96 + ((x + pan / 2) * 64 / cw.max(1)) as u32 % 64) as u8;
                v[y * cw + x] = (100 + ((y + t / 4) * 64 / ch.max(1)) as u32 % 64) as u8;
            }
        }
        self.frame += 1;
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psnr_of_a_picture_against_itself_is_the_ceiling_and_drops_with_error() {
        let mut s = TestSource::new(64, 48);
        let a = s.next_picture();
        assert_eq!(psnr(&a.view(), &a.view()), Some(100.0));
        let mut b = a.clone();
        for p in b.data.iter_mut().step_by(7) {
            *p = p.wrapping_add(8);
        }
        let v = psnr(&a.view(), &b.view()).expect("same size");
        assert!((20.0..60.0).contains(&v), "{v}");
        assert_eq!(psnr(&a.view(), &I420Buffer::new(32, 32).view()), None);
    }

    #[test]
    fn scaling_halves_by_averaging_and_keeps_the_picture_recognisable() {
        let mut s = TestSource::new(64, 48);
        let a = s.next_picture();
        let mut half = I420Buffer::default();
        scale_into(&a.view(), 32, 24, &mut half);
        assert_eq!((half.width, half.height), (32, 24));
        assert_eq!(half.data.len(), 32 * 24 + 2 * 16 * 12);
        // Each output luma sample is the rounded mean of its 2x2 block.
        let av = a.view();
        let mean = (u32::from(av.y[0])
            + u32::from(av.y[1])
            + u32::from(av.y[64])
            + u32::from(av.y[65])
            + 2)
            / 4;
        assert_eq!(u32::from(half.view().y[0]), mean);
        // Scaled back up (nearest), it is close to the source.
        let mut back = I420Buffer::default();
        scale_into(&half.view(), 64, 48, &mut back);
        let q = psnr(&a.view(), &back.view()).expect("same size");
        assert!(q > 18.0, "{q:.1} dB");
        // The same size is a copy.
        let mut same = I420Buffer::default();
        scale_into(&a.view(), 64, 48, &mut same);
        assert_eq!(same, a);
    }

    #[test]
    fn the_source_moves_and_odd_sizes_round_the_chroma_up() {
        let mut s = TestSource::new(33, 17);
        let a = s.next_picture();
        let b = s.next_picture();
        assert_ne!(a, b);
        assert_eq!(a.data.len(), 33 * 17 + 2 * 17 * 9);
        assert!(a.view().is_valid());
        assert_eq!(a.view().to_buffer(), a);
    }
}
