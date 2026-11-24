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
