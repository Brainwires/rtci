//! Concealment for codecs that have none (G.711, G.722): the last pitch period repeated,
//! as in ITU-T G.711 Appendix I. Full level for the first 10 ms, then 20 % less every 10 ms,
//! silent after 60 ms; the return to decoded audio is cross-faded ("merge").

use crate::dsp::timestretch;

/// How much decoded audio the concealment keeps to find the period in (40 ms).
const HISTORY_SECS: f64 = 0.04;

#[derive(Debug, Clone)]
pub(crate) struct GenericPlc {
    rate: u32,
    channels: usize,
    history: Vec<f32>,
    period: Vec<f32>,
    lag: usize,
    pos: usize,
    /// Samples (per channel) concealed since the concealment began.
    concealed: usize,
    active: bool,
}

impl GenericPlc {
    pub(crate) fn new(rate: u32, channels: u16) -> Self {
        Self {
            rate,
            channels: usize::from(channels.max(1)),
            history: Vec::new(),
            period: Vec::new(),
            lag: 1,
            pos: 0,
            concealed: 0,
            active: false,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active
    }

    /// Remembers decoded audio (interleaved).
    pub(crate) fn push_history(&mut self, samples: &[f32]) {
        self.history.extend_from_slice(samples);
        let keep = (HISTORY_SECS * f64::from(self.rate)) as usize * self.channels;
        if self.history.len() > keep {
            let drop = self.history.len() - keep;
            self.history.drain(..drop);
        }
    }

    fn start(&mut self) {
        let ch = self.channels;
        let n = self.history.len() / ch;
        let need = timestretch::required_input(self.rate);
        self.lag = if n >= need {
            // The lag search reads forward; search the most recent audio.
            let recent = &self.history[(n - need) * ch..];
            let mono: Vec<f32> = recent
                .chunks_exact(ch)
                .map(|f| f.iter().sum::<f32>() / ch as f32)
                .collect();
            timestretch::find_lag(&mono, self.rate).0
        } else {
            (self.rate / 200) as usize // 5 ms
        }
        .min(n.max(1));
        self.period = if n > 0 {
            self.history[(n - self.lag.min(n)) * ch..].to_vec()
        } else {
            vec![0.0; self.lag * ch]
        };
        self.lag = self.period.len() / ch;
        self.pos = 0;
        self.concealed = 0;
        self.active = true;
    }

    fn gain(&self, i: usize) -> f32 {
        let ten_ms = (self.rate / 100) as usize;
        let t = self.concealed + i;
        if t < ten_ms {
            1.0
        } else {
            (1.0 - 0.2 * (t - ten_ms) as f32 / ten_ms as f32).max(0.0)
        }
    }

    /// Appends `samples` per channel of concealment to `out`.
    pub(crate) fn conceal(&mut self, samples: usize, out: &mut Vec<f32>) {
        if !self.active {
            self.start();
        }
        let ch = self.channels;
        for i in 0..samples {
            let g = self.gain(i);
            for c in 0..ch {
                out.push(self.period[self.pos * ch + c] * g);
            }
            self.pos = (self.pos + 1) % self.lag.max(1);
        }
        self.concealed += samples;
    }

    /// Ends the concealment: cross-fades its continuation into the start of `decoded`
    /// (interleaved) over 2.5 ms.
    pub(crate) fn merge_into(&mut self, decoded: &mut [f32]) {
        if !self.active {
            return;
        }
        let ch = self.channels;
        let m = ((self.rate / 400) as usize).min(decoded.len() / ch);
        let mut tail = Vec::with_capacity(m * ch);
        self.conceal(m, &mut tail);
        for i in 0..m {
            let w = (i as f32 + 0.5) / m as f32;
            for c in 0..ch {
                let k = i * ch + c;
                decoded[k] = tail[k] * (1.0 - w) + decoded[k] * w;
            }
        }
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Tone;

    #[test]
    fn a_period_is_repeated_then_faded_out() {
        let mut plc = GenericPlc::new(8000, 1);
        let mut t = Tone::new(8000, 250.0, 0.5);
        let mut x = vec![0.0f32; 320];
        t.fill(&mut x);
        plc.push_history(&x);
        let mut out = Vec::new();
        plc.conceal(80, &mut out);
        // The continuation of a 250 Hz tone is the tone: compare with what came next.
        let mut next = vec![0.0f32; 80];
        t.fill(&mut next);
        let err: f32 = out
            .iter()
            .zip(&next)
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f32::max);
        assert!(err < 0.05, "{err}");
        // Faded out over the next 50 ms: nothing is left after 60 ms.
        out.clear();
        plc.conceal(400, &mut out);
        assert!(out[..80].iter().any(|s| *s != 0.0));
        out.clear();
        plc.conceal(80, &mut out);
        assert!(out.iter().all(|s| *s == 0.0));
    }
}
