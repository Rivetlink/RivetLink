//! H.264 encoding for the live stream (Linux host).
//!
//! OpenH264 in its screen-content real-time mode, fed I420 frames straight from
//! the Mutter/GStreamer capture. Compiled from source into the agent, so it
//! needs no system codec package and no GStreamer development headers.
//!
//! Every encoded access unit is queued only when the consumer has room, so no
//! reference frame is ever dropped behind the decoder's back. Loss further
//! downstream (the broker's lossy fan-out, a client decode error) is repaired
//! through [`VideoControl`]: it asks for a keyframe and, on congestion, makes
//! the encoder step its bitrate down.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, RateControlMode, UsageType, VuiConfig,
};
use openh264::formats::YUVSlices;
use openh264::OpenH264API;
use tokio::sync::mpsc::{error::TrySendError, Sender};

use rivetlink_sdk::lan::{StreamFrame, VideoFrame};

use super::screencast::VideoControl;
use crate::error::{AgentError, AgentResult};

/// Bitrate bounds. A LAN link usually takes the maximum; congestion steps the
/// rate down towards the minimum and quiet periods step it back up.
const MAX_BPS: u32 = 10_000_000;
const MIN_BPS: u32 = 1_000_000;
/// Re-encode the last frame at least this often on a static screen, so the
/// client can tell a static screen from a stalled link (like tile heartbeats).
const HEARTBEAT: Duration = Duration::from_millis(1000);
/// Wait this long without congestion before raising the bitrate again. Each
/// change rebuilds the encoder (one keyframe), so it must stay rare.
const RAISE_AFTER: Duration = Duration::from_secs(10);
/// Ignore further congestion this soon after lowering the bitrate: frames that
/// were already in flight would otherwise push it straight to the minimum.
const LOWER_HOLDOFF: Duration = Duration::from_secs(1);

/// Byte length of one tightly packed I420 frame.
pub(crate) const fn i420_len(w: usize, h: usize) -> usize {
    w * h + 2 * ((w / 2) * (h / 2))
}

/// Stateful H.264 encoder for one stream. Dimensions are fixed; they must be
/// even (the capture's `fit_output` guarantees that).
pub(crate) struct H264Encoder {
    encoder: Encoder,
    w: usize,
    h: usize,
    fps: u16,
    bitrate: u32,
    control: Arc<VideoControl>,
    /// The newest frame, re-encoded for heartbeats and after a skipped frame.
    last: Option<Vec<u8>>,
    /// `last` has not reached the consumer yet (skipped while it was behind).
    pending: bool,
    last_sent: Instant,
    last_rate_change: Instant,
    last_congestion: Instant,
}

impl H264Encoder {
    pub(crate) fn new(
        w: usize,
        h: usize,
        fps: u16,
        control: Arc<VideoControl>,
    ) -> AgentResult<Self> {
        if w == 0 || h == 0 || !w.is_multiple_of(2) || !h.is_multiple_of(2) {
            return Err(AgentError::Lan(format!(
                "h264: unsupported frame size {w}x{h}"
            )));
        }
        let encoder = build_encoder(MAX_BPS, fps)?;
        Ok(Self {
            encoder,
            w,
            h,
            fps,
            bitrate: MAX_BPS,
            control,
            last: None,
            pending: false,
            last_sent: Instant::now(),
            last_rate_change: Instant::now(),
            last_congestion: Instant::now(),
        })
    }

    /// Encode one I420 frame (`i420_len(w, h)` bytes) and queue it. Returns
    /// `false` when the consumer is gone (caller should stop capturing).
    pub(crate) fn push(&mut self, data: Vec<u8>, tx: &Sender<StreamFrame>) -> bool {
        if data.len() != i420_len(self.w, self.h) {
            return true; // skip a malformed frame, keep going
        }
        if tx.is_closed() {
            return false;
        }
        // Consumer behind: skip encoding instead of dropping an encoded frame,
        // so the decoder never misses a reference. Send it once there is room.
        if tx.capacity() == 0 {
            self.last = Some(data);
            self.pending = true;
            self.control.report_congestion();
            return true;
        }
        self.adapt();
        let frame = match self.encode(&data) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                // Rate control skipped this frame; retry on the next tick.
                self.last = Some(data);
                self.pending = true;
                return true;
            },
            Err(e) => {
                tracing::debug!(error = %e, "h264: encode failed, skipping frame");
                self.control.request_keyframe();
                return true;
            },
        };
        self.last = Some(data);
        self.pending = false;
        let keyframe = frame.keyframe;
        match tx.try_send(StreamFrame::Video(frame)) {
            Ok(()) => {
                self.last_sent = Instant::now();
                tracing::debug!(keyframe, "h264 frame sent");
                true
            },
            // Single producer and room was checked above; a full queue here
            // still must not desync the decoder, so restart from a keyframe.
            Err(TrySendError::Full(_)) => {
                self.pending = true;
                self.control.request_keyframe();
                true
            },
            Err(TrySendError::Closed(_)) => false,
        }
    }

    /// Re-send the newest frame when it is still pending or the screen has
    /// been idle for a while. Returns `false` when the consumer is gone.
    pub(crate) fn heartbeat(&mut self, tx: &Sender<StreamFrame>) -> bool {
        if !self.pending && self.last_sent.elapsed() < HEARTBEAT {
            return true;
        }
        match self.last.take() {
            Some(last) => self.push(last, tx),
            None => !tx.is_closed(),
        }
    }

    /// Apply keyframe requests and bitrate changes before encoding a frame.
    fn adapt(&mut self) {
        if self.control.congested.swap(false, Ordering::AcqRel) {
            self.last_congestion = Instant::now();
            if self.last_rate_change.elapsed() >= LOWER_HOLDOFF {
                self.set_bitrate((self.bitrate / 3 * 2).max(MIN_BPS));
            }
        } else if self.last_congestion.elapsed() >= RAISE_AFTER
            && self.last_rate_change.elapsed() >= RAISE_AFTER
        {
            self.set_bitrate((self.bitrate / 4 * 5).min(MAX_BPS));
        }
        if self.control.keyframe.swap(false, Ordering::AcqRel) {
            self.encoder.force_intra_frame();
        }
    }

    /// Rebuild the encoder at `bps`. A fresh encoder starts with an IDR frame.
    fn set_bitrate(&mut self, bps: u32) {
        if bps == self.bitrate {
            return;
        }
        self.last_rate_change = Instant::now();
        match build_encoder(bps, self.fps) {
            Ok(encoder) => {
                tracing::info!(from = self.bitrate, to = bps, "h264: bitrate changed");
                self.encoder = encoder;
                self.bitrate = bps;
                self.control.keyframe.store(false, Ordering::Release);
            },
            Err(e) => tracing::warn!(error = %e, "h264: could not rebuild encoder"),
        }
    }

    /// Encode one frame; `None` when rate control skipped it.
    fn encode(&mut self, data: &[u8]) -> AgentResult<Option<VideoFrame>> {
        let (w, h) = (self.w, self.h);
        let (y, uv) = data.split_at(w * h);
        let (u, v) = uv.split_at((w / 2) * (h / 2));
        let yuv = YUVSlices::new((y, u, v), (w, h), (w, w / 2, w / 2));
        let bitstream = self
            .encoder
            .encode(&yuv)
            .map_err(|e| AgentError::Lan(format!("h264 encode: {e}")))?;
        let keyframe = match bitstream.frame_type() {
            FrameType::IDR | FrameType::I => true,
            FrameType::P | FrameType::IPMixed => false,
            FrameType::Skip | FrameType::Invalid => return Ok(None),
        };
        let bytes = bitstream.to_vec();
        if bytes.is_empty() {
            return Ok(None);
        }
        Ok(Some(VideoFrame {
            w: u32::try_from(w).unwrap_or(0),
            h: u32::try_from(h).unwrap_or(0),
            keyframe,
            data_b64: B64.encode(bytes),
        }))
    }
}

fn build_encoder(bitrate: u32, fps: u16) -> AgentResult<Encoder> {
    let config = EncoderConfig::new()
        .usage_type(UsageType::ScreenContentRealTime)
        .rate_control_mode(RateControlMode::Bitrate)
        .bitrate(BitRate::from_bps(bitrate))
        .max_frame_rate(FrameRate::from_hz(f32::from(fps.max(1))))
        // Matches the capture's `colorimetry=bt709` I420 output.
        .vui(VuiConfig::bt709());
    Encoder::with_api_config(OpenH264API::from_source(), config)
        .map_err(|e| AgentError::Lan(format!("h264 encoder: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openh264::decoder::Decoder;

    const W: usize = 320;
    const H: usize = 240;

    /// A grey I420 frame with a bright square at `offset`.
    fn frame(offset: usize) -> Vec<u8> {
        let mut data = vec![128u8; i420_len(W, H)];
        for y in 40..120 {
            for x in offset..offset + 80 {
                data[y * W + x] = 235;
            }
        }
        data
    }

    fn decode_all(decoder: &mut Decoder, frame: &StreamFrame) -> (usize, usize) {
        let StreamFrame::Video(video) = frame else {
            panic!("expected a video frame");
        };
        let bytes = B64.decode(&video.data_b64).unwrap();
        let picture = decoder.decode(&bytes).unwrap().expect("a decoded picture");
        openh264::formats::YUVSource::dimensions(&picture)
    }

    #[test]
    fn frames_round_trip_through_a_decoder() {
        let control = Arc::new(VideoControl::default());
        let mut enc = H264Encoder::new(W, H, 30, Arc::clone(&control)).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut decoder = Decoder::new().unwrap();

        assert!(enc.push(frame(0), &tx));
        let first = rx.try_recv().unwrap();
        assert!(matches!(&first, StreamFrame::Video(v) if v.keyframe && v.w == 320 && v.h == 240));
        assert_eq!(decode_all(&mut decoder, &first), (W, H));

        assert!(enc.push(frame(10), &tx));
        let second = rx.try_recv().unwrap();
        assert!(matches!(&second, StreamFrame::Video(v) if !v.keyframe));
        assert_eq!(decode_all(&mut decoder, &second), (W, H));

        control.request_keyframe();
        assert!(enc.push(frame(20), &tx));
        assert!(matches!(rx.try_recv().unwrap(), StreamFrame::Video(v) if v.keyframe));
    }

    #[test]
    fn a_full_queue_skips_encoding_and_resends_later() {
        let control = Arc::new(VideoControl::default());
        let mut enc = H264Encoder::new(W, H, 30, Arc::clone(&control)).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        assert!(enc.push(frame(0), &tx));
        // Queue full: the next frame is held back, not encoded and dropped.
        assert!(enc.push(frame(10), &tx));
        assert!(enc.pending);
        assert!(matches!(rx.try_recv().unwrap(), StreamFrame::Video(v) if v.keyframe));
        assert!(rx.try_recv().is_err());

        // Room again: the held frame goes out on the next tick, as a keyframe
        // (congestion asked for one) at a lower bitrate.
        enc.last_rate_change -= LOWER_HOLDOFF;
        assert!(enc.heartbeat(&tx));
        assert!(!enc.pending);
        assert!(matches!(rx.try_recv().unwrap(), StreamFrame::Video(v) if v.keyframe));
        assert!(enc.bitrate < MAX_BPS);
    }

    #[test]
    fn malformed_frames_are_skipped_and_odd_sizes_rejected() {
        let control = Arc::new(VideoControl::default());
        let mut enc = H264Encoder::new(W, H, 30, control).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        assert!(enc.push(vec![0; 10], &tx));
        assert!(rx.try_recv().is_err());
        assert!(H264Encoder::new(321, 240, 30, Arc::new(VideoControl::default())).is_err());
    }

    #[test]
    fn a_closed_consumer_stops_the_encoder() {
        let mut enc = H264Encoder::new(W, H, 30, Arc::new(VideoControl::default())).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        assert!(!enc.push(frame(0), &tx));
    }
}
