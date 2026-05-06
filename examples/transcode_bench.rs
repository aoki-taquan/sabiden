//! 簡易ベンチマーク: NGN→WebRTC / WebRTC→NGN 変換 1 通話 1 秒分のコスト計測。
//!
//! `cargo run --release --example transcode_bench` で実行する。
//!
//! 出力例:
//! ```text
//! NGN→WebRTC : 50 frames, total=4.123ms, per-frame=82.46us, real-time-budget=20ms (0.41% CPU)
//! WebRTC→NGN : 50 frames, total=5.812ms, per-frame=116.24us, real-time-budget=20ms (0.58% CPU)
//! ```
//!
//! 1 通話 = 50 frames/sec の 20ms フレームを処理する。CPU 使用率は
//! `per-frame / 20ms * 100%` で算出 (シングルコア比)。

use std::time::Instant;

use sabiden::rtp::codec::opus::{OpusDecoder, OpusEncoder, OPUS_FRAME_SAMPLES, OPUS_SAMPLE_RATE};
use sabiden::rtp::codec::resample::{
    DownsamplerWbToNb, UpsamplerNbToWb, NARROW_BAND_RATE, NB_FRAME_SAMPLES,
};
use sabiden::rtp::codec::AudioFrame;
use sabiden::rtp::{decode_ulaw, encode_ulaw};

const FRAMES_PER_SECOND: usize = 50; // 20ms × 50 = 1秒
const FRAME_BUDGET_US: f64 = 20_000.0;

fn make_test_signal_8k() -> Vec<u8> {
    // 1 kHz トーン
    (0..NB_FRAME_SAMPLES)
        .map(|i| {
            let t = i as f32 / NARROW_BAND_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            encode_ulaw(v as i16)
        })
        .collect()
}

fn make_test_signal_48k() -> AudioFrame {
    let samples: Vec<i16> = (0..OPUS_FRAME_SAMPLES)
        .map(|i| {
            let t = i as f32 / OPUS_SAMPLE_RATE as f32;
            let v = (2.0 * std::f32::consts::PI * 1000.0 * t).sin() * 8000.0;
            v as i16
        })
        .collect();
    AudioFrame::new(OPUS_SAMPLE_RATE, samples)
}

fn bench_ngn_to_web() {
    let mut up = UpsamplerNbToWb::new().unwrap();
    let mut enc = OpusEncoder::new().unwrap();
    let ulaw_packet = make_test_signal_8k();

    let start = Instant::now();
    for _ in 0..FRAMES_PER_SECOND {
        let pcm: Vec<i16> = ulaw_packet.iter().map(|b| decode_ulaw(*b)).collect();
        let nb = AudioFrame::new(NARROW_BAND_RATE, pcm);
        let wb = up.process(&nb).unwrap();
        let _opus = enc.encode(&wb).unwrap();
    }
    let elapsed = start.elapsed();
    let per_frame_us = elapsed.as_secs_f64() * 1_000_000.0 / FRAMES_PER_SECOND as f64;
    println!(
        "NGN→WebRTC : {} frames, total={:.3}ms, per-frame={:.2}us, real-time-budget=20ms ({:.2}% CPU)",
        FRAMES_PER_SECOND,
        elapsed.as_secs_f64() * 1000.0,
        per_frame_us,
        per_frame_us / FRAME_BUDGET_US * 100.0
    );
}

fn bench_web_to_ngn() {
    // 事前に 1 フレーム Opus を作る
    let mut enc = OpusEncoder::new().unwrap();
    let signal = make_test_signal_48k();
    let opus_pkt = enc.encode(&signal).unwrap();

    let mut dec = OpusDecoder::new().unwrap();
    let mut down = DownsamplerWbToNb::new().unwrap();

    let start = Instant::now();
    for _ in 0..FRAMES_PER_SECOND {
        let wb = dec.decode(&opus_pkt).unwrap();
        let nb = down.process(&wb).unwrap();
        let _ulaw: Vec<u8> = nb.samples.iter().map(|s| encode_ulaw(*s)).collect();
    }
    let elapsed = start.elapsed();
    let per_frame_us = elapsed.as_secs_f64() * 1_000_000.0 / FRAMES_PER_SECOND as f64;
    println!(
        "WebRTC→NGN : {} frames, total={:.3}ms, per-frame={:.2}us, real-time-budget=20ms ({:.2}% CPU)",
        FRAMES_PER_SECOND,
        elapsed.as_secs_f64() * 1000.0,
        per_frame_us,
        per_frame_us / FRAME_BUDGET_US * 100.0
    );
}

fn main() {
    println!("== sabiden Opus トランスコード簡易ベンチマーク ==");
    println!("(1 通話 1 秒 = 50 フレーム × 20ms を逐次処理)");
    println!();
    // 1 ループ目はキャッシュ未温で外れ値になりやすい → 捨てる
    bench_ngn_to_web();
    bench_web_to_ngn();
    println!();
    println!("(2 回目: ウォームアップ後)");
    bench_ngn_to_web();
    bench_web_to_ngn();
}
