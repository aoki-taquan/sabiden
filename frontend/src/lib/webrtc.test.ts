// Issue #92 / RFC 8840 §4 (Trickle ICE end-of-candidates) /
// W3C WebRTC §4.4.1.6 (`RTCPeerConnection.addIceCandidate`):
//
// `WebRtcCall.addIce()` 経由で empty string / "end-of-candidates" 文字列が
// 来たとき、 内部で `pc.addIceCandidate(null)` を呼ぶことを確認する。
// 旧挙動 (空文字列で silent return) は ICE failure 判定の遅延 (chromium で
// 30 秒以上) を生むため、 本テストは regression 防止用。

import { describe, expect, it, vi } from "vitest";
import { WebRtcCall } from "./webrtc";
import type { SignalingClient } from "./signaling";

/**
 * 最小限の `RTCPeerConnection` mock。 `addIceCandidate` の呼び出し履歴
 * (引数 = candidate dict / null) を `calls` に記録する。
 *
 * `WebRtcCall` constructor は `new RTCPeerConnection(...)` を呼ぶため、
 * globalThis に factory を生やしてここで返す形にする。
 */
class FakeRTCPeerConnection {
  static lastInstance: FakeRTCPeerConnection | null = null;
  calls: Array<RTCIceCandidateInit | null> = [];
  // 必須プロパティ (型上必要)
  iceConnectionState: RTCIceConnectionState = "new";
  iceGatheringState: RTCIceGatheringState = "new";
  signalingState: RTCSignalingState = "stable";
  connectionState: RTCPeerConnectionState = "new";
  onicecandidate: ((ev: RTCPeerConnectionIceEvent) => void) | null = null;
  onicecandidateerror: ((ev: Event) => void) | null = null;
  oniceconnectionstatechange: (() => void) | null = null;
  onicegatheringstatechange: (() => void) | null = null;
  onsignalingstatechange: (() => void) | null = null;
  onconnectionstatechange: (() => void) | null = null;
  onnegotiationneeded: (() => void) | null = null;
  ontrack: ((ev: RTCTrackEvent) => void) | null = null;

  constructor() {
    FakeRTCPeerConnection.lastInstance = this;
  }

  async addIceCandidate(c: RTCIceCandidateInit | RTCIceCandidate | null): Promise<void> {
    // W3C WebRTC §4.4.1.6: `addIceCandidate(null)` は end-of-candidates。
    // RTCIceCandidate オブジェクトは init 形式に正規化して記録する。
    this.calls.push(c as RTCIceCandidateInit | null);
  }
}

// vitest 環境 (jsdom) は RTCPeerConnection を提供しないため、 globalThis を上書き。
(globalThis as unknown as { RTCPeerConnection: typeof FakeRTCPeerConnection }).RTCPeerConnection =
  FakeRTCPeerConnection;

/**
 * `MediaStream` の最小モック。 `WebRtcCall` constructor が `new MediaStream()` を
 * 呼ぶため、 jsdom 環境では globalThis に factory を生やしておく。
 * `addTrack` / `getTracks` / `getAudioTracks` は本テスト経路では使われないので
 * no-op で十分 (addIce 経路は ontrack を経由しない)。
 */
class FakeMediaStream {
  private tracks: MediaStreamTrack[] = [];
  addTrack(t: MediaStreamTrack): void {
    this.tracks.push(t);
  }
  getTracks(): MediaStreamTrack[] {
    return this.tracks;
  }
  getAudioTracks(): MediaStreamTrack[] {
    return this.tracks;
  }
}
(globalThis as unknown as { MediaStream: typeof FakeMediaStream }).MediaStream = FakeMediaStream;

/** signaling は addIce 経路では使われないので最小限の no-op shim。 */
function makeSignalingShim(): SignalingClient {
  return {
    send: vi.fn(),
    close: vi.fn(),
    connect: vi.fn(),
    state: "open",
    readyState: 1,
  } as unknown as SignalingClient;
}

describe("WebRtcCall.addIce (Issue #92, RFC 8840 §4)", () => {
  // RFC 8840 §4 / W3C WebRTC §4.4.1.6:
  // empty string は end-of-candidates marker → `pc.addIceCandidate(null)` に翻訳。
  it("rfc8840_4_translates_empty_string_to_addIceCandidate_null", async () => {
    const call = new WebRtcCall(makeSignalingShim(), {
      onRemoteTrack: () => {},
      onConnectionState: () => {},
    });
    const pc = FakeRTCPeerConnection.lastInstance!;
    await call.addIce("");
    expect(pc.calls).toEqual([null]);
  });

  // RFC 8840 §4: `end-of-candidates` 文字列 (W3C 旧式 / 一部実装) も marker。
  it("rfc8840_4_translates_end_of_candidates_keyword_to_addIceCandidate_null", async () => {
    const call = new WebRtcCall(makeSignalingShim(), {
      onRemoteTrack: () => {},
      onConnectionState: () => {},
    });
    const pc = FakeRTCPeerConnection.lastInstance!;
    await call.addIce("end-of-candidates");
    expect(pc.calls).toEqual([null]);
  });

  // RFC 8840 §4: leading whitespace / 大文字小文字違いも実装によっては送られる。
  // 厳密にトリムして判定する。
  it("rfc8840_4_translates_whitespace_only_string_to_addIceCandidate_null", async () => {
    const call = new WebRtcCall(makeSignalingShim(), {
      onRemoteTrack: () => {},
      onConnectionState: () => {},
    });
    const pc = FakeRTCPeerConnection.lastInstance!;
    await call.addIce("   ");
    expect(pc.calls).toEqual([null]);
  });

  // RFC 8839 §4.2 / W3C: 実 candidate は dict 形式で渡す (sdpMid / sdpMLineIndex 付き)。
  it("rfc8839_4_2_passes_real_candidate_as_dict", async () => {
    const call = new WebRtcCall(makeSignalingShim(), {
      onRemoteTrack: () => {},
      onConnectionState: () => {},
    });
    const pc = FakeRTCPeerConnection.lastInstance!;
    const cand = "candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host";
    await call.addIce(cand);
    expect(pc.calls).toHaveLength(1);
    const first = pc.calls[0] as RTCIceCandidateInit;
    expect(first).not.toBeNull();
    expect(first.candidate).toBe(cand);
  });
});
