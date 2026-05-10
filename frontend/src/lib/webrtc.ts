// WebRTC PeerConnection ラッパ。
//
// sabiden は WebRTC ↔ G.711 トランスコードを Opus 経由で行うため、
// ブラウザは Opus / PCMU 両方を offer に含める。
// (Opus 優先: バックエンドが対応済み (#27))

import type { SignalingClient } from "./signaling";

const log = (...args: unknown[]) => console.log("[PWA/webrtc]", ...args);
const warn = (...args: unknown[]) => console.warn("[PWA/webrtc]", ...args);

export type CallEvents = {
  onRemoteTrack: (stream: MediaStream) => void;
  onConnectionState: (state: RTCPeerConnectionState) => void;
};

export class WebRtcCall {
  private pc: RTCPeerConnection;
  private localStream: MediaStream | null = null;
  private readonly signaling: SignalingClient;
  private readonly events: CallEvents;
  private remoteStream: MediaStream;
  private startedAt: number = performance.now();

  private elapsed(): string {
    return `+${(performance.now() - this.startedAt).toFixed(0)}ms`;
  }

  constructor(signaling: SignalingClient, events: CallEvents, iceServers?: RTCIceServer[]) {
    this.signaling = signaling;
    this.events = events;
    log("ctor: creating RTCPeerConnection", { iceServers });
    this.pc = new RTCPeerConnection({
      iceServers: iceServers ?? [{ urls: "stun:stun.cloudflare.com:3478" }],
      // 半二重音声でも sendrecv で問題なし。bundle/rtcp-mux は既定で有効。
    });
    this.remoteStream = new MediaStream();

    this.pc.ontrack = (ev) => {
      const tracks = ev.streams[0]?.getTracks() ?? [];
      log(this.elapsed(), "ontrack", {
        track_kind: ev.track.kind,
        track_id: ev.track.id,
        track_enabled: ev.track.enabled,
        track_muted: ev.track.muted,
        track_readyState: ev.track.readyState,
        stream_track_count: tracks.length,
      });
      tracks.forEach((t) => this.remoteStream.addTrack(t));
      this.events.onRemoteTrack(this.remoteStream);
    };

    this.pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        log(this.elapsed(), "onicecandidate", {
          candidate: ev.candidate.candidate,
          sdpMid: ev.candidate.sdpMid,
          sdpMLineIndex: ev.candidate.sdpMLineIndex,
        });
        try {
          this.signaling.send({ type: "ice", candidate: ev.candidate.candidate });
        } catch (e) {
          warn("ICE send failed", e);
        }
      } else {
        // Issue #92 / RFC 8840 §4 (Trickle ICE) / W3C WebRTC §4.4.7
        // (`icecandidate` event): `event.candidate === null` は ICE gathering
        // complete を表す。 これを wire 上で `{type:"ice",candidate:""}` として
        // sabiden に送出し、 server-side trickle ICE 終端を通知する
        // (sabiden 側 `process_client_message::Ice` は RFC 8840 §4 に従い
        //  空文字列を end-of-candidates marker として silent OK 受理する)。
        //
        // sabiden は ICE-Lite (controlled、 RFC 8445 §2.4) で str0m が
        // 「end-of-remote-candidates を IceAgent に通知する」 public API を
        // 持たないため、 server-side 観測ログのみに使われる。 PWA→sabiden 方向の
        // 候補列挙終了は、 RFC 8840 §4 が SHOULD としているシグナリング層通知を
        // 実装する目的 (相互運用性、 将来 str0m が API を公開した時の前方互換性)。
        log(this.elapsed(), "onicecandidate: end-of-candidates (null) → wire ''");
        try {
          this.signaling.send({ type: "ice", candidate: "" });
        } catch (e) {
          warn("ICE end-of-candidates send failed", e);
        }
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      log(this.elapsed(), "iceConnectionState =", this.pc.iceConnectionState);
    };

    this.pc.onicegatheringstatechange = () => {
      log(this.elapsed(), "iceGatheringState =", this.pc.iceGatheringState);
    };

    this.pc.onsignalingstatechange = () => {
      log(this.elapsed(), "signalingState =", this.pc.signalingState);
    };

    this.pc.onconnectionstatechange = () => {
      log(this.elapsed(), "connectionState =", this.pc.connectionState);
      this.events.onConnectionState(this.pc.connectionState);
    };

    this.pc.onnegotiationneeded = () => {
      log(this.elapsed(), "negotiationneeded fired");
    };
  }

  /** マイクを取得して送信トラックに追加。 */
  async acquireMic(): Promise<void> {
    log(this.elapsed(), "acquireMic: getUserMedia start");
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
      video: false,
    });
    const tracks = this.localStream.getTracks();
    log(this.elapsed(), "acquireMic: got stream", {
      track_count: tracks.length,
      tracks: tracks.map((t) => ({ kind: t.kind, label: t.label, enabled: t.enabled })),
    });
    tracks.forEach((t) => this.pc.addTrack(t, this.localStream!));
    log(this.elapsed(), "acquireMic: tracks added to pc", {
      senders: this.pc.getSenders().length,
    });
  }

  /**
   * SDP offer を作成し、 シグナリング経由で送出する。
   *
   * `target` を渡すと sabiden は PWA→NGN 発信フローを起動する
   * (Issue #145, RFC 3264 §5)。 sabiden 側は browser に SAVPF answer を
   * 返しつつ、 内部で AVP/PCMU SDP に変換した INVITE を NGN へ出す。
   *
   * `target` 省略時は旧来 echo モード (sabiden 内 str0m との折返し、 試験用)。
   */
  async createOffer(target?: string): Promise<void> {
    log(this.elapsed(), "createOffer start", { target });
    const offer = await this.pc.createOffer({ offerToReceiveAudio: true });
    log(this.elapsed(), "createOffer done", { sdp_len: offer.sdp?.length });
    await this.pc.setLocalDescription(offer);
    log(this.elapsed(), "setLocalDescription done");
    const msg: { type: "offer"; sdp: string; target?: string } = {
      type: "offer",
      sdp: offer.sdp ?? "",
    };
    if (target !== undefined) {
      msg.target = target;
    }
    this.signaling.send(msg);
    log(this.elapsed(), "offer sent over WS");
  }

  /** サーバから受け取った answer SDP を適用。 */
  async applyAnswer(sdp: string): Promise<void> {
    log(this.elapsed(), "applyAnswer start", { sdp_len: sdp.length });
    await this.pc.setRemoteDescription({ type: "answer", sdp });
    log(this.elapsed(), "applyAnswer done");
  }

  /**
   * NGN 着信 (sabiden 発の `ServerMessage::offer`) を受理し、
   * answer を生成してシグナリング経由で返送する。
   *
   * `acquireMic()` を先に呼んで送信トラックを準備しておくこと
   * (応答ボタン押下時に App から呼ぶ想定)。
   */
  async acceptIncomingOffer(callId: string, offerSdp: string): Promise<void> {
    log(this.elapsed(), "acceptIncomingOffer start", { call_id: callId, sdp_len: offerSdp.length });
    await this.pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    this.signaling.send({
      type: "answer",
      call_id: callId,
      sdp: answer.sdp ?? "",
    });
    log(this.elapsed(), "acceptIncomingOffer done, answer sent");
  }

  /**
   * サーバから受け取った ICE candidate を追加。
   *
   * Issue #92 / RFC 8840 §4 (Trickle ICE end-of-candidates) / W3C WebRTC
   * §4.4.1.6 (`RTCPeerConnection.addIceCandidate`): 空文字列 / `end-of-candidates`
   * 文字列は trickle ICE の **終端マーカ** であり、 candidate 本体ではない。
   * これを `addIceCandidate(null)` (= W3C 仕様で end-of-candidates と等価) に
   * 翻訳することで、 ブラウザ ICE エージェントは「以後候補は来ない」と確定し、
   * RFC 8445 §6.1.4 の nominated pair 不在 → ICE failed/disconnected 遷移
   * timer を即時起動できる。
   *
   * 旧挙動 (空文字列を silent return) では、 ブラウザは候補追加待ちで
   * `connectionState=failed` 検知が iceTransportPolicy の既定 timeout
   * (chromium で 30 秒以上) まで遅延し、 UI が「応答」 → 30 秒沈黙 → ended の
   * 遷移を起こしていた (Issue #92)。
   */
  async addIce(candidate: string): Promise<void> {
    // RFC 8840 §4 / W3C WebRTC §4.4.1.6: 空文字列 / `end-of-candidates` 文字列を
    // 終端マーカとして扱い、 null candidate (= end-of-candidates) に翻訳する。
    // server-side (sabiden `signaling.rs`) は両方の形式を「同じ意味」として送出
    // するため、 受信側はどちらでも end-of-candidates として処理する。
    const trimmed = candidate.trim();
    if (trimmed === "" || trimmed.includes("end-of-candidates")) {
      log(this.elapsed(), "addIce: end-of-candidates (RFC 8840 §4)");
      try {
        // W3C WebRTC §4.4.1.6: `addIceCandidate(null)` または
        // `addIceCandidate({ candidate: "" })` で end-of-candidates を表す。
        await this.pc.addIceCandidate(null);
      } catch (e) {
        // 古いブラウザは null を受理しない場合がある。 silent ignore (end-of-
        // candidates は MUST ではなく SHOULD なので、 不在でも ICE 確立自体は通る)。
        warn("addIceCandidate(null) failed (browser may not support it)", e);
      }
      return;
    }
    log(this.elapsed(), "addIce", { candidate });
    try {
      await this.pc.addIceCandidate({ candidate, sdpMid: "0", sdpMLineIndex: 0 });
    } catch (e) {
      // sdpMid が一致しない場合のフォールバック (Trickle ICE 半端実装対策)
      try {
        await this.pc.addIceCandidate({ candidate });
      } catch (e2) {
        warn("addIceCandidate failed", e, e2);
      }
    }
  }

  /** マイクのミュートを切り替える。返り値は新しい mute 状態。 */
  toggleMute(): boolean {
    if (!this.localStream) return false;
    const tracks = this.localStream.getAudioTracks();
    if (tracks.length === 0) return false;
    const newEnabled = !tracks[0]!.enabled;
    tracks.forEach((t) => (t.enabled = newEnabled));
    return !newEnabled; // mute = !enabled
  }

  hangup(): void {
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.localStream = null;
    this.pc.getSenders().forEach((s) => s.track && s.track.stop());
    try {
      this.pc.close();
    } catch {
      /* ignore */
    }
  }
}
