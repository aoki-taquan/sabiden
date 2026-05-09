// WebRTC PeerConnection ラッパ。
//
// sabiden は WebRTC ↔ G.711 トランスコードを Opus 経由で行うため、
// ブラウザは Opus / PCMU 両方を offer に含める。
// (Opus 優先: バックエンドが対応済み (#27))

import type { SignalingClient } from "./signaling";

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

  constructor(signaling: SignalingClient, events: CallEvents, iceServers?: RTCIceServer[]) {
    this.signaling = signaling;
    this.events = events;
    this.pc = new RTCPeerConnection({
      iceServers: iceServers ?? [{ urls: "stun:stun.cloudflare.com:3478" }],
      // 半二重音声でも sendrecv で問題なし。bundle/rtcp-mux は既定で有効。
    });
    this.remoteStream = new MediaStream();

    this.pc.ontrack = (ev) => {
      ev.streams[0]?.getTracks().forEach((t) => this.remoteStream.addTrack(t));
      this.events.onRemoteTrack(this.remoteStream);
    };

    this.pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        try {
          this.signaling.send({ type: "ice", candidate: ev.candidate.candidate });
        } catch (e) {
          console.warn("ICE send failed", e);
        }
      }
    };

    this.pc.onconnectionstatechange = () => {
      this.events.onConnectionState(this.pc.connectionState);
    };
  }

  /** マイクを取得して送信トラックに追加。 */
  async acquireMic(): Promise<void> {
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
      },
      video: false,
    });
    this.localStream.getTracks().forEach((t) => this.pc.addTrack(t, this.localStream!));
  }

  /** offer を作成し、シグナリング経由で送出する。 */
  async createOffer(): Promise<void> {
    const offer = await this.pc.createOffer({ offerToReceiveAudio: true });
    await this.pc.setLocalDescription(offer);
    this.signaling.send({ type: "offer", sdp: offer.sdp ?? "" });
  }

  /** サーバから受け取った answer SDP を適用。 */
  async applyAnswer(sdp: string): Promise<void> {
    await this.pc.setRemoteDescription({ type: "answer", sdp });
  }

  /**
   * NGN 着信 (sabiden 発の `ServerMessage::offer`) を受理し、
   * answer を生成してシグナリング経由で返送する。
   *
   * `acquireMic()` を先に呼んで送信トラックを準備しておくこと
   * (応答ボタン押下時に App から呼ぶ想定)。
   */
  async acceptIncomingOffer(callId: string, offerSdp: string): Promise<void> {
    await this.pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    this.signaling.send({
      type: "answer",
      call_id: callId,
      sdp: answer.sdp ?? "",
    });
  }

  /** サーバから受け取った ICE candidate を追加。 */
  async addIce(candidate: string): Promise<void> {
    if (!candidate) return;
    try {
      await this.pc.addIceCandidate({ candidate, sdpMid: "0", sdpMLineIndex: 0 });
    } catch (e) {
      // sdpMid が一致しない場合のフォールバック (Trickle ICE 半端実装対策)
      try {
        await this.pc.addIceCandidate({ candidate });
      } catch (e2) {
        console.warn("addIceCandidate failed", e, e2);
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
