// sabiden /signal WebSocket クライアント。
//
// バックエンドプロトコル (src/webrtc/signaling.rs と同期):
//   C→S: register / offer / answer / ice / bye
//   S→C: registered / answer / ice / error / bye
//
// 認証はクエリ `?token=...` (HMAC-SHA256 トークン) を用いる。
// `Authorization: Bearer` はブラウザ WS API では指定不可のためクエリのみ。

export type ClientMessage =
  | { type: "register"; ext_id: string }
  | { type: "offer"; sdp: string }
  | { type: "answer"; sdp: string }
  | { type: "ice"; candidate: string }
  | { type: "bye" };

export type ServerMessage =
  | { type: "registered"; ext_id: string }
  | { type: "answer"; sdp: string }
  | { type: "ice"; candidate: string }
  | { type: "error"; code: string; message: string }
  | { type: "bye" };

export type SignalingHandlers = {
  onMessage: (msg: ServerMessage) => void;
  onOpen?: () => void;
  onClose?: (ev: CloseEvent) => void;
  onError?: (ev: Event) => void;
};

export class SignalingClient {
  private ws: WebSocket | null = null;
  private readonly url: string;
  private readonly handlers: SignalingHandlers;

  constructor(baseUrl: string, token: string, handlers: SignalingHandlers) {
    const u = new URL(baseUrl);
    u.searchParams.set("token", token);
    this.url = u.toString();
    this.handlers = handlers;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.onopen = () => {
        this.handlers.onOpen?.();
        resolve();
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as ServerMessage;
          this.handlers.onMessage(msg);
        } catch (e) {
          console.error("Failed to parse signaling message", e, ev.data);
        }
      };
      ws.onclose = (ev) => this.handlers.onClose?.(ev);
      ws.onerror = (ev) => {
        this.handlers.onError?.(ev);
        // open 前のエラー = 接続失敗
        if (ws.readyState !== WebSocket.OPEN) reject(new Error("WebSocket connect failed"));
      };
    });
  }

  send(msg: ClientMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("signaling: not connected");
    }
    this.ws.send(JSON.stringify(msg));
  }

  close(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify({ type: "bye" } satisfies ClientMessage));
      } catch {
        /* ignore */
      }
    }
    this.ws?.close();
    this.ws = null;
  }

  get state(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }
}

/**
 * トークン形式 `<ext_id>.<expiry>.<sig>` から ext_id だけ取り出す。
 * 署名検証はサーバ側で行う (クライアントは秘密鍵を持たない)。
 */
export function parseExtIdFromToken(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  return parts[0] ?? null;
}

/** 既定のシグナリング URL を解決する (env > 同一オリジン)。 */
export function resolveSignalingUrl(): string {
  const fromEnv = import.meta.env.VITE_SIGNAL_URL as string | undefined;
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/signal`;
}
