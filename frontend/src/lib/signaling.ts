// sabiden /signal WebSocket クライアント。
//
// バックエンドプロトコル (src/webrtc/signaling.rs と同期):
//   C→S: register / offer / answer{call_id,sdp} / ice / bye
//   S→C: registered / answer / offer{call_id,sdp} / cancel{call_id} / ice / error / bye
//
// 認証はクエリ `?token=...` (HMAC-SHA256 トークン) を用いる。
// `Authorization: Bearer` はブラウザ WS API では指定不可のためクエリのみ。

export type ClientMessage =
  | { type: "register"; ext_id: string }
  | { type: "offer"; sdp: string }
  /**
   * sabiden 発の offer (NGN 着信を browser に push) に対する応答。
   * `call_id` は対応する S→C `offer` のものをそのまま返す。
   */
  | { type: "answer"; call_id: string; sdp: string }
  | { type: "ice"; candidate: string }
  | { type: "bye" };

export type ServerMessage =
  | { type: "registered"; ext_id: string }
  /** browser 発の offer に対する sabiden の answer。 */
  | { type: "answer"; sdp: string }
  /**
   * NGN 着信 INVITE を browser に push する offer。
   * browser は `ClientMessage::answer` で `call_id` を含めて応答する。
   */
  | { type: "offer"; call_id: string; sdp: string }
  /** 進行中の着信が NGN CANCEL 等で中止されたことを browser に通知する。 */
  | { type: "cancel"; call_id: string }
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
        const msg = parseServerMessage(typeof ev.data === "string" ? ev.data : "");
        if (!msg) {
          console.error("Failed to parse signaling message", ev.data);
          return;
        }
        this.handlers.onMessage(msg);
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
 * 受信した WS テキストフレームを `ServerMessage` にパースする。
 * 不正な JSON / 既知でない `type` / 必須フィールド欠落の場合は `null`。
 *
 * 純関数なのでテストから直接呼び出して `offer` / `cancel` 等の round-trip を
 * 確認できる。実 WS から切り離して検証するために `SignalingClient` から
 * 抽出している。
 */
export function parseServerMessage(raw: string): ServerMessage | null {
  let obj: unknown;
  try {
    obj = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  const t = o.type;
  if (typeof t !== "string") return null;

  const str = (k: string): string | null => (typeof o[k] === "string" ? (o[k] as string) : null);

  switch (t) {
    case "registered": {
      const ext_id = str("ext_id");
      return ext_id === null ? null : { type: "registered", ext_id };
    }
    case "answer": {
      const sdp = str("sdp");
      return sdp === null ? null : { type: "answer", sdp };
    }
    case "offer": {
      const call_id = str("call_id");
      const sdp = str("sdp");
      return call_id === null || sdp === null ? null : { type: "offer", call_id, sdp };
    }
    case "cancel": {
      const call_id = str("call_id");
      return call_id === null ? null : { type: "cancel", call_id };
    }
    case "ice": {
      const candidate = str("candidate");
      return candidate === null ? null : { type: "ice", candidate };
    }
    case "error": {
      const code = str("code");
      const message = str("message");
      return code === null || message === null ? null : { type: "error", code, message };
    }
    case "bye":
      return { type: "bye" };
    default:
      return null;
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
