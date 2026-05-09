// sabiden /signal WebSocket クライアント。
//
// バックエンドプロトコル (src/webrtc/signaling.rs と同期):
//   C→S: register / offer / answer{call_id,sdp} / ice / bye
//   S→C: registered / answer / offer{call_id,sdp} / cancel{call_id} / ice / error / bye
//
// 認証はクエリ `?token=...` (HMAC-SHA256 トークン) を用いる。
// `Authorization: Bearer` はブラウザ WS API では指定不可のためクエリのみ。
//
// 自動再接続 (Issue #119):
//   WebSocket は WiFi の電源管理 / モバイルデータ切替 / Cloudflare Tunnel idle
//   timeout (~100s) 等で簡単に切れる。 W3C WebSocket API §10.7 では「open 後の
//   close からの再接続は application 責務」 と明記されているため、 本クライアント
//   は exponential backoff (1s, 2s, 4s, 8s, ..., cap 30s) + jitter で自動再接続
//   する。 `close()` を明示的に呼んだ場合は再接続しない。

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

/**
 * 接続フェーズ。 UI 表示と再接続制御の両方に使う。
 *
 * - `idle`: `connect()` がまだ呼ばれていない / `close()` 後。
 * - `connecting`: 初回接続試行中 (open 待ち)。
 * - `open`: open 済み。 ハートビート的に messages を送受信できる。
 * - `reconnecting`: 一度 open した後 close され、 backoff 待ちまたは再 open 待ち。
 * - `closed`: `close()` で意図的に閉じた。 自動再接続しない。
 */
export type SignalingState = "idle" | "connecting" | "open" | "reconnecting" | "closed";

export type SignalingHandlers = {
  onMessage: (msg: ServerMessage) => void;
  /**
   * 接続が open するたびに発火する (初回および再接続成功時)。
   * 内線の Re-Register 等の「接続復活時に毎回必要な処理」 はここで送る。
   */
  onOpen?: () => void;
  /**
   * underlying WebSocket が close したときに発火する。
   * `client.state === "reconnecting"` であればこの後 backoff で再 connect する。
   * `closed` であれば再接続しない。
   */
  onClose?: (ev: CloseEvent) => void;
  onError?: (ev: Event) => void;
  /** 状態変化通知 (UI 表示用)。 */
  onStateChange?: (state: SignalingState) => void;
};

/** 再接続 backoff の設定 (ms 単位)。 ユニットテストから差し替えるためにも export。 */
export type ReconnectOptions = {
  /** 1 回目の遅延。 既定 1000ms (Issue #119 DoD)。 */
  initialDelayMs: number;
  /** backoff 上限。 既定 30000ms (Issue #119 DoD)。 */
  maxDelayMs: number;
  /** 加算する jitter の上限 (0..maxJitterMs の uniform 乱数)。 既定 250ms。 */
  maxJitterMs: number;
  /** WebSocket factory。 テストから mock を注入するため。 既定は `new WebSocket(url)`。 */
  webSocketFactory?: (url: string) => WebSocket;
  /** setTimeout / clearTimeout を差し替えるためのフック (fake timer 用)。 */
  setTimeout?: (handler: () => void, ms: number) => number;
  clearTimeout?: (id: number) => void;
  /** 0..1 の乱数。 jitter に使う。 既定は `Math.random`。 */
  random?: () => number;
};

const DEFAULT_RECONNECT: Required<Omit<ReconnectOptions, "webSocketFactory">> = {
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  maxJitterMs: 250,
  setTimeout: (h, ms) => window.setTimeout(h, ms) as unknown as number,
  clearTimeout: (id) => window.clearTimeout(id),
  random: Math.random,
};

export class SignalingClient {
  private ws: WebSocket | null = null;
  private readonly url: string;
  private readonly handlers: SignalingHandlers;
  private readonly opts: Required<Omit<ReconnectOptions, "webSocketFactory">> & {
    webSocketFactory: (url: string) => WebSocket;
  };

  /** UI 用に外部公開する論理状態 (WebSocket.readyState とは別)。 */
  private _state: SignalingState = "idle";
  /** backoff 待ちの timer id。 `close()` 時に clear する。 */
  private reconnectTimer: number | null = null;
  /** 連続失敗回数 (open 成功でリセットする)。 */
  private reconnectAttempts = 0;
  /** `close()` 済みフラグ。 一度でも close すると以降再接続しない。 */
  private disposed = false;

  constructor(
    baseUrl: string,
    token: string,
    handlers: SignalingHandlers,
    options?: ReconnectOptions,
  ) {
    const u = new URL(baseUrl);
    u.searchParams.set("token", token);
    this.url = u.toString();
    this.handlers = handlers;
    this.opts = {
      ...DEFAULT_RECONNECT,
      ...(options ?? {}),
      webSocketFactory: options?.webSocketFactory ?? ((url) => new WebSocket(url)),
    };
  }

  /**
   * 初回接続。 resolve するのは最初の `open` イベントが届いた時点。
   * 以後 close されたら自動で再接続する (この Promise は再接続を待たない)。
   *
   * 失敗 (open 前に error/close) した場合は reject するが、 reject の有無に
   * 関わらず内部では再接続スケジュールを始める。 これにより 「最初の試行は失敗
   * したがネットワーク復旧後は自動で繋がる」 ケースを成立させる。
   */
  connect(): Promise<void> {
    if (this.disposed) {
      return Promise.reject(new Error("signaling: client is closed"));
    }
    return new Promise((resolve, reject) => {
      this.openSocket({
        onOpen: () => resolve(),
        onFail: (err) => reject(err),
      });
    });
  }

  /**
   * 内部用: 新しい WebSocket を 1 つ張る。 close されたら自動で次の attempt を
   * scheduleReconnect する。 connect() の Promise resolve/reject は最初の 1 度
   * だけ呼ぶ (後続の再接続では呼ばない)。
   */
  private openSocket(promise?: { onOpen: () => void; onFail: (e: Error) => void }): void {
    if (this.disposed) return;

    this.setState(this.reconnectAttempts === 0 ? "connecting" : "reconnecting");

    let ws: WebSocket;
    try {
      ws = this.opts.webSocketFactory(this.url);
    } catch (e) {
      // factory 自体が同期 throw した: 即時 backoff へ。
      const err = e instanceof Error ? e : new Error("WebSocket factory threw");
      promise?.onFail(err);
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;

    let settled = false;

    ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.setState("open");
      try {
        this.handlers.onOpen?.();
      } catch (e) {
        console.error("signaling onOpen handler threw", e);
      }
      if (!settled && promise) {
        settled = true;
        promise.onOpen();
      }
    };

    ws.onmessage = (ev) => {
      const data = typeof ev.data === "string" ? ev.data : "";
      const msg = parseServerMessage(data);
      if (!msg) {
        console.error("Failed to parse signaling message", ev.data);
        return;
      }
      this.handlers.onMessage(msg);
    };

    ws.onclose = (ev) => {
      try {
        this.handlers.onClose?.(ev);
      } catch (e) {
        console.error("signaling onClose handler threw", e);
      }
      this.ws = null;
      if (!settled && promise) {
        settled = true;
        promise.onFail(new Error(`WebSocket closed before open (code=${ev.code})`));
      }
      if (!this.disposed) {
        this.scheduleReconnect();
      } else {
        this.setState("closed");
      }
    };

    ws.onerror = (ev) => {
      try {
        this.handlers.onError?.(ev);
      } catch (e) {
        console.error("signaling onError handler threw", e);
      }
      // open 前に error が来た場合は close も続けて来る (W3C §10.6 step 3)。
      // ここでは reject せず onclose に任せて backoff を一本化する。
    };
  }

  /**
   * 次の再接続を schedule する。 `1s, 2s, 4s, 8s, ..., cap 30s` + 小さな jitter。
   * Issue #119 の DoD に従う。
   */
  private scheduleReconnect(): void {
    if (this.disposed) return;
    if (this.reconnectTimer !== null) return; // 二重スケジュール防止

    const base = Math.min(
      this.opts.maxDelayMs,
      this.opts.initialDelayMs * 2 ** this.reconnectAttempts,
    );
    const jitter = this.opts.random() * this.opts.maxJitterMs;
    const delay = base + jitter;

    this.setState("reconnecting");
    this.reconnectTimer = this.opts.setTimeout(() => {
      this.reconnectTimer = null;
      this.reconnectAttempts++;
      this.openSocket();
    }, delay);
  }

  send(msg: ClientMessage): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("signaling: not connected");
    }
    this.ws.send(JSON.stringify(msg));
  }

  /**
   * 明示的に閉じる。 以後自動再接続しない。
   * pending な backoff timer もキャンセルする。
   */
  close(): void {
    this.disposed = true;
    if (this.reconnectTimer !== null) {
      this.opts.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify({ type: "bye" } satisfies ClientMessage));
      } catch {
        /* ignore */
      }
    }
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
    this.ws = null;
    this.setState("closed");
  }

  get state(): SignalingState {
    return this._state;
  }

  /** WebSocket の readyState を直接見たい場合の escape hatch (デバッグ用)。 */
  get readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }

  private setState(s: SignalingState): void {
    if (this._state === s) return;
    this._state = s;
    try {
      this.handlers.onStateChange?.(s);
    } catch (e) {
      console.error("signaling onStateChange handler threw", e);
    }
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
