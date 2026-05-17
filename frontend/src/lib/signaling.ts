// sabiden /signal WebSocket クライアント。
//
// バックエンドプロトコル (src/webrtc/signaling.rs と同期):
//   C→S: register / offer / answer{call_id,sdp} / decline{call_id} / ice / bye
//   S→C: registered / answer / offer{call_id,sdp} / cancel{call_id} / ice / error / bye
//
// Issue #107: `decline{call_id}` は ringing 中の着信を browser が拒否すると
// 送出する (RFC 3261 §21.6.2 603 Decline 相当)。 sabiden は対応する内線フォーク
// レッグを 603 Decline で集約し、 fork に他レッグが居なければ NGN へ 603 を返す。
// 「bye」 は WS セッション (=内線登録) ごと閉じる別物。
//
// 認証はクエリ `?token=...` (HMAC-SHA256 トークン) を用いる。
// `Authorization: Bearer` はブラウザ WS API では指定不可のためクエリのみ。
//
// 自動再接続 (Issue #119):
//   WebSocket は WiFi の電源管理 / モバイルデータ切替 / Cloudflare Tunnel idle
//   timeout (~100s) 等で簡単に切れる。 W3C WebSocket Standard §7.1.5 (close
//   handshake) / §11.7 (close events) では close からの再接続は application
//   責務と整理されているため、 本クライアントは exponential backoff
//   (1s, 2s, 4s, 8s, ..., cap 30s) + jitter で自動再接続する。 `close()` を
//   明示的に呼んだ場合は再接続しない。
//
// close code 別扱い (Issue #127, RFC 6455 §7.4, W3C WebSocket §7.1.5 / §11.7):
//   token 期限切れ等でサーバが WS upgrade を拒否したケースを再接続ループから
//   除外する必要がある (上記 backoff のままだと 30 秒周期で 401 を撃ち続け、
//   Cloudflare Access の rate-limit に当たる)。 本クライアントは close code を
//   3 つのカテゴリに分類する:
//
//     - normal (1000): 「正常終了」 RFC 6455 §7.4.1 / W3C WebSocket §7.1.5。
//       再接続しない (closed)。
//     - auth (1008 / 4xxx): 「ポリシー違反 / アプリ独自 close」
//       RFC 6455 §7.4.1, §7.4.2。 token 失効時の現状サーバ挙動は HTTP 401 で
//       WS upgrade させない (`src/webrtc/signaling.rs::ws_handler` →
//       `StatusCode::UNAUTHORIZED`) ため、 ブラウザは 1006 (Abnormal Closure) で
//       onclose を発火する。 1008 は **現サーバが emit しない** が、 将来
//       ハンドシェイク後に policy 違反で close するパスを追加した場合や、
//       Cloudflare Access 経由で WS Worker が独自に 1008 を返す構成でも止まる
//       ように、 防御的に permanent 分類に入れている。 永続的エラーとして扱い、
//       再接続しない (closed + reason="auth")。
//     - transient (1001 / 1006 / 1009 / 1011 / 1012 / その他): 「going away /
//       abnormal closure / message too big / internal server error / service
//       restart」 RFC 6455 §7.4.1。 既存の指数バックオフで再接続を継続。
//
//   ただし transient であっても `maxReconnectAttempts` (既定 20 回) に
//   達したら停止する (closed + reason="exhausted")。 累積遅延は backoff
//   `1+2+4+8+16+30×15 ≈ 481s ≈ 約 8 分` (per-attempt delay の単純積では
//   ない: 序盤は exponential、 7 回目以降は cap=30s)。
//
//   1011 (Internal Server Error) は **transient** 扱い (Issue #127 review #1):
//   sabiden サーバ (`src/webrtc/signaling.rs`) は WS keepalive Pong 不着 (=
//   モバイル WiFi スリープ / Cloudflare Tunnel 100s idle / 端末バックグラウンド)
//   時に 1011 で close してくる。 これは「token 失効」ではなく「無線の眠り」
//   なので、 1011 を permanent にすると Issue #119 の auto-reconnect が
//   keepalive 1 発で永続停止する回帰を起こす。 ループ防止は
//   `maxReconnectAttempts` (約 8 分上限) で達成済みなので、 1011 を permanent に
//   入れる利得がない。
//
//   1006 は token 失効でも瞬断でも区別が付かないため transient 扱い (再接続は
//   試みるが、 上限到達で必ず停止するためループにはならない)。 サーバが
//   1008 を返してくるパスは確実に auth として早期に止める。

export type ClientMessage =
  | { type: "register"; ext_id: string }
  /**
   * browser 発の SDP offer。
   * `target` を付けると PWA→NGN 発信フロー (Issue #145, RFC 3264 §5):
   * sabiden は browser に SAVPF answer を返しつつ、 内部で
   * SAVPF→AVP→PCMU 変換した SDP で NGN P-CSCF へ INVITE を出す。
   * `target` 無しは旧来 echo モード (sabiden 内 str0m と P2P 折返し、 試験用)。
   */
  | { type: "offer"; sdp: string; target?: string }
  /**
   * sabiden 発の offer (NGN 着信を browser に push) に対する応答。
   * `call_id` は対応する S→C `offer` のものをそのまま返す。
   */
  | { type: "answer"; call_id: string; sdp: string }
  /**
   * sabiden 発の offer (NGN 着信を browser に push) に対する **拒否** (Issue #107)。
   * ringing 中の着信を browser ユーザが「拒否」ボタンで拒んだことを sabiden に
   * 伝える。 RFC 3261 §21.6.2 (603 Decline) 相当。 sabiden は対応する fork レッグを
   * `LegResult::Failed { status: 603 }` に倒し、 fork に他レッグが居なければ
   * NGN へ 603 Decline を返す。
   *
   * `bye` (= WS セッション=内線登録ごと閉じる) とは別物。 個別の進行中着信のみ
   * 拒否し、 WS / 内線登録は維持する。
   */
  | { type: "decline"; call_id: string }
  | { type: "ice"; candidate: string }
  /**
   * Issue #294: PWA Web Push 購読を sabiden に登録する (RFC 8030 / RFC 8291
   * / RFC 8292 VAPID)。 Service Worker が `PushManager.subscribe` で得た
   * subscription を JSON 化して送る。 sabiden は AOR (= 認証済 ext_id) に
   * 紐づけて store に保存し、 NGN INVITE で push を fan-out する。
   */
  | {
      type: "pushsubscribe";
      endpoint: string;
      keys: { p256dh: string; auth: string };
    }
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
  /** Issue #294: PWA Web Push 購読登録成功通知。 endpoint は echo (idempotency 判定用)。 */
  | { type: "pushsubscribed"; endpoint: string }
  | { type: "bye" };

/**
 * 接続フェーズ。 UI 表示と再接続制御の両方に使う。
 *
 * - `idle`: `connect()` がまだ呼ばれていない / `close()` 後。
 * - `connecting`: 初回接続試行中 (open 待ち)。
 * - `open`: open 済み。 ハートビート的に messages を送受信できる。
 * - `reconnecting`: 一度 open した後 close され、 backoff 待ちまたは再 open 待ち。
 * - `closed`: `close()` で意図的に閉じた、 または永続的エラー / 上限到達で
 *   自動再接続を諦めた状態 (Issue #127)。 `onClosedReason(reason)` で詳細が
 *   分かる。
 */
export type SignalingState = "idle" | "connecting" | "open" | "reconnecting" | "closed";

/**
 * `closed` 状態の理由 (Issue #127)。 UI で 「token を入れ直してください」 等の
 * 文言を出し分けるために用いる。 W3C WebSocket §11.7 の `CloseEvent.code` を
 * 解釈して導出する。
 *
 * - `normal`: `client.close()` の明示呼び出し / RFC 6455 §7.4.1 1000 受信。
 * - `auth`: token 失効等でサーバが永続的にエラーを返した
 *   (RFC 6455 §7.4.1 1008 Policy Violation, §7.4.2 4xxx 私的使用域)。
 *   同じ token で再試行しても通らないため、 UI から再ログイン (token 再投入)
 *   を促す。
 * - `exhausted`: 一時的エラー (1006 等) が続き `maxReconnectAttempts` に
 *   達した。 1011 (Internal Server Error) もこのパス経由でしか到達しない。
 */
export type SignalingCloseReason = "normal" | "auth" | "exhausted";

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
  /**
   * 永続的に閉じた (= 自動再接続を諦めた) ときに、 理由付きで 1 度だけ発火する
   * (Issue #127)。 UI で 「認証失敗、 token を入れ直してください」 等を出すため。
   *
   * **API 契約 (この順序を future refactor で壊さないこと):**
   * 1. **同一 client インスタンスで生涯ちょうど 1 回だけ呼ばれる**
   *    (二重 close() / 二重 finalize() でも再発火しない、 `finalize` が
   *    `disposed` 既セット時に早期 return することで保証)。
   * 2. **`onStateChange("closed")` の直前に同期発火する** (call site:
   *    `finalize()` 内で `onClosedReason → setState("closed")` の順で呼ぶ)。
   *    UI 側で `closed` 状態を見たときに reason を取り損ねることが無いよう、
   *    state 遷移より前に通知する。
   * 3. **`connect()` Promise の reject よりも同期的に先に発火する**
   *    (永続 close 受信時、 ws.onclose ハンドラ内で `finalize()` →
   *    `onClosedReason()` を呼んでから、 同じハンドラで Promise を reject
   *    するため)。 これにより呼び出し側は catch ブロックで signaling 参照
   *    の null 化等から「reason 既処理かどうか」 を判定できる
   *    (App.tsx::connect の race fix も この保証に依存)。
   *
   * 呼ばれるトリガ:
   * - `client.close()` の明示呼び出し (reason=`normal`)
   * - 永続 close code 受信: 1000 (`normal`) / 1008 / 4xxx (`auth`)
   * - transient close code が `maxReconnectAttempts` を使い切る (`exhausted`)
   */
  onClosedReason?: (reason: SignalingCloseReason) => void;
};

/** 再接続 backoff の設定 (ms 単位)。 ユニットテストから差し替えるためにも export。 */
export type ReconnectOptions = {
  /** 1 回目の遅延。 既定 1000ms (Issue #119 DoD)。 */
  initialDelayMs: number;
  /** backoff 上限。 既定 30000ms (Issue #119 DoD)。 */
  maxDelayMs: number;
  /** 加算する jitter の上限 (0..maxJitterMs の uniform 乱数)。 既定 250ms。 */
  maxJitterMs: number;
  /**
   * 連続失敗の上限 (Issue #127)。 既定 20 回でギブアップ。
   *
   * 累積遅延の目安: backoff は `1s, 2s, 4s, 8s, 16s, 30s, 30s, ...` (cap=30s)
   * なので `1+2+4+8+16+30×15 ≈ 481 秒 ≈ 約 8 分` でやっと諦める計算。
   * 「30s × 20 = 10 分」 という直感的計算は per-attempt delay の単純積で
   * あって正しくない (序盤 6 回が exponential 区間で短いため)。
   *
   * 0 以下を渡すと 「無制限」 として扱う (テスト用)。 既存の Issue #119 テスト
   * との互換のため optional。
   */
  maxReconnectAttempts?: number;
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
  maxReconnectAttempts: 20,
  setTimeout: (h, ms) => window.setTimeout(h, ms) as unknown as number,
  clearTimeout: (id) => window.clearTimeout(id),
  random: Math.random,
};

/**
 * close code → 永続的か (= 再接続をやめるべきか) の判定。
 * W3C WebSocket §11.7 で UA から渡される `CloseEvent.code` を分類する。
 *
 * - RFC 6455 §7.4.1 1000 (Normal Closure): サーバ / クライアントが行儀よく
 *   閉じた。 再接続しない。
 * - RFC 6455 §7.4.1 1008 (Policy Violation): token が認証ポリシー上 invalid。
 *   再試行しても通らない。 **現サーバ (`src/webrtc/signaling.rs`) は emit しない**
 *   (HTTP 401 で WS upgrade を拒否 → ブラウザは 1006 で onclose) が、 将来
 *   ハンドシェイク完了後の policy 違反 close や Cloudflare Access Worker が
 *   1008 を返す構成のために防御的に permanent 分類に入れている。
 * - RFC 6455 §7.4.2 4000-4999 (private use): アプリ独自 close。 sabiden Worker /
 *   sabiden 本体は token 失効を 4401 / 4403 等で送出する想定 (現状未実装、 防御的
 *   分類)。 RFC 上もこの帯はアプリ仕様で定義してよい。
 *
 * 注意: 1011 (Internal Server Error) は **transient** として扱う
 * (Issue #127 review #1)。 sabiden サーバの WS keepalive idle timeout が
 * 1011 で close するため (`src/webrtc/signaling.rs::ws_loop`)、 permanent に
 * すると Issue #119 の auto-reconnect が keepalive 1 発で永続停止する。
 * ループ防止は `maxReconnectAttempts` で達成済み。
 */
export function isPermanentCloseCode(code: number): boolean {
  if (code === 1000) return true;
  if (code === 1008) return true;
  if (code >= 4000 && code <= 4999) return true;
  return false;
}

/**
 * close code から `closed` 理由を導出する (永続終了確定時のみ呼ばれる)。
 * 1000 のみ `normal`、 それ以外の永続コード (1008 / 4xxx) は `auth` 扱い
 * (UI に「認証失敗」 を出す)。 W3C WebSocket §11.7 の `CloseEvent.code` 解釈。
 */
export function permanentCloseReason(code: number): SignalingCloseReason {
  if (code === 1000) return "normal";
  return "auth";
}

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
      if (this.disposed) {
        // close() 経由の close。 setState("closed") は close() 側で済んでいる。
        return;
      }
      // RFC 6455 §7.4 / W3C WebSocket §11.7: close code を見て auth 失敗等の
      // 永続的エラーを再接続ループから除外する (Issue #127)。 1006 (abnormal
      // closure) と 1011 (internal server error / keepalive idle timeout) は
      // 瞬断の判別が付かないので transient 扱い (上限到達で必ず止まる)。
      if (isPermanentCloseCode(ev.code)) {
        this.finalize(permanentCloseReason(ev.code));
        return;
      }
      this.scheduleReconnect();
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
   *
   * Issue #127: `maxReconnectAttempts` 到達で諦める (closed + reason="exhausted")。
   * これにより token 失効が close code 1006 (= 再接続継続) に化けるブラウザでも
   * 永久ループを回避できる。 既定 20 回での累積遅延は約 8 分
   * (`1+2+4+8+16+30×15 ≈ 481s`、 ReconnectOptions.maxReconnectAttempts の
   *  docstring 参照)。
   */
  private scheduleReconnect(): void {
    if (this.disposed) return;
    if (this.reconnectTimer !== null) return; // 二重スケジュール防止

    if (
      this.opts.maxReconnectAttempts > 0 &&
      this.reconnectAttempts >= this.opts.maxReconnectAttempts
    ) {
      this.finalize("exhausted");
      return;
    }

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

  /**
   * 再接続を諦めて closed 状態に移行する (Issue #127)。 `disposed=true` を立て、
   * pending timer を片付け、 onClosedReason / onStateChange を発火する。
   * 以後 `connect()` 等は no-op (Promise.reject) になる。
   *
   * 順序契約 (SignalingHandlers.onClosedReason の docstring と対):
   *   `disposed=true` 早期 return → 1 回限定発火を保証
   *   `onClosedReason(reason)` → 同期発火 (state は依然 reconnecting/connecting)
   *   `setState("closed")` → onStateChange("closed") を発火
   * future refactor でこの順序を変えると 「UI が reason を取り損ねる」
   * 「二重発火する」 等の回帰が出るため触らない。
   */
  private finalize(reason: SignalingCloseReason): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.reconnectTimer !== null) {
      this.opts.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws = null;
    try {
      this.handlers.onClosedReason?.(reason);
    } catch (e) {
      console.error("signaling onClosedReason handler threw", e);
    }
    this.setState("closed");
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
    if (this.disposed) return;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify({ type: "bye" } satisfies ClientMessage));
      } catch {
        /* ignore */
      }
    }
    try {
      // RFC 6455 §7.1.1 / §7.4.1 1000 (Normal Closure) で閉じる。
      this.ws?.close(1000, "client close");
    } catch {
      /* ignore */
    }
    this.finalize("normal");
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
 * `ServerMessage::error` の `message` 本文から retry_after 秒数を抽出する
 * (Issue #194, PR #193 連動)。
 *
 * sabiden backend (`src/call/orchestrator.rs`) は PWA が SIP dialog を持たない
 * ため、 NGN P-CSCF / 自前 rate limiter からの抑制秒数を **WS の
 * `ServerMessage::error.message` 本文に文字列埋込** で渡す (構造化フィールドは
 * wire format 互換性のため追加していない、 Issue #194 「touch しない」 領域)。
 * RFC 3261 §20.33 Retry-After / TTC JJ-90.24v2 §5.7.1 (連続抑制) /
 * §5.7.3 (5xx 自動 retry 禁止) を PWA UI 側で観測できる経路はこの埋込のみ。
 *
 * backend 既知の 2 系統 (orchestrator.rs ソース由来):
 *
 *   1. `rate_limited`:
 *      `"outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after <N> sec"`
 *      → `retry after <N> sec` を拾う。
 *   2. `outbound_failed` (NGN 503 + Retry-After):
 *      `"NGN INVITE 失敗: 503 Service Unavailable (retry_after=<N>s)"`
 *      → `retry_after=<N>s` を拾う。
 *
 * どちらの形式でも非負整数の秒数のみ受け付ける。 該当パターンが無い (例:
 * `outbound_failed` で NGN が Retry-After を返さなかったケース) や、 0 以下 /
 * NaN の場合は `null` (= UI ロックを開始しない)。
 *
 * 純関数 (副作用なし)。 vitest からそのまま呼べる。
 */
export function parseRateLimitedRetryAfter(message: string): number | null {
  // 1) `rate_limited` 形式: `retry after <N> sec` (英大小は backend で固定だが念のため大小無視)。
  const m1 = /retry\s+after\s+(\d+)\s*sec/i.exec(message);
  if (m1) {
    const n = Number(m1[1]);
    if (Number.isFinite(n) && n > 0) return n;
  }
  // 2) `outbound_failed` 形式: `retry_after=<N>s` (orchestrator.rs PR #193 review #2 🟡#1)。
  const m2 = /retry_after\s*=\s*(\d+)\s*s/i.exec(message);
  if (m2) {
    const n = Number(m2[1]);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return null;
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
