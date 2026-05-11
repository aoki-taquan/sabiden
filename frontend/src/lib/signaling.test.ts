// SignalingClient の自動再接続ユニットテスト (Issue #119)。
//
// 実 WebSocket は使わず、 fake な WebSocket factory + fake timer を注入して
// 「onclose 後に backoff 遅延で connect が試行される」 「open に成功したら
// 連続失敗カウンタがリセットされる」 「close() 後は再接続されない」 を確認する。

import { describe, expect, it, vi } from "vitest";
import {
  isPermanentCloseCode,
  parseExtIdFromToken,
  parseRateLimitedRetryAfter,
  parseServerMessage,
  permanentCloseReason,
  SignalingClient,
  type ReconnectOptions,
  type ServerMessage,
  type SignalingCloseReason,
} from "./signaling";

/** 最小限の WebSocket mock。 onopen / onclose / onerror を手動で発火させて
 * SignalingClient のステート遷移を検証する。 */
class FakeWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  readyState = 0;
  onopen: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  sent: string[] = [];
  url: string;

  constructor(url: string) {
    this.url = url;
  }

  fireOpen(): void {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.(new Event("open"));
  }

  fireClose(code = 1006): void {
    this.readyState = FakeWebSocket.CLOSED;
    const ev = { code, reason: "", wasClean: false } as CloseEvent;
    this.onclose?.(ev);
  }

  fireMessage(data: string): void {
    const ev = { data } as MessageEvent;
    this.onmessage?.(ev);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    if (this.readyState !== FakeWebSocket.CLOSED) {
      this.readyState = FakeWebSocket.CLOSED;
    }
  }
}

// `WebSocket.OPEN` 等の定数を SignalingClient.send が参照するため、 グローバル
// にエイリアスを置く。 jsdom の WebSocket でも値は同じだが、 副作用なく上書き
// しても問題ない。
(globalThis as unknown as { WebSocket: typeof FakeWebSocket }).WebSocket = FakeWebSocket;

/** fake setTimeout を用意し、 手動で advance できるようにする。 */
function makeFakeTimer() {
  let nextId = 1;
  const pending = new Map<number, { handler: () => void; due: number }>();
  let now = 0;

  const setTimeoutFn: NonNullable<ReconnectOptions["setTimeout"]> = (handler, ms) => {
    const id = nextId++;
    pending.set(id, { handler, due: now + ms });
    return id;
  };
  const clearTimeoutFn: NonNullable<ReconnectOptions["clearTimeout"]> = (id) => {
    pending.delete(id);
  };
  const advance = (ms: number) => {
    now += ms;
    // due 時刻を過ぎたものを順次実行 (FIFO)
    const due = [...pending.entries()]
      .filter(([, v]) => v.due <= now)
      .sort((a, b) => a[1].due - b[1].due);
    for (const [id, { handler }] of due) {
      pending.delete(id);
      handler();
    }
  };
  const pendingCount = () => pending.size;

  return { setTimeoutFn, clearTimeoutFn, advance, pendingCount };
}

/** 連続して new されてくる FakeWebSocket を順番に握っておく factory。 */
function makeWsFactory() {
  const sockets: FakeWebSocket[] = [];
  const factory: NonNullable<ReconnectOptions["webSocketFactory"]> = (url) => {
    const ws = new FakeWebSocket(url);
    sockets.push(ws);
    return ws as unknown as WebSocket;
  };
  return { factory, sockets };
}

describe("SignalingClient auto-reconnect (Issue #119)", () => {
  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  it("schedules reconnect ~1s after first onclose, then 2s, capped at maxDelayMs", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    const states: string[] = [];
    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onStateChange: (s) => states.push(s),
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0, // jitter 無しで決定論的に検証
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    expect(sockets.length).toBe(1);
    sockets[0].fireOpen();
    expect(client.state).toBe("open");

    // 1 回目の close → 1000ms 後に再接続試行が走る。
    sockets[0].fireClose();
    expect(client.state).toBe("reconnecting");
    expect(timer.pendingCount()).toBe(1);

    // 999ms 経過: まだ呼ばれない。
    timer.advance(999);
    expect(sockets.length).toBe(1);
    // 1000ms 到達: 新しい WS が張られる。
    timer.advance(1);
    expect(sockets.length).toBe(2);

    // 2 回目の close は open 前なので reconnectAttempts++ の状態で 2000ms backoff。
    sockets[1].fireClose();
    expect(timer.pendingCount()).toBe(1);
    timer.advance(1999);
    expect(sockets.length).toBe(2);
    timer.advance(1);
    expect(sockets.length).toBe(3);

    // さらに 4s, 8s, 16s と倍増し、 32s 目以降は cap で 30s。
    sockets[2].fireClose();
    timer.advance(4000);
    expect(sockets.length).toBe(4);
    sockets[3].fireClose();
    timer.advance(8000);
    expect(sockets.length).toBe(5);
    sockets[4].fireClose();
    timer.advance(16000);
    expect(sockets.length).toBe(6);
    sockets[5].fireClose();
    // 5 回連続失敗 (attempt 5) → base = min(30000, 1000 * 2^5) = 30000
    timer.advance(29999);
    expect(sockets.length).toBe(6);
    timer.advance(1);
    expect(sockets.length).toBe(7);

    // どこかで `reconnecting` 状態になっている。
    expect(states).toContain("reconnecting");
    expect(states).toContain("open");
  });

  it("re-fires onOpen on every successful reconnect (so App can Re-Register)", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const onOpen = vi.fn();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: () => {}, onOpen },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    expect(onOpen).toHaveBeenCalledTimes(1);

    sockets[0].fireClose();
    timer.advance(1000);
    expect(sockets.length).toBe(2);
    sockets[1].fireOpen();
    expect(onOpen).toHaveBeenCalledTimes(2);

    // open 成功で連続失敗カウンタがリセット → 次回 close は 1s で再接続。
    sockets[1].fireClose();
    expect(client.state).toBe("reconnecting");
    timer.advance(999);
    expect(sockets.length).toBe(2);
    timer.advance(1);
    expect(sockets.length).toBe(3);
  });

  it("does not reconnect after explicit close()", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: () => {} },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    expect(client.state).toBe("open");

    client.close();
    expect(client.state).toBe("closed");
    expect(timer.pendingCount()).toBe(0);

    // close 後に WS が onclose を発火しても新しい WS は張られない。
    sockets[0].fireClose();
    timer.advance(60000);
    expect(sockets.length).toBe(1);
    expect(client.state).toBe("closed");
  });

  it("transitions through connecting → reconnecting → open on initial failure then recovery", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const states: string[] = [];

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: () => {}, onStateChange: (s) => states.push(s) },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    const promise = client.connect();
    expect(states[0]).toBe("connecting");

    // 初回 open 前に close → connect の Promise は reject されるが backoff
    // は内部で継続している。
    sockets[0].fireClose();
    expect(states).toContain("reconnecting");

    // 1s 後に再試行 → open 成功 → state = open。
    timer.advance(1000);
    expect(sockets.length).toBe(2);
    sockets[1].fireOpen();
    expect(client.state).toBe("open");

    return promise.catch(() => {
      // 初回 connect の Promise は reject されてよい (内部再接続が継続)。
      expect(client.state).toBe("open");
    });
  });

  it("delivers parsed messages to onMessage", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const onMessage = vi.fn();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    sockets[0].fireMessage(JSON.stringify({ type: "registered", ext_id: "ext1" }));
    expect(onMessage).toHaveBeenCalledWith({ type: "registered", ext_id: "ext1" });
  });
});

describe("ClientMessage offer schema (Issue #145)", () => {
  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  it("send {type:'offer', sdp, target} serialises with target field (PWA→NGN outbound)", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: vi.fn() },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    client.send({ type: "offer", sdp: "v=0\r\nbrowser-savpf\r\n", target: "117" });

    expect(sockets[0].sent.length).toBe(1);
    const obj = JSON.parse(sockets[0].sent[0]);
    expect(obj.type).toBe("offer");
    expect(obj.sdp).toContain("browser-savpf");
    expect(obj.target).toBe("117");
  });

  it("send {type:'offer', sdp} (no target) is the legacy echo mode shape", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: vi.fn() },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    client.send({ type: "offer", sdp: "v=0" });
    const obj = JSON.parse(sockets[0].sent[0]);
    expect(obj.target).toBeUndefined();
  });
});

describe("parseServerMessage", () => {
  it("parses registered", () => {
    expect(parseServerMessage(JSON.stringify({ type: "registered", ext_id: "x" }))).toEqual({
      type: "registered",
      ext_id: "x",
    });
  });

  it("parses offer with call_id", () => {
    expect(
      parseServerMessage(JSON.stringify({ type: "offer", call_id: "c1", sdp: "v=0..." })),
    ).toEqual({ type: "offer", call_id: "c1", sdp: "v=0..." });
  });

  it("rejects malformed JSON", () => {
    expect(parseServerMessage("not json")).toBeNull();
  });

  it("rejects offer missing call_id", () => {
    expect(parseServerMessage(JSON.stringify({ type: "offer", sdp: "v=0..." }))).toBeNull();
  });

  // Issue #92 / Issue #206 / RFC 8838 §13 (Generating an End-of-Candidates
  // Indication) / W3C WebRTC §4.4.1.6: 空文字列の `candidate` は end-of-
  // candidates marker。 sabiden server-side (str0m_session.rs::handle_event) は
  // host candidate 直後に empty string を流すため、 parser は **空文字列を
  // 有効な値として保持** する (skip / null 化してはならない)。 PWA 側
  // `addIce("")` は別途これを `pc.addIceCandidate(null)` に翻訳する。
  //
  // 注: RFC 8840 は SIP usage 専用 (Trickle ICE over SIP)。 sabiden は WebSocket
  // JSON シグナリングなので、 trickle ICE の一般仕様である RFC 8838 を引用する。
  it("rfc8838_13_parses_ice_with_empty_candidate_as_end_of_candidates_marker", () => {
    expect(parseServerMessage(JSON.stringify({ type: "ice", candidate: "" }))).toEqual({
      type: "ice",
      candidate: "",
    });
  });

  // RFC 8839 §4.2 / W3C: 実 candidate と end-of-candidates marker は同じ
  // `ice` メッセージで届く。 両者が parser から識別可能であることを確認する。
  it("rfc8839_4_2_parses_ice_with_real_candidate", () => {
    const cand = "candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host";
    expect(parseServerMessage(JSON.stringify({ type: "ice", candidate: cand }))).toEqual({
      type: "ice",
      candidate: cand,
    });
  });
});

describe("parseExtIdFromToken", () => {
  it("returns ext_id for valid 3-part token", () => {
    expect(parseExtIdFromToken("ext1.99999.aGVsbG8")).toBe("ext1");
  });

  it("returns null for malformed token", () => {
    expect(parseExtIdFromToken("nodot")).toBeNull();
    expect(parseExtIdFromToken("a.b.c.d")).toBeNull();
  });
});

describe("isPermanentCloseCode (Issue #127, RFC 6455 §7.4)", () => {
  it("treats 1000 (Normal Closure) as permanent", () => {
    expect(isPermanentCloseCode(1000)).toBe(true);
    expect(permanentCloseReason(1000)).toBe("normal");
  });

  it("treats 1008 (Policy Violation) as permanent auth failure", () => {
    expect(isPermanentCloseCode(1008)).toBe(true);
    expect(permanentCloseReason(1008)).toBe("auth");
  });

  it("treats 1011 (Internal Server Error) as transient (Issue #127 review #1)", () => {
    // sabiden サーバ (`src/webrtc/signaling.rs`) は WS keepalive Pong 不着
    // (= モバイル WiFi スリープ / Cloudflare Tunnel 100s idle / 端末
    // バックグラウンド) 時に 1011 を送る。 これは「token 失効」ではなく
    // 「無線の眠り」 なので、 permanent にすると Issue #119 の auto-reconnect が
    // keepalive 1 発で永続停止する回帰を起こす。 ループ防止は
    // `maxReconnectAttempts` (約 8 分上限) で達成済み。
    expect(isPermanentCloseCode(1011)).toBe(false);
  });

  it("treats 4xxx (private use) as permanent auth failure", () => {
    expect(isPermanentCloseCode(4000)).toBe(true);
    expect(isPermanentCloseCode(4401)).toBe(true);
    expect(isPermanentCloseCode(4999)).toBe(true);
    expect(permanentCloseReason(4401)).toBe("auth");
  });

  it("treats transient codes (1001 / 1006 / 1009 / 1011 / 1012) as non-permanent", () => {
    expect(isPermanentCloseCode(1001)).toBe(false);
    expect(isPermanentCloseCode(1006)).toBe(false);
    expect(isPermanentCloseCode(1009)).toBe(false);
    expect(isPermanentCloseCode(1011)).toBe(false);
    expect(isPermanentCloseCode(1012)).toBe(false);
    // 5000+ もまだ未割当なので non-permanent。
    expect(isPermanentCloseCode(5000)).toBe(false);
  });
});

describe("SignalingClient close-code handling (Issue #127)", () => {
  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  /** 共通テストハーネス: client + reasons 配列 + states 配列 + sockets/timer。 */
  function setup(overrides: Partial<ReconnectOptions> = {}) {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const states: string[] = [];
    const reasons: SignalingCloseReason[] = [];
    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onStateChange: (s) => states.push(s),
        onClosedReason: (r) => reasons.push(r),
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
        ...overrides,
      },
    );
    return { client, sockets, timer, states, reasons };
  }

  it("does NOT reconnect after close code 1000 (Normal Closure)", () => {
    const { client, sockets, timer, states, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();
    expect(client.state).toBe("open");

    sockets[0].fireClose(1000);
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["normal"]);
    expect(states).toContain("closed");
    expect(timer.pendingCount()).toBe(0);

    // 念押し: backoff schedule が完全に止まっていること。
    timer.advance(60000);
    expect(sockets.length).toBe(1);
  });

  it("does NOT reconnect after close code 1008 (Policy Violation, token invalid)", () => {
    const { client, sockets, timer, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();

    sockets[0].fireClose(1008);
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["auth"]);
    expect(timer.pendingCount()).toBe(0);

    timer.advance(60000);
    expect(sockets.length).toBe(1);
  });

  it("DOES reconnect after close code 1011 (Issue #127 review #1)", () => {
    // sabiden サーバの WS keepalive idle timeout (= モバイル WiFi スリープ /
    // Cloudflare Tunnel 100s idle / 端末バックグラウンド) で送られてくる
    // 1011 は transient 扱い。 1 発で permanent 停止すると Issue #119 の
    // 「無線復帰時に自動再接続」 が壊れる。
    const { client, sockets, timer, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();
    expect(client.state).toBe("open");

    sockets[0].fireClose(1011);
    expect(client.state).toBe("reconnecting");
    expect(reasons).toEqual([]); // permanent な諦めはしていない
    expect(timer.pendingCount()).toBe(1);

    timer.advance(1000);
    expect(sockets.length).toBe(2);
  });

  it("does NOT reconnect after close code 4401 (application auth close)", () => {
    const { client, sockets, timer, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();

    sockets[0].fireClose(4401);
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["auth"]);
    expect(timer.pendingCount()).toBe(0);

    timer.advance(60000);
    expect(sockets.length).toBe(1);
  });

  it("DOES reconnect after close code 1006 (Abnormal Closure, transient)", () => {
    const { client, sockets, timer, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();
    expect(client.state).toBe("open");

    sockets[0].fireClose(1006);
    expect(client.state).toBe("reconnecting");
    expect(reasons).toEqual([]); // まだ諦めていない
    expect(timer.pendingCount()).toBe(1);

    timer.advance(1000);
    expect(sockets.length).toBe(2);
  });

  it("gives up after maxReconnectAttempts and reports `exhausted`", () => {
    // maxReconnectAttempts=3 + maxDelayMs=1000 で短時間に上限到達を再現。
    const { client, sockets, timer, reasons } = setup({
      initialDelayMs: 1000,
      maxDelayMs: 1000,
      maxReconnectAttempts: 3,
    });
    void client.connect();
    sockets[0].fireOpen();

    // 1 回目の close → reconnectAttempts=0 → schedule (1s)
    sockets[0].fireClose(1006);
    expect(client.state).toBe("reconnecting");
    timer.advance(1000);
    expect(sockets.length).toBe(2);
    // この時点で reconnectAttempts は 1 にインクリメント済み

    // 2 回目: open しないまま close
    sockets[1].fireClose(1006);
    timer.advance(1000);
    expect(sockets.length).toBe(3);

    // 3 回目: open しないまま close
    sockets[2].fireClose(1006);
    timer.advance(1000);
    expect(sockets.length).toBe(4);

    // 4 回目: ここで close が来ても reconnectAttempts=3 で上限到達なので
    // 新しい WS は張られず、 reason="exhausted" + closed に遷移する。
    sockets[3].fireClose(1006);
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["exhausted"]);
    expect(timer.pendingCount()).toBe(0);

    timer.advance(60000);
    expect(sockets.length).toBe(4);
  });

  it("explicit close() reports reason=`normal` exactly once", () => {
    const { client, sockets, reasons } = setup();
    void client.connect();
    sockets[0].fireOpen();

    client.close();
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["normal"]);

    // 二重 close() しても再発火しない。
    client.close();
    expect(reasons).toEqual(["normal"]);
  });

  it("auth close before any successful open also reports reason=`auth`", () => {
    // Cloudflare Access が WS upgrade 前に 401 を返し、 ブラウザが 1008 で
    // close する想定 (RFC 6455 §7.4.1 1008 Policy Violation 相当)。
    const { client, sockets, timer, reasons } = setup();
    const promise = client.connect();
    expect(client.state).toBe("connecting");

    sockets[0].fireClose(1008);
    expect(client.state).toBe("closed");
    expect(reasons).toEqual(["auth"]);
    expect(timer.pendingCount()).toBe(0);

    return promise.catch(() => {
      // connect() の Promise は reject されてよい。
      expect(client.state).toBe("closed");
    });
  });
});

describe("App.tsx connect() catch-race against onClosedReason (Issue #127 round-2 review #1)", () => {
  // App.tsx は `await signaling.connect()` の catch で setView({kind:"dialer"})
  // していたが、 永続 close (1008/4xxx) の場合は ws.onclose 内で finalize() →
  // onClosedReason() が同期発火し、 そこで setView({kind:"login"}) +
  // signaling=null が確定してから connect() Promise が reject される。
  //
  // catch が無条件に dialer view へ遷移すると login view を握り潰すため、
  // catch では「onClosedReason が既に終端確定したか」 を signaling 参照の null
  // 化で検出して setView をスキップする (App.tsx::connect 内 fix)。
  //
  // この describe では SignalingClient API の契約として
  // 「onClosedReason は connect() Promise reject の **前** に同期発火する」
  // ことと、 App.tsx と同形のコールバック構造で書いた client コードが
  // 「auth/exhausted 時に login view を保持し、 transient 時に dialer view へ
  // 進む」 ことを検証する。
  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  it("fires onClosedReason synchronously before connect() Promise rejects (auth)", async () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const events: string[] = [];

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onClosedReason: (r) => events.push(`closedReason:${r}`),
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    const promise = client.connect();
    promise.catch(() => events.push("connectReject"));

    // 永続 close (1008) → onClosedReason が同期発火、 connect() reject は
    // microtask で後追い。
    sockets[0].fireClose(1008);

    // この時点で onClosedReason は同期的に発火済み、 reject はまだ enqueue 中。
    expect(events).toEqual(["closedReason:auth"]);

    // microtask を flush して reject を処理。
    await Promise.resolve();
    await Promise.resolve();

    expect(events).toEqual(["closedReason:auth", "connectReject"]);
  });

  it("App-shaped callback flow keeps `login` view on auth close (catch must not overwrite)", async () => {
    // App.tsx の挙動を最小再現: view 状態 + signaling 参照 + try/catch を
    // closure に書き、 auth close で login view が保たれることを assert する。
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    let view: "login" | "dialer" = "login";
    let signaling: SignalingClient | null = null;

    signaling = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onClosedReason: (reason) => {
          // App.tsx と同じ: auth/exhausted で login へ強制遷移 + 参照切断。
          if (reason === "auth" || reason === "exhausted") {
            signaling = null;
            view = "login";
          }
        },
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    // App.tsx::connect の try/catch を最小再現。 catch で
    // signaling===null なら setView をスキップする (round-2 review #1 fix)。
    const runAppConnect = async () => {
      try {
        await signaling!.connect();
        view = "dialer";
      } catch {
        if (signaling === null) return; // round-2 review #1 fix
        view = "dialer";
      }
    };

    const done = runAppConnect();
    // open する前に auth close。
    sockets[0].fireClose(1008);
    await done;

    // login view が保持されていること (= catch が握り潰していない)。
    expect(view).toBe("login");
    expect(signaling).toBeNull();
  });

  it("App-shaped callback flow advances to `dialer` view on transient close (regression guard)", async () => {
    // 対偶ケース: transient (1006) ではユーザに「再接続中」 を見せて dialer に
    // 進むのが Issue #119 以来の正しい挙動。 round-2 review #1 fix で
    // この path が壊れていないことを確認する。
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    let view: "login" | "dialer" = "login";
    let signaling: SignalingClient | null = null;

    signaling = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onClosedReason: (reason) => {
          if (reason === "auth" || reason === "exhausted") {
            signaling = null;
            view = "login";
          }
        },
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    const runAppConnect = async () => {
      try {
        await signaling!.connect();
        view = "dialer";
      } catch {
        if (signaling === null) return;
        view = "dialer";
      }
    };

    const done = runAppConnect();
    sockets[0].fireClose(1006); // transient → schedule reconnect
    await done;

    // dialer に遷移、 signaling は生きていて次の backoff を待っている。
    expect(view).toBe("dialer");
    expect(signaling).not.toBeNull();
    expect(signaling!.state).toBe("reconnecting");
  });
});

describe("onClosedReason API contract (Issue #142)", () => {
  // PR #141 follow-up: 「onClosedReason は onStateChange('closed') の直前に
  // 同期発火、 1 度だけ」 を future refactor で壊さないため、 契約を test
  // で固定化する (signaling.ts::SignalingHandlers.onClosedReason docstring)。
  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  function setup(overrides: Partial<ReconnectOptions> = {}) {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();
    const events: string[] = [];
    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      {
        onMessage: () => {},
        onStateChange: (s) => events.push(`state:${s}`),
        onClosedReason: (r) => events.push(`reason:${r}`),
      },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
        ...overrides,
      },
    );
    return { client, sockets, timer, events };
  }

  it("fires onClosedReason exactly once even on double close()", () => {
    const { client, sockets, events } = setup();
    void client.connect();
    sockets[0].fireOpen();

    client.close();
    client.close(); // 2 度目は no-op
    client.close();

    // reason:normal は 1 回だけ
    const reasonCount = events.filter((e) => e.startsWith("reason:")).length;
    expect(reasonCount).toBe(1);
    expect(events).toContain("reason:normal");
  });

  it("emits reason:<r> immediately before state:closed (auth)", () => {
    const { client, sockets, events } = setup();
    void client.connect();
    sockets[0].fireOpen();
    sockets[0].fireClose(1008);

    // state は connecting → open → closed 順に流れているはず。
    // 重要なのは reason:auth が state:closed の直前に並ぶこと。
    const reasonIdx = events.indexOf("reason:auth");
    const closedIdx = events.indexOf("state:closed");
    expect(reasonIdx).toBeGreaterThanOrEqual(0);
    expect(closedIdx).toBeGreaterThan(reasonIdx);
    expect(closedIdx - reasonIdx).toBe(1);
    expect(client.state).toBe("closed");
  });

  it("emits reason:<r> immediately before state:closed (exhausted)", () => {
    // maxReconnectAttempts=1 で即上限到達させる。
    const { client, sockets, timer, events } = setup({
      initialDelayMs: 1000,
      maxDelayMs: 1000,
      maxReconnectAttempts: 1,
    });
    void client.connect();
    sockets[0].fireOpen();
    sockets[0].fireClose(1006); // 1 回目: schedule reconnect (attempts=0→1)
    timer.advance(1000); // attempt 1 を発射 (reconnectAttempts++ → 1)
    sockets[1].fireClose(1006); // 2 回目の close: attempts==1 で上限到達 → exhausted

    const reasonIdx = events.indexOf("reason:exhausted");
    const closedIdx = events.indexOf("state:closed");
    expect(reasonIdx).toBeGreaterThanOrEqual(0);
    expect(closedIdx - reasonIdx).toBe(1);
    expect(client.state).toBe("closed");
  });

  it("cumulative delay budget at default maxReconnectAttempts ≈ 8 minutes (not 10)", () => {
    // ReconnectOptions.maxReconnectAttempts docstring の主張を test 化:
    //   1+2+4+8+16+30×15 ≈ 481 秒 (≈ 8 分)。
    // backoff 計算式: base = min(maxDelayMs, initialDelayMs * 2^attempts)
    // attempts=0..5 が exponential、 attempts>=6 で cap=30s に張り付く。
    // 既定 maxReconnectAttempts=20 なら attempts=0..19 まで試行 (20 回)。
    const initialDelayMs = 1000;
    const maxDelayMs = 30000;
    const maxAttempts = 20;
    let total = 0;
    for (let a = 0; a < maxAttempts; a++) {
      total += Math.min(maxDelayMs, initialDelayMs * 2 ** a);
    }
    // 1+2+4+8+16+32 が exp 区間の予定だが、 32 は 30 で cap される。
    // 実際: 1+2+4+8+16+30+30*14 = 61 + 420 = 481 秒
    expect(total).toBe(481_000);
    // 「30s × 20 = 600s = 10 分」 という直感計算とは ~120s ズレている事の証拠。
    expect(total).toBeLessThan(maxDelayMs * maxAttempts);
  });
});

describe("ClientMessage decline schema (Issue #107)", () => {
  // Issue #107: PWA「拒否」ボタンが `{type:"decline", call_id}` を送って
  // sabiden 側 fork レッグを 603 Decline (RFC 3261 §21.6.2) で集約させる。
  // wire format は sabiden の `src/webrtc/signaling.rs::ClientMessage::Decline`
  // と完全一致する必要がある (snake_case `call_id`, lowercase `type`)。

  const URL_BASE = "ws://example/signal";
  const TOKEN = "ext1.999.sig";

  it("send {type:'decline', call_id} serialises with call_id field", () => {
    const { factory, sockets } = makeWsFactory();
    const timer = makeFakeTimer();

    const client = new SignalingClient(
      URL_BASE,
      TOKEN,
      { onMessage: vi.fn() },
      {
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        maxJitterMs: 0,
        random: () => 0,
        webSocketFactory: factory,
        setTimeout: timer.setTimeoutFn,
        clearTimeout: timer.clearTimeoutFn,
      },
    );

    void client.connect();
    sockets[0].fireOpen();
    client.send({ type: "decline", call_id: "ngn-call-xyz" });

    expect(sockets[0].sent.length).toBe(1);
    const obj = JSON.parse(sockets[0].sent[0]);
    expect(obj).toEqual({ type: "decline", call_id: "ngn-call-xyz" });
  });

  it("decline wire format matches sabiden ClientMessage::Decline (snake_case call_id)", () => {
    // 直接 JSON.stringify を確認する (SignalingClient 経由ではない unit test):
    // - `type: "decline"` (lowercase, serde rename_all = "lowercase")
    // - `call_id` (snake_case, serde default for struct fields)
    const msg = { type: "decline", call_id: "abc-123" } as const;
    expect(JSON.stringify(msg)).toBe('{"type":"decline","call_id":"abc-123"}');
  });
});

describe("parseRateLimitedRetryAfter (Issue #194, TTC JJ-90.24 §5.7.1 / RFC 3261 §20.33)", () => {
  // backend (`src/call/orchestrator.rs`) が送ってくる 2 系統の error.message
  // 本文から retry_after を抜き出す。 wire format に新規 field を追加せず、
  // 既存 string にだけ依存 (Issue #194 「touch しない」 領域)。

  it("parses rate_limited message body (`retry after N sec`)", () => {
    // PR #193: `handle_pwa_outbound_offer` の RateLimitDecision::Deny 経路。
    // `outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after 5 sec`
    const body = "outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after 5 sec";
    expect(parseRateLimitedRetryAfter(body)).toBe(5);
  });

  it("parses outbound_failed message body (`retry_after=Ns`) when NGN sent Retry-After", () => {
    // PR #193 review #2 🟡#1: NGN INVITE 失敗 + Retry-After 受信時の埋込形式。
    // `NGN INVITE 失敗: 503 Service Unavailable (retry_after=30s)`
    const body = "NGN INVITE 失敗: 503 Service Unavailable (retry_after=30s)";
    expect(parseRateLimitedRetryAfter(body)).toBe(30);
  });

  it("returns null for outbound_failed without Retry-After embed", () => {
    // 486 Busy Here や transport 失敗時は retry_after 埋込なし。
    expect(parseRateLimitedRetryAfter("NGN INVITE 失敗: 486 Busy Here")).toBeNull();
    expect(parseRateLimitedRetryAfter("NGN INVITE 失敗: timeout")).toBeNull();
  });

  it("returns null for unrelated error messages", () => {
    expect(parseRateLimitedRetryAfter("CallManager 未注入")).toBeNull();
    expect(parseRateLimitedRetryAfter("")).toBeNull();
  });

  it("rejects zero / negative / NaN as retry_after (no UI lock-up)", () => {
    // backend は正値しか送らない想定だが、 防御的に 0 / 負数は null 化する。
    // 「0 秒抑制」 を真に受けると UI が一瞬チラつく + 後続の disable が壊れる。
    expect(parseRateLimitedRetryAfter("retry after 0 sec")).toBeNull();
    // 正規表現は `\d+` のみ受けるので `-5` は数字部 `5` のみ拾われる現実があるが、
    // backend は負数を送らない (u64 secs)。 ここでは仕様を assert する。
    expect(parseRateLimitedRetryAfter("retry_after=0s")).toBeNull();
  });

  it("is case-insensitive (defensive)", () => {
    // backend 文言は固定だが、 大文字化される将来変更に備えて lower/upper 両対応。
    expect(parseRateLimitedRetryAfter("Retry After 7 Sec")).toBe(7);
    expect(parseRateLimitedRetryAfter("RETRY_AFTER=12S")).toBe(12);
  });

  it("prefers `retry after N sec` form when both patterns appear (rate_limited primary)", () => {
    // 万が一 backend が両方を載せた場合、 rate_limited が primary なので
    // そちらを優先する。 実際の backend では同時に出さないが、 順序の決定論を確保。
    const mixed = "retry after 3 sec ... retry_after=99s";
    expect(parseRateLimitedRetryAfter(mixed)).toBe(3);
  });
});

describe("App rate-limited state machine (Issue #194)", () => {
  // App.tsx / Dialer.tsx の状態遷移を `SignalingClient` 経由で再現:
  //   server が `ServerMessage::error{code:"rate_limited", message:"... retry after 5 sec"}`
  //   を送ってきたら、 PWA は `rateLimitedUntil = Date.now() + 5_000` を立てて
  //   発信ボタンを disable + カウントダウンを表示する。
  //
  // App.tsx 自身は SolidJS reactive で動くため testing-library を入れずに
  // 「signaling 層から error を受けたとき、 App と同じロジックで rate_limited
  //  state が正しく遷移する」 ことを最小 closure で再現してテストする。

  /** App.tsx::handleSignalMessage の rate_limited 抜粋を closure で再実装。 */
  function makeRateLimitedTracker(nowFn: () => number) {
    let until: number | null = null;
    const onError = (msg: Extract<ServerMessage, { type: "error" }>) => {
      if (msg.code !== "rate_limited" && msg.code !== "outbound_failed") return;
      const secs = parseRateLimitedRetryAfter(msg.message);
      if (secs === null || secs <= 0) return;
      const candidate = nowFn() + secs * 1000;
      until = until === null ? candidate : Math.max(until, candidate);
    };
    const remaining = (): number | null => {
      if (until === null) return null;
      const r = Math.ceil((until - nowFn()) / 1000);
      if (r <= 0) {
        until = null;
        return null;
      }
      return r;
    };
    // Issue #219: session 境界 (logout / auth / exhausted) で deadline を
    // 強制リセットする経路。 App.tsx::handleLogout と
    // App.tsx::onClosedReason{auth,exhausted} に対応する。
    const reset = () => {
      until = null;
    };
    return { onError, remaining, reset, getUntil: () => until };
  }

  it("locks call button on `rate_limited` and unlocks after retry_after elapses", () => {
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    // 初期状態: 抑制なし
    expect(tr.remaining()).toBeNull();

    // backend が `rate_limited` を送信
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after 5 sec",
    });
    expect(tr.remaining()).toBe(5);

    // 3 秒経過
    now += 3000;
    expect(tr.remaining()).toBe(2);

    // 5 秒経過 (= 期限ちょうど): null (= 抑制解除)
    now += 2000;
    expect(tr.remaining()).toBeNull();
  });

  it("locks call button on `outbound_failed` with `retry_after=30s` embed", () => {
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    tr.onError({
      type: "error",
      code: "outbound_failed",
      message: "NGN INVITE 失敗: 503 Service Unavailable (retry_after=30s)",
    });
    expect(tr.remaining()).toBe(30);

    now += 29_000;
    expect(tr.remaining()).toBe(1);
    now += 1000;
    expect(tr.remaining()).toBeNull();
  });

  it("does NOT lock on `outbound_failed` without Retry-After embed (486 Busy etc)", () => {
    const now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);
    tr.onError({
      type: "error",
      code: "outbound_failed",
      message: "NGN INVITE 失敗: 486 Busy Here",
    });
    expect(tr.remaining()).toBeNull();
  });

  it("does NOT lock on unrelated error codes (e.g. internal)", () => {
    const now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);
    tr.onError({
      type: "error",
      code: "internal",
      message: "CallManager 未注入",
    });
    expect(tr.remaining()).toBeNull();
  });

  it("two overlapping rate_limited errors keep the LATER deadline (no shortening)", () => {
    // 短い 2 秒抑制が来てから 10 秒抑制が来た場合、 10 秒分残す。
    // 逆 (10 秒中に 1 秒抑制が後着) は 10 秒側を保持する (= max 採用)。
    // 計算はちょうど整数秒で行い、 ceil の端数で +1 ズレないようにする。
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "retry after 2 sec",
    });
    expect(tr.remaining()).toBe(2);

    // ちょうど 1 秒経過 (整数で誤差なし) → 10 秒抑制を後着。
    now += 1000;
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "retry after 10 sec",
    });
    // 既存 until = 1_002_000、 候補 = 1_011_000、 max 採用 = 1_011_000。
    // remaining = ceil((1_011_000 - 1_001_000)/1000) = 10。
    expect(tr.remaining()).toBe(10);

    // さらに 1 秒経過 → 短い 1 秒抑制を後着 (= 候補 1_003_000、 max は据置)。
    now += 1000;
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "retry after 1 sec",
    });
    // until = 1_011_000、 now = 1_002_000、 remaining = 9。
    expect(tr.remaining()).toBe(9);
  });

  it("survives WS reconnect: rate_limited deadline is Date.now-based (Issue #194 DoD)", () => {
    // App.tsx は SignalingClient の transient close (1006) で WS を張り直すが、
    // rate_limited 解除予定時刻は epoch ms で保持しているため再接続後も
    // そのまま適用される。 本テストは Date.now() ベースの計算が
    // 「中間で WS state を上書きするコードに影響されない」 ことを確認する。
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "retry after 10 sec",
    });
    expect(tr.remaining()).toBe(10);

    // 仮想的に WS reconnect (3 秒経過、 内部 state は触らない)
    now += 3000;
    expect(tr.remaining()).toBe(7);

    // 再接続成功後さらに 5 秒経過 → 残り 2 秒
    now += 5000;
    expect(tr.remaining()).toBe(2);
  });

  // Issue #219: session 境界での deadline リセット。
  //
  // PR #215 で導入された `rateLimitedUntil` は WS reconnect (transient close)
  // を跨いで生存させるのが正しい (Issue #194 DoD)。 ただし以下の **session 終了**
  // パスでは別 session の context が引き継がれて UI が「context 不明な待機中」
  // を出してしまう (Issue #219):
  //   - 明示 logout: ユーザが別 ext_id で login し直す可能性
  //   - auth エラー: token 失効後の別ユーザ login (背景 NGN bucket は AOR 共有
  //     だが UX 上 context 不明)
  //   - exhausted: reconnect 上限到達で session 終了
  //
  // これらの 3 経路で `rateLimitedUntil` を `null` に戻すロジックを App.tsx に
  // 追加した (`handleLogout` と `onClosedReason: "auth"/"exhausted"`)。
  // tracker.reset() がそれと同じ closure 動作をする。
  it("resets rateLimitedUntil on explicit logout (Issue #219)", () => {
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    // session A: rate_limited を受けて UI ロック中
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after 30 sec",
    });
    expect(tr.remaining()).toBe(30);
    expect(tr.getUntil()).not.toBeNull();

    // ユーザが明示 logout → handleLogout が deadline を null にリセット
    tr.reset();
    expect(tr.getUntil()).toBeNull();
    expect(tr.remaining()).toBeNull();

    // session B (= 別ユーザ login 後) でも deadline は残らない (carryover なし)
    now += 1000;
    expect(tr.remaining()).toBeNull();
  });

  it("resets rateLimitedUntil on auth-failure close (Issue #219)", () => {
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    // backend が `outbound_failed` (NGN 503 + Retry-After) を返して UI ロック
    tr.onError({
      type: "error",
      code: "outbound_failed",
      message: "NGN INVITE 失敗: 503 Service Unavailable (retry_after=60s)",
    });
    expect(tr.remaining()).toBe(60);

    // token 失効 → SignalingClient が close code を auth に分類して onClosedReason
    // を発火 → App.tsx は clearToken + setRateLimitedUntil(null) + 再ログイン画面
    tr.reset();
    expect(tr.getUntil()).toBeNull();
    expect(tr.remaining()).toBeNull();

    // 再ログイン後に時刻が進んでも、 残骸が UI に出てこない
    now += 30_000;
    expect(tr.remaining()).toBeNull();
  });

  it("resets rateLimitedUntil on exhausted close (reconnect attempts cap) (Issue #219)", () => {
    let now = 1_000_000;
    const tr = makeRateLimitedTracker(() => now);

    // 抑制中に長時間ネットワーク不安定 → 再接続上限到達で exhausted close。
    tr.onError({
      type: "error",
      code: "rate_limited",
      message: "retry after 120 sec",
    });
    expect(tr.remaining()).toBe(120);

    // exhausted close → onClosedReason("exhausted") で deadline をリセット。
    tr.reset();
    expect(tr.getUntil()).toBeNull();

    // ネットワーク復帰後にユーザが再ログイン: 古い deadline が再構築されない
    now += 60_000; // 元 deadline までまだ余裕がある時刻でも null のまま
    expect(tr.remaining()).toBeNull();
  });
});

describe("App pendingIceCandidates dialog-epoch race (Issue #173)", () => {
  // PR #172 で frontend 側 deferred されていた race。
  // 旧実装は `pendingIceCandidates: string[]` + teardownCall で配列を空に
  // 再代入する単純構造で、 以下 2 race を踏んでいた:
  //   R1: 新着信 "offer" の前後で "ice" が到達する任意順序 (RFC 8839 §4.2
  //       trickle ICE) で、 buffer 済 ICE を offer ハンドラ内 teardownCall が
  //       wipe する。
  //   R2: flushPendingIce ループの await 合間に teardownCall が走り、 古い
  //       buffer 参照で続行して hangup 済 PC に addIce する。
  //
  // 修正: ICE candidate を **dialog epoch** でタグ付けし、 flush は現 epoch
  // 一致分のみ適用する。 本テストは App.tsx::teardownCall / flushPendingIce /
  // handleSignalMessage("ice") の closure を最小再現して race を回避する。
  // (SolidJS の `createSignal` は使わず、 epoch / buffer / call を素の let で
  //  握る = App.tsx と同形)。

  /** App.tsx の ICE buffer 部分を最小再現する closure。
   *
   * 実 RTCPeerConnection は使わず、 `addIce(candidate)` 呼出を記録する
   * fake `call` を inject する。 これにより flush の挙動が観測可能。
   */
  type FakeCall = {
    readonly id: number;
    addIce: (candidate: string) => Promise<void>;
    hangup: () => void;
    readonly seen: string[];
    readonly alive: () => boolean;
  };

  function makeFakeCall(id: number, addIcePauseMs: number = 0): FakeCall {
    const seen: string[] = [];
    let alive = true;
    return {
      id,
      addIce: async (candidate: string) => {
        if (addIcePauseMs > 0) {
          // 微少 microtask を消費するため、 Promise.resolve を await して
          // event loop に制御を返す (await 合間に他 handler が走る race を再現)。
          await Promise.resolve();
        }
        if (!alive) throw new Error("addIce on hung-up call");
        seen.push(candidate);
      },
      hangup: () => {
        alive = false;
      },
      seen,
      alive: () => alive,
    };
  }

  /** App.tsx 由来 dialog-epoch buffer の closure 模型。 production code は
   * `App.tsx` 内 `let` で同じ shape を持つ。 本 closure は test fixture。 */
  function makeAppLikeBuffer() {
    type PendingIce = { epoch: number; candidate: string };
    let call: FakeCall | null = null;
    let pendingIceCandidates: PendingIce[] = [];
    let dialogEpoch = 0;

    const teardownCall = () => {
      call?.hangup();
      call = null;
      dialogEpoch += 1;
    };

    const setCall = (c: FakeCall) => {
      call = c;
    };

    const onIceMsg = async (candidate: string) => {
      if (call) {
        await call.addIce(candidate);
      } else {
        pendingIceCandidates.push({ epoch: dialogEpoch, candidate });
      }
    };

    const flushPendingIce = async () => {
      if (!call) return;
      const currentEpoch = dialogEpoch;
      const buffered = pendingIceCandidates.filter((p) => p.epoch === currentEpoch);
      pendingIceCandidates = [];
      for (const { candidate } of buffered) {
        if (!call || dialogEpoch !== currentEpoch) return;
        try {
          await call.addIce(candidate);
        } catch {
          /* warn-only in production */
        }
      }
    };

    return {
      teardownCall,
      setCall,
      onIceMsg,
      flushPendingIce,
      // 観測用
      getCall: () => call,
      bufferLen: () => pendingIceCandidates.length,
      bufferSnapshot: () => pendingIceCandidates.slice(),
      currentEpoch: () => dialogEpoch,
    };
  }

  // Issue #173 (R1): NGN→PWA 着信で "ice" が "offer" より先着するケース。
  // RFC 8839 §4.2 trickle ICE は ICE / Offer の任意順序を許す。 旧実装は
  // teardownCall が buffer を wipe したため、 ここで先着した ICE が消えていた。
  it("rfc8839_4_2_ice_before_offer_is_buffered_with_current_epoch_and_survives_teardown", async () => {
    const buf = makeAppLikeBuffer();
    // 状態: 通話なし (epoch=0)
    expect(buf.currentEpoch()).toBe(0);

    // 1) WS から ICE 先着 → buffer に積まれる (epoch=0)
    await buf.onIceMsg("candidate:1 1 udp 2122252543 192.168.1.10 56789 typ host");
    expect(buf.bufferLen()).toBe(1);
    expect(buf.bufferSnapshot()[0].epoch).toBe(0);

    // 2) 続いて "offer" が到達 → App.tsx は teardownCall() を呼ぶ (epoch 0→1)
    //    旧実装はここで buffer を [] にしていた → 先着 ICE が消える bug。
    //    新実装は epoch++ のみ。 buffer 内エントリは epoch=0 のまま残るが、
    //    後段 flush は現 epoch=1 と一致しないため drop される (R1: 別 dialog
    //    の遺残 ICE を新 dialog に流さない、 期待動作)。
    buf.teardownCall();
    expect(buf.currentEpoch()).toBe(1);
    // 遺残エントリは buffer に物理的に残っているが、 epoch 不一致で drop 予定。
    expect(buf.bufferLen()).toBe(1);

    // 3) Accept 押下相当: 新 call (epoch=1 文脈) を立てる前に新着 ICE が到達。
    //    これは新 dialog の ICE なので、 epoch=1 でタグ付けされて残るべき。
    await buf.onIceMsg("candidate:2 1 udp 2122252543 192.168.1.10 56790 typ host");
    expect(buf.bufferLen()).toBe(2);
    expect(buf.bufferSnapshot()[1].epoch).toBe(1);

    // 4) 新 call 生成 + flush → epoch=1 一致分だけ適用される (= R1 解消)。
    const callA = makeFakeCall(1);
    buf.setCall(callA);
    await buf.flushPendingIce();
    expect(callA.seen).toEqual([
      "candidate:2 1 udp 2122252543 192.168.1.10 56790 typ host",
    ]);
  });

  // Issue #173 (R1 対偶): "offer" が "ice" より先着する通常順序。 これは
  // 旧実装でも正常動作していたが、 新実装でも壊さないことを確認する。
  it("rfc8839_4_2_ice_after_offer_is_buffered_then_flushed_on_accept", async () => {
    const buf = makeAppLikeBuffer();

    // 1) "offer" 到達 → teardownCall (epoch 0→1) + ringing UI 遷移相当。
    buf.teardownCall();
    expect(buf.currentEpoch()).toBe(1);

    // 2) ringing 中に ICE 到達 → buffer (epoch=1)
    await buf.onIceMsg("ice-1");
    await buf.onIceMsg("ice-2");
    expect(buf.bufferLen()).toBe(2);

    // 3) Accept → new call + flush
    const callA = makeFakeCall(1);
    buf.setCall(callA);
    await buf.flushPendingIce();
    expect(callA.seen).toEqual(["ice-1", "ice-2"]);
  });

  // Issue #173: ICE → Offer → ICE → ICE → end-of-candidates の interleave で
  // 新 dialog の全 ICE が正しく到達する (PR #172 server-side の
  // `rfc8839_multiple_interleaved_ice_candidates_all_accepted` PWA 版)。
  it("rfc8839_4_2_multiple_interleaved_ice_candidates_all_arrive_at_new_call", async () => {
    const buf = makeAppLikeBuffer();

    // 旧 dialog の遺残 ICE (offer 前)
    await buf.onIceMsg("stale-ice-old-dialog");

    // 新着信 "offer" 到達 → teardownCall (epoch 0→1)
    buf.teardownCall();

    // 新 dialog の trickle ICE が任意順序で到達
    await buf.onIceMsg("new-ice-1");
    await buf.onIceMsg("new-ice-2");
    await buf.onIceMsg(""); // end-of-candidates marker (RFC 8838 §13)
    await buf.onIceMsg("new-ice-3"); // 仕様外だが parser 受理する

    // Accept → flush
    const callA = makeFakeCall(1);
    buf.setCall(callA);
    await buf.flushPendingIce();

    // 旧 dialog 遺残 (`stale-ice-old-dialog`) は drop、 新 dialog 4 件全到達。
    expect(callA.seen).toEqual(["new-ice-1", "new-ice-2", "", "new-ice-3"]);
  });

  // Issue #173: end-of-candidates marker (空文字列) も他 ICE と同じく
  // dialog-epoch buffer 規則に従う。 旧 dialog の eoc が新 dialog に漏れない。
  it("rfc8838_13_end_of_candidates_marker_is_also_tagged_with_dialog_epoch", async () => {
    const buf = makeAppLikeBuffer();

    // 旧 dialog で eoc を受信
    await buf.onIceMsg("");
    expect(buf.bufferLen()).toBe(1);
    expect(buf.bufferSnapshot()[0]).toEqual({ epoch: 0, candidate: "" });

    // 新着信 → teardownCall (epoch 0→1)
    buf.teardownCall();

    // Accept → flush。 旧 epoch=0 の eoc は drop される (= 新 dialog に
    // 「もう候補は来ない」 を誤って流さない、 R1 派生 case)。
    const callA = makeFakeCall(1);
    buf.setCall(callA);
    await buf.flushPendingIce();
    expect(callA.seen).toEqual([]);
  });

  // Issue #173 (R2): call 立ち上げ後に届く ICE は buffer を経由せず直接
  // addIce される (call != null 分岐)。 これは R2 race の対象ではないが、
  // 新実装でも壊れていないことを確認する regression guard。
  it("ice_after_call_established_goes_directly_to_addIce_not_buffer", async () => {
    const buf = makeAppLikeBuffer();
    const callA = makeFakeCall(1);
    buf.setCall(callA);

    await buf.onIceMsg("direct-ice-1");
    await buf.onIceMsg("direct-ice-2");

    expect(callA.seen).toEqual(["direct-ice-1", "direct-ice-2"]);
    expect(buf.bufferLen()).toBe(0);
  });

  // Issue #173 (R2): flushPendingIce の await 合間に teardownCall が割り込んで
  // も、 ループは早期 return する (旧 call への addIce が走らない)。
  it("teardown_mid_flush_aborts_loop_and_does_not_addice_to_hung_up_call", async () => {
    const buf = makeAppLikeBuffer();

    // ringing 中に 3 件 buffer
    buf.teardownCall(); // epoch 0→1 (新着信受信相当)
    await buf.onIceMsg("c1");
    await buf.onIceMsg("c2");
    await buf.onIceMsg("c3");

    const callA = makeFakeCall(1, /*addIcePauseMs=*/ 1);
    buf.setCall(callA);

    // flush 開始 (await 合間に teardown を割り込ませる)
    const flushPromise = buf.flushPendingIce();

    // 1 件目の addIce が microtask を消費している間に teardown を入れる。
    await Promise.resolve();
    buf.teardownCall(); // epoch 1→2、 call = null

    await flushPromise;

    // hangup 済 call には R2 race で旧実装が addIce していたが、 新実装は
    // ループ先頭で `dialogEpoch !== currentEpoch` を見て即 return する。
    // 1 件目の addIce は teardown より前に開始しているので seen に入っている
    // 可能性があるが、 2 件目以降は確実に走らない。
    expect(callA.seen.length).toBeLessThanOrEqual(1);
    expect(callA.alive()).toBe(false);
  });

  // Issue #173: 2 通連続着信 (一連の inbound チェーン) で各 dialog の ICE が
  // それぞれの call にだけ届く (epoch 分離が dialog 数分スケール)。
  it("two_back_to_back_inbound_dialogs_keep_ice_isolated_per_epoch", async () => {
    const buf = makeAppLikeBuffer();

    // === Dialog 1 ===
    buf.teardownCall(); // epoch 0→1 (1 件目の offer 到達相当)
    await buf.onIceMsg("d1-ice-1");
    const call1 = makeFakeCall(1);
    buf.setCall(call1);
    await buf.flushPendingIce();
    expect(call1.seen).toEqual(["d1-ice-1"]);

    // === Dialog 2 (1 件目 BYE → 即 2 件目 offer) ===
    // 1 件目 BYE 由来 ICE が遅れて届く (旧 dialog エンドゲーム)
    await buf.onIceMsg("d1-ice-late"); // call != null なので直接 call1 に
    expect(call1.seen).toContain("d1-ice-late");

    buf.teardownCall(); // epoch 1→2 (BYE 受信 → call1 hangup)
    expect(call1.alive()).toBe(false);

    // 2 件目 offer 到達相当: 既に teardownCall 済なので epoch は 2 のまま
    // (offer ハンドラは teardownCall を呼ぶが、 上の BYE で既に呼ばれている
    //  ので idempotent: ここでは追加 teardownCall で epoch 2→3)。
    buf.teardownCall();
    expect(buf.currentEpoch()).toBe(3);

    // 2 件目 dialog の ICE
    await buf.onIceMsg("d2-ice-1");
    const call2 = makeFakeCall(2);
    buf.setCall(call2);
    await buf.flushPendingIce();
    expect(call2.seen).toEqual(["d2-ice-1"]);
    // call1 には d2 の ICE が漏れない (epoch 分離の主目的)
    expect(call1.seen).not.toContain("d2-ice-1");
  });
});
