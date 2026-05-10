// SignalingClient の自動再接続ユニットテスト (Issue #119)。
//
// 実 WebSocket は使わず、 fake な WebSocket factory + fake timer を注入して
// 「onclose 後に backoff 遅延で connect が試行される」 「open に成功したら
// 連続失敗カウンタがリセットされる」 「close() 後は再接続されない」 を確認する。

import { describe, expect, it, vi } from "vitest";
import {
  isPermanentCloseCode,
  parseExtIdFromToken,
  parseServerMessage,
  permanentCloseReason,
  SignalingClient,
  type ReconnectOptions,
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
    // `maxReconnectAttempts` (10 分上限) で達成済み。
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
