// signaling-proxy `proxySignal` の単体テスト (Issue #101)。
//
// Cloudflare Workers Runtime や miniflare を立てずに、 `proxySignal` に fetch
// 実装と Env を直接注入して、 リクエスト形 / 失敗時レスポンスを検証する。
//
// 検証観点 (Issue #101 DoD):
//   1. Host ヘッダが上書きされる (SIGNAL_HOST_HEADER 優先、 未指定なら
//      SIGNAL_ORIGIN の host)
//   2. Cloudflare Access service token (CF-Access-Client-Id /
//      CF-Access-Client-Secret) が必ず付与される
//   3. production で service token 欠如 → 503 (200 でない)
//   4. SIGNAL_ORIGIN 未設定 → 500
//   5. fetch には `redirect: "manual"` が指定されていない (= 既定 follow)

import { describe, expect, it, vi, beforeEach, afterEach, type MockInstance } from "vitest";
import { proxySignal, type Env, type FetchLike } from "./signaling-proxy";

/** `proxySignal` に渡す最小 Env を生成するヘルパ。 */
function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    ASSETS: { fetch: async () => new Response("", { status: 404 }) },
    SIGNAL_ORIGIN: "https://signal.a-taquan.com",
    CF_ACCESS_CLIENT_ID: "client-id-stub",
    CF_ACCESS_CLIENT_SECRET: "client-secret-stub",
    ENVIRONMENT: "production",
    ...overrides,
  };
}

/** 上流に飛んだ Request を握る fetch スタブ。 Node の Response 実装は
 * status 101 をコンストラクタ引数として受け付けないため (Web Fetch
 * standard `init.status` は 200..=599)、 上流疎通成功は 200 で代用する
 * (WS upgrade の検証は別途 statusCode-agnostic に観測する)。 */
function makeCaptureFetch(): { fetchImpl: FetchLike; captured: Request[] } {
  const captured: Request[] = [];
  const fetchImpl: FetchLike = async (req) => {
    captured.push(req);
    return new Response(null, { status: 200 });
  };
  return { fetchImpl, captured };
}

describe("proxySignal: Issue #101 (Host header + CF Access service token)", () => {
  // console.error / console.warn を抑制 (テストごとに spy する)
  let errSpy: MockInstance;
  let warnSpy: MockInstance;

  beforeEach(() => {
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    errSpy.mockRestore();
    warnSpy.mockRestore();
  });

  it("DoD §1: overrides Host header with SIGNAL_HOST_HEADER when set", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ SIGNAL_HOST_HEADER: "private-tunnel.internal" });
    const req = new Request("https://phone.a-taquan.com/signal?token=ext1.99.sig", {
      method: "GET",
      headers: { host: "phone.a-taquan.com", upgrade: "websocket" },
    });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(200);
    expect(captured).toHaveLength(1);
    expect(captured[0].headers.get("host")).toBe("private-tunnel.internal");
  });

  it("DoD §1: defaults Host header to SIGNAL_ORIGIN host when SIGNAL_HOST_HEADER unset", async () => {
    // PWA 側 client の Host (phone.a-taquan.com) がそのまま上流に漏れると
    // Cloudflare が 530/1016 を返すため、 SIGNAL_ORIGIN の host
    // (signal.a-taquan.com) を Host ヘッダに使うのが正解。
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ SIGNAL_HOST_HEADER: undefined });
    const req = new Request("https://phone.a-taquan.com/signal", {
      method: "GET",
      headers: { host: "phone.a-taquan.com" },
    });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(200);
    expect(captured[0].headers.get("host")).toBe("signal.a-taquan.com");
  });

  it("DoD §2: adds CF-Access-Client-Id and CF-Access-Client-Secret to upstream request", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({
      CF_ACCESS_CLIENT_ID: "id-xyz.access",
      CF_ACCESS_CLIENT_SECRET: "secret-abc",
    });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    await proxySignal(req, env, fetchImpl);

    expect(captured[0].headers.get("cf-access-client-id")).toBe("id-xyz.access");
    expect(captured[0].headers.get("cf-access-client-secret")).toBe("secret-abc");
  });

  it("DoD §3: returns 503 (not 200) in production when CF_ACCESS_CLIENT_ID is missing", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ CF_ACCESS_CLIENT_ID: undefined });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(503);
    expect(captured).toHaveLength(0); // 上流には飛ばしていない
    expect(errSpy).toHaveBeenCalled();
  });

  it("DoD §3: returns 503 (not 200) in production when CF_ACCESS_CLIENT_SECRET is missing", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ CF_ACCESS_CLIENT_SECRET: undefined });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(503);
    expect(captured).toHaveLength(0);
    expect(errSpy).toHaveBeenCalled();
  });

  it("DoD §3: returns 503 in production when both service token vars are missing", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({
      CF_ACCESS_CLIENT_ID: undefined,
      CF_ACCESS_CLIENT_SECRET: undefined,
    });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(503);
    expect(captured).toHaveLength(0);
  });

  it("staging (ENVIRONMENT != production) does NOT fail-fast on missing service token, only warns", async () => {
    // wrangler dev / ローカル上流 (service token なし) を妨げないための逃げ道。
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({
      ENVIRONMENT: "staging",
      CF_ACCESS_CLIENT_ID: undefined,
      CF_ACCESS_CLIENT_SECRET: undefined,
    });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(200);
    expect(captured).toHaveLength(1);
    expect(warnSpy).toHaveBeenCalled();
    // 上流リクエストには CF-Access-* ヘッダが付かない
    expect(captured[0].headers.get("cf-access-client-id")).toBeNull();
    expect(captured[0].headers.get("cf-access-client-secret")).toBeNull();
  });

  it("DoD §4: returns 500 when SIGNAL_ORIGIN is unset", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ SIGNAL_ORIGIN: "" });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(500);
    expect(captured).toHaveLength(0);
  });

  it("rewrites upstream URL to SIGNAL_ORIGIN host while preserving /signal path and query", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({ SIGNAL_ORIGIN: "https://signal.example.com:8443" });
    const req = new Request("https://phone.a-taquan.com/signal?token=ext1.99.sig", {
      method: "GET",
    });

    await proxySignal(req, env, fetchImpl);

    const upstreamUrl = new URL(captured[0].url);
    expect(upstreamUrl.protocol).toBe("https:");
    expect(upstreamUrl.host).toBe("signal.example.com:8443");
    expect(upstreamUrl.pathname).toBe("/signal");
    expect(upstreamUrl.searchParams.get("token")).toBe("ext1.99.sig");
  });

  it("forwards CF-Connecting-IP as X-Forwarded-For for upstream logging", async () => {
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv();
    const req = new Request("https://phone.a-taquan.com/signal", {
      method: "GET",
      headers: { "cf-connecting-ip": "203.0.113.42" },
    });

    await proxySignal(req, env, fetchImpl);

    expect(captured[0].headers.get("x-forwarded-for")).toBe("203.0.113.42");
  });

  it("ENVIRONMENT comparison is case-insensitive", async () => {
    // "Production" / "PRODUCTION" でも fail-fast を発火させる。
    const { fetchImpl, captured } = makeCaptureFetch();
    const env = makeEnv({
      ENVIRONMENT: "Production",
      CF_ACCESS_CLIENT_ID: undefined,
    });
    const req = new Request("https://phone.a-taquan.com/signal", { method: "GET" });

    const res = await proxySignal(req, env, fetchImpl);

    expect(res.status).toBe(503);
    expect(captured).toHaveLength(0);
  });
});
