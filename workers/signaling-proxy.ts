// Cloudflare Worker: sabiden PWA のエッジ。
//
// - `/signal` (HTTP/WS): Cloudflare Tunnel 経由で自宅 sabiden に転送する。
//   Cloudflare は WebSocket アップグレードを `fetch` でそのまま中継できる。
// - その他のパス: `ASSETS` バインディング (frontend/dist) を SPA フォール
//   バック付きで返す。
//
// セキュリティ (Issue #101):
//   - `phone.a-taquan.com` (このWorker) は Cloudflare Access (email allow) で保護。
//   - 上流 `signal.a-taquan.com` (Tunnel → K8s) は Cloudflare Access の
//     Service Token policy で保護されており、本 Worker のみがアクセス可能。
//   - 上流呼び出し時に `CF-Access-Client-Id` / `CF-Access-Client-Secret`
//     ヘッダを付与する (Cloudflare Access service token 認証)。
//     [Cloudflare docs] https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/
//   - HMAC トークンは `?token=` または `Authorization: Bearer` で
//     クライアントから直接 sabiden 側に渡る (本 Worker は素通し)。
//
// Issue #101 修正:
//   1. `SIGNAL_HOST_HEADER` 未設定時は `SIGNAL_ORIGIN` の host を Host ヘッダに
//      設定する (標準 reverse proxy 挙動。 client が送ってきた Host が漏れて
//      `530 Origin DNS error` を引くのを防ぐ)。
//   2. `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` が片方でも欠けていれば
//      production (ENVIRONMENT==="production") では `503 Service Unavailable` を
//      返して fail-fast する。 200 のまま上流 403 を食らうのではなく、 PWA 側
//      ログで設定ミスを即時識別できるようにする。
//   3. `redirect: "manual"` を削除。 上流 30x は通常の fetch 既定 (= follow)
//      に任せ、 WS upgrade では redirect は来ないので意味のあるリダイレクトを
//      握り潰す band-aid を撤去する。

export interface Env {
  ASSETS: { fetch: (req: Request) => Promise<Response> };
  /** 例: https://signal.a-taquan.com (Cloudflare Tunnel hostname) */
  SIGNAL_ORIGIN: string;
  /** 任意: アップストリームに渡す Host ヘッダ (未指定なら SIGNAL_ORIGIN の host を使う) */
  SIGNAL_HOST_HEADER?: string;
  /** Cloudflare Access service token Client ID (上流 signal.* への認証用) */
  CF_ACCESS_CLIENT_ID?: string;
  /** Cloudflare Access service token Client Secret */
  CF_ACCESS_CLIENT_SECRET?: string;
  /** `"production"` で上流 secret 欠如時に fail-fast。 それ以外は warn ログのみ */
  ENVIRONMENT?: string;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/signal") {
      return proxySignal(request, env, globalThis.fetch);
    }

    // それ以外は静的アセット (SPA fallback は wrangler.toml で指定)
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

/** `proxySignal` が依存する `fetch` 実装を test 時に注入できるように分離。
 * production では `globalThis.fetch` (Cloudflare Workers runtime fetch) を渡す。 */
export type FetchLike = (req: Request) => Promise<Response>;

/** `/signal` リクエストを上流 sabiden (Cloudflare Tunnel 越し) に中継する。
 *
 * Issue #101 で次を満たす:
 *   - `SIGNAL_ORIGIN` 未設定 → 500 (誤設定検知)
 *   - production で service token 欠如 → 503 (上流 403 でなく Worker レイヤで停止)
 *   - Host ヘッダは `SIGNAL_HOST_HEADER` 優先、 未指定は `SIGNAL_ORIGIN` の host
 *   - WebSocket upgrade を含む `fetch` 中継、 redirect は既定 (= follow)
 *
 * Export している理由: vitest で fetch を mock してリクエスト形を assert する
 * 単体テストを書くため (test-strategy.md §2.1 の純粋関数寄りに整える)。 */
export async function proxySignal(
  request: Request,
  env: Env,
  fetchImpl: FetchLike,
): Promise<Response> {
  if (!env.SIGNAL_ORIGIN) {
    return new Response("SIGNAL_ORIGIN not configured", { status: 500 });
  }

  // Issue #101 §2: production で service token が片方でも欠けていたら
  // 上流 Access policy が必ず 403 を返すので、 Worker レイヤで先に 503 を返す。
  // staging / dev (`wrangler dev`) では warn ログのみで通過させ、 ローカル
  // 上流 (= service token 不要) に向ける開発を妨げない。
  const hasClientId = !!env.CF_ACCESS_CLIENT_ID;
  const hasClientSecret = !!env.CF_ACCESS_CLIENT_SECRET;
  const isProduction = (env.ENVIRONMENT ?? "").toLowerCase() === "production";
  if (!hasClientId || !hasClientSecret) {
    const msg =
      "CF_ACCESS_CLIENT_ID / CF_ACCESS_CLIENT_SECRET missing (set via `wrangler secret put`)";
    if (isProduction) {
      console.error(`[signaling-proxy] ${msg}; refusing to proxy /signal`);
      return new Response(
        "Cloudflare Access service token not configured on this Worker. " +
          "See docs/CLOUDFLARE.md §2.",
        { status: 503 },
      );
    }
    // production 以外でも気づけるよう warn は必ず出す。
    console.warn(`[signaling-proxy] ${msg} (allowed because ENVIRONMENT !== "production")`);
  }

  const upstream = new URL(env.SIGNAL_ORIGIN);
  const target = new URL(request.url);
  target.protocol = upstream.protocol;
  target.host = upstream.host;
  target.port = upstream.port;
  // path はそのまま (/signal) を維持

  // ヘッダを引き継ぎつつ、 Host を上書きする。
  // Issue #101 §1: 未指定の場合は SIGNAL_ORIGIN の host を使う (標準 reverse
  // proxy 挙動)。 client の Host (例: phone.a-taquan.com) が上流 Tunnel
  // (signal.a-taquan.com) に漏れると Cloudflare が `530 / 1016` を返す。
  const headers = new Headers(request.headers);
  const hostHeader = env.SIGNAL_HOST_HEADER ?? upstream.host;
  headers.set("host", hostHeader);

  // Cloudflare はクライアント IP を CF-Connecting-IP に入れるため、
  // 上流に X-Forwarded-For として追加 (sabiden 側のロギング用)
  const cfip = request.headers.get("cf-connecting-ip");
  if (cfip) headers.set("x-forwarded-for", cfip);

  // Cloudflare Access service token 認証ヘッダを付与。
  // これがないと上流 (signal.a-taquan.com) の Access policy で拒否される。
  // 未設定 (= production 以外) のときは付けないでそのまま中継する。
  if (hasClientId && hasClientSecret) {
    headers.set("CF-Access-Client-Id", env.CF_ACCESS_CLIENT_ID as string);
    headers.set("CF-Access-Client-Secret", env.CF_ACCESS_CLIENT_SECRET as string);
  }

  // WebSocket アップグレードでも fetch でそのまま中継できる
  // ([Cloudflare docs] https://developers.cloudflare.com/workers/runtime-apis/websockets/#using-websockets)。
  // `redirect: "manual"` は WS upgrade では発火せず、 通常 HTTP では 30x を
  // そのまま PWA に流してしまうため Issue #101 §3 で撤去 (既定 = follow)。
  return fetchImpl(
    new Request(target.toString(), {
      method: request.method,
      headers,
      body: request.body,
    }),
  );
}
