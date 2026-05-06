// Cloudflare Worker: sabiden PWA のエッジ。
//
// - `/signal` (HTTP/WS): Cloudflare Tunnel 経由で自宅 sabiden に転送する。
//   Cloudflare は WebSocket アップグレードを `fetch` でそのまま中継できる。
// - その他のパス: `ASSETS` バインディング (frontend/dist) を SPA フォール
//   バック付きで返す。
//
// セキュリティ:
//   - Cloudflare Access で Worker ルートを保護する場合は zero-trust の
//     CF-Access-JWT-Assertion を見る形で拡張する (Phase 2)。
//   - HMAC トークンは `?token=` または `Authorization: Bearer` で
//     クライアントから直接 sabiden 側に渡る (本 Worker は素通し)。

export interface Env {
  ASSETS: { fetch: (req: Request) => Promise<Response> };
  /** 例: https://home-sabiden.example.com (Cloudflare Tunnel hostname) */
  SIGNAL_ORIGIN: string;
  /** 任意: アップストリームに渡す Host ヘッダ */
  SIGNAL_HOST_HEADER?: string;
  ENVIRONMENT?: string;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/signal") {
      return proxySignal(request, env);
    }

    // それ以外は静的アセット (SPA fallback は wrangler.toml で指定)
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;

async function proxySignal(request: Request, env: Env): Promise<Response> {
  if (!env.SIGNAL_ORIGIN) {
    return new Response("SIGNAL_ORIGIN not configured", { status: 500 });
  }
  const upstream = new URL(env.SIGNAL_ORIGIN);
  const target = new URL(request.url);
  target.protocol = upstream.protocol;
  target.host = upstream.host;
  target.port = upstream.port;
  // path はそのまま (/signal) を維持

  // ヘッダを引き継ぎつつ、Host を上書きする
  const headers = new Headers(request.headers);
  if (env.SIGNAL_HOST_HEADER) headers.set("host", env.SIGNAL_HOST_HEADER);
  // Cloudflare はクライアント IP を CF-Connecting-IP に入れるため、
  // 上流に X-Forwarded-For として追加 (sabiden 側のロギング用)
  const cfip = request.headers.get("cf-connecting-ip");
  if (cfip) headers.set("x-forwarded-for", cfip);

  // WebSocket アップグレードでも fetch でそのまま中継できる
  return fetch(
    new Request(target.toString(), {
      method: request.method,
      headers,
      body: request.body,
      redirect: "manual",
    }),
  );
}
