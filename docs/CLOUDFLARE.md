# Cloudflare デプロイ手順

`sabiden` の PWA フロントエンドを Cloudflare 経由で公開し、自宅の `sabiden`
バックエンドと WebSocket シグナリングを行うためのレシピ。

```
[ブラウザ] ──HTTPS──► [Cloudflare Edge: Worker / Pages] ──Tunnel──► [自宅 sabiden:8080]
              静的: frontend/dist                                  axum /signal (WS)
              /signal: WS パススルー
```

## 0. 前提

- Cloudflare アカウント (Free プランで可。Zero Trust も Free 50 user)
- 公開ドメイン (例 `example.com`) の Cloudflare DNS
- 自宅で `sabiden` が `0.0.0.0:8080` を listen していること

## 1. Cloudflare Tunnel (自宅 → エッジ)

`cloudflared` を自宅マシンにインストールし、`sabiden` を非公開で
Cloudflare に接続する。

```bash
# 1) ログイン (ブラウザでドメイン認可)
cloudflared tunnel login

# 2) トンネル作成
cloudflared tunnel create sabiden

# 3) 設定 (~/.cloudflared/config.yml)
cat > ~/.cloudflared/config.yml <<'YAML'
tunnel: sabiden
credentials-file: /home/sabiden/.cloudflared/<UUID>.json

ingress:
  - hostname: home-sabiden.example.com
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
      # WebSocket は自動アップグレード (cloudflared 既定で OK)
  - service: http_status:404
YAML

# 4) DNS ルート
cloudflared tunnel route dns sabiden home-sabiden.example.com

# 5) systemd サービス化
sudo cloudflared service install
```

`https://home-sabiden.example.com/healthz` が 200 を返せば疎通 OK。
このホスト名は **エッジ → 家** の内部経路で使うだけで、PWA からは
直接叩かない (Worker が中継するため)。

## 2. Cloudflare Workers (エッジ + WS プロキシ)

`workers/` ディレクトリの `wrangler.toml` を使う。

```bash
cd frontend && npm install && npm run build && cd ..
cd workers && npm install

# 上流 Tunnel ホスト名を秘密値として登録 (公開しない)
echo "https://home-sabiden.example.com" | npx wrangler secret put SIGNAL_ORIGIN
# 任意: 上流に渡す Host ヘッダの上書き
# echo "home-sabiden.example.com" | npx wrangler secret put SIGNAL_HOST_HEADER

# デプロイ
npx wrangler deploy
```

これで `https://sabiden-pwa.<account>.workers.dev` (もしくは Worker
ルート ` https://pwa.example.com/* `) で配信される。

### ルーティング

`workers/signaling-proxy.ts` の動作:

- `GET /signal` → `SIGNAL_ORIGIN/signal` に **WebSocket** で中継 (HMAC トークンはクエリで素通し)
- それ以外 → `frontend/dist` を SPA フォールバック付きで配信

## 3. Cloudflare Pages 構成 (代替)

Workers Assets ではなく Pages を使いたい場合:

1. リポジトリを Pages にコネクト
2. ビルドコマンド: `cd frontend && npm ci && npm run build`
3. 出力ディレクトリ: `frontend/dist`
4. `frontend/dist/_worker.js` か Pages Functions (`functions/signal.ts`) で
   `/signal` を Tunnel ホストに転送 (`workers/signaling-proxy.ts` と同等の処理)

## 4. Cloudflare Access (Phase 2: SSO)

現状の `sabiden` は HMAC 認証のみだが、Worker の前段に Cloudflare Access
を被せて SSO (Google / GitHub / Okta) を強制できる。

1. Zero Trust ダッシュボード → Access → Applications → Self-hosted
2. Domain: `pwa.example.com` (Worker ルート)
3. Identity provider: Google など
4. Policy 例:

   | name | action | rule |
   | --- | --- | --- |
   | family | Allow | Emails ending in `@example.com` |
   | block-others | Block | Everyone |

5. (Phase 2) Worker で `Cf-Access-Jwt-Assertion` を検証し、JWT の `sub`
   を ext_id にマッピングして HMAC 不要にする。バックエンド側で
   `jsonwebtoken` を有効化する PR が必要 (Issue 残)。

注意: `/signal` の WebSocket は **Service Token** ではブラウザから付与
できないため、Access を効かせる場合は Cookie ベース (`CF_Authorization`)
を許可するか、Access を Worker ルート全体ではなく `/admin` 等のみに
限定する設計を推奨。

## 5. CSP / セキュリティヘッダ

Worker レイヤで以下を付与することを推奨 (現状未実装、TODO):

```
Content-Security-Policy: default-src 'self'; connect-src 'self' wss:; media-src 'self' blob:; img-src 'self' data:; script-src 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: microphone=(self)
```

## 6. トラブルシュート

| 症状 | 確認 |
| --- | --- |
| WS が 502 | `cloudflared tunnel info sabiden` で接続確認、`SIGNAL_ORIGIN` 値 |
| WS が 401 | HMAC トークンの `expiry` 過去 / `secret` 不一致 |
| 音が出ない | iOS Safari は user gesture 後でないと `audio.play()` できない (本 PWA は応答ボタンで起動) |
| PWA インストール不可 | HTTPS と manifest が必須。Workers/Pages なら自動 HTTPS |
