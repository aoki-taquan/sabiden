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
# home-ops の terraform-cloudflare で signal.a-taquan.com の Tunnel を立てる構成
echo "https://signal.a-taquan.com" | npx wrangler secret put SIGNAL_ORIGIN
# 任意: 上流に渡す Host ヘッダの上書き
# echo "signal.a-taquan.com" | npx wrangler secret put SIGNAL_HOST_HEADER

# Cloudflare Access service token (上流 Tunnel が non_identity policy で
# 保護されているため、本 Worker が認証ヘッダを付ける必要がある)
# home-ops apply 後に terraform output で取得した値を投入する
#   terraform output -raw sabiden_pwa_worker_service_token_client_id
#   terraform output -raw sabiden_pwa_worker_service_token_client_secret
echo "$CLIENT_ID"     | npx wrangler secret put CF_ACCESS_CLIENT_ID
echo "$CLIENT_SECRET" | npx wrangler secret put CF_ACCESS_CLIENT_SECRET

# デプロイ
npx wrangler deploy
```

これで `https://sabiden-pwa.<account>.workers.dev` (もしくは Worker
ルート ` https://pwa.example.com/* `) で配信される。

> **自動デプロイ**: 上記の `wrangler deploy` は初回と secret 変更時のみ手動で実行する。
> `main` ブランチへ `frontend/**` または `workers/**` の変更がマージされると、
> `.github/workflows/pwa-deploy.yml` が GitHub Actions 上で同等のビルドと
> `wrangler deploy` を自動実行する。
> GitHub リポジトリの Secrets に以下を事前登録しておくこと:
>
> - `CLOUDFLARE_API_TOKEN` ... `Edit Cloudflare Workers` 権限を持つ API token
> - `CLOUDFLARE_ACCOUNT_ID` ... 対象アカウントの ID
>
> Worker 側の secret (`SIGNAL_ORIGIN`, `CF_ACCESS_CLIENT_ID`,
> `CF_ACCESS_CLIENT_SECRET`, `HMAC_SECRET` 等) は CI からは投入しない。
> 漏洩経路を最小化するため、上記 `wrangler secret put` を **初回と値変更時のみ**
> 手元で実行する運用とする。

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
| WS が 503 (`Cloudflare Access service token not configured`) | Worker 自体が fail-fast (Issue #101)。 `npx wrangler secret list` で `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` の両方が登録されているか確認。 欠けていれば §2 の `wrangler secret put` を再実行する。 ENVIRONMENT=production 限定の挙動 (staging/dev では warn のみで通す) |
| WS が 530 / 1016 (Origin DNS error) | 上流 Tunnel hostname と Worker の Host ヘッダが不一致。 `SIGNAL_HOST_HEADER` を `SIGNAL_ORIGIN` の host に揃えるか、 設定を外す (未指定なら SIGNAL_ORIGIN の host が自動採用される、 Issue #101) |
| WS が 401 | HMAC トークンの `expiry` 過去 / `secret` 不一致 |
| WS が 100 秒で切れる | Cloudflare Tunnel の **idle timeout = 100 秒** で切断される (cloudflared 既定動作)。 sabiden は 30 秒周期で WebSocket Ping (RFC 6455 §5.5.2) を送り続けて経路上の idle timer をリセットしている。 PWA 側 `SignalingClient` は close code 別に再接続するため通話継続は維持される (Issue #98 / #127)。 周期の調整は `[webrtc] keepalive_interval_secs` / `idle_timeout_secs` (Issue #131) |
| 音が出ない | iOS Safari は user gesture 後でないと `audio.play()` できない (本 PWA は応答ボタンで起動) |
| PWA インストール不可 | HTTPS と manifest が必須。Workers/Pages なら自動 HTTPS |

### 6.1 WebSocket keepalive 設計 (Issue #98 / #131)

Cloudflare Tunnel は **idle 100 秒で WebSocket を切断する**。 sabiden は経路上の
idle timer を確実にリセットするため、 サーバ → クライアント方向に WebSocket
Ping (RFC 6455 §5.5.2) を周期的に送る:

| パラメータ | 既定値 | 用途 |
| --- | --- | --- |
| `keepalive_interval_secs` | 30 | Ping 送出周期 (RFC 6455 §5.5.2、 経路 idle timer リセット) |
| `idle_timeout_secs` | 60 | 受信フレーム不在で WS 撤収する閾値 (Pong 不在検知、 RFC 6455 §7.4.1 status 1011 Close で撤収) |

両者とも Cloudflare の 100 秒 timeout より十分短い。 通常は既定で十分だが、
他の idle timer (別 LB / SBC / NAT) が経路に挟まる場合のみ短縮する。 環境変数
`SABIDEN_WEBRTC_KEEPALIVE_INTERVAL_SECS` / `SABIDEN_WEBRTC_IDLE_TIMEOUT_SECS`
でも上書き可能 (K8s Secret マウント等)。

ブラウザ側は Pong を自動で返す (RFC 6455 §5.5.3 SHOULD、 axum WebSocket は
受信 Ping 自動応答)。 PWA は能動的な keepalive を持たない。
