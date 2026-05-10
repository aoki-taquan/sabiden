# sabiden frontend

NTT ひかり電話 (NGN) を喋る `sabiden` の WebRTC PWA フロントエンド。

- フレームワーク: SolidJS + TypeScript + Vite
- PWA: `vite-plugin-pwa` (Workbox / autoUpdate)
- バックエンド: `sabiden` の `/signal` WebSocket (HMAC-SHA256 認証)
- デプロイ先: Cloudflare Workers / Pages (詳細は [docs/CLOUDFLARE.md](../docs/CLOUDFLARE.md))

## 必要環境

- Node.js 20 LTS 以降
- npm 10 以降

## セットアップ

```bash
cd frontend
cp .env.example .env
npm install
```

環境変数:

| 変数 | 用途 |
| --- | --- |
| `VITE_SIGNAL_URL` | 本番ビルド時の WS URL (例: `wss://example.com/signal`)。空なら同一オリジン |
| `VITE_SIGNAL_BACKEND` | `npm run dev` 時に `/signal` をプロキシする宛先 (既定: `http://127.0.0.1:8080`) |

## 開発

別端末で sabiden を起動 (HMAC secret は `config.toml` 参照)。

```bash
# 1. 開発トークン発行 (cargo example or 手元スクリプトで):
#    <ext_id>.<expiry_unix>.<base64url(hmac-sha256(secret, "ext.expiry"))>
#
# 2. dev server 起動
npm run dev
# -> http://localhost:5173
```

トークンは:

- ログイン画面の入力欄に貼り付け
- もしくは `http://localhost:5173/#token=<token>` でアクセス (URL から自動取込)

## ビルド

```bash
npm run build      # -> dist/ にバンドル
npm run preview    # 本番ビルドのローカル確認
```

## Lint / Format

```bash
npm run lint
npm run format
```

## ディレクトリ

```
frontend/
├── public/icons/         # PWA アイコン (PNG は CI 前に生成: README 参照)
├── src/
│   ├── components/       # Login / Dialer / CallScreen
│   ├── lib/
│   │   ├── signaling.ts  # /signal WS クライアント (JSON プロトコル)
│   │   ├── webrtc.ts     # RTCPeerConnection ラッパ
│   │   └── storage.ts    # トークン保管 (in-memory + sessionStorage、 Issue #109)
│   ├── App.tsx
│   ├── main.tsx
│   └── styles.css        # iOS / Android 両対応
├── index.html
├── vite.config.ts        # PWA プラグイン + dev proxy
└── tsconfig.json
```

## バックエンドプロトコル要約

詳細は `src/webrtc/signaling.rs`。

- C→S: `register` / `offer` / `answer` / `ice` / `bye`
- S→C: `registered` / `answer` / `ice` / `error` / `bye`
- 認証: WS 接続時に `?token=<HMAC>` を付与 (ブラウザ WS API は HTTP ヘッダを足せないためクエリのみ)

## モバイル動作確認

- iOS Safari: `getUserMedia` は HTTPS 必須 (Cloudflare Pages なら自動)
- Android Chrome: 「ホーム画面に追加」で PWA インストール
- バックグラウンド着信は Service Worker + Web Push (Phase 2 TODO)

## TODO

- [ ] サーバ → クライアント方向の `offer` (NGN 着信通知) 配線 (バックエンド側 #25 と協調)
- [ ] Web Push 着信通知
- [ ] Cloudflare Access JWT 検証経路 (`Cf-Access-Jwt-Assertion`)
- [ ] PWA アイコン PNG の自動生成スクリプト
