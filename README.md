# sabiden

[![CI](https://github.com/aoki-taquan/sabiden/actions/workflows/ci.yml/badge.svg)](https://github.com/aoki-taquan/sabiden/actions/workflows/ci.yml)
[![Release](https://github.com/aoki-taquan/sabiden/actions/workflows/release.yml/badge.svg)](https://github.com/aoki-taquan/sabiden/actions/workflows/release.yml)
[![PWA Deploy](https://github.com/aoki-taquan/sabiden/actions/workflows/pwa-deploy.yml/badge.svg)](https://github.com/aoki-taquan/sabiden/actions/workflows/pwa-deploy.yml)
[![Container](https://ghcr-badge.egpl.dev/aoki-taquan/sabiden/latest_tag?label=ghcr.io)](https://github.com/aoki-taquan/sabiden/pkgs/container/sabiden)

NTT ひかり電話 (NGN) を直接喋れる Rust 実装の SIP クライアント。
HGW (ホームゲートウェイ) を介さず、ONU 直収のルーター配下から
ひかり電話を発着信できるようにすることを目指す。

> **sabi (錆 = Rust の日本語) + den (電話)**

## 特徴 (目標)

- HGW 不要、SIP UA を直接 NGN に登録
- 内線として複数のスマホ・SIP 端末を収容 (Asterisk 風フォーク着信)
- IPv6 ネイティブ (NGN 内 SIP は IPv6)
- DHCP Option 120 (RFC 3361) による SIP サーバ自動検出
- DSCP 32 / Session Timer / Via rport 除去等、NTT NGN の特殊事情に対応
- systemd / Docker / Kubernetes デプロイ対応

## ステータス

| Phase | 内容 | 状態 |
|-------|------|------|
| 1 | SIP トランザクション層 / SDP / RTP / Health | ✅ 完了 |
| 2 | INVITE/BYE UAC / 内線 UAS / Call Manager | ✅ 完了 |
| 2.5 | main.rs 結線 / NGN 着信受付 / RTP ブリッジ / 観測機能 | ✅ 完了 |
| 3 | Cloudflare WebRTC ゲートウェイ / Opus トランスコード | ✅ 完了 |
| 4 | PWA フロントエンド / Cloudflare Workers デプロイ | 進行中 |

実機投入可能な状態に到達。詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) と [docs/INSTALL.md](docs/INSTALL.md) を参照。

## ドキュメント / デプロイ資材

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - アーキテクチャ概要
- [docs/INSTALL.md](docs/INSTALL.md) - 実機インストールガイド (NGN 直収)
- [docs/CLOUDFLARE.md](docs/CLOUDFLARE.md) - Cloudflare Tunnel + Workers デプロイ
- [frontend/README.md](frontend/README.md) - PWA フロントエンド (SolidJS) 開発手順
- [deploy/dhcp/](deploy/dhcp/) - DHCP Option 120 取得スクリプトと設定例
- [deploy/systemd/](deploy/systemd/) - systemd ユニット (ハードニング済)
- [deploy/docker/](deploy/docker/) - Dockerfile / docker-compose.yml (host network)
- [deploy/k8s/](deploy/k8s/) - Kubernetes マニフェスト (hostNetwork)

## クイックスタート

### ビルド
```bash
cargo build --release
```

### 設定
```bash
cp config.example.toml config.toml
# 値を編集
```

### 起動
```bash
./target/release/sabiden register --config config.toml
```

### Docker
```bash
# ghcr.io から取得 (main ブランチ最新)
docker pull ghcr.io/aoki-taquan/sabiden:main
# 安定版が出れば SemVer タグも利用可能
# docker pull ghcr.io/aoki-taquan/sabiden:v0.1.0

docker run --network host \
  -v $(pwd)/config.toml:/etc/sabiden/config.toml \
  ghcr.io/aoki-taquan/sabiden:main

# ローカルビルドが必要な場合
docker build -t sabiden -f deploy/docker/Dockerfile .
```

### Kubernetes
```bash
kubectl apply -f deploy/k8s/deployment.yaml
```

## 必要な環境

- ひかり電話契約 (DHCPv6-PD で /56 取得のため)
- フレッツ光ネクスト (NGN 接続)
- Linux (libc IPV6_TCLASS による DSCP 設定のため)
- Rust 1.95 以降

## 関連 RFC

| RFC | 内容 |
|-----|------|
| 3261 | SIP: Session Initiation Protocol |
| 3264 | SDP Offer/Answer Model |
| 4566 | SDP: Session Description Protocol |
| 4028 | Session Timers in SIP |
| 3361 | DHCP Option for SIP Servers |
| 2617 | HTTP Digest Authentication |
| 3550 | RTP: Real-time Transport Protocol |

## ライセンス

MIT
