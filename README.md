# sabiden

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

Phase 1 (基盤実装) 進行中。
詳細は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照。

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
docker build -t sabiden -f deploy/docker/Dockerfile .
docker run --network host -v $(pwd)/config.toml:/etc/sabiden/config.toml sabiden
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
