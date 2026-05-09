# sabiden アーキテクチャ

## 全体構成

```
                  ┌─────────────────────────────────────┐
                  │     スマホ (Linphone/Zoiper等)      │
                  │     SIP UA (内線として登録)          │
                  └──────────────┬──────────────────────┘
                                 │ SIP/UDP (内線)
                                 │ RTP/RTCP
                                 ▼
┌────────────────────────────────────────────────────┐
│             sabiden (Rust, Linux)                  │
│                                                    │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │ SIP UAS     │  │ Call Manager │  │ SIP UAC   │ │
│  │ (内線受付)   │◄─┤ (転送/ブリッジ)├─►│ (NGN登録) │ │
│  └─────────────┘  └──────┬───────┘  └─────┬─────┘ │
│                          │                │       │
│                   ┌──────▼────────────────▼─────┐ │
│                   │  RTP Relay / Transcoder     │ │
│                   │  (G.711 ⇔ G.711 / Opus)     │ │
│                   └──────────────┬──────────────┘ │
└──────────────────────────────────┼────────────────┘
                                   │ SIP/UDP + RTP
                                   │ (NGN IPv6 経由)
                                   ▼
                       ┌────────────────────┐
                       │   NTT NGN / IMS    │
                       │   (P-CSCF)         │
                       └────────────────────┘
```

## モジュール構成

```
src/
├── sip/              # SIP プロトコル層
│   ├── message.rs    # メッセージ パース/シリアライズ (RFC 3261)
│   ├── auth.rs       # Digest 認証 (RFC 2617)
│   ├── transport.rs  # UDP/TLS トランスポート (将来)
│   ├── transaction.rs # トランザクション層 (RFC 3261 §17)
│   ├── dialog.rs     # ダイアログ層 (RFC 3261 §12)
│   ├── register.rs   # REGISTER + Session Timer (RFC 4028)
│   ├── invite.rs     # INVITE/BYE/ACK (UAC)
│   └── uas.rs        # UAS (内線受付)
├── sdp/              # SDP パーサ (RFC 4566)
├── rtp/              # RTP/RTCP (RFC 3550)
│   ├── packet.rs
│   ├── session.rs
│   └── codec/
│       ├── ulaw.rs   # G.711 μ-law
│       └── opus.rs   # Opus (将来)
├── dhcp/             # DHCP Option 120 検出 (RFC 3361)
├── call/             # 通話制御 (Call Manager)
│   ├── manager.rs    # 着信フォーク・通話状態管理
│   └── bridge.rs     # RTPブリッジ
├── config/           # 設定 (TOML + 環境変数 for K8s)
├── health/           # ヘルスチェック HTTP サーバ
└── main.rs
```

## レイヤ責務

### SIP Transport Layer
- UDP ソケット送受信 (TCP/TLS は将来)
- DSCP マーキング (32 / TOS 0x80)
- 受信メッセージのトランザクション層へのルーティング
- UDP recv バッファは **UDP datagram 上限 65535 オクテット** (`MAX_UDP_DATAGRAM_SIZE` in `src/sip/transaction.rs`)。
  RFC 3261 §18.1.1 / §18.3 により UDP では 1 SIP メッセージ = 1 datagram だが、
  `recv_from` は buf を超える datagram を silently truncate する。NGN の 200 OK は通常 1〜2 KB だが、
  Path / Service-Route / Authentication-Info 多段で 8 KB を超える事例があるため、上限まで確保する
  (issue #88)。`n == buf.len()` で受信した場合は truncate の兆候として warn ログを残す
  (RFC 3261 §18.4 Error Handling)。

### SIP Transaction Layer (RFC 3261 §17)
- トランザクション ID (branch + via-sent-by + cseq-method)
- タイマー T1/T2/T4 管理
- 再送制御

### SIP Dialog Layer (RFC 3261 §12)
- ダイアログ ID (Call-ID + From-tag + To-tag)
- CSeq 管理
- Route Set 管理

### Call Manager
- 着信を全内線にフォーク (Asterisk 風)
- 最初に応答した内線で通話確立、他はキャンセル
- 通話中の RTP ブリッジ

## 通話フロー

### 着信 (NGN → スマホ)

```
NGN ──INVITE──► sabiden(UAC)
                    │
                    │ 全内線にフォーク
                    ├──INVITE──► スマホ1
                    ├──INVITE──► スマホ2
                    └──INVITE──► スマホ3

スマホ1 ──200 OK──► sabiden ──200 OK──► NGN
スマホ2 ◄──CANCEL── sabiden
スマホ3 ◄──CANCEL── sabiden

[RTPブリッジ確立: NGN ⇔ sabiden ⇔ スマホ1]
```

### 発信 (スマホ → NGN)

```
スマホ ──INVITE──► sabiden(UAS)
                    │
                    │ 内線認証
                    │
sabiden(UAC) ──INVITE──► NGN
                    │
sabiden ◄──200 OK── NGN
スマホ ◄──200 OK── sabiden

[RTPブリッジ確立]
```

## Phase 計画

### Phase 1: 基本機能（現在）
- SIP REGISTER (NGN への登録)
- SIP INVITE/BYE (発着信)
- SDP/RTP 基本実装
- G.711 μ-law コーデック
- 内線 UAS (スマホ受付)
- 設定ファイル (TOML + 環境変数)

### Phase 2: スマホ統合
- マルチデバイス着信フォーク
- DTMF 転送
- ヘルスチェック / メトリクス
- Docker / K8s デプロイ
- 内線 SIP 認証

### Phase 3: Cloudflare 連携
- WebRTC ゲートウェイ
- Cloudflare Workers / Realtime 統合
- Zero Trust 認証連携
- Opus トランスコード

### Phase 4: 拡張
- ボイスメール
- 通話録音
- 通話履歴 API
- 複数回線対応

## デプロイ形態

### systemd
- 単一バイナリ
- `/etc/sabiden/config.toml`
- ログは journald

### Docker / K8s
- 環境変数で設定上書き (`SABIDEN_SIP_PASSWORD` など)
- Secret マウント `/run/secrets/sabiden/`
- liveness: HTTP `/healthz`
- readiness: HTTP `/readyz` (REGISTER 成功後 ready)
- hostNetwork: true 推奨 (SIP は NAT 越え難しいため)

### NGN 接続要件
- IPv6 接続性必須
- DHCPv6-PD で /56 取得済み (ひかり電話契約必須)
- DHCP Option 120 で SIP サーバ取得
