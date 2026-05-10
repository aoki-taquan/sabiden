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
- `parse_message` は **生バイト** ベース。 Content-Length (RFC 3261 §20.14)
  を見て本文を切り出し、 truncate 検知時 / 重複 Content-Length 時は `Err` で
  drop。 body は opaque octet 列 (RFC 3261 §7.4) として扱い、UTF-8 妥当性は
  要求しない。 ヘッダ部も `from_utf8_lossy` で U+FFFD 置換し、 不正バイト
  混入による DoS 経路を遮断する (詳細 → [`architecture.md`](./architecture.md) §11.6)。

### SIP Transaction Layer (RFC 3261 §17)
- トランザクション ID (branch + via-sent-by + cseq-method)
- タイマー T1/T2/T4 管理
- 再送制御

### SIP Dialog Layer (RFC 3261 §12)
- ダイアログ ID (Call-ID + From-tag + To-tag)
- CSeq 管理
- Route Set 管理 (UAC 視点では Record-Route の **逆順**, RFC 3261 §12.1.2)
- **Next-hop 計算 (RFC 3261 §12.2.1.1, Issue #79)**: in-dialog リクエスト
  (2xx ACK / BYE / Re-INVITE / その ACK / INFO 等) の **宛先 SocketAddr**
  は dialog の next-hop URI から導出する。 INVITE 送信先 (= 通常 P-CSCF) を
  そのまま流用しない。
  - `route_set` 空: next-hop = remote target (= 2xx 応答の Contact)。
  - `route_set` 非空 (loose / strict 共通): next-hop = 先頭 Route URI。
  - host が IPv4 / IPv6 リテラル + 明示 port のときのみ確定し、 FQDN /
    port 省略時は INVITE 送信先 (`server_addr`) にフォールバック (RFC 3263
    SRV / NAPTR 解決は別 Issue)。
  - NGN 直収では Contact / Record-Route が `<IP>:5060` 確定 (`docs/asterisk-real-invite.md` §5.6)
    なので、 結果として既存 117 通話パスは挙動不変 (NGN P-CSCF == Contact-host)。

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

### Re-INVITE (内線 → sabiden、 RFC 3261 §14.2 / Issue #94)

確立済み dialog 内で内線 UA が SDP renegotiation (hold/un-hold) や
Session-Timer (RFC 4028) 更新を要求する場合、 **To-tag 付き INVITE** を送る。
sabiden は新規 dialog として扱わず、 既存 B2BUA dialog ペアを引いて NGN
レッグへ Re-INVITE を伝搬する。 200 OK の To-tag は **既存 dialog の
local-tag を保持** する (RFC 3261 §12.2.2)。

```
スマホ ──Re-INVITE (To-tag=existing)──► sabiden(UAS)
                                             │
                                             │ Call-ID で OutboundCallRegistry を引く:
                                             │   confirmed dialog あり → 100 Trying を返し下記の通り伝搬
                                             │   confirmed 無し / pending INVITE あり → 491 Request Pending
                                             │       (RFC 3261 §14.2: glare 検出)
                                             │   confirmed も pending も無し → 481 Call/Transaction Does Not Exist
                                             │       (RFC 3261 §12.2.2)
                                             │
sabiden(UAC) ──Re-INVITE (新 SDP offer)──► NGN
                                             │
sabiden ◄──200 OK + 新 SDP answer── NGN
sabiden(UAC) ──ACK──► NGN
スマホ ◄──200 OK + 新 SDP answer (To-tag=existing 保持)── sabiden

[RTP は既存ブリッジを継続使用; SDP direction (sendrecv↔sendonly) のみ変化]
```

**判定基準** (`src/sip/uas.rs::handle_invite`):

- `To` ヘッダに `;tag=...` がある → `UasEvent::Reinvite` を上位に通知
  (binding 検証 skip; in-dialog request は既存 dialog state で認可される)。
  パラメータ名 `tag` は **case-insensitive** 比較 (RFC 3261 §7.3.1 / §25.1)
  なので `;Tag=` `;TAG=` も Re-INVITE と判定する。
- `To` に tag が無い → 従来通り `UasEvent::Invite` (新規 dialog 確立経路)

**491 Request Pending (RFC 3261 §14.2 glare)**:

確立済み dialog (`lookup_by_ext`) が無いが、 同じ Call-ID で進行中 INVITE
(`get_pending`) がある場合 (= 初回 INVITE 完了前に同 Call-ID で再度 INVITE
が来た = race / glare) は **491 Request Pending** で返す。 RFC 3261 §14.2:
"If a UA receives a re-INVITE for an existing dialog while it has an INVITE
it had sent in the same dialog still pending, it MUST return a 491 (Request
Pending) response to the received INVITE"。 内線 UA は 491 を受けて
Section 14.1 のバックオフ (T1 数倍の random jitter) で Re-INVITE を再試行する。

**既知の制限** (Phase R3 で改善):

- RTP ブリッジ媒介時の Re-INVITE SDP 書換 (sabiden 側 port / IP 差替) は
  未実装。 現状は SDP 透過モードでの hold/un-hold / Session-Timer 更新のみ
  正しく動く。 ブリッジ媒介時の Re-INVITE 経路は `prepare_outbound_bridge` /
  `finalize_outbound_bridge` を `handle_ext_reinvite` にも結線する必要がある
  (`docs/refactor-plan.md` §1.4 / Phase R3 Negotiator)。
- PRACK / 100rel (RFC 3262)、 UPDATE (RFC 3311) は別 Issue (Phase R2)。
- NGN 側 Re-INVITE が 4xx/5xx で失敗した場合は同コードを内線へ中継する
  (491 Request Pending を含む RFC 3261 §14.2 glare 解消は内線 UA の責務)。
- **Follow-up: Issue #138** —
  Re-INVITE 200 OK 中継時の SDP rewrite (RTP ブリッジ媒介での sabiden 側
  port / IP 差し替え)、 Min-SE (RFC 4028 §5) の整合、 NGN→sabiden 向き
  Re-INVITE (NGN-initiated re-negotiation) の対応は本 PR #136 の scope
  外として #138 で別途追跡。

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
