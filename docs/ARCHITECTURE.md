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
│   ├── auth.rs       # Digest 認証 (RFC 2617 / RFC 7616 §3.3 stale + opaque)
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
│   ├── bridge.rs     # RTPブリッジ
│   ├── orchestrator.rs # B2BUA orchestration (NGN inbound / 内線・PWA outbound)
│   └── rate_limiter.rs # outbound INVITE per-AOR rate limiter (TTC JJ-90.24 §5.7.1, Issue #157)
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
- `parse_message_classified` は **生バイト** ベース。 Content-Length (RFC 3261 §20.14)
  を見て本文を切り出し、 truncate 検知時 / 重複 Content-Length 時 / 非数値
  Content-Length 時は分類済 `ParseError` を返し、`recv_loop` 側で必須ヘッダ
  (Via/From/To/Call-ID/CSeq) を best-effort 抽出できれば RFC 3261 §21.4.1
  に従い `400 Bad Request` を UDP source へ返送する (Issue #126)。 抽出
  不能なケースは silent drop (RFC 3261 §16.3)。 body は opaque octet 列
  (RFC 3261 §7.4) として扱い、UTF-8 妥当性は要求しない。 ヘッダ部も
  `from_utf8_lossy` で U+FFFD 置換し、 不正バイト混入による DoS 経路を
  遮断する (詳細 → [`architecture.md`](./architecture.md) §11.6)。

### SIP Transaction Layer (RFC 3261 §17)
- トランザクション ID (branch + via-sent-by + cseq-method)
- タイマー T1/T2/T4 管理
- 再送制御
- **応答 skeleton header echo の不変条件 (RFC 3261 §8.2.6.2 / §12.1.1 / §20.38, Issue #90)**:
  `src/sip/transaction.rs::build_response_skeleton` は受信 request から
  応答に必須 / 推奨される ヘッダを **過不足なく** コピーする:
  - Via / From / To / Call-ID / CSeq: §8.2.6.2 で MUST copy。
  - **Record-Route**: §12.1.1 で 2xx 応答は MUST copy (順序と多重度を保つ)。
    UAS 側で echo しないと UAC 側 dialog の route set (§12.1.2 で逆順) が
    空になり、 in-dialog BYE / Re-INVITE / UPDATE が proxy 多段経路で
    loose routing 解決失敗する。 全応答 (provisional / final) で一律 echo
    して呼出側の漏れを防ぐ (UAC 側は 2xx のみ参照する仕様)。
  - **Timestamp**: §20.38 で SHOULD echo (RTT 計測用途)。
  - **意図的に非コピー**: Contact (§20.10 で UAS 連絡先)、 Route (§16.4
    request 側ヘッダ)、 Max-Forwards / Allow / Supported 等は呼出側で組み立てる。

### SIP Dialog Layer (RFC 3261 §12)
- ダイアログ ID (Call-ID + From-tag + To-tag)
- CSeq 管理
- **UAS To-tag 付与の不変条件 (RFC 3261 §8.2.6.2 / Issue #100)**: 内線 UAS
  (`src/sip/uas.rs::ResponderHandle`) は **100 Trying を除く全応答**
  (1xx provisional / 2xx / 3xx / 4xx / 5xx / 6xx) で To に tag を付与する。
  `respond_with_body` は元から `ensure_to_tag` を通すが、 `quick` も同様に
  通す (二重付与防止は `has_to_tag` の case-insensitive 比較で in-dialog
  request の既存 tag を保持)。 100 Trying のみ §8.2.6.2 例外条項に従い tag
  付与をスキップ。 これにより strict UA (Asterisk pjsip 旧版 / Cisco /
  Polycom) が tag 無し final 応答を silently drop する経路を遮断する。
- Route Set 管理 (UAC 視点では Record-Route の **逆順**, RFC 3261 §12.1.2)
- **Next-hop 計算 (RFC 3261 §12.2.1.1, Issue #79 / Issue #133)**: in-dialog
  リクエスト (2xx ACK / BYE / Re-INVITE / その ACK / INFO 等) の **宛先
  SocketAddr** は dialog の next-hop URI から導出する。 INVITE 送信先
  (= 通常 P-CSCF) をそのまま流用しない。 単一情報源は
  `Dialog::next_hop_socket(fallback)` (Issue #133 で uac.rs から dialog 層へ
  push)、 uac.rs / UacDialog はこのメソッドへ委譲する。
  - `route_set` 空: next-hop = remote target (= 2xx 応答の Contact)。
  - `route_set` 非空 (loose / strict 共通): next-hop = 先頭 Route URI。
  - host が IPv4 / IPv6 リテラル + 明示 port のときのみ確定し、 FQDN /
    port 省略時は INVITE 送信先 (`server_addr`) にフォールバック
    (**RFC 3263 §4.1 SRV / NAPTR 解決は未実装、 別 Issue で対応予定**)。
  - NGN 直収では Contact / Record-Route が `<IP>:5060` 確定 (`docs/asterisk-real-invite.md` §5.6)
    なので、 結果として既存 117 通話パスは挙動不変 (NGN P-CSCF == Contact-host)。
  - regression 防止: BYE / Re-INVITE の **dual-server harness** test
    (`rfc3261_12_2_1_1_{bye,reinvite}_goes_to_dialog_remote_target_not_server_addr`)
    で `server_addr` と Contact-host を別 SocketAddr に分け、 in-dialog
    リクエストが Contact 側に届くことを検証。

### Call Manager
- 着信を全内線にフォーク (Asterisk 風)
- 最初に応答した内線で通話確立、他はキャンセル
- 通話中の RTP ブリッジ

### NGN UAS メソッド ディスパッチ (Issue #110)

`NgnInboundHandler::handle_inbound` は NGN 側 `TransactionLayer` から
受信した SIP リクエストを method 別に振り分ける。 以前 (PR #154 以前) は
`SipMethod::Other(String)` を含む未対応メソッドを **一律 405** で
拒否していたが、 RFC 3261 §8.2.1 が要求する `Allow` ヘッダが欠落しており、
かつ NOTIFY (reg-event) / MESSAGE (SMS) 等で UA の再送ストームを誘発する
band-aid だった。 Issue #110 で以下の通り個別 default 応答に整理:

| Method | 応答 | 根拠 |
|---|---|---|
| `INVITE` | 100 Trying → フォーク → 200/4xx/487 | RFC 3261 §13 |
| `ACK` | 応答なし (pending 1 件消費) | RFC 3261 §17.2.7 |
| `BYE` | NGN レッグ確定後の通話終了 | RFC 3261 §15.1.1 |
| `CANCEL` | 200 OK + 内線フォーク中止通知 | RFC 3261 §9.2 |
| `OPTIONS` | 200 OK + `Allow` | RFC 3261 §11 / §20.5 |
| `NOTIFY` | 481 Subscription Does Not Exist + `Allow` | RFC 3265 §3.2 |
| `SUBSCRIBE` | 489 Bad Event + `Allow` | RFC 3265 §7.2.4 |
| `PRACK` | 481 Call/Transaction Does Not Exist + `Allow` | RFC 3262 §4 |
| `PUBLISH` | 489 Bad Event + `Allow` | RFC 3903 §11.1 |
| `UPDATE` | 481 + `Allow` | RFC 3311 §5.2 |
| `INFO` | 481 + `Allow` | RFC 6086 §4 |
| `MESSAGE` | 200 OK + `Allow` (本文破棄) | RFC 3428 §7 |
| `REFER` | 405 Method Not Allowed + `Allow` | RFC 3261 §8.2.1 |
| `Other(_)` | 405 + `Allow` | RFC 3261 §8.2.1 |

`Allow` ヘッダは sabiden NGN UAS が実装経路を持つ method のみ列挙する:
`INVITE, ACK, BYE, CANCEL, OPTIONS` (定数 `SUPPORTED_METHODS_ALLOW`)。
UPDATE 等は 481 で拒否するため Allow には含めない (§20.5 「supports」の
語義に合わせる)。

`SipMethod` enum 側 (`src/sip/message.rs`) も `Update` / `Message` /
`Refer` を専用バリアント化済 (旧来は `Other(String)` 経由)。 これにより
上位ハンドラは `match` 式の網羅性チェックを得る。

内線側 (`src/sip/uas.rs`) の同種ディスパッチは Phase R2 で同様の方針で
整理する予定 (`docs/refactor-plan.md` §4.4)。

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
                    │ [OutboundRateLimiter::check_and_record(from_aor)]
                    │   Allow → 続行
                    │   Deny  → 503 Service Unavailable + Retry-After で内線へ返却
                    │
sabiden(UAC) ──INVITE──► NGN
                    │
sabiden ◄──200 OK── NGN
スマホ ◄──200 OK── sabiden

[RTPブリッジ確立]
```

#### outbound INVITE per-AOR rate limiter (Issue #157)

TTC JJ-90.24v2 §5.7.1 (連続リクエスト送信制限) / §5.7.3 (INVITE 5xx 自動 retry
禁止) を遵守するため、 `UasEventHandler` は per-AOR で発信間隔を計測し、
short window 内の連投を local で **503 Service Unavailable + Retry-After**
(RFC 3261 §21.5.4 / §20.33) で早期拒否する。 これにより NGN P-CSCF が
過負荷状態に入って 5xx を返し、 周辺端末まで巻き込まれる事故 (= cooldown 連鎖)
を防ぐ。

```rust
struct OutboundRateLimiter {
    state: Mutex<HashMap<AOR, AorState>>,
    config: RateLimiterConfig {
        min_interval: Duration,            // 既定 3 秒 (HGW 推定値)
        failure_backoff_steps: Vec<Duration>, // 既定 [5, 10, 30] 秒
    },
}
```

判定ロジック (TTC §5.7.1 / §5.7.3):

| 状態 | effective wait | 出口 |
|---|---|---|
| 初回発信 | 0 (即時 Allow) | Allow |
| 直近 INVITE が成功 (2xx) | `min_interval` | Allow / 短い Retry-After |
| 直近 INVITE が 5xx | `max(min_interval, failure_backoff_steps[streak-1])` | 長めの Retry-After |
| NGN から `Retry-After: N` 受信中 | 上記の max と Retry-After 残時間 | NGN 指示時間まで Deny |

- **fail feedback**: NGN INVITE が 5xx で失敗したら `record_failure(aor, status, retry_after_secs)`
  を呼んで `failure_streak` を 1 増やし、 `Retry-After` ヘッダがあれば
  `retry_after_until` を記録する。 4xx (例 486 Busy Here) は streak 対象外。
- **success feedback**: 2xx 確立で `record_success(aor)` → `failure_streak=0` リセット。
- **AOR 抽出**: 内線→NGN は `UasEvent::Invite::from_aor`、 PWA→NGN は
  `ngn_uac.config().local_uri` (sabiden REGISTER 番号、 全 PWA WS で共通) を bucket key にする。

メトリクス (`/metrics` Prometheus exposition):

- `sabiden_sip_invite_blocked_by_rate_limit_total{direction=...}` — rate limiter で
  503 拒否した INVITE 累計 (TTC §5.7.1 適用回数)。
- `sabiden_sip_invite_interval_seconds_{sum,count}` — 連続 outbound INVITE 発射間隔の summary。

### 発信 (PWA → NGN、 Issue #145 / #147)

PWA (WebRTC ブラウザ) は SIP dialog を持たず、 専用 WS シグナリングと
str0m (ICE/DTLS-SRTP) で sabiden に接続する。 NGN レッグは sabiden が
UAC として通常の SIP INVITE で発呼する。 B2BUA SDP anchoring (RFC 5853 §3.2)
で 2 つの SDP 交渉は完全に独立: PWA 側は SAVPF/Opus、 NGN 側は AVP/PCMU。

```
PWA ──ClientMessage::Offer{target,sdp(SAVPF)}──► sabiden(WS シグナリング)
                                                       │
                                                       │ [OutboundRateLimiter::check_and_record(ngn_aor)]
                                                       │   Deny → ServerMessage::Error{code:"rate_limited", retry_after} で PWA へ返却
                                                       │
                                                       │ peer.handle_offer → SAVPF answer
                                                       ▼
PWA ◄──ServerMessage::Answer{sdp(SAVPF)}── sabiden  (RFC 8829 / RFC 3264 §6)
        ▲
        │  (背景タスク化、 RFC 8839 §4 trickle ICE 詰まり対策)
        │
sabiden(UAC) ──INVITE (AVP/PCMU)──► NGN
                                       │
sabiden ◄──200 OK── NGN              (`docs/asterisk-real-invite.md` §5)
                                       │
sabiden ──ACK──► NGN                  (RFC 3261 §17.1.1.3 ACK for 2xx)
                                       │
[MediaBridge::WebRtcAudio 起動: NGN UDP ⇄ Opus⇔PCMU ⇄ str0m peer]
```

PWA 経路の rate limiter 詳細は「発信 (スマホ → NGN)」セクション (Issue #157) を参照。
PWA 経路では bucket key として ngn_uac の REGISTER AOR を使うため、 複数 PWA
WS セッションが同時に連投しても同じ bucket で集約され、 NGN cooldown 連鎖を防ぐ。

**双方向 BYE 連動 (Issue #147)**:

PWA は SIP dialog を持たないため、 既存の `OutboundCallRegistry`
(内線→NGN 発信用 = `ext_dialog` 必須) は使えない。 専用テーブル
`webrtc_outbound_active: HashMap<NGN_Call_ID, WebRtcOutboundEntry>` を
`UasEventHandler` と `NgnInboundHandler` で **同じ Arc を共有** することで、
RFC 3261 §15.1.2 / RFC 5853 §3.2.2 SBC framework の片側 dialog 終了を
もう片側に伝搬する責務を満たす:

| エントリ要素 | 用途 |
|---|---|
| `ngn_dialog: Mutex<UacDialog>` | PWA 切断時に NGN へ BYE を撃つ (RFC 3261 §15.1.1) |
| `ws: WsSink` | NGN 切断時に PWA へ `ServerMessage::Bye` を push |
| `bridge_call_id: CallId` | BYE 時に `CallManager::terminate` で RTP ブリッジ停止 |

```
[NGN→PWA BYE flow]                                  [PWA→NGN BYE flow]
NGN ──BYE──► sabiden                                PWA ──ClientMessage::Bye / WS close──► sabiden
              │                                                                              │
              │ (1) NGN へ 200 OK 即返答                                                    │ (1) PwaOutboundCloser::close_pwa_outbound_for_ws
              │ (2) webrtc_outbound_active.remove(call_id)                                  │ (2) webrtc_outbound_active から WS 一致エントリ remove
              │ (3) CallManager::terminate(bridge_call_id)                                  │ (3) ngn_dialog.send_bye() (RFC 3261 §15.1.1)
              │ (4) metrics.dec_call_active                                                 │ (4) CallManager::terminate(bridge_call_id)
              │ (5) ngn_dialog.terminate (state)                                            │ (5) metrics.dec_call_active
              │ (6) ws.send(ServerMessage::Bye)                                             │
              ▼                                                                              ▼
PWA ◄──ServerMessage::Bye── sabiden                 sabiden(UAC) ──BYE──► NGN
                                                    sabiden          ◄──200 OK── NGN
```

両 flow とも同じ手順 (テーブル先 `remove` → bridge `terminate` → `dec_call_active`) を踏み、
最後に dialog 終了通知を反対側 (PWA / NGN) に出して完了する。 `CallManager` Arc を outbound と
inbound で共有することで `bridge_call_id` の `terminate` がどちら経路から来ても確実に効く
(PR #154 review #2 🔴: 別 Arc 構成だと NGN→PWA BYE 経路の `terminate` が silent no-op に
なり RTP bridge socket / spawn task が leak する)。

**leak 防止 (Issue #147)**:

PWA outbound 成立 branch (`UasEventHandler::handle_pwa_outbound_offer` の
`Established(call)` arm 内、 bridge attach 完了後) のみテーブルに insert する。
途中失敗 (NGN SDP 解析失敗 / `CallManager` 未注入 / `attach_media_bridge`
失敗) では:

1. テーブルには insert しない (leak しない)
2. **best-effort で NGN BYE を撃つ** (`ngn_dialog.send_bye()`) — NGN は
   既に 200 OK を返して dialog confirmed だが、 sabiden 側で通話を保持
   できないので即座に閉じる。 これを怠ると NGN が 5 分タイムアウトまで
   dialog を残し、 同番号への再発信が 486 Busy Here で弾かれる
   (Issue #147 の根本要因)。

**idempotency**:

NGN→PWA BYE と PWA→NGN BYE が同時に発火しても (例: PWA 切断中に NGN が
タイムアウト BYE を送る)、 テーブルから先に `remove` してから処理する
設計のため、 後勝ちは 0 件 = no-op で `dec_call_active` の二重減算は
起きない (`Metrics::dec_call_active` 自体も saturating-zero なので二重防御)。

### WS シグナリング keepalive (Issue #98 / #131)

Cloudflare Tunnel は **idle 100 秒で WebSocket を切断する** (`docs/CLOUDFLARE.md`
§6)。 sabiden 側 (`src/webrtc/signaling.rs::run_keepalive_loop`) は経路上の
idle timer をリセットするため、 サーバ → クライアント方向に WebSocket Ping
(RFC 6455 §5.5.2) を `keepalive_interval` 周期で送る。 Pong 不在
(= `last_recv` が `idle_timeout` を超えて更新されない) なら Close frame
(RFC 6455 §7.4.1 status 1011) を送って撤収する。

| パラメータ | 既定 | 設定 (`[webrtc]` セクション) | 環境変数 |
|---|---|---|---|
| `keepalive_interval` | 30 秒 | `keepalive_interval_secs` | `SABIDEN_WEBRTC_KEEPALIVE_INTERVAL_SECS` |
| `idle_timeout` | 60 秒 | `idle_timeout_secs` | `SABIDEN_WEBRTC_IDLE_TIMEOUT_SECS` |

**シャットダウン通知 (Issue #131)**: 受信ループ / 送信 forwarder / keepalive
の 3 タスクは `Arc<Notify>` で協調終了する。 通知側は **`notify_one()`** を
使う (tokio 1.x docs)。 `notify_waiters` だと awaiting でない瞬間に通知が
消滅するが、 `notify_one` は permit を蓄えるので受信ループが深い await から
戻った直後に即時 `notified()` が解決し、 アイドル切断時の撤収遅延を防ぐ
(Issue #131 で PR #128 由来の最大数秒遅延を解消)。

```
[3 タスク協調終了モデル]

run_session 受信ループ ──┐
                         ├── shutdown.notified() を select! 内で監視
keepalive タスク ────────┘
                         shutdown.notify_one() を発火する経路:
                         (1) keepalive: idle timeout 検知後 Close 送出 → notify_one → return
                         (2) keepalive: send_ping 失敗 (相手切断) → notify_one → return
                         (3) forwarder: WS send 失敗 → notify_one → break
                         (4) run_session: 受信ループ離脱 → notify_one (周辺タスク撤収)
```

PWA 側は能動的な Ping を送らない (axum / ブラウザ WebSocket は受信 Ping を
RFC 6455 §5.5.3 自動応答)。 PWA の WS close ハンドリング (close code 別の再
接続 / バックオフ) は `frontend/src/lib/SignalingClient.ts` 側で完結する
(Issue #119 / #127)。

#### WS セッション終了時の resource cleanup (Issue #117)

`run_session` が受信ループから抜けるとき (= WS close / `Bye` 受信 / keepalive
idle / shutdown notify のいずれか) の **撤収シーケンス** は以下の固定順:

1. `shutdown.notify_one()` で keepalive タスクを起こす (Issue #131)。
2. `pwa_outbound_closer.close_pwa_outbound_for_ws(&ws_sink)` で PWA→NGN
   outbound 通話に NGN BYE を撃つ (Issue #147)。 これで
   `webrtc_outbound_active` テーブル内の同 WS 由来エントリ (= `WsSink`
   クローン保持) が drop される。
3. `pending_answers.cancel_all()` で **inbound fork waiter の全 oneshot::Sender
   を drop** する (Issue #117)。 これにより orchestrator 側
   `run_webrtc_leg::tokio::time::timeout(leg_timeout, waiter)` が `Ok(Err(_))`
   で即時抜け、 `LegResult::Errored` が返って `close_and_drain_webrtc_legs`
   で `WebRtcLegHandle.ws` (= `WsSink` クローン) が drop される。
   旧挙動 (WS 切断 → leg_timeout 30 秒待ち → 408) を即時撤収に短縮する。
4. `extensions.unregister(aor)` で `ExtensionRegistrar` から Binding を消す。
   Binding が保持していた `ExtTransport::WebRtc { ws: WsSink, .. }` クローンも
   ここで drop される。
5. `peer.close()` で str0m PeerSession を閉じる。 trickle ICE forwarder タスク
   は `local_cand_rx.recv() = None` で抜け、 自身が保持していた `WsSink`
   クローンを drop する。
6. `drop(ws_sink); drop(out_tx);` で `run_session` が握っている最後の `mpsc::
   UnboundedSender` を解放する。

全 sender が drop され次第 (= 上記 2-6 の完了時)、 forwarder タスクの
`out_rx.recv()` は `None` を返してタスクが終了する (tokio mpsc 仕様: 全
sender drop 時のみ recv が None)。 これにより **タスク / Sender / Mutex の
リークが発生しない**。

旧設計 (PR #165 以前) は `out_tx` を明示 drop しなかったため、 `run_session`
を抜けたあとも forwarder が `out_rx.recv()` で永久待機し、 `Arc<Mutex<
SplitSink>>` (= WebSocket sender) と forwarder タスクがリークしていた。
ピーク 100 接続/秒の WS 切断流入で数千の orphan task が発生し、 メモリと
CPU を浪費する事象が #117 で報告された。

### SDP 変換ヘルパ `convert_avp_to_savpf` / `convert_savpf_to_avp` (Issue #99)

`src/sdp/builder.rs` の 2 関数は B2BUA SDP anchoring (RFC 5853 §3.2) のうち
「SDP 翻訳」だけを担当する低レベルヘルパ。 現状の production 経路は
str0m の `create_offer` (`src/webrtc/str0m_session.rs`) を使うため、 本関数群は
**test fixture と将来の B2BUA 透過モード用**。

`convert_avp_to_savpf` (NGN AVP → ブラウザ SAVPF) は RFC 8829 §5.2.1 (JSEP) /
W3C webrtc-pc §5.7 に従い、 ブラウザ `setRemoteDescription()` が受理する
最低セットを生成する:

| 行 | 出力 | 根拠 |
|---|---|---|
| `m=audio <port> UDP/TLS/RTP/SAVPF 0` | proto 書換 | RFC 5764 §6 (SAVPF) |
| `a=rtcp-mux` | 多重化 | RFC 8843 §7.2 |
| `a=rtcp:<port>` | RTCP port 明示 | RFC 3605 §2.1 (rtcp-mux 併用でも互換) |
| `a=ice-ufrag` / `a=ice-pwd` | ICE credentials | RFC 8839 §5.4 |
| `a=fingerprint:<algo> <hex>` / `a=setup:<role>` | DTLS-SRTP | RFC 8842 §5 |
| `a=mid:0` | BUNDLE tag | RFC 8843 §7.2 |
| `a=sendrecv` (無ければ補う) | direction | RFC 4566 §6 |
| `a=msid:<stream> <track>` | track binding | RFC 8830 §2 |
| `a=ssrc:<id> cname:<cname>` | SSRC ⇔ Stream | RFC 5576 §6.1 |
| `a=ssrc:<id> msid:<stream> <track>` | SSRC ⇔ track 二重化 | RFC 5576 §4.1 / W3C unified-plan |
| `a=group:BUNDLE 0` (session level) | bundling | RFC 8843 §7.2 |
| `a=msid-semantic:WMS *` (session level) | MediaStream semantic | RFC 8830 §2 |
| `a=ice-options:trickle` (session level) | trickle ICE | RFC 8840 §4 |

SSRC / CNAME / msid は `DtlsIceParams::with_ssrc()` / `with_cname()` /
`with_msid()` で呼び出し側が指定可能。 未指定なら `o=` の session-id 由来の
安定値 (CNAME は `"sabiden"`、 track id は `"audio0"`) が補われ、 同一 SDP に
対する変換は冪等 (二度かけても重複しない)。

`convert_savpf_to_avp` (ブラウザ SAVPF → NGN AVP) は逆方向で、 DTLS-SRTP /
ICE / msid / ssrc / extmap 等の NGN が解釈しない属性を全て剥がし、
`m=audio <port> RTP/AVP 0` + PCMU rtpmap だけに正規化する (RFC 5853 §3.2、
NGN 制約は CLAUDE.md §5)。

### WebRtcAudioBridge メディア経路 (PWA ↔ NGN、 Issue #148 / #153)

PWA レッグと NGN レッグはそれぞれ独立に SDP 交渉する (B2BUA SDP anchoring,
RFC 5853 §3.2)。 通話中の音声バイトは `MediaBridge::WebRtcAudio`
(= `WebRtcAudioBridge`、 `src/call/transcoder.rs`) が「NGN 側 UDP socket」と
「str0m peer の MediaFrame mpsc」を 2 本の async ループで結ぶ:

| ループ | 入力 | 出力 | 関数 |
|---|---|---|---|
| `ngn_to_peer_loop` | NGN UDP socket | `peer.send_media(MediaFrame)` | `src/call/transcoder.rs::ngn_to_peer_loop` |
| `peer_to_ngn_loop` | `peer_media_rx: mpsc::Receiver<MediaFrame>` | NGN UDP socket | `src/call/transcoder.rs::peer_to_ngn_loop` |

#### str0m が PCMU 1 codec のみ negotiate する理由

`src/webrtc/str0m_session.rs:187-191` で `RtcConfig` を `clear_codecs()` →
`enable_pcmu(true)` で構成しているため、 ブラウザに返す SDP も sabiden が
受理する RTP も **PCMU PT 0 のみ**。 sabiden は NGN ↔ ブラウザを G.711 μ-law
で **トランスコード無し**にパススルーする想定 (`webrtc/str0m_session.rs` 行内
コメント抜粋: "NGN ↔ ブラウザの間を G.711 μ-law でパススルーする想定。 Opus
は本パスでは使わない")。

これは band-aid ではなく、 NGN 側コーデックが PCMU only に確定 (CLAUDE.md §5、
`docs/asterisk-real-invite.md` §2) しているため:

- **両側 PCMU**: 8 kHz / 20 ms / 160 sample → sample rate も frame size も一致。
  upsample / downsample / Opus encode/decode を挟む理由が無い。
- **CPU / レイテンシ削減**: フレーム境界待ち (~20 ms) と Opus codec 演算 (数 %
  CPU) を全て省ける。 PWA ↔ NGN の片道遅延は SRTP/DTLS と ICE 経路のみで決まる。
- **品質**: 8 kHz μ-law を 48 kHz Opus に往復させる無駄な再標本化を避ける。

#### `direct_pcmu_passthrough` 二モード分岐

`WebRtcAudioConfig::direct_pcmu_passthrough: bool` で 1 ブリッジが 2 モードを
切替える。 現状の orchestrator (`src/call/orchestrator.rs:811`、 同 `:2337`)
は **常に `true`** で起動する (NGN 着信 / PWA 発信どちらの経路も str0m PCMU
only 構成のため)。 false 経路は Opus 有効化時の path として残置 (将来拡張)。

```text
                    ┌──────────────────────────────────────────────┐
                    │  WebRtcAudioBridge (src/call/transcoder.rs)  │
                    └──────────────────────────────────────────────┘

  [direct_pcmu_passthrough = true]            [direct_pcmu_passthrough = false]
  (現行: str0m PCMU only、 Issue #148)        (将来: PWA Opus 有効化時の path)

  NGN UDP                                     NGN UDP
   │ RTP/PCMU PT0 8kHz/160sample              │ RTP/PCMU PT0 8kHz/160sample
   ▼                                          ▼
  ngn_to_peer_loop                           ngn_to_peer_loop
   │ (1) RtpPacket::from_bytes               │ (1) RtpPacket::from_bytes
   │ (2) PT==PCMU & len==160 確認            │ (2) PT==PCMU & len==160 確認
   │ (3) payload をそのまま MediaFrame        │ (3) decode_ulaw → AudioFrame(8k)
   │     {pt:0, rtp_time+=160}               │ (4) UpsamplerNbToWb(8k→48k)
   │                                         │ (5) OpusEncoder::encode → Opus payload
   │                                         │ (6) MediaFrame{pt:opus_pt, rtp_time+=960}
   ▼                                          ▼
  peer.send_media(MediaFrame)                peer.send_media(MediaFrame)
   │                                         │
   ▼                                          ▼
  str0m → DTLS-SRTP → PWA                    str0m → DTLS-SRTP → PWA
                                              (PT=opus_pt 経路は str0m が
                                               negotiate しない限り drop)

  ── 反対方向 ──                              ── 反対方向 ──

  PWA → DTLS-SRTP → str0m                    PWA → DTLS-SRTP → str0m
   │                                         │
   ▼                                          ▼
  peer_to_ngn_loop                           peer_to_ngn_loop
   │ peer_media_rx.recv()                    │ peer_media_rx.recv()
   │ (1) frame.pt==PCMU(=expected_pt) 確認   │ (1) frame.pt==opus_pt 確認
   │ (2) payload をそのまま μ-law 列に       │ (2) OpusDecoder::decode → 48k PCM (N×960)
   │ (3) RtpPacket{PT0, seq+=1, ts+=160}     │ (3) chunks(960) で 20ms 分割 (Issue #89)
   │                                         │ (4) 各 chunk: DownsamplerWbToNb(48k→8k)
   │                                         │ (5) 各 chunk: encode_ulaw → 8k μ-law 列
   │                                         │ (6) 各 chunk: RtpPacket{PT0, seq+=1, ts+=160}
   ▼                                          ▼
  NGN UDP                                     NGN UDP (N packet)
```

両モードとも:

- **NGN 出口は常に PCMU PT 0** (RFC 3551 §4.5.14): `peer_to_ngn_loop` の
  `RtpPacket::payload_type` は `PAYLOAD_TYPE_ULAW` 固定。
- **NGN 側 DSCP=32** を `set_rtp_dscp` で設定 (CLAUDE.md §5、 `bridge.rs` と
  パリティ)。
- **late binding peer**: NGN 側 peer は `LegState::peer: Mutex<Option<SocketAddr>>`
  で SDP `c=`/`m=` から事前知識として与えるが、 受信した最初の datagram の
  src で上書き学習する (NAT/symmetric RTP 対応、 RFC 5853 §3.2.2 SBC framework)。
- **送信 RTP egress state は bridge 共有** (Issue #112 / RFC 3550 §5.1):
  SSRC / sequence / timestamp は loop ローカル変数ではなく
  `BridgeState::{ngn_to_web_egress, web_to_ngn_egress}: Mutex<RtpEgressState>`
  に集約。 bridge 起動時に random で 1 度払い出した後、 通話 lifetime 中は
  維持する。 これにより flow 中に SSRC が変動してブラウザ jitter buffer /
  NGN 端末側の SSRC change handler が走るリスクを除去している
  (テスト: `rfc3550_5_1_transcode_*_ssrc_stable_across_flow_*`)。

passthrough モードでの **frame fast path**:

| 工程 | 直送 (true) | トランスコード (false) |
|---|---|---|
| RTP parse | あり | あり |
| PT/length 検証 | PT=0 / len=160 | PT=0 / len=160 |
| codec 変換 | **無し** (payload clone のみ) | μ-law decode → upsample → Opus encode |
| RTP timestamp 増分 | 160 (8 kHz) | 960 (48 kHz) |
| MediaFrame.pt | 0 (PCMU) | `opus_payload_type` (= SDP negotiated、 default 111) |
| 反対方向 expected_pt | `PAYLOAD_TYPE_ULAW` | `opus_payload_type` |

#### 既存 transcode 経路 (Opus⇔PCMU) の存在意義

`peer_to_ngn_loop` / `ngn_to_peer_loop` の **`!direct_pcmu_passthrough` 分岐は
削除しない**。 理由:

1. **str0m に Opus を negotiate させる将来拡張**: ブラウザ側の音質を上げるため
   `enable_opus(true)` を併用する選択肢が残っている。 そのとき NGN 側が
   PCMU only で固定された制約は変わらないので、 transcoder で μ-law ⇔ Opus
   変換が必要になる (RFC 7587 §4.2)。
2. **`TranscodingBridge`** (UDP socket ⇔ UDP socket、 `transcoder.rs`
   1L〜) は SIP-only 内線 (Asterisk / Linphone) が Opus を offer してきた
   場合の経路として残置済み。 PWA/str0m 経路 (`WebRtcAudioBridge`) と並列。
3. **コードの単一情報源**: `direct_pcmu_passthrough = false` 経路を消すと、
   将来 Opus 経路を追加する際にトランスコード処理を再実装する負債になる。
   現状では同じ `ngn_to_peer_loop` / `peer_to_ngn_loop` 関数に 2 モードを
   `if direct_pcmu_passthrough { ... } else { ... }` で同居させる方が安い。

#### `TranscodingBridge` のジッタバッファ (Issue #105)

`TranscodingBridge::{ngn_to_web_loop, web_to_ngn_loop}` は **両方向とも
`JitterBuffer` (`src/rtp/jitter.rs`) を経由する**。 受信タスクと
エンコード送信タスクは 1 つの async 関数内 `tokio::select!` で同居し、
[`JitterBuffer`] への排他アクセスを Mutex なしで実現する。

```text
recv_from(UDP)  ─push─►  JitterBuffer  ─pull─►  codec pipeline  ─send_to(UDP)
                          (depth=4)              (transcode)
                          ▲       ▲
                          │       └ tokio::time::interval (20 ms tick)
                          └ select! arm: 受信時即 push
```

| 項目 | 値 | 根拠 |
|---|---|---|
| バッファ深度 | 4 packet ≒ 80 ms | `src/rtp/jitter.rs::DEFAULT_DEPTH`、 RFC 3550 §6.4.1/§6.4.2 |
| Pull 周期 | 20 ms (`JITTER_PULL_INTERVAL`) | RFC 3551 §4.5.14 (PCMU) / RFC 7587 §4.2 (Opus) |
| MissedTickBehavior | `Delay` | tick lag 時の bursty 送出を避ける |
| PLC | 未実装 (端末側に委ねる) | RFC 7587 §6.2 (将来拡張余地) |
| RR cumulative_lost | `JitterStats::cumulative_lost()` = `max_seq_ext - base_seq_ext + 1 - received` (RFC 3550 §A.3) | Issue #93。 旧 `JitterStats.lost` (バッファ overflow 検出) は legacy 指標として残置 |

`WebRtcAudioBridge` (`ngn_to_peer_loop` / `peer_to_ngn_loop`) は str0m 自体が
ICE/SRTP 経路で再整列するため、 sabiden 側 jitter buffer は **挟まない**。
NGN ↔ UDP socket の `TranscodingBridge` のみが reorder 緩和の責務を負う
(SIP-only 内線が UDP で symmetric RTP を流す前提)。

#### Opus フレーム長と PCMU 分割 (Issue #89)

WebRTC ブラウザは通常 20 ms (= 960 samples @ 48 kHz) で Opus を送るが、
RFC 7587 §4.1 では **2.5 / 5 / 10 / 20 / 40 / 60 ms** が許される。 さらに
RFC 6716 §3.2 の code-3 (multi-frame) packet で 1 RTP に複数フレームを
集約でき、 合算 120 ms までデコード可能。 ブラウザの DTX (silence suppression)
復帰や Chrome の特定経路で 40 / 60 ms フレームが現れることが報告されている。

NGN 側は PCMU 20 ms 固定 (RFC 3551 §4.5.14) なので、 transcoder は
受信した N×20 ms Opus packet を 20 ms chunk に分割し、 N 個の PCMU RTP
packet として NGN へ送出する。

| ソース | 修正前の挙動 | 修正後 (Issue #89) |
|---|---|---|
| `OpusDecoder::decode` | 出力バッファ 960 固定、 40/60 ms は libopus エラー or truncate | `get_nb_samples` で必要量を取り、 5760 まで対応 |
| `TranscodingBridge::web_to_ngn_loop` | `len != 960` で silently drop | `chunks(960)` で N packet 送出 |
| `WebRtcAudioBridge::peer_to_ngn_loop` (non-passthrough) | 同上 | 同上 |
| PLC (packet.is_empty()) | 不変 | 不変 (RFC 7587 §6.2、 20 ms 固定で `OPUS_GET_LAST_PACKET_DURATION` 連動は将来) |

2.5 / 5 / 10 ms (= 20 ms の倍数でない非標準フレーム長) は現時点で未サポート
(transcoder で drop)。 これらは VoIP では稀で WebRTC ブラウザも生成しないため、
内部累積バッファでの 20 ms 揃え直しは将来 Issue で扱う。

#### orchestrator 配線

```text
[NGN → PWA 着信 (Issue #145、 src/call/orchestrator.rs:799-815)]

  NGN INVITE (PCMU only)
   ▼
  UasEventHandler / NgnInboundHandler
   │ ext_answer = browser SAVPF answer (str0m PCMU only)
   │ pcmu_only = restrict_audio_to_pcmu[_with_dtmf](ext_answer)  (RFC 3264 §5.1)
   │ rewritten = rewrite_rtp_endpoint(pcmu_only, sabiden NGN IP, port)
   ▼
  WebRtcAudioBridge::start(WebRtcAudioConfig{
      ngn_socket, ngn_peer, peer, peer_media_rx,
      opus_payload_type: handle.opus_payload_type,  // 参照のみ、 直送モードでは未使用
      direct_pcmu_passthrough: true,                 // ← str0m PCMU only 構成の必然
      metrics,
  })
   ▼
  CallManager::attach_media_bridge(call_id, MediaBridge::WebRtcAudio(bridge))


[PWA → NGN 発信 (Issue #145 / #147、 src/call/orchestrator.rs:2329-2340)]

  PWA Offer (SAVPF, PCMU only by str0m enable_pcmu)
   ▼ peer.handle_offer → SAVPF answer
   ▼ ServerMessage::Answer back to PWA
   ▼ NGN INVITE (AVP/PCMU)  →  200 OK + NGN SDP
   ▼ opus_pt = find_opus_payload_type(browser_answer) ?? DEFAULT_OPUS_PT
   ▼
  WebRtcAudioBridge::start(WebRtcAudioConfig{
      direct_pcmu_passthrough: true,                 // 同上、 PCMU 直送
      ...
  })
   ▼
  CallManager 登録 → BYE 連動 (CLAUDE.md §13 / Issue #147)
```

`opus_payload_type` フィールドは直送モードでも構造体に存在するが、
`peer_to_ngn_loop` の `expected_pt` は `direct_pcmu_passthrough = true` で
`PAYLOAD_TYPE_ULAW` に切替わるため (`src/call/transcoder.rs::peer_to_ngn_loop`
内 `let expected_pt = if direct_pcmu_passthrough { PAYLOAD_TYPE_ULAW } else { opus_pt };`)、
直送経路で参照されるのは `false` 分岐に切替えた将来時点のみ。

**`WebRtcAudioBridge::start` シグネチャ (Issue #135 🟡 3)**:
`pub fn start(cfg) -> Self` (旧 `Result<Self>` から変更)。 内部は
`set_rtp_dscp` warn 握り + `tokio::spawn` infallible で error path が
実行時に到達不能だったため、 `Result` を返さない誠実な API に揃えた。
呼出側 (`orchestrator.rs:799` / `orchestrator.rs:2329`) は `?` / `match Result`
不要、 戻り値を直接 `MediaBridge::WebRtcAudio` に `.into()` する。

#### ICE host candidate のアドレスファミリ (IPv4 / IPv6、 Issue #103)

`[webrtc] public_ip` は IPv4 リテラル / IPv6 リテラルどちらも受理する
(RFC 8839 §5.1 / RFC 5245 §4.1.1.2: ICE candidate の connection-address は
IP リテラル)。 `src/webrtc/str0m_session.rs::bind_udp_in_range` が
`public_ip` のファミリに応じて UDP socket を `0.0.0.0` (IPv4 UNSPECIFIED)
または `::` (IPv6 UNSPECIFIED) に bind し、 host candidate は `public_ip`
そのものを広告する。

純 IPv6 構成 (NGN 直収ホスト + Cloudflare Tunnel IPv6 backbone 等) でも
str0m バックエンドを有効化できる。 IPv4 / IPv6 同時 dual-stack 広告は
ファミリ別にソケットが必要で str0m 側の単一-Rtc / 単一-socket 設計から
踏み込んだ refactor が要るため、 本 PR 範囲では対応せず将来課題 (Issue #103
の DoD 末尾参照)。

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
- PRACK / 100rel (RFC 3262)、 UPDATE (RFC 3311) は内線 UAS 側で **未対応**
  (Phase R2)。 NGN 側は Issue #110 で 481 default を返すよう整理済 (「NGN UAS
  メソッド ディスパッチ」セクション参照)。
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
