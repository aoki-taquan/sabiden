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
│   ├── parser.rs    # 入力パース
│   ├── builder.rs   # シリアライズ + AVP↔SAVPF 変換 + restrict_audio_to_pcmu (Negotiator alias)
│   └── negotiation.rs # Negotiator: codec subset + WebRTC attr 剥離 + NGN 媒体正規化 (Phase R3, Issue #272)
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
│   ├── orchestrator.rs # B2BUA orchestration (NGN inbound / 内線・PWA outbound) + NGN even-port RTP allocator (Issue #260 Phase 1-D) + PwaDtmfHandler (Issue #277 RFC 4733) + voicemail hook (Issue #288) + active call recording hook (Issue #296) + PwaSmsHandler (Issue #299 RFC 3428)
│   ├── dtmf.rs       # RFC 4733 telephone-event RTP packet 列生成 + RFC 6086 SIP INFO body パース
│   ├── intercom.rs   # 内線間 direct dial (Issue #313): classify_dial_target / InternalCallRegistry / IntercomService / WebRtcRelay bridge helper
│   ├── rate_limiter.rs # outbound INVITE per-AOR rate limiter (TTC JJ-90.24 §5.7.1, Issue #157)
│   ├── recording.rs  # active call recording (Issue #296): PWA WS RecordStart/Stop で 通話中 RTP→WAV
│   ├── message_log.rs # SMS (RFC 3428 MESSAGE) 受信 / 送信 ring buffer (Issue #299): `/api/sms/recent` / `POST /api/sms` + WS SendSms
│   └── voicemail/    # 留守録 (Issue #288): NGN inbound fork all-fail → 200 OK + RTP→WAV recording
│       ├── mod.rs    # VoicemailRecorder / VoicemailFile / VoicemailHandle / VoicemailConfig
│       └── wav.rs    # WavWriter (RIFF/WAVE linear PCM 16-bit mono 8 kHz、 recording からも再利用)
├── config/           # 設定 (TOML + 環境変数 for K8s)
├── health/           # ヘルスチェック HTTP サーバ + JSON API (/api/call-log/recent、 Issue #278; /api/voicemail/* Issue #288; /api/recording/* Issue #296; /api/sms/* Issue #299; /api/{voicemail,recording}/:id/transcript Issue #300; /api/push/vapid-public-key Issue #294)
├── observability/    # メトリクス (Prometheus) + SIP トレース + call_log ring buffer (Issue #278) + transcription stub (Issue #300)
│   ├── mod.rs        # Metrics (atomic counter 群) + SipTraceWriter
│   ├── call_log.rs   # 通話履歴 ring buffer (Direction / Outcome / CallLogEntry / CallLog)
│   └── transcription.rs # AI 文字起こし stub (Issue #300): Transcriber trait + StubTranscriber + sidecar `.txt` I/O
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
- **`to_bytes` シリアライズ不変条件 (RFC 3261 §7.3.1 / §20.14、 Issue #85)**:
  `SipRequest::to_bytes` / `SipResponse::to_bytes` は `Content-Length` を
  ヘッダマップから出力せず、 末尾で `self.body.len()` から **正規生成** した
  1 行のみを書き出す。 `parse_message` は受信値を `headers` に格納するため、
  この防御がないと proxy / relay 透過パスや `parse → to_bytes` round-trip で
  `Content-Length` が二重に出力され、 strict parser (Asterisk pjsip 等) が
  400 Bad Request にする / request smuggling 経路を作る恐れがある。

### SIP Transaction Layer (RFC 3261 §17)
- トランザクション ID (branch + via-sent-by + cseq-method)
- タイマー T1/T2/T4 管理
- 再送制御
- **INVITE 応答受信進捗 watch (RFC 3261 §9.1 / Issue #97)**:
  `TransactionLayer::create_client` は INVITE 用クライアント transaction を
  登録するとき、 同時に `watch::Sender<InviteResponseProgress>` を
  `TransactionTable::provisional` に保持する。 状態は `Pending` 初期、
  `dispatch_response` で 1xx → `Provisional` / 最終応答 → `Final` に
  遷移する (monotonic、 Provisional → Final は許可、 Final → Provisional は不可)。
  `Uac::cancel_pending` は `TransactionLayer::provisional_watch(id)` で
  receiver を取り、 RFC 3261 §9.1 が要求する "CANCEL MUST NOT be sent
  before any provisional response" を満たすためここで Provisional への遷移を
  待機してから CANCEL を組み立てる。 最終応答が先に到達した場合は no-op
  (`CancelOutcome::NotSent`) で返り、 §9.1 後半 "CANCEL SHOULD NOT be sent
  if final response received" を満たす。 transaction 終了時 (`drop_client` /
  Timer D 経過後の absorber) には provisional エントリも一緒に drop される
  ため、 待機中の receiver は `changed()` で `Err` を受け取り NotSent で抜ける。
- **応答 skeleton header echo の不変条件 (RFC 3261 §8.2.6.2 / §12.1.1 / §20.38, Issue #90 / Issue #168)**:
  `src/sip/transaction.rs::build_response_skeleton` は受信 request から
  応答に必須 / 推奨される ヘッダを **過不足なく** コピーする:
  - Via / From / To / Call-ID / CSeq: §8.2.6.2 で MUST copy。
  - **To-tag 自動付与 (Issue #168)**: §8.2.6.2 "The UAS MUST add a tag to
    the To header field in the response (with the exception of the 100
    (Trying) response, in which a tag MAY be present)" に従い、
    `status != 100` かつ受信 To に tag が無ければ `;tag=sabiden-<random>`
    を自動付与する。 既存 tag (in-dialog Re-INVITE / BYE / UPDATE) は
    `has_to_tag` (case-insensitive) で検出して **そのまま echo**
    (§12.2.2: `;tag=old;tag=new` の二重 tag は dialog ID 不一致で
    内線 UA が ACK を返さず切断する罠)。 これにより stateless 400 /
    403 path (`try_send_400_bad_request` 等) で呼出側が
    `headers.set("To", ...)` を忘れても §8.2.6.2 MUST が満たされる。
    呼出側で B2BUA の他レッグ応答 tag を上書きしたい場合は
    `headers.set("To", "<uri>;tag=peer-tag")` で上書き可能 (set で再代入)。
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
- **UAS To-tag 付与の不変条件 (RFC 3261 §8.2.6.2 / Issue #100 / Issue #168)**:
  内線 UAS (`src/sip/uas.rs::ResponderHandle`) は **100 Trying を除く全応答**
  (1xx provisional / 2xx / 3xx / 4xx / 5xx / 6xx) で To に tag を付与する。
  単一情報源は **`build_response_skeleton` 内の `status != 100` 分岐**
  (Issue #168)。 これにより `respond_with_body` / `quick` だけでなく、
  stateless responder (`try_send_400_bad_request`) や transaction.rs
  経由の全 callsite で MUST が自動的に満たされる。 `uas.rs::ensure_to_tag`
  は **defensive な二重チェック** (skeleton 後に呼出側で `headers.set("To", ...)`
  が走るケース) として残るが、 skeleton 側で既に tag が乗るので no-op に
  なるのが定常パス。 100 Trying のみ §8.2.6.2 例外条項に従い tag 付与を
  スキップ。 これにより strict UA (Asterisk pjsip 旧版 / Cisco / Polycom)
  が tag 無し final 応答を silently drop する経路を遮断する。
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
受信した SIP リクエストを method 別に振り分ける。 以前 (PR #189 以前) は
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
| `MESSAGE` | 200 OK + `Allow` (`text/plain` 本文は ring buffer に store、 それ以外は破棄、 Issue #299) | RFC 3428 §7 / §10 |
| `REFER` | 405 Method Not Allowed + `Allow` | RFC 3261 §8.2.1 |
| `Other(_)` | 405 + `Allow` | RFC 3261 §8.2.1 |

`Allow` ヘッダは sabiden NGN UAS が実装経路を持つ method のみ列挙する:
`INVITE, ACK, BYE, CANCEL, OPTIONS` (定数 `SUPPORTED_METHODS_ALLOW`)。
UPDATE 等は 481 で拒否するため Allow には含めない (§20.5 「supports」の
語義に合わせる)。

`SipMethod` enum 側 (`src/sip/message.rs`) も `Update` / `Message` /
`Refer` を専用バリアント化済 (旧来は `Other(String)` 経由)。 これにより
上位ハンドラは `match` 式の網羅性チェックを得る。

内線側 (`src/sip/uas.rs::handle_request`) も同じ方針で整理済 (Issue #273)。
`ExtensionUas` は SUBSCRIBE state machine / EventStateCompositor / refer-event
NOTIFY 経路を持たないため、 以下の通り default 応答を返す:

| Method | 応答 | 根拠 |
|---|---|---|
| `REGISTER` | 401 / 200 (Digest) | RFC 3261 §10.2 |
| `INVITE` | 100 → フォーク → 200/4xx | RFC 3261 §13 |
| `ACK` | 応答なし | RFC 3261 §17.2.7 |
| `BYE` | 200 OK (上位経由) | RFC 3261 §15.1.1 |
| `CANCEL` | 200 OK + 内線フォーク中止通知 | RFC 3261 §9.2 |
| `OPTIONS` | 200 OK | RFC 3261 §11 |
| `INFO` | 上位委譲 → 481 (未接続時) | RFC 6086 §3 / §4 |
| `NOTIFY` | 481 Subscription Does Not Exist + `Allow` | RFC 3265 §3.2 / RFC 6665 §3.2 |
| `SUBSCRIBE` | 489 Bad Event + `Allow` | RFC 6665 §4.1.4 |
| `PRACK` | 481 Call/Transaction Does Not Exist + `Allow` | RFC 3262 §4 |
| `PUBLISH` | 200 OK + `Allow` (本文破棄、 受け流し) | RFC 3903 §6 |
| `UPDATE` | 481 + `Allow` | RFC 3311 §5.2 |
| `MESSAGE` | 200 OK + `Allow` (`text/plain` body は ring buffer に store、 それ以外は破棄、 Issue #299) | RFC 3428 §7 / §10 |
| `REFER` | 202 Accepted → implicit sub + sipfrag NOTIFY (B2BUA 経路) / 上位未接続時のみ 405 + `Allow` | RFC 3515 §2.4.6 + RFC 3265 §3.1.2 |
| `Other(_)` | 405 + `Allow` | RFC 3261 §8.2.1 |

`Allow` ヘッダ値は内線側 `INVITE, ACK, BYE, CANCEL, OPTIONS, REFER` (定数
`SUPPORTED_METHODS_ALLOW` in `src/sip/uas.rs`)。 NGN 側は REFER を実装しない
(carrier 由来 REFER は Issue #289 scope 外) ため `INVITE, ACK, BYE, CANCEL,
OPTIONS` のみ。
PUBLISH の応答が NGN 側 (489 Bad Event) と内線側 (200 OK) で異なるのは、
NGN 側は carrier IMS が EventStateCompositor を期待するのに対し、 内線側
UA は presence publish を盲目的に 200 OK で吸って再送を止めるのが
推奨されるため (Issue #273)。

### REFER 内線間転送 (Issue #289、 RFC 3515 §2.4.6 + RFC 3265 §3.1.2)

内線 A が NGN 通話中に「内線 B へつなぐ」 を押下すると、 A が dialog 内 REFER
(Refer-To: `<sip:B@...>`) を sabiden に送る。 sabiden は B2BUA として以下の
signaling を駆動する (`src/call/orchestrator.rs::handle_ext_refer`):

```
内線 A         sabiden        内線 B (transferee)         NGN P-CSCF
  │              │                    │                       │
  ├─ REFER ─────►│                    │                       │
  │              │ (dialog lookup_by_ext, Refer-To parse)     │
  │              │ (scheme allowlist: sip:/sips: のみ, §2.4.1) │
  │◄─ 202 Accepted (RFC 3515 §2.4.6)  │                       │
  │              │ (implicit subscription start, §2.4.4)      │
  │◄─ NOTIFY sipfrag "SIP/2.0 100 Trying" (§2.4.5)            │
  ├─ 200 OK (NOTIFY) ──►│              │                       │ (RFC 6665 §4.2.2)
  │              │ (NOTIFY 100 await 完了、 順序保証 §3.2.2) │
  │              │ (registrar.lookup で B の binding 引き)    │
  │              │ (=toll fraud 防御: 未登録 AOR は INVITE 不発、 §26.1) │
  │              ├─ INVITE (offer-less, §13.2.1) ──►│         │
  │              │◄────────── 200 OK (SDP offer) ───┤         │
  │              ├─ ACK (TODO: SDP answer, §13.2.1 + RFC 3264 §5) ──►│
  │              │                    │                       │
  │◄─ NOTIFY sipfrag "SIP/2.0 200 OK", Subscription-State: terminated
  ├─ 200 OK (NOTIFY) ──►│              │                       │ (RFC 6665 §4.2.2)
  │              │                    │                       │
  │◄─ BYE (元 dialog) (RFC 3261 §15.1.1)                       │
  │              ├─────────────────── BYE (NGN レッグ) ───────►│
  │              │                    │                       │
```

**ノート (sequence の読み方):**

- 各 NOTIFY の `200 OK (NOTIFY)` は transferor UA が返す ACK 相当の応答
  (RFC 6665 §4.2.2 + RFC 3265 §3.2.2)。 sabiden 側は **進捗 NOTIFY を
  await し終わってから次の step に進む** (`send_refer_notify` で同期化)。
  これにより `100 Trying → terminated` の状態遷移が UDP 上で逐次保証され、
  transferor 側で「terminated を先に受けてから active を受ける」 race を
  防止する。 NOTIFY 200 OK が返らなくても 4 秒で timeout して進行する
  (transferor 不在時のフェイルセーフ)。
- transferee B への INVITE は **offer-less** で送出する (RFC 3261
  §13.2.1)。 本来 RFC 3264 §5 に従い ACK で SDP answer を返す必要が
  あるが、 本 PR は signaling 完成までの MVP として未実装。 媒体面
  (RTP bridge re-routing + NGN への Re-INVITE) は Issue #289 follow-up。

ステップ詳細:

1. **A → sabiden REFER**: dialog 内 (Call-ID = ext_call_id) で受信。 `src/sip/uas.rs`
   の REFER 分岐は `UasEvent::Refer` を上位へ流す (上位未接続時のみ 405 fallback)。
2. **dialog 検証 + Refer-To 解析 + 202 Accepted**: `OutboundCallRegistry::lookup_by_ext`
   で transferor の dialog を引く (見つからなければ 481、 RFC 3261 §12.2.2)。
   `Refer-To` ヘッダの user 部を `extract_refer_to_aor` で抽出する。 ここで
   **`sip:` / `sips:` 以外の scheme (`tel:` / `http:` / `https:` 等) は 400 で
   reject** する (RFC 3515 §2.4.1 + RFC 3261 §26.1 toll fraud 防御の素材レベル
   ガード)。 user 部抽出失敗時も 400。
3. **NOTIFY 100 Trying (await 完走)**: `Dialog::build_notify_refer_sipfrag` で
   `Event: refer` + `Subscription-State: active;expires=60` + `Content-Type:
   message/sipfrag;version=2.0` + body `SIP/2.0 100 Trying\r\n` を組み立て、
   ext_layer 経由で transferor へ送出。 **`tokio::spawn` は使わず `await` まで
   完走** することで、 RFC 3265 §3.2.2 が要求する subscription state 遷移の
   順序保証 (active → terminated) を UDP 送信側で逐次化する。 transferor
   からの NOTIFY 200 OK (RFC 6665 §4.2.2) は 4 秒で timeout (応答不要)。
4. **binding lookup + toll fraud gating**: `ExtensionRegistrar::lookup(target_aor)`
   で B の binding を引く。 **lookup 成功時のみ B への INVITE を発行** すること
   で、 外線番号風の AOR (例: `<sip:0312345678@ntt-east.ne.jp>`) が指定されても
   gateway を介した「踏み台外線発信」 が成立しない (RFC 3261 §26.1 + RFC 3515
   §2.4.1)。 二重防御として step 2 の scheme allowlist と組み合わせる。
   - 不在: NOTIFY sipfrag `SIP/2.0 404 Not Found` + `Subscription-State:
     terminated;reason=noresource` を送って終了 (元 dialog は維持)。
5. **B2BUA INVITE to transferee (offer-less, MVP)**: `UasEventHandler::ext_inviter`
   (= `NgnInboundHandler` と共有する `Arc<UacForker>`) で B へ INVITE を送出。
   **SDP body は空 (offer-less INVITE, RFC 3261 §13.2.1)**。 RFC 3264 §5 では
   ACK に SDP answer を載せる必要があるが、 本 PR では未実装 (B 側 UA が自前
   で SDP を組んで 200 OK で返す前提の blind transfer MVP)。 媒体面 (RTP bridge
   re-routing + NGN への Re-INVITE で SDP 再ネゴ) は Issue #289 follow-up。
6. **final NOTIFY + 元 dialog 終了**:
   - B が 2xx (Established): NOTIFY sipfrag `SIP/2.0 200 OK` を transferor へ送り、
     **元 dialog (transferor 内線 + NGN レッグ) を BYE** で閉じる (RFC 3261 §15.1.1)。
     `teardown_transferred_dialog` で UacDialog::send_bye + Dialog::build_bye の双方を
     fire し、 RTP bridge も `CallManager::terminate` で停止する。
   - B が 4xx/5xx/6xx: NOTIFY sipfrag (`SIP/2.0 486 Busy Here` 等) を送って終了。
     元 dialog は維持 (transferor は元通話を継続できる)。
   - inviter エラー: NOTIFY `SIP/2.0 503 Service Unavailable`。

NGN 側から sabiden への REFER (carrier 由来) は本実装の scope 外 (Issue #289)。
`NgnInboundHandler::handle_inbound` の REFER 分岐は default の 405 reject のまま。

## 通話フロー

### 着信ルーティング rules (Issue #295、 `src/call/routing.rs`)

NGN inbound INVITE のフォーク先を `[[routing.rule]]` で時間帯 / 曜日 / 発信者番号により絞る。

#### 評価モデル

- `RoutingRules.evaluate(now, from_number, all_bindings) -> RoutingDecision`
- 全 rule を `priority` **降順** (同値は宣言順、 安定ソート) で評価
- match 条件 (weekday / time_range / from_number) は全部 **AND**、 省略項目は無条件 match
- `time_range` は半開区間 `[start, end)`、 終端 < 始端なら midnight wrap (`22:00-06:00` = `22:00..24:00 ∪ 00:00..06:00`)
- 最初に match した rule の `fork = [aor, ...]` で binding を filter

#### 戻り値

| RoutingDecision | 意味 | orchestrator の挙動 |
|---|---|---|
| `Matched { rule_name, bindings: Vec<(aor, Binding)> }` (非空) | rule match、 fork 対象あり | bindings に対して fork (= 既存 fork_to_bindings) |
| `Matched { ... bindings: [] }` | rule match、 fork なし (= `after_hours rule { fork = [] }` の意図的 voicemail 直行) | **voicemail 起動 (= fork-all-fail 経路と合流)、 voicemail 無効なら 480** |
| `NoRule` | 全 rule no-match (空 rule リスト含む) | 後方互換: `registrar.snapshot()` 全 fork (従来挙動) |

#### TOML スキーマ例 (`config.example.toml` 参照)

```toml
# priority 高い順に評価。 最初に match した rule の fork を採用
[[routing.rule]]
name = "vip_customer"
priority = 200
match.from_number = ["0312345678"]
fork = ["boss-mobile"]

[[routing.rule]]
name = "office_hours"
priority = 100
match.weekday = ["mon", "tue", "wed", "thu", "fri"]
match.time_range = "09:00-18:00"
fork = ["iphone", "office-phone"]

[[routing.rule]]
name = "after_hours"
priority = 0
# 条件なし = 常に match (= 上位 rule が no-match なら必ずここに落ちる)
fork = []  # voicemail 直行 (もしくは voicemail 無効なら 480)
```

#### NGN 制約との整合

- `from_number` 抽出失敗時は `"unknown"` 固定 (rule 側で `from_number = ["unknown"]` で捕捉可能)
- 非通知発信 (carrier IMS が PAI/PPI を strip して `anonymous@anonymous.invalid` を載せるケース、 memory `project_ngn_inbound_caller_id_stripped`) は `from_number = "anonymous"` で評価される
- `"anonymous"` と `"unknown"` は別物 (前者は明示的非通知、 後者は抽出失敗)

#### RFC

- RFC 3261 §16.4 (Determining Targets): 「target を絞る方針」 は administrative policy として §16.4-5 / §16.7 で proxy / B2BUA に許容される
- RFC 3261 §20.20 (From): user 部のみ比較、 case-sensitive

### 着信 (NGN → スマホ)

```
NGN ──INVITE──► sabiden(UAS)
                    │
                    │ 100 Trying 即送出 (RFC 3261 §17.2.1)
NGN ◄──100 Trying── sabiden
                    │
                    │ RFC 3261 §8.2.2.3 (Issue #251 Phase A):
                    │   INVITE の Require ヘッダの option-tag を検査。 既知
                    │   (`timer` / `replaces`) 以外があれば 420 Bad Extension
                    │   + Unsupported ヘッダで reject MUST。
                    │
                    │ RFC 4028 §10 (Issue #249):
                    │   INVITE の Session-Expires が sabiden Min-SE (90s) 未満 →
                    │   422 + Min-SE で打ち切る
                    │
                    │ RFC 3261 §13.3.1.4 (Issue #249):
                    │   フォーク開始と同時に 180 Ringing を送出 (= remote callee
                    │   is being alerted)。 180 / 200 OK の To-tag は同値必須
                    │   (RFC 3261 §12.1.1 early == confirmed dialog)。
                    │ RFC 3261 §20.5 / §20.17 / §20.41 (Issue #251 Phase A):
                    │   180 / 200 OK 両方に Allow / Supported / Date / Server を
                    │   常時付与 (Asterisk 実機 §3.1 同等)。 欠落すると carrier
                    │   IMS が 「機能不足端末」 「時刻同期不能」 「capability
                    │   negotiate 不可」 判定で即 BYE する経路に入る。
                    │ RFC 3262 §3 (Issue #251 Phase B):
                    │   INVITE が `Supported: 100rel` (または `Require: 100rel`)
                    │   を載せていれば reliable 180 経路に分岐し、 180 に
                    │   `Require: 100rel` + `RSeq: <random 1..=2^31-1>` を付与。
                    │   T1 (500ms) 起点・T2 (4s) 頭打ち・64*T1 (32s) limit の
                    │   指数バックオフで自発再送 (`spawn_reliable_provisional_retransmit`)。
                    │   PRACK 不在のまま 32 秒経過すれば 408 で INVITE トランザクション
                    │   を終結 (= UAC は再 INVITE で recovery 可能)。
NGN ◄──180 Ringing── sabiden  (Allow/Supported/Date/Server 付き、 100rel offer 時は Require:100rel + RSeq 付き)
                    │
                    │ [100rel フロー (RFC 3262 §4)、 invite_wants_100rel = true のみ]
                    │
NGN ──PRACK (RAck: <RSeq> 1 INVITE)──► sabiden
                    │
                    │   handle_prack: Call-ID で rc100rel state を引き、
                    │   RAck (RSeq, INVITE CSeq, "INVITE") と一致確認。
                    │   不一致 / state 不在 → 481 (RFC 3262 §4 / §7.1)。
                    │   一致 → 200 OK PRACK 送出 + oneshot.tx::send で
                    │   handle_invite::wait_for_prack を解除 +
                    │   cleanup_rc100rel (retransmit task abort)。
NGN ◄──200 OK PRACK── sabiden
                    │
                    │ 全内線にフォーク
                    ├──INVITE──► スマホ1
                    ├──INVITE──► スマホ2
                    └──INVITE──► スマホ3 / PWA (WS Offer/Answer)

スマホ1 ──200 OK──► sabiden
                    │
                    │ 200 OK 構築 (Issue #249 / #251):
                    │ - RFC 3264 §6.1 a=ptime echo (NGN PCMU = 20ms)
                    │ - RFC 4028 §7 / §9: Session-Expires + Require: timer + refresher
                    │   (UAC 要求 refresher=uac を echo、 不在なら uas にフォールバック)
                    │ - RFC 3261 §20.5 Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,UPDATE,INFO
                    │ - RFC 3261 §20.37 Supported: timer, replaces
                    │ - RFC 3261 §20.17 / RFC 7231 §7.1.1.1 Date: IMF-fixdate
                    │ - RFC 3261 §20.41 Server: sabiden/<version>
                    │
sabiden ──200 OK──► NGN
スマホ2 ◄──CANCEL── sabiden
スマホ3 ◄──CANCEL── sabiden

[RTPブリッジ確立: NGN ⇔ sabiden ⇔ スマホ1]
```

#### NGN inbound 200 OK の RFC 整合 (Issue #249 / #251 Phase A)

実機 evidence (`/tmp/sabiden-080-inbound.pcap`、 2026-05-11): 080 携帯からの
着信で、 旧フロー `100 Trying → 4.1 秒 silent → 200 OK` が NGN carrier IMS
の call setup timeout を超え、 200 OK の **28ms 後に NGN 側 BYE** で
打ち切られていた。 NGN INVITE は以下を載せている:

```
k: timer,100rel              ← Supported: timer, 100rel
x: 300;refresher=uac          ← Session-Expires: 300; refresher=uac
Min-SE: 300
a=ptime:20                    ← PCMU 20ms 固定
```

これに対する sabiden 旧 200 OK は **Session-Expires 不在** / **Require: timer
不在** / **a=ptime 不在** で、 RFC 4028 §7 / RFC 3264 §6.1 違反 + 4 秒 silent
で carrier 側 setup timeout の二重要因が成立。 Issue #249 で:

1. **180 Ringing** (RFC 3261 §13.3.1.4): 100 Trying 直後にフォーク開始と
   同時送出。 carrier IMS に call setup 進行中を示す。 180 の To-tag を
   保存し 200 OK で同値を使う (RFC 3261 §12.1.1 dialog ID)。
2. **Session-Expires echo** (RFC 4028 §7): INVITE の SE 値を `refresher=uas`
   で 200 OK に echo + `Require: timer` で negotiate 完了を明示。 INVITE が
   Min-SE 未満 (< 90s) を要求するなら 422 + Min-SE で先に打ち切る (§10)。
3. **a=ptime echo** (RFC 3264 §6.1): NGN offer の `a=ptime:N` を 200 OK SDP
   に追加 (内線 answer に既に ptime があれば上書きしない)。

新フロー: `100 Trying → 180 Ringing (即) → 200 OK (内線 pickup)`、 carrier
IMS は 180 受領で setup 進行中と認識し、 4 秒〜 PWA mic 許可待ちを許容する。

Issue #251 Phase A (2026-05-11、 v4 pcap audit fix): 180 / 200 OK 両方に
RFC 互換ヘッダ集合 (`Allow` / `Supported` / `Date` / `Server`) を常時付与し、
`refresher` パラメータは UAC 要求値を echo (RFC 4028 §9)、 受信 `Require` の
未対応 option-tag は 420 Bad Extension + `Unsupported` で reject MUST
(RFC 3261 §8.2.2.3)。 これにより 080 inbound `ACK 直後 4ms 切断` の
top-3 原因 (Allow/Supported/Date 欠落) と #6 (refresher 強制書換) の
4 つを同時に解消する。

#### NGN inbound 100rel / PRACK 経路 (Issue #251 Phase B、 RFC 3262)

実機 NGN 080 着信 INVITE は `Supported: timer,100rel` + `Allow: ..PRACK..` を
載せて来る。 carrier 側 IMS は reliable 18x → PRACK の hand-shake を期待し、
sabiden が non-reliable 180 のみで進めると `ACK 直後 4ms 切断` 経路の
**残余 1 因子** (Phase A の 4 因子に続く #5) として観測される。

Phase B (本書時点で実装済) は以下を導入:

1. **`Supported` / `Require` / `Allow` で `100rel` / `PRACK` を表明**
   (`UAS_INBOUND_2XX_SUPPORTED = "timer, replaces, 100rel"` / `UAS_INBOUND_2XX_ALLOW`
   末尾に `, PRACK` / `KNOWN_OPTION_TAGS` に `100rel` を追加)。 これにより
   `Require: 100rel` を載せる carrier も 420 で蹴られず通せる。
2. **reliable 180 経路**: INVITE が `Supported: 100rel` / `Require: 100rel`
   を提示したら、 180 Ringing に `Require: 100rel` + `RSeq: <random 1..=2^31-1>`
   を付ける (RFC 3262 §3 / §7.1)。 同時に per-Call-ID の `Rc100relState` に
   `rseq` / `invite_cseq` / Notify (retransmit task 用) / `oneshot::Sender`
   (`wait_for_prack` 用) を保管。
3. **自発再送タスク** (`spawn_reliable_provisional_retransmit`): T1 = 500ms
   から始め、 2T1, 4T1, ... で T2 = 4s 頭打ち、 64*T1 = 32s で諦め。 再送ごとに
   **同一 RSeq** (§3 MUST) を保つため、 1 回目送出時の bytes を Vec で snapshot
   して使い回す。 Notify が `notify_one` されたら即停止 (PRACK 受信ハンドラから fire)。
4. **PRACK 受信ハンドラ** (`handle_prack`): Call-ID で `rc100rel` を引き、
   受信 `RAck` を `parse_rack_header` で (RSeq, CSeq-num, Method) に分解、
   保管した (rseq, invite_cseq, "INVITE") と完全一致なら 200 OK PRACK +
   oneshot.tx::send で `handle_invite::wait_for_prack` を解除 +
   `cleanup_rc100rel` (retransmit task abort)。 不一致 / state 不在 / RAck
   パース失敗 / Call-ID 無し はすべて 481 + Allow ヘッダ (§4 / §7.1)。
5. **`wait_for_prack`**: `handle_invite` が fork 完了後・200 OK 送出前に呼ぶ。
   reliable 18x を出した経路 (`invite_wants_100rel = true`) でのみ実行。
   `oneshot::Receiver` を 32 秒 timeout で await し、 受信成功 → 200 OK 経路、
   timeout → 408 経路に分岐。 `tokio::sync::Notify` ではなく `oneshot::channel`
   を使う理由は、 Phase B 開発時に Notify::notified() の waker 取り逃しが
   `start_paused` 仮想時間下で観測されたため (= test-only race だが production
   経路にも潜むため、 確実性優先で oneshot を採用)。

state cleanup の流れ (idempotent):

- **正常系**: PRACK 受信 → handle_prack が `cleanup_rc100rel` を呼ぶ → 200 OK INVITE。
- **timeout**: wait_for_prack が PrackOutcome::Timeout を返す → 408 送出前に
  `cleanup_rc100rel` を呼ぶ。
- **NGN CANCEL**: `cancel_notify.notified()` 経路で 487 送出前に `cleanup_rc100rel`。
- **fork 失敗 / 502**: 各 early-return 直前に `cleanup_rc100rel` を呼ぶ。
- **handle_invite 関数末尾**: 全 match arm 共通で `cleanup_rc100rel` を最後に
  呼び保険にする (idempotent なので重複呼び出しは無害)。

残る Phase R5 タスク (Timer L = 2xx INVITE の ACK 待ち、 RFC 6026 §7.1) は
別 Issue で対応。

#### PWA 着信拒否 (Issue #107、 RFC 3261 §21.6.2 603 Decline)

WebRTC 内線 (PWA) は SIP UAS を持たないため、 ringing 中の着信を拒否する
には専用の WS シグナリングメッセージ `ClientMessage::Decline { call_id }` を
sabiden に送る。 sabiden は対応する `PendingAnswers` waiter に
`AnswerOutcome::Decline { status: 603 }` を流し、 `run_webrtc_leg` が
`LegResult::Failed { status: 603 }` を返す。

```
NGN ──INVITE──► sabiden(UAS)
                    │
                    │ fork_to_bindings
                    ├──ServerMessage::Offer{call_id, sdp(SAVPF)}──► PWA  (run_webrtc_leg)
                    └──INVITE────────────────────────────────────► SIP 内線 (居れば並列)

PWA ──ClientMessage::Decline{call_id}──► sabiden
                                              │ pending.decline(call_id, 603)
                                              │   → oneshot に AnswerOutcome::Decline { status: 603 }
                                              ▼
                                          run_webrtc_leg
                                              │ LegResult::Failed { status: 603 }
                                              ▼
                                          fork_to_bindings
                                              │ 他レッグ 200 OK 無し
                                              │ → ForkResult::AllFailed { last_status: Some(603) }
                                              ▼
NGN ◄──603 Decline── sabiden                   (RFC 3261 §16.7 best response, §21.6.2)
```

SIP 内線が並走する fork で先に SIP 側が 200 OK を返した場合は、 PWA の Decline
は破棄され通話は SIP 側で確立する (Asterisk 風 fork、 RFC 3261 §13.3 / §16.7)。
fork 確定後に PWA レッグが Cancel される標準パス (`close_and_drain_webrtc_legs`)
は変更なし。

##### 6xx 早期 terminate と best response priority (Issue #211 / RFC 3261 §16.7 step 5/6)

PR #210 では「先着 603 を後着 SIP 486 が `last_status` を上書きする」 race が
残っていた。 Issue #211 で `fork_to_bindings` に以下を導入し、 RFC 3261 §16.7
step 5/6 に準拠させた。

- **step 5 (6xx 早期 terminate)**: 任意レッグから 6xx 受領した時点で fork loop を
  抜け、 残レッグ (SIP/WebRTC) の結果を待たない。 WebRTC 残レッグへは下段の
  `close_and_drain_webrtc_legs` で `ServerMessage::Cancel` が流れる。 SIP 残レッグ
  は spawn 済 future が継続するが結果は drop される (= 緩 cancel)。
- **step 6 (best response priority)**: `should_replace_status` で
  「6xx > 4xx > 5xx > 3xx、 同クラスは first-wins」 を実装。 これにより 603 先着
  → 486 後着 race でも `last_status = Some(603)` が維持され、 NGN へ 603 Decline
  が正しく返る。 RFC 3261 §16.7 step 6 は「4xx と 5xx 間の厳密な順序」 を明示し
  ていないが (`MUST` 列挙は 6xx 最優先のみ)、 sabiden は内線 fork の代表的失敗
  (= 4xx Busy 系) を 5xx (= server-side 障害) より優先採用する簡略化を選択。
  厳密化は将来 issue で扱う。
- **603 reason phrase**: PR #210 では誤って "Declined" (過去分詞) を返していたが、
  RFC 3261 §21.6.2 の正規表記は **単数** "Decline"。 `reason_phrase_for_status`
  で 486/487/603 + 既定の reason phrase を集中管理する。

旧挙動 (Issue #107 修正前): PWA「拒否」 ボタンはローカル UI のみクリアし、
sabiden へは何も送らなかった。 そのため sabiden は `leg_timeout` (= fork 全体
タイムアウト) が来るまで待ち、 NGN 側 INVITE が 30 秒程度保留される
UX 不具合があった。

Decline は WS 接続 (= 内線登録) ごと閉じる `Bye` とは別物。 個別の進行中着信
のみを拒否し、 WS は維持する。 詳細は `src/webrtc/signaling.rs::ClientMessage`
docstring。

##### Fork lifecycle: 全 `ForkResult` で WebRTC レッグへ Cancel 通知 (Issue #83)

`fork_to_bindings` の `ForkResult` は 3 種 (`Answered` / `Timeout` / `AllFailed`)
だが、 走り出している WebRTC レッグ (= browser に `ServerMessage::Offer` を
push 済) は **どの結果で抜けても** `close_and_drain_webrtc_legs` 経由で
`ServerMessage::Cancel { call_id }` を受け取る。

| `ForkResult` | Cancel 送出対象 | 期待される PWA 側挙動 |
|---|---|---|
| `Answered` | winner 以外の losing legs (winner は `WsSink::same_channel` で除外) | losing legs: `App.tsx::cancel` で ended 遷移。 winner: 確立通話継続 |
| `Timeout` | 走っている全 WebRTC legs | 全 leg: ringing UI を ended に閉じる |
| `AllFailed` | 走っている全 WebRTC legs (Failed/Errored 経路含む) | 全 leg: ringing UI を ended に閉じる |

旧実装 (PR #137 以前) は `Answered` のときだけ losing legs を Cancel しており、
`Timeout` / `AllFailed` では browser がオファ送出後ハングする (= 永続 ringing /
内線登録解放不能) 不具合があった。 W3C webrtc-pc §4.4.1 (UA は long-running
pending state を放置すべきでない) / RFC 3261 §9.1 (CANCEL semantics、 ただし
WebRTC レッグ向けは WS 層の通知形) に従い、 一括 Cancel に変更した。

スロー競合 (Issue #140 race): `peer.create_offer` 完了が winner 確定より遅い
レッグは `try_register_webrtc_leg` が `closed=true` を観測して Offer push を
skip し、 自前で Cancel を送って終了する (`close_and_drain_webrtc_legs` の
snapshot に含まれない経路)。 このため上表「走っている全 WebRTC legs」 は
「Offer push 完了済または try_register 失敗で自前 Cancel した legs」 を含む。

#### `webrtc_active` 双方向 BYE 連動 + leak sweeper (Issue #81 / #139 / #268)

NGN→WebRTC 着信成立時、 `NgnInboundHandler::handle_invite` は winner WebRTC
レッグの `WsSink` + UAS dialog state を
`webrtc_active: HashMap<Call-ID, Arc<WebRtcInboundEntry>>` に保持する
(Issue #81 + Bug B 拡張)。 `WebRtcInboundEntry` は以下を持つ:

| フィールド | 役割 |
|---|---|
| `ws: WsSink` | NGN→PWA BYE 通知用 (RFC 3261 §15.1.2)。 Issue #81 経路。 |
| `uas_dialog: Option<Mutex<Dialog>>` | PWA→NGN BYE 送出用の RFC 3261 §12.1.1 UAS dialog state (受信 INVITE + 200 OK から `Dialog::from_uas_invite` で構築)。 |
| `layer: Option<Arc<TransactionLayer>>` | BYE 送信に使う NGN 側 TransactionLayer。 |
| `fallback_peer: SocketAddr` | dialog next-hop URI 解決失敗時の fallback (= 受信 INVITE の `remote`)。 |

`DialogConfig` の組み立て規約 (RFC 3261 §12.1.1、 Issue #258 で確立):

- `local_uri` = **INVITE の To URI そのまま** (例: `<sip:0191349809@ntt-east.ne.jp>`)。
  sabiden Contact URI (`sip:sabiden@<eth1>:5060`) を入れてはならない。
- `remote_uri` = **INVITE の From URI** (例: `<sip:anonymous@anonymous.invalid>`)。
- `local_contact` = sabiden が 200 OK で返した Contact URI (= eth1 IP)。
- `sent_by` = sabiden の Via sent-by (eth1 IP + 5060)。

このうち最重要は `local_uri`。 sabiden が UAC として in-dialog request (BYE) を
組み立てるとき `From: <local_uri>;tag=<local_tag>` が carrier 視点の
**dialog の remote (= sabiden side) URI** と完全一致する必要がある (RFC 3261
§12.2.1.1 / §15.1.1)。 旧実装は local_uri に sabiden Contact URI を入れていた
ため、 PWA disconnect 経路の BYE が 481 Call/Transaction Does Not Exist で
reject された (実機 v9 evidence、 2026-05-11)。

双方向 BYE 経路 (RFC 5853 §3.2.2 SBC framework: B2BUA は片側 dialog 終了を
もう片側へ伝搬する責務):

```
NGN → sabiden BYE → handle_bye → entry.ws.send(ServerMessage::Bye)        (Issue #81)
                              → entry.uas_dialog.terminate()
                              → webrtc_active.remove                       (idempotent gate)

PWA WS close → close_pwa_inbound_for_ws (PwaInboundCloser trait)           (Bug B / Issue #268)
            → webrtc_active.extract_if(ws.same_channel)                    (idempotent gate)
            → entry.send_bye() = build_bye + layer.send_request            (RFC 3261 §15.1.1)
            → entry.uas_dialog.terminate()
            → CallManager::terminate(self.active[call_id])                 (bridge 停止)
            → metrics.dec_call_active
```

旧実装 (Bug B 修正前) は PWA WS close 時に何も送らず、 NGN が 5-10 秒の
タイムアウトで BYE を投げ返してくるまで `self.active` の bridge が生きた
まま放置されていた (実機 v7 で 6 秒 `recv BYE` 待ち観測)。 本修正で sabiden
は WS close を検知した瞬間に NGN へ BYE を撃ち、 bridge / metrics を
即時 cleanup する。 signaling 層は `PwaInboundCloser` trait 経由でしか
内部テーブルに触らない (依存方向: signaling → orchestrator)。

leak sweeper (Issue #139) は依然として安全網として残す: BYE 経由の `remove`
を逃した entry (= 古い `close_pwa_inbound_for_ws` 不在経路 / 旧 fixture)
を `webrtc_active_sweep_interval` 周期 (既定 30 秒) で `WsSink::is_closed`
一致 entry を `HashMap::retain` で除去する。 sweeper は `Arc::downgrade` の
弱参照で動くため、 `NgnInboundHandler` が drop されたら次の tick で
`Weak::upgrade` が `None` を返して自動終了する。

各経路 (NGN BYE / WS close / sweeper) は同じ `Mutex` で逐次化されるため、
並走しても二重 remove / panic を起こさない (`HashMap::remove` /
`extract_if` は 1 回目以降は no-op、 idempotent)。

`Duration::ZERO` 防御 (Issue #218): `tokio::time::interval(Duration::ZERO)` は
panic するため、 `spawn_webrtc_active_sweeper` 入口で `is_zero()` をチェック
し、 [`MIN_SWEEP_INTERVAL`] (= 30s 既定値) にフォールバックする。 production
config TOML / `Default` 派生ミスで 0 が流入しても sweeper task が落ちないよう
defense-in-depth で抑止。 同種事例: `WebRtcConfig::default()` (Issue #166)。

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
- `sabiden_ngn_5xx_total{status="500"|"503"|"other"}` — NGN P-CSCF から受信した
  5xx 応答累計 (Issue #260 Phase 1-A、 3GPP TS 24.229 §5.2.7: 500 = per-INVITE 失敗
  / 503 = overload を区別観測)。 既存 `sabiden_sip_invite_total{direction="ngn",result="error"}`
  は 4xx と 5xx を合算するので別軸として導入 (RFC 3261 §21.5)。 同時に 5xx 受信時は
  `Reason` (RFC 3326) / `Retry-After` (§20.33) / `Server` (§20.35) / `Warning` (§20.43) /
  Via `received` / `rport` (RFC 3581 §4) を `warn!` 構造化フィールドで dump し、
  carrier intermittent 解析の手がかりにする。
- `sabiden_ngn_carrier_retry_total{outcome="not_retried"|"succeeded"|"failed"|"aborted_by_cancel"}`
  — Issue #260 Phase 1-B: NGN carrier intermittent reject (500/486/503) に対する
  1 回限定 auto-retry の結果別累計。 `decide_retry` (`src/call/carrier_retry.rs`) で
  policy 判定: 500/486/503 のみ retry 対象、 default wait = 2s + ±0.5s jitter、
  Retry-After ヘッダがあれば遵守 (RFC 3261 §20.33)、 Retry-After が 5s を超えるなら
  諦め。 retry は新 Call-ID で再 INVITE (RFC 3261 §8.1.1.5)、 sleep 中の内線
  CANCEL / PWA WS close は select / `WsSink::is_closed` で検出して
  `aborted_by_cancel` に分類。 TTC JJ-90.24 §5.7.3 (Retry-After 遵守 + 過度な retry
  回避) に整合。

### Observability / Call history (Issue #278、 `src/observability/call_log.rs`)

Prometheus 累積カウンタ (`/metrics`) は集計値しか持たず、 1 件ずつの通話を
特定する用途には使えない。 PWA「最近の通話」 UI のように **個別通話の方向 /
相手番号 / 開始時刻 / 通話時間 / 結果** を表示するため、 `CallLog` という
in-memory ring buffer を導入する (永続化は別 Issue)。

**データ構造**:

- `CallLogEntry { direction, remote_number, start_time, duration, outcome, call_id }`
  - `direction`: `Outbound` (内線→NGN / PWA→NGN) or `Inbound` (NGN→内線 / NGN→PWA)
  - `remote_number`: 相手番号 (発信時 = ダイヤル先、 着信時 = `From` の user 部)
  - `start_time`: 通話試行開始時刻 (`SystemTime`、 JSON 出力は Unix epoch ms)
  - `duration`: `record_end` 時に確定する経過時間 (秒、 `Outcome` が確定する前は `None`)
  - `outcome`: `Answered` / `Missed` / `Failed { status }` / `Cancelled`
- `CallLog { entries: Mutex<VecDeque<CallLogEntry>>, max_size }` — FIFO ring buffer。
  `max_size` (production = 200 件) を超えたら `pop_front` で古い方から evict。
- `record_start(Direction, remote, call_id)` で開始時刻を残し、 `record_end(call_id, Outcome)`
  で `outcome` と `duration` を確定 (Call-ID 線形検索、 ring buffer から evict 済なら no-op)。

**hook ポイント** (`src/call/orchestrator.rs` 内、 各経路 record_start / record_end を
**対称に発火**。 PR #286 review #1〜#4 の orphan entry 修正で全 reject 経路に record_end 付与済):

- NGN inbound INVITE (`NgnInboundHandler::handle_invite`)
  - 100 Trying 直後 → `record_start(Inbound, from-user, call_id)`
  - **420 Bad Extension** (RFC 3261 §8.2.2.3、 未対応 option-tag) → `record_end(Failed { status: 420 })`
  - **422 Session Interval Too Small** (RFC 4028 §10、 SE < Min-SE) → `record_end(Failed { status: 422 })`
  - **481 Call/Transaction Does Not Exist** (RFC 3261 §12.2.2、 in-dialog INVITE で該当 dialog 無し) →
    `record_end(Failed { status: 481 })`
  - **480 Temporarily Unavailable** (登録内線無し) → `record_end(Missed)` (鳴らせる端末が無い = Missed カテゴリ、
    RFC 3261 §21.4.18 と整合)
  - NGN **CANCEL → 487 Request Terminated** (応答前 NGN UAC 中断) → `record_end(Missed)` (RFC 3261 §21.4.27、
    PASSIVE 中断 = 着信側視点での不在着信)
  - **PRACK 32 秒不到来 → 408 Request Timeout** (RFC 3262 §3 reliable 18x の PRACK 不到来) →
    `record_end(Failed { status: 408 })`
  - `ForkResult::FirstSuccess` → 確立 (record_end は BYE 時)
  - `ForkResult::AllFailed` (内線全敗、 486 / 603 等) → `record_end(Missed)`
  - `ForkResult::Timeout` (内線 fork timeout) → `record_end(Missed)`
- NGN inbound BYE (`NgnInboundHandler::handle_bye`)
  - SIP 内線 path 1: `active` から removed → `record_end(Answered)`
  - PWA outbound BYE path (NGN 始動): `record_end(Answered)` (Outbound 側の終了)
- PWA disconnect (`close_pwa_inbound_for_ws`) → `record_end(Answered)`
- 内線→NGN INVITE (`UasEventHandler::handle_invite`)
  - rate-limit / 422 通過後、 build_invite 直前 → `record_start(Outbound, dialed-number, call_id)`
  - **`Ok(InviteOutcome::Established)` + `was_cancelled = true`** (RFC 3261 §15.1.1 CANCEL と 200 OK の競合
    glare、 sabiden 即 BYE) → `record_end(Cancelled)`
  - `Ok(InviteOutcome::Established)` (通常確立) → 確立 (record_end は BYE 時)
  - `Ok(InviteOutcome::Failed { response })` → `record_end(Failed { status })`
  - `Err(_)` (was_cancelled = true) → `record_end(Cancelled)`
  - `Err(_)` (was_cancelled = false) → `record_end(Failed { status: 503 })`
  - 注: `InviteOutcome` は `Established` / `Failed { response }` の 2 variant のみ
    (`src/sip/uac.rs::InviteOutcome`)。 487 は `Failed { response.status_code = 487 }` 経路に乗り、
    `was_cancelled` 由来の 487 は `Err(_)` の Timer B / CANCEL race 経路に乗ることもある。
- 内線→NGN BYE (`UasEventHandler::handle_ext_bye`) → `record_end(Answered)`
- PWA→NGN INVITE (`UasEventHandler::handle_pwa_outbound_offer`、 spawn 内)
  - plan 生成後 → `record_start(Outbound, target, call_id)`
  - `Ok(InviteOutcome::Failed)` → `record_end(Failed { status })`
  - `Err(_)` → `record_end(Failed { status: 503 })`
- PWA→NGN WS close (`close_pwa_outbound_for_ws`) → `record_end(Answered)`

**JSON API**: `GET /api/call-log/recent?n=20` (`src/health/mod.rs`)

- `n` 省略時は 20 件、 ring buffer 容量超過時は内部で打ち切り。
- レスポンス例:
  ```json
  [
    {
      "direction": "outbound",
      "remote_number": "117",
      "start_unix_ms": 1747567890123,
      "duration_secs": 12.345,
      "outcome": { "kind": "answered" },
      "call_id": "abc@host"
    },
    {
      "direction": "inbound",
      "remote_number": "anonymous",
      "start_unix_ms": 1747567880000,
      "duration_secs": 4.2,
      "outcome": { "kind": "missed" },
      "call_id": "xyz@host"
    }
  ]
  ```
- 新しい順 (= 最新通話が配列先頭)。 `outcome.kind` は `answered` / `missed` /
  `failed` / `cancelled`、 `failed` のみ `status` (u16) フィールドが追加される。

**結線**: `main.rs` で `Arc<CallLog>` を 1 個生成し、 `HealthState` と
`NgnInboundHandler::set_call_log` / `UasEventHandler::set_call_log` の全経路に
同じ Arc を渡す (= record_start / record_end が突合する)。 setter は `Mutex<Option<_>>`
ベースで spawn 後 (= shared) でも安全に呼べる (`outbound_forwarder` と同じ pattern)。

### Voicemail / 留守録 (Issue #288、 `src/call/voicemail/`)

NGN inbound 着信で **fork all-fail** (内線 / PWA 全 leg 応答失敗 = 486 / 408
/ 480) かつ `voicemail.enabled = true` のとき、 sabiden が UAS として代理で
200 OK + sabiden SDP を返し、 NGN から流入する RTP 音声 (PCMU 8 kHz mono) を
WAV ファイルに保存する。 PWA からは REST API (`/api/voicemail/*`) で一覧 /
再生 / 削除可能。

**データ構造**:

- `VoicemailFile { call_id, remote_number, recorded_at_unix_ms, duration_ms }`
  ── sidecar JSON で永続化。 `GET /api/voicemail/list` がそのまま返す。
- `VoicemailRecorder { storage_dir, max_duration }` ── 録音 task spawn を司る。
  config の `[voicemail]` セクション (`enabled` / `storage_dir` / `max_duration_secs`)
  と 1:1 対応。
- `VoicemailHandle { stop_signal, join }` ── recorder task の制御ハンドル。
  `stop()` で stop_signal を notify、 `Drop` で再発火 (idempotent)。
- `WavWriter` (`src/call/voicemail/wav.rs`) ── RIFF/WAVE (linear PCM 16-bit
  mono 8 kHz) を逐次追記 + finalize で `chunk_size` / `subchunk2_size` を書き戻す。
  WAVE_FORMAT_MULAW (0x0007) ではなく linear PCM で書く理由はブラウザ `<audio>`
  互換性 (PR #288 `src/call/voicemail/wav.rs` docstring 参照)。

**動作シーケンス** (NGN inbound fork all-fail → voicemail):

```text
NGN (P-CSCF)         sabiden                                 内線 / PWA
    │                  │                                          │
    │ INVITE + offer SDP                                          │
    │ ───────────────►│                                          │
    │                  │ 100 Trying                               │
    │ ◄───────────────│                                          │
    │                  │ 180 Ringing                              │
    │ ◄───────────────│                                          │
    │                  │ fork_to_bindings ───────────────────────►│
    │                  │                                          │ (全 leg 486/408 等)
    │                  │ ◄───────────────────────────────────────│
    │                  │ ForkResult::AllFailed { last_status }    │
    │                  │                                          │
    │                  │ ┌── try_start_voicemail ──┐              │
    │                  │ │ bind_ngn_rtp_socket     │              │
    │                  │ │ rewrite_rtp_endpoint    │              │
    │                  │ │ apply_uas_inbound_2xx_  │              │
    │                  │ │   headers + Contact     │              │
    │                  │ └──────────┬──────────────┘              │
    │ 200 OK + sabiden SDP (PCMU、 c=NGN-side IP、 m=<even port>) │
    │ ◄───────────────│                                          │
    │ ACK              │ inc_call_active                          │
    │ ───────────────►│ voicemail_active.insert(cid, handle)     │
    │                  │ spawn VoicemailRecorder task             │
    │                  │   (recv_from RTP → decode_ulaw           │
    │                  │    → WavWriter::write_samples)           │
    │ RTP (PCMU)       │                                          │
    │ ═══════════════►│ (WAV に書き込み続ける)                   │
    │                  │                                          │
    │                  │ ─── max_duration (60s 既定) 経過 ───►   │
    │                  │ recorder finalize (chunk_size 書戻し +   │
    │                  │   sidecar JSON 書出し)                   │
    │ BYE              │                                          │
    │ ───────────────►│ 200 OK BYE                               │
    │ ◄───────────────│ voicemail_active.remove                   │
    │                  │ dec_call_active                          │
    │                  │ record_end(Answered)                     │
```

NGN が先に BYE を送ってきた場合 (= 留守録メッセージを残し終わって NGN 側が
切断) も同じ経路で `handle_bye` が `voicemail_active` から handle を引いて
`stop()` を発火、 録音 task は WAV を finalize する。

**hook ポイント** (`src/call/orchestrator.rs::NgnInboundHandler`):

- `try_start_voicemail` (Issue #288 専用 helper):
  1. `cfg.voicemail_recorder` 不在 → false (= 旧挙動)。
  2. NGN INVITE に SDP body 無し → false (offer-only 経路は voicemail 不能)。
  3. NGN 側 RTP socket を `bind_ngn_rtp_socket` (even-port allocator、
     Issue #260 Phase 1-D Final と同じ) で確保。
  4. `rewrite_rtp_endpoint` で sabiden NGN-side endpoint に書き換え、
     200 OK + `apply_uas_inbound_2xx_headers` (Issue #251 Phase A) で応答。
  5. `VoicemailRecorder::start` で recorder task を spawn し、
     `voicemail_active: HashMap<Call-ID, VoicemailHandle>` に登録。
- 呼び出し元 (`handle_invite`):
  - **登録内線なし → 480** 経路 → 先に voicemail を試す。
  - **`ForkResult::AllFailed`** 経路 → 先に voicemail を試す。
  - **`ForkResult::Timeout`** 経路 → 先に voicemail を試す。
  - voicemail 起動成功時は `inc_call_active` + 経路 return (200 OK 送出済)。
  - voicemail 起動失敗 / 未設定時は従来の 480/486/408 等を返す (= 既存挙動)。
- `handle_bye`:
  - 既存 inbound BYE クリーンアップの後段で `voicemail_active.remove(cid)`、
    handle.`stop()` 発火 + `dec_call_active` + `record_end(Answered)`。

**JSON API** (`src/health/mod.rs`):

- `GET /api/voicemail/list` ── 保存済 voicemail を `recorded_at_unix_ms`
  降順で返す (`Vec<VoicemailFile>`)。 voicemail 無効時は 503。
- `GET /api/voicemail/{id}/audio` ── WAV ファイル本体を `audio/wav` で返す。
  未知 ID は 404。 ID は `sanitize_id` で正規化 (path-traversal 防止)。
- `DELETE /api/voicemail/{id}` ── WAV + JSON sidecar 両方削除。 成功は
  204 No Content、 未知 ID は 404。

**結線**: `main.rs` で `Arc<VoicemailRecorder>` を 1 個生成し、 `HealthState`
(`with_voicemail`) と `NgnInboundConfig.voicemail_recorder` の両方に同じ Arc
を渡す (= 録音した WAV が即座に REST API で見える)。 `voicemail.enabled = false`
(既定) の場合は recorder を生成せず両側とも `None`、 API は 503、 録音経路は
従来の失敗 status (480/486/408) で旧挙動と同一。

### Active call recording / 通話中録音 (Issue #296、 `src/call/recording.rs`)

通話確立中に PWA UI で「録音開始」 / 「録音停止」 を押した瞬間、 sabiden が
当該 active call の RTP 音声 (PCMU 8 kHz mono) を WAV ファイルへ dump する
機構。 留守録 (Issue #288) が **不在着信時の自動録音** なのに対し、 本機能は
**通話確立中に PWA からのトリガで開始/停止** する点が違う。 RTP→WAV 変換は
voicemail の `WavWriter` を **logic 変更なしで再利用** する (Issue #296 制約)。

**データ構造** (`src/call/recording.rs`):

- `RecordingFile { recording_id, call_id, remote_number, started_at_unix_ms,
  duration_ms }` ── sidecar JSON で永続化。 `recording_id` は voicemail と
  違って `call_id` と独立 (= 同一通話で start/stop を繰り返せる)。
- `CallRecorder { storage_dir, max_duration, active: HashMap<Call-ID, ActiveEntry> }`
  ── 同時複数 call の録音 task を管理。 config の `[recording]` セクション
  (`enabled` / `storage_dir` / `max_duration_secs`、 既定 600 秒) と 1:1 対応。
- `RecordingHandle { recording_id, started_at_unix_ms, stop_signal, join }`
  ── recorder task の制御ハンドル。 `stop()` で stop_signal を notify、
  `Drop` で再発火 (idempotent)。
- `RecordingSender { tx: mpsc::Sender<RtpPacket> }` ── bridge tap から RTP
  packet を流すための送信側 handle (best-effort、 channel 容量超過は silent drop)。
- `PwaRecordHandlerImpl { recorder: Arc<CallRecorder> }` ── signaling 層
  `webrtc::PwaRecordHandler` trait を実装するブリッジ (`SignalingState::with_pwa_record`
  に注入する)。 PWA WS `ClientMessage::RecordStart` / `RecordStop` を
  `CallRecorder::start` / `stop` に取り次ぐ。

**動作シーケンス** (PWA RecordStart → bridge tap → RecordStop):

```text
PWA (browser)        sabiden (signaling)              CallRecorder       WavWriter
    │                  │                                 │                  │
    │ ClientMessage::RecordStart { call_id }             │                  │
    │ ───────────────►│                                 │                  │
    │                  │ PwaRecordHandlerImpl::start_recording              │
    │                  │ ─────────────────────────────►│                  │
    │                  │                                 │ CallRecorder::start
    │                  │                                 │   active.insert(call_id, ActiveEntry)
    │                  │                                 │   WavWriter::create
    │                  │                                 │ ───────────────►│
    │                  │                                 │   spawn run_recording_loop
    │                  │ ◄─── RecordingStartedInfo ─────│                  │
    │ ServerMessage::RecordingStarted { recording_id }   │                  │
    │ ◄───────────────│                                 │                  │
    │                  │                                 │                  │
    │                  │ (bridge tap: NGN/内線 RTP packet → sender.try_send) │
    │                  │ (※ Issue #296 follow-up で配線、 本 PR では未配線)  │
    │                  │                                 │                  │
    │ ClientMessage::RecordStop { call_id }              │                  │
    │ ───────────────►│                                 │                  │
    │                  │ PwaRecordHandlerImpl::stop_recording               │
    │                  │ ─────────────────────────────►│                  │
    │                  │                                 │ CallRecorder::stop
    │                  │                                 │   active.remove → drop sender
    │                  │                                 │   handle.stop() (notify)
    │                  │                                 │   task: rx.recv → None → break
    │                  │                                 │   WavWriter::finalize
    │                  │                                 │ ───────────────►│
    │                  │                                 │   sidecar JSON 書き出し
    │                  │ ◄─── RecordingStoppedInfo ─────│                  │
    │ ServerMessage::RecordingStopped {                  │                  │
    │   recording_id, duration_ms                        │                  │
    │ }                                                  │                  │
    │ ◄───────────────│                                 │                  │
```

明示 `RecordStop` を待たずに NGN/内線 BYE が来た場合 (RFC 5853 §3.2.2 B2BUA は
片側 dialog 終了で付随リソースを cleanup する責務) は、 `NgnInboundHandler::handle_bye`
と `UasEventHandler::close_pwa_outbound_for_ws` が `recording_recorder` 経由で
`CallRecorder::stop(call_id)` を呼んで自動 finalize する。 該当無し (= 通常通話
の BYE) は `NotFound` で silent ignore。

**hook ポイント** (`src/call/orchestrator.rs`):

- `UasEventHandler::set_recording_recorder` / `NgnInboundHandler::set_recording_recorder`
  ── `set_call_log` と同じ `Mutex<Option<_>>` ベースの setter。 `main.rs` で
  同じ `Arc<CallRecorder>` を両方に注入する。
- `NgnInboundHandler::handle_bye` ── NGN BYE 受領時に `recording_recorder_clone()`
  経由で `CallRecorder::stop(call_id)` を呼ぶ。 `voicemail_active` の cleanup
  と並列の後段 hook。
- `UasEventHandler::close_pwa_outbound_for_ws` ── PWA WS close / BYE 経由の
  cleanup で同じ `CallRecorder::stop(call_id)` を呼ぶ。 PWA `RecordStop` 先行時
  も `NotFound` で idempotent。
- **bridge tap** (Issue #296 follow-up): `MediaBridge` / `RtpBridge::forward_loop`
  の各 RTP 受信ポイントで `CallRecorder::sender_for(call_id)` を引いて
  `RecordingSender::try_send` する。 本 PR では未配線で WAV は 0 byte。

**JSON API** (`src/health/mod.rs`、 voicemail と別 path):

- `GET /api/recording/list` ── 保存済 recording を `started_at_unix_ms`
  降順で返す (`Vec<RecordingFile>`)。 recording 無効時は 503。
- `GET /api/recording/{id}/audio` ── WAV 本体を `audio/wav` で返す。
  未知 ID は 404。 ID は `sanitize_id` で正規化 (path-traversal 防止)。
- `DELETE /api/recording/{id}` ── WAV + JSON sidecar 両方削除。 成功は
  204 No Content、 未知 ID は 404。

**結線**: `main.rs` で `Arc<CallRecorder>` を 1 個生成し、 (a) `HealthState`
(`with_recording`、 REST API)、 (b) `SignalingState` (`with_pwa_record` 経由で
`PwaRecordHandlerImpl`、 PWA WS dispatch)、 (c) `NgnInboundHandler` /
`UasEventHandler` の `set_recording_recorder` (BYE 経路の cleanup) の 3 経路に
同じ Arc を渡す。 `recording.enabled = false` (既定) なら recorder を生成せず、
全 hook が `None` で旧挙動と同一。

### AI 文字起こし stub (Issue #300、 `src/observability/transcription.rs`)

Voicemail (Issue #288) / Recording (Issue #296) が保存した WAV (RFC 3551 §4.5.14
PCMU → RIFF/WAVE linear PCM 16-bit / mono / 8 kHz) を AI ASR (Whisper API /
faster-whisper 等) に投げて文字起こしを生成し、 WAV と同じディレクトリに
sidecar `.txt` を保存する仕組み。 **本 PR (Issue #300) は stub レベル**で、
実 ASR backend は別 Issue で wire-up する。 既定 `[transcription] enabled = false`
で `.txt` は生成されず、 既存挙動と完全互換。

**データ構造** (`src/observability/transcription.rs`):

- `Transcriber` trait (`Send + Sync`) ── WAV path を受けて `Result<TranscriptionResult>`
  を返す sync API。 `Arc<dyn Transcriber>` で voicemail / recording に渡す。
- `TranscriptionResult { text, language, duration_ms, model }` ── 文字起こし
  本文 (UTF-8) + 検出言語 (ISO 639-1) + 処理時間 + backend 識別子。
- `StubTranscriber` ── 常に「(transcription unavailable - configure backend)」
  + `model = "stub"` を返す no-op 実装。 PWA UI は `model == "stub"` で
  「未対応」 と判別する想定。
- `TranscriptionConfig { enabled, backend, api_key_env, model_path }` ── TOML
  `[transcription]` セクション。 `backend = "stub"` のみ wire 済、
  `"whisper-api"` / `"faster-whisper"` は将来。
- `build_transcriber(cfg)` ── 設定値から `Arc<dyn Transcriber>` を組み立てる
  factory。 未対応 backend は起動時に fail-fast。
- `transcript_path_for(wav)` / `write_transcript(wav, res)` / `read_transcript(wav)`
  ── sidecar `.txt` のパス計算 + 入出力ヘルパ。 拡張子を `.txt` に置換、
  UTF-8 LF で書く。

**動作シーケンス** (voicemail finalize ‐ recording finalize も同形):

```
voicemail recorder task          transcription::Transcriber  filesystem
        │                                  │                       │
        │ WAV write_samples / finalize     │                       │
        │ ────────────────────────────────►│                       │
        │                                  │                       │
        │ run_transcription_hook(wav_path) │                       │
        │ ────────────────────────────────►│ transcribe(wav_path)  │
        │                                  │ (stub: instant return)│
        │ ◄────────────────────────────────│ TranscriptionResult   │
        │ write_transcript(wav, result)    │                       │
        │ ─────────────────────────────────┼──────────────────────►│ <id>.txt
        │                                  │                       │
        │ JSON sidecar 書込み (既存)         │                       │
        │ ─────────────────────────────────┼──────────────────────►│ <id>.json
```

`transcriber` が `None` (= 既定 disabled) の場合は `run_transcription_hook`
が早期 return し、 transcript dispatch も `.txt` 書込も発生しない (I/O ゼロ、
完全な後方互換)。 transcribe / write が `Err` を返しても warn ログのみで
WAV / JSON 本体は保護する (production code で panic 禁止、 CLAUDE.md §6.5)。

**JSON API** (`src/health/mod.rs`):

- `GET /api/voicemail/{id}/transcript` ── sidecar `.txt` の中身を
  `text/plain; charset=utf-8` で返す。 voicemail 無効 → 503、 voicemail 不在
  → 404、 transcript 不在 (= `[transcription] enabled = false` で運用中 /
  生成失敗) → 404。
- `GET /api/recording/{id}/transcript` ── 同様。

`DELETE /api/voicemail/{id}` / `DELETE /api/recording/{id}` は **sidecar `.txt`
も合わせて削除** する (= 残骸を残さない)。 transcript 単独欠如は 404 判定
には影響しない (主資源 = WAV/JSON が無いと 404)。

**結線**: `main.rs` で `[transcription] enabled = true` のときに
`transcription::build_transcriber(&cfg.transcription)` で `Arc<dyn Transcriber>`
を組み立て、 `VoicemailRecorder::with_transcriber` / `CallRecorder::with_transcriber`
で **どちらかの recorder を経由する WAV finalize 経路に**注入する。
disabled (既定) なら hook 自体が呼ばれず旧挙動と同一。

### PWA Web Push 通知 (Issue #294、 `src/webrtc/push.rs`)

PWA tab が閉じている / 画面 lock 中でも NGN inbound INVITE を通知するため、
Web Push (RFC 8030 / RFC 8291 / RFC 8292 VAPID) で browser に push する機構。

**RFC 引用**:

- **RFC 8030**: HTTP Web Push の wire protocol (POST `<endpoint>` +
  `TTL` / `Urgency` ヘッダ等)。 §5 で 404/410 受信時は subscription を
  「永続的に無効」 と扱い、 store から削除する。
- **RFC 8291**: payload は ECDH 派生鍵 + HKDF + AES128-GCM (= aes128gcm,
  RFC 8188) で encrypt。 `p256dh` (subscriber 公開鍵) / `auth` (16 byte
  secret) は base64url (no padding)。
- **RFC 8292** (VAPID): "Voluntary Application Server Identification"。 push
  service (FCM 等) に「誰が送ったか」 を JWT で示す。 P-256 ECDSA 鍵対 +
  `sub` claim (`mailto:` or `https:`)。 公開鍵は uncompressed base64url で
  PWA の `applicationServerKey` に渡す。
- **W3C Push API**: browser 側 API (`navigator.serviceWorker` →
  `PushManager.subscribe`)。

**データ構造** (`src/webrtc/push.rs`):

- `PushSubscription { endpoint, p256dh, auth }` ── 1 device の購読単位。
  `validate()` で HTTPS scheme / base64url / 空鍵を検査。
- `PushSubscriptionStore { AOR → Vec<PushSubscription> }` ── 1 AOR に複数
  device (= PC + スマホ) を許容。 同一 `endpoint` の再 subscribe は dedup
  (= 鍵 rotation 上書き)。
- `VapidKeys { private_pem, public_b64url, subject }` ── 起動時に PEM から
  派生して keep。 `public_key_b64url()` を `/api/push/vapid-public-key` で
  PWA に配信。
- `PushNotifier` trait + `WebPushNotifier` 実装 ── 本番は `IsahcWebPushClient`
  (HTTP/2)。 test は `MockPushNotifier` で fan-out / Gone 経路を検証。
- `IncomingCallPayload { type: "incoming_call", call_id, caller_number,
  issued_at }` ── Service Worker 側で受け取って Notification API で表示する
  JSON。

**動作シーケンス** (PWA 購読登録 → NGN inbound INVITE → push fan-out):

```text
PWA (browser)         sabiden                Push Service     PWA SW
   │ ① /api/push/vapid-public-key (GET)            │             │
   │ ─────────────────────────►│                   │             │
   │ ◄─────────────────────────│ { publicKey, subject }          │
   │ ② PushManager.subscribe({ applicationServerKey })           │
   │ ─── (browser → push svc) ────────────────────►│             │
   │ ◄───────────────────────────────────────── PushSubscription │
   │ ③ WS: { type: "pushsubscribe", endpoint, keys }             │
   │ ─────────────────────────►│                   │             │
   │                           │ store.upsert(aor=ext_id, sub)   │
   │ ◄─────────────────────────│ { type: "pushsubscribed", ep }  │
   │                           │                   │             │
   │       (later)             │                   │             │
   │ NGN INVITE  ─────────────►│                   │             │
   │                           │ store.list(aor) → notify_incoming_call
   │                           │ ──── POST endpoint (AES128-GCM、 VAPID JWT) ──►
   │                           │                   │ push event  │
   │                           │                   │ ──────────► │
   │                           │                   │             │ showNotification
   │                           │                   │             │ (caller_number 表示)
   │   tap → notificationclick │                   │             │
   │ ◄────── clients.openWindow / focus ───────────│             │
```

**fan-out 経路** (`src/call/orchestrator.rs::NgnInboundHandler::handle_invite`、
180 Ringing 直前):

1. `bindings = registrar.snapshot() + routing.evaluate(...)` で alert 対象 AOR
   が確定。
2. `push_clones()` で store + notifier の Arc を取得 (= push 機能 ON のとき)。
3. `tokio::spawn` で background task に切り出し、 各 AOR に対して
   `notify_incoming_call(store, notifier, aor, payload)` を呼ぶ。
4. push 送信は INVITE 処理の hot path をブロックしない (= 180/200 OK 経路に
   影響を与えない、 RFC 5853 §3.2.2 B2BUA 副次的 notification の規範)。
5. `Gone` (404/410) は store から自動削除 (RFC 8030 §5)。

**結線** (`src/main.rs`):

1. `[push] enabled = true` + `vapid_private_pem` + `subject` が揃えば、
   `VapidKeys::from_pem` で `Arc<VapidKeys>`、 `PushSubscriptionStore::new()`
   で `Arc<PushSubscriptionStore>`、 `WebPushNotifier::new(keys)` で
   `Arc<dyn PushNotifier>` を生成。
2. (a) `HealthState::with_vapid` (`GET /api/push/vapid-public-key`)、
   (b) `SignalingState::with_pwa_push` (`PushSubscriptionStore` 自身が
   `PwaPushHandler` を実装、 `ClientMessage::PushSubscribe` を dispatch)、
   (c) `NgnInboundHandler::set_push` (NGN INVITE で fan-out) の 3 経路に
   同じ Arc を渡す。
3. `push.enabled = false` (既定) なら全 hook が `None` で旧挙動完全互換。

**Service Worker** (`frontend/public/sw.js`、 vite-plugin-pwa `injectManifest`):

- `push` event: payload を JSON parse して `showNotification(title, options)`
  で表示。 iOS Safari 16.4+ は `userVisibleOnly: true` 強制 (silent push 禁止)。
- `notificationclick` event: 既存 tab があれば `focus` + postMessage
  (`incoming_call_action`)、 無ければ `clients.openWindow("/?#incoming=<id>")`。
  action ボタン (`accept` / `decline`) は Chrome/Android で表示される。
- `notificationclose`: 現状 no-op。

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

**PWA UI 側 retry_after 反映 (Issue #194)**:

backend が `ServerMessage::error` で抑制秒数を返すのに合わせて、 PWA フロント
エンドは発信ボタンを N 秒 disable + 残秒数カウントダウン表示する。 wire
format は既存の `error.message` 本文に文字列埋込のまま (Issue #194 で
「protocol を触らない」 制約)、 PWA 側 parser (`frontend/src/lib/signaling.ts::parseRateLimitedRetryAfter`)
で抽出する。

| `error.code` | message 本文 (backend 固定文言) | PWA 側挙動 |
|---|---|---|
| `rate_limited` | `outbound INVITE rate-limited (TTC JJ-90.24 §5.7.1): retry after <N> sec` | 発信ボタン N 秒 disable、 カウントダウン表示、 解除まで `placeCall` をローカルで弾く |
| `outbound_failed` | `NGN INVITE 失敗: <code> <reason> (retry_after=<N>s)` (Retry-After 受信時のみ) | 同上 |
| `outbound_failed` (Retry-After なし) | `NGN INVITE 失敗: 486 Busy Here` 等 | 通常エラー表示のみ (発信ボタンは disable しない) |

カウントダウンは `Date.now()` ベースで保持 (`rateLimitedUntil: epoch_ms`)。 WS
が transient close (1006 等) で再接続しても期限が残っていれば適用継続する。
複数 error が重なった場合は max(既存期限, 新候補) を採用し、 短い後続値で
解除予定を縮めない (= NGN 抑制を緩めない方向に倒す)。 WAI-ARIA 1.2 §6 Live
Region (`role="status" aria-live="polite" aria-atomic="true"`) で screen
reader にも残秒数を割り込みなしで読み上げる。

**session 境界でのリセット (Issue #219)**: WS reconnect (transient) は deadline
を温存するが、 session 自体が終了する以下の経路では PWA 側で `rateLimitedUntil`
を `null` に戻す:

- 明示 logout (`App.tsx::handleLogout`)
- auth 失敗 close (`onClosedReason: "auth"`、 token 失効で `clearToken` 後)
- exhausted close (`onClosedReason: "exhausted"`、 再接続上限到達後)

これは「別ユーザが同 PWA で続けて login するシナリオで前 session の deadline が
残り、 ユーザが context 不明な待機中 UI を見るバグ」 を防ぐ。 backend bucket は
AOR 共有なので技術的には継続中だが、 PWA 側は新 session 開始時点で UI ロックを
一旦クリアし、 次の `rate_limited` error 受信で正しく再構成する。

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

### 内線間 direct dial (intercom、 Issue #313、 `src/call/intercom.rs`)

PWA / SIP UA から発信した INVITE の dial target が sabiden の
[`ExtensionRegistrar`](#) に登録済みの AOR にヒットする場合、 NGN を介さず
内線同士で通話する経路。 NGN ch (= 物理 1 回線) を消費せず、 NGN 発着信と
並列に動く (= multi-line)。

> **scope (PR #314 landing 範囲、 PR #314 review #2 fix で明示化)**: PWA から
> 内線 dial する経路は WS 入口の [`is_valid_dial_target`] (charset
> `[0-9*#+]{1,32}`、 RFC 3261 §25.1 user 文法のサブセット、 CRLF injection
> 防御) を通過する必要があるため、 production 到達可能な AOR は **numeric**
> (例 `"101"`, `"*9"`) のみ。 alphabetic AOR (`"alice"` / `"iphone"` 等) は
> WS validator で `invalid_target` として弾かれる。 内線 SIP UA / 内線 PWA は
> AOR を numeric (`"101"`, `"102"` 等) で REGISTER する想定。 alphabetic AOR
> 対応 (WS validator 拡張 / `[extensions]` alias map) は follow-up Issue で扱う。
> dispatcher 単体 (= classify_dial_target / bridge attach) は AOR 文字種に
> 制約を持たないため、 lib unit test / trait-API direct integration test では
> `"alice"` 等の alphabetic AOR で挙動を検証している。

#### dispatcher (`classify_dial_target`)

```text
caller (PWA / SIP UA)
       │ INVITE target = "101" (numeric AOR) or "0312345678" (NGN 番号)
       ▼
WS validator [PWA のみ] is_valid_dial_target([0-9*#+]{1,32})
       │ pass
       ▼
sabiden orchestrator
       │
       ▼  classify_dial_target(target, ExtensionRegistrar)
       │
       ├── Internal { binding, aor }  ──► 内線間 dial へ分岐 (本セクション)
       └── Ngn { target }             ──► 既存 NGN プロキシ経路 (`docs/asterisk-real-invite.md` §5)
```

PWA 経路では WS 入口 [`is_valid_dial_target`] が先に立つので、 production 到達
する AOR は numeric のみ。 SIP UA 経路 (`handle_invite`) には WS validator は
ない (= SIP message 自体の Request-URI parse でホスト/パラメータが分離されるため、
任意 user 部が直接 dispatcher に来る) が、 SIP UA → 内線 AOR は本 PR では
fail-fast 480 で gate されており full multi-leg orchestration は follow-up。

判定ルールは 1 行:

- `registrar.lookup(target)` が有効 binding を返したら `Internal`。
- それ以外 (= 期限切れ含む) は `Ngn`。

AOR が「存在しない内線番号」 のケース (例 `"99999"` だが registrar 未登録) は
NGN へ流れて 404 で帰る。 これは sabiden 側が「内線番号文法」 を解釈する
band-aid を避ける設計選択 (CLAUDE.md §6.1)。

#### 設定 (`[intercom]`)

```toml
[intercom]
enabled = true                       # 既定 true
max_concurrent_internal_calls = 4    # 既定 4
```

`enabled = false` のとき dispatcher は完全 skip され、 旧挙動 (target に
関わらず NGN プロキシ) を維持する (= 完全な後方互換)。

#### Bridge variant (`MediaBridge::WebRtcRelay`、 `src/call/bridge.rs`)

PWA-PWA 中継のため新規追加した bridge variant。 両 peer の
`take_media_rx()` を pull し、 反対側の peer の `send_media()` に push する。
sabiden 側に UDP socket は持たない (str0m が ICE/DTLS-SRTP 経路で多重化済み)。
SRTP 鍵は各 peer 独立 (RFC 8827 §5)、 sabiden は decoded MediaFrame のみを
扱うので片側の SRTP context は他方に晒れない。

| caller | callee | bridge variant |
|---|---|---|
| PWA | PWA | `MediaBridge::WebRtcRelay` (新規、 Issue #313) |
| PWA | SIP UA | `MediaBridge::WebRtcAudio` (既存、 ngn_socket は SIP UA 側 UDP に流用、 PCMU 直送) |
| SIP UA | PWA | `MediaBridge::WebRtcAudio` (向き反転、 同上) |
| SIP UA | SIP UA | `MediaBridge::Relay` (既存、 両側 PCMU UDP) |

#### 並列性 / multi-line 耐性

- `InternalCallRegistry` は NGN レッグを持たない独立テーブル。 既存
  `OutboundCallRegistry` (NGN UAC dialog 必須) とは別管理。
- caller / callee 両 Call-ID で引ける双方向 index。 BYE 経路がどちら側から
  来ても同じエントリを解放できる。
- `IntercomService::try_admit` で
  [`max_concurrent_internal_calls`](#intercom-設定-intercom) を atomic に
  チェックし、 超過時は RFC 3261 §21.4.20 486 Busy Here 相当の error で
  reject (PWA は `ServerMessage::Error { code: "intercom_busy" }` 受領)。

#### Wiring ステージ (PR #314 + review follow-up)

PR #314 で landing 済み (production 結線):

1. **Foundation**: `intercom` module (`classify_dial_target`,
   `InternalCallRegistry`, `IntercomService`, `IntercomConfig`)。
2. **Bridge**: `MediaBridge::WebRtcRelay` variant + `WebRtcRelayBridge` 実装。
3. **main.rs 結線**: `UasEventHandler::set_intercom_service` 呼出で
   `[intercom]` 設定を読んだ `IntercomService` を注入 (前は欠落、 PR #314
   review #3 fix)。
4. **PWA→PWA full multi-leg orchestration**: caller の
   `handle_pwa_outbound_offer` で classify → admit → caller SAVPF answer 即時返却
   → callee `peer.create_offer()` で SAVPF offer 生成 → callee WS に
   `ServerMessage::Offer { call_id, sdp }` push → callee の `PendingAnswers` 経由で
   answer 待ち (30s timeout) → callee `accept_answer` → `WebRtcRelayBridge`
   attach → `InternalCallRegistry::insert` の full path を実装
   (`UasEventHandler::dispatch_pwa_internal_call`)。
5. **SIP UA → 内線 AOR の dispatcher gate**: `handle_invite` 冒頭で
   classify を呼び、 Internal hit なら **480 Temporarily Unavailable**
   (RFC 3261 §21.4.18) で fail-fast。 NGN に内線 AOR が漏れる band-aid を
   遮断する (CLAUDE.md §6.1)。
6. **PWA → SIP UA full multi-leg orchestration** (Issue #316、 PR で landing):
   `dispatch_pwa_internal_call` の `ExtTransport::Sip` arm で
   (a) caller `peer.handle_offer` で SAVPF answer 即時返却、 (b) caller
   `peer.take_media_rx` で MediaFrame source 取得、 (c) sabiden 内線 NIC に
   ephemeral RTP socket bind、 (d) SAVPF answer を AVP→PCMU only に正規化し
   c=/o=/m= を sabiden の bind addr に書換え (RFC 4566)、
   (e) `LegInviter::invite_intercom`
   (`Uac::invite_to`: destination = `binding.remote` 明示) で INVITE 送出、
   (f) 200 OK SDP から callee RTP endpoint 抽出 (RFC 3264 §6)、 (g)
   `WebRtcAudioBridge` (direct_pcmu_passthrough = true) を起動して PWA peer ⇄
   sabiden RTP socket ⇄ SIP UA endpoint の双方向 PCMU 透過、 (h)
   `IntercomService::register_call` で `InternalCallRegistry` 登録、 の full
   flow を実装。 caller cleanup (RFC 8829 §5.1) は全 Err path で
   `caller_peer.close()` + (2xx 後の attach 失敗時のみ) `dialog.send_bye()` を
   送出する。

本 PR review follow-up Issue で残務 (= まだ実装されていない経路):

7. **SIP UA → SIP UA full multi-leg**: `handle_invite` の dispatcher gate で
   480 を返している箇所を、 `ext_inviter` + `RtpBridge` で実 INVITE proxy +
   PCMU UDP リレーに差し替える。
8. **SIP UA → PWA full multi-leg**: `run_webrtc_leg` パターンを再利用して
   SIP UA INVITE 受信側で peer.create_offer → callee WS → answer → bridge attach。
9. **PWA→SIP UA 経路の BYE 連動**: 現状は SIP UA 側から BYE を受けると
   UAS 層で処理されるが、 sabiden 発の BYE (= PWA WS close 経由) を SIP UA
   に流すには `webrtc_outbound_active` 相当の SIP-leg dialog テーブルが要る。
   establish までは Issue #316 で完了、 双方向 BYE 連動は別 Issue に切り出す。
10. **alphabetic AOR 対応** (`"alice"` 等): WS 入口 [`is_valid_dial_target`] の
    charset を拡張するか、 `[extensions]` に numeric ↔ alphabetic alias map を
    入れて WS validator は numeric のまま維持する設計選択。 CRLF injection /
    SIP smuggling 防御 (PR #146 review #1 🔴#1) を破らない範囲で対応する。

#### PWA → SIP UA full multi-leg シーケンス (Issue #316)

```text
PWA (caller)                sabiden                              SIP UA (callee, registrar 経由)
  │                            │                                          │
  │ WS ClientMessage::Offer    │                                          │
  │  { target="101", sdp(SAVPF) }                                         │
  ├───────────────────────────►│                                          │
  │                            │ classify_dial_target → Internal{Sip,..}  │
  │                            │ try_admit (capacity OK)                  │
  │                            │ peer.handle_offer → SAVPF answer ─┐      │
  │ WS ServerMessage::Answer   │                                   │      │
  │  { sdp(SAVPF answer) }     │                                   │      │
  │◄───────────────────────────┤                                   │      │
  │                            │ peer.take_media_rx (caller mpsc)  │      │
  │                            │ UdpSocket::bind (内線 NIC)        │      │
  │                            │ SAVPF→AVP→PCMU rewrite c=/m=      │      │
  │                            │   = sabiden internal addr         │      │
  │                            │                                          │
  │                            │ Uac::invite_to(dest=binding.remote)      │
  │                            │   plan = sip:callee@host (PCMU SDP)      │
  │                            ├─────────────────────────────────────────►│
  │                            │                                          │ INVITE 受信 / 200 OK 組立
  │                            │◄─────────────────────────────────────────┤ 200 OK + PCMU SDP
  │                            │ ACK 自動送出 (RFC 3261 §13.2.2.4)         │
  │                            ├─────────────────────────────────────────►│
  │                            │ extract_rtp_endpoint(callee SDP)         │
  │                            │ WebRtcAudioBridge::start                 │
  │                            │   peer ⇄ sabiden internal UDP ⇄ callee   │
  │                            │ IntercomService::register_call           │
  │                            │                                          │
  │ (str0m PCMU 8kHz / 20ms)   │ direct_pcmu_passthrough = true           │ (RTP PCMU PT 0)
  ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ►│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│
  │◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│◄ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤
```

Err path での caller cleanup (RFC 8829 §5.1) は dispatcher の全 fail-fast 経路に
仕込まれており、 sabiden 側 socket bind 失敗 / SDP rewrite 失敗 / SIP UA 拒否 /
200 OK SDP 不正 / `attach_media_bridge` 失敗 のいずれでも `caller_peer.close()`
を best-effort で呼ぶ。 2xx 確立後の bridge 起動失敗時は `dialog.send_bye()`
で SIP UA 側 dialog も即時終了させ leak を防ぐ (RFC 3261 §15.1.1)。

実装状況 vs テスト命名 (PR #314 review #1 fix):

| 経路 | production wiring | テスト |
|---|---|---|
| PWA → PWA (numeric AOR) | ✅ full multi-leg orchestration (WS validator pass) | **WS-entry e2e**: `tests/intercom_integration.rs::ws_entry_numeric_aor_e2e_dispatches_to_intercom_not_ngn` (`process_client_message` 経由で numeric AOR `"101"` → validator pass → dispatcher → Internal、 NGN socket 0 件) |
| PWA → PWA (dispatcher 単体) | dispatcher 層単体 (WS validator bypass、 trait API 直叩き) | **integration**: `tests/intercom_integration.rs::rfc5853_pwa_to_pwa_dispatcher_e2e_no_ngn_traffic_and_bridge_forwards_media` (`handle_pwa_outbound_offer` 経由で実 dispatcher → 実 WS Offer push → 実 bridge attach → caller→callee MediaFrame 配送、 NGN socket 到達 0 件) |
| PWA → SIP UA | ✅ full multi-leg orchestration (Issue #316) | **integration**: `tests/intercom_integration.rs::issue316_pwa_to_sip_ua_full_multi_leg_e2e_bidirectional_pcmu_no_ngn_traffic` (fake SIP UA = UdpSocket 直叩きで INVITE 受信 → 200 OK PCMU SDP 返却 → sabiden が `WebRtcAudioBridge` を attach → 双方向 PCMU RTP forward 観測、 NGN socket 0 件) + lib unit: `call::manager::tests::issue316_leg_inviter_default_invite_intercom_returns_err` (`LegInviter::invite_intercom` の default impl は unsupported Err を返すことの確認) |
| SIP UA → 内線 | dispatcher gate のみ (480) | lib test: `call::orchestrator::tests::rfc3261_21_4_18_sip_ua_to_internal_aor_returns_480_temporarily_unavailable` |
| 容量上限 reject | ✅ full | integration: `tests/intercom_integration.rs::rfc3261_21_4_20_intercom_capacity_overflow_rejects_with_intercom_busy_error` |
| caller cleanup (callee timeout) | ✅ `caller_peer.close()` on Err paths (RFC 8829 §5.1) | integration: `tests/intercom_integration.rs::dispatch_pwa_internal_call_closes_caller_peer_on_callee_timeout` |
| Bridge primitive | ✅ | lib unit: `call::intercom::tests::rfc3551_webrtc_relay_bridge_forwards_pcmu_both_directions` 等 (旧名は "integration" を詐称していたため PR #314 review #1 で改名) |
| alphabetic AOR (`"alice"` 等) | ❌ WS validator で reject (follow-up) | — |

### 通話中 DTMF: PWA → NGN (Issue #277、 RFC 4733 telephone-event)

通話確立後に PWA dial pad で押下した DTMF (0-9, `*`, `#`, A-D) を
NGN レッグへ in-band で送る経路。 銀行 / 携帯会社 IVR、 117 オペレータ呼出等の
実用上必須機能。

#### Wire 形式 (`ClientMessage::Dtmf`)

```json
{ "type": "dtmf", "call_id": "<NGN レッグ Call-ID>", "digit": "5" }
```

`call_id` は対象通話を一意に識別する文字列。 sabiden は以下の優先順で lookup:

1. **PWA→NGN 発信** (`WebRtcOutboundActive`、 NGN UAC dialog の Call-ID)
2. **NGN→PWA 着信** (`NgnInboundHandler.active`、 受信 INVITE の Call-ID)

`digit` は 1 文字の文字列 (例 `"5"` / `"*"` / `"A"`)。 範囲外 / 複数文字は
silent drop (`ServerMessage::Error` は返さず通話を維持)。

#### sabiden 内処理 (`PwaDtmfHandler` 経路)

```
PWA                              sabiden(WS シグナリング)                       NGN
 │                                       │                                       │
 │ ClientMessage::Dtmf{call_id, digit}   │                                       │
 ├──────────────────────────────────────►│                                       │
 │                                       │ digit → 1 文字 char へ正規化           │
 │                                       │ (1 文字でなければ silent drop)         │
 │                                       │                                       │
 │                                       │ CompositePwaDtmfHandler                │
 │                                       │  ├ UasEventHandler (outbound)         │
 │                                       │  │   WebRtcOutboundActive で call_id  │
 │                                       │  │   lookup → bridge_call_id 取得     │
 │                                       │  └ NgnInboundHandler (inbound)        │
 │                                       │      self.active で call_id           │
 │                                       │      lookup → bridge_call_id 取得     │
 │                                       │                                       │
 │                                       │ inject_dtmf_event_to_ngn:             │
 │                                       │  1. RFC 4733 §3.2 digit→event 変換     │
 │                                       │  2. build_dtmf_packet_sequence で      │
 │                                       │     start (M=1) + 中間 + end triplet  │
 │                                       │     (RFC 4733 §2.5.1.1 / §2.5.1.2)    │
 │                                       │  3. CallManager::inject_to_ngn で     │
 │                                       │     NGN socket へ PT=101 RTP 送出      │
 │                                       │                                       │
 │                                       │                                       ├─PT 101 RTP─►
 │                                       │                                       │
```

`call_id` lookup miss / digit 範囲外 / bridge 未起動 のいずれも `Ok(false)` で
silent drop (通話 UI 上は dial pad 押下が no-op になるだけ、 通話切断は起こらない)。
NGN socket I/O failure は `Err` を返すが signaling 層で warn ログするのみで
session は継続 (`SessionAction::Continue`、 RFC 6086 §3 best-effort hint message と同じ
defense-in-depth)。

#### SIP INFO 内線経路との関係 (Issue #69)

`UasEventHandler::handle_ext_info` (RFC 6086) が SIP 内線 UA からの
`application/dtmf-relay` / `application/dtmf` body を同じ
`inject_dtmf_event_to_ngn` ヘルパへ流す。 PWA 経路 (本セクション) は
WS message を直接受けて同じヘルパに到達する。 RFC 4733 §2.5 packet 列
生成・SSRC/timestamp 払い出しロジックは両経路で共有 (DRY)。

#### Negotiation 前提

NGN レッグ SDP は `Negotiator::for_ngn_with_dtmf()` で
`a=rtpmap:101 telephone-event/8000` + `a=fmtp:101 0-15` を offer 済
(Issue #145 PWA outbound / Issue #110 NGN inbound 両経路)。 NGN P-CSCF は
telephone-event を audio と同 m=audio 内で 8kHz クロックで処理する
(RFC 4733 §3.2、 `docs/asterisk-real-invite.md` §2)。

#### 設計判断: WS message 経由 (SIP INFO ではない)

PWA は SIP dialog を持たないため、 内線 UA 風に `application/dtmf-relay`
SIP INFO を送る経路は採れない。 sabiden 内部で WS → RFC 4733 telephone-event
変換することで、 PWA から見れば「dial pad ボタン → JSON 1 行」 の単純な
インタフェースになる。

### WS シグナリング keepalive (Issue #98 / #131 / #167)

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

**シャットダウン通知 (Issue #131 / #167)**: 受信ループ / 送信 forwarder /
keepalive の 3 タスクは `Arc<Notify>` で協調終了する。 通知側は
**`notify_one()`** を使う (tokio 1.x docs)。 `notify_waiters` だと awaiting
でない瞬間に通知が消滅するが、 `notify_one` は permit を蓄えるので受信
ループが深い await から戻った直後に即時 `notified()` が解決し、 アイドル
切断時の撤収遅延を防ぐ (Issue #131 で PR #128 由来の最大数秒遅延を解消)。

**active waiter 数と `notify_one()` 呼び回数 (Issue #167)**:
`tokio::sync::Notify::notify_one()` は **最大 1 waiter** しか起こさない
仕様 (tokio 1.x doc)。 同時に `notified()` を能動 await している タスクが
N 個ある状態で全員を即時起床させたい場合、 `notify_one()` を **N 回** 呼ぶ
必要がある。 経路別の active waiter 数:

| `notify_one()` 経路 | その瞬間の active waiter | 呼び回数 |
|---|---|---|
| (1) keepalive: idle timeout 検知後 Close 送出 → return | 受信ループのみ (keepalive 自身は return 直前) | 1 |
| (2) keepalive: send_ping 失敗 → return | 受信ループのみ (同上) | 1 |
| (3) forwarder: WS send 失敗 → break | 受信ループ + keepalive の 2 つ | **2** (Issue #167 fix) |
| (4) run_session: 受信ループ離脱後の cleanup | keepalive のみ (受信ループは既に break 済) | 1 |

```
[3 タスク協調終了モデル]

run_session 受信ループ ──┐
                         ├── shutdown.notified() を select! 内で監視
keepalive タスク ────────┘
                         shutdown.notify_one() を発火する経路:
                         (1) keepalive: idle timeout 検知後 Close 送出 → notify_one ×1 → return
                         (2) keepalive: send_ping 失敗 (相手切断) → notify_one ×1 → return
                         (3) forwarder: WS send 失敗 → notify_one ×2 → break (Issue #167)
                         (4) run_session: 受信ループ離脱 → notify_one ×1 (keepalive 撤収)
```

PR #165 までは (3) も 1 回呼びだったが、 forwarder 失敗時点では受信ループ
と keepalive の **両方** が `shutdown.notified()` を能動 await している
ため、 片方しか起きず RFC 6455 §7.4.1 abnormal closure 撤収が片方分だけ
遅延していた。 Issue #167 で 2 回呼びに修正。

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

### Trickle ICE end-of-candidates (Issue #92)

sabiden は ICE-Lite (RFC 8445 §2.4、 controlled 側) を採用しており、 公開する
ICE candidate は **host candidate 1 件のみ** (`public_ip` 由来、 STUN/TURN
反射 / 中継候補は生成しない、 `src/webrtc/str0m_session.rs:170-210`)。 この
場合 ICE candidate gathering の終了タイミングは「host candidate を送出した
直後」 で確定するため、 sabiden run_loop は host を 1 件送出した直後に
**空文字列 (`""`) を end-of-candidates marker** として WS シグナリングに流す
(RFC 8838 §13 (Generating an End-of-Candidates Indication) / W3C WebRTC
§4.4.1.6: end-of-candidates は null candidate / empty string で表す)。

> **注**: RFC 8840 は **SIP usage 専用** (Trickle ICE over SIP)。 sabiden は
> WebSocket JSON シグナリング経路なので、 trickle ICE の一般仕様である
> **RFC 8838** (§13 Generating / §14 Receiving) を主引用とする。

```
[sabiden → PWA trickle ICE flow]

str0m run_loop                          signaling.rs                       PWA
 │                                       (forwarder task)                   (frontend/src/lib/webrtc.ts)
 │ ICE state Checking 遷移 (= 候補列挙が                                   │
 │ 始まる、 RFC 8839 §3.1)                                                  │
 │                                                                          │
 ├─ host_candidate (typ host, public_ip)  ──► ServerMessage::Ice{candidate} ──►  pc.addIceCandidate({candidate})
 │                                                                          │
 └─ "" (RFC 8838 §13 marker, 同 tick)     ──► ServerMessage::Ice{candidate:""} ──►  pc.addIceCandidate(null)
                                                                            │
                                                                            ▼
                                          ブラウザ: gathering 完了確定。 ICE failure timer
                                          (RFC 8445 §6.1.4 nominated pair 不在判定) を即時起動。
                                          checks 全失敗 → `connectionState = failed` に
                                          数秒で遷移 (旧挙動: 30 秒+ 待ち)。
```

PWA → sabiden 方向の end-of-candidates marker (`{type:"ice", candidate:""}` /
`candidate:"end-of-candidates"` / `candidate:"a=end-of-candidates"`) は
`process_client_message::Ice` で silent OK 受理する (RFC 8838 §14 MAY)。
**比較は trim 後の厳密 equality** で行う (Issue #206: `contains` ベースの
部分一致は `xxx-end-of-candidates-yyy` 型の擬陽性を生む)。 str0m 0.19 /
is-0.9.0 は public API として「end-of-remote-candidates を `IceAgent` に通知
する」 メソッドを提供しない (is-0.9.0/src/agent.rs:205 のコメント: "We never
end trickle ice")。 そのため本 marker は観測ログのみに使われ、 ICE 失敗
判定は str0m 内部 timer に委ねる (sabiden は ICE-Lite controlled なので、
ブラウザ側の候補列挙完了を待つ必要はない)。

### PWA 側 ICE buffer (dialog epoch、 Issue #91 / #173)

NGN→PWA 着信フローで sabiden は ringing 段階 (browser が応答ボタンを押す
前) で `ServerMessage::Ice` を push し始める (trickle ICE、 RFC 8839 §4.2)。
browser 側 `RTCPeerConnection` は応答ボタン押下時に初めて生成されるため、
**応答前の ICE candidate は `App.tsx::pendingIceCandidates` で buffer** し、
`acceptIncomingOffer` / `placeCall` で call を生成した直後に `flushPendingIce`
で適用する (W3C WebRTC §4.4.6: `setRemoteDescription` 前の candidate は
buffer 推奨)。

buffer エントリは **dialog epoch (call 世代カウンタ)** でタグ付けする
(Issue #173)。 `teardownCall()` は `dialogEpoch += 1` するだけで配列は
触らず、 `flushPendingIce()` は **現 epoch と一致するエントリだけ** addIce
する。 これにより以下 2 race を解消する:

| Race | 旧実装 | 新実装 (dialog epoch) |
|---|---|---|
| R1: "ice" → "offer" 順 (= RFC 8839 §4.2 任意順序、 NGN 着信開始時) | offer ハンドラ内 `teardownCall` が `pendingIceCandidates = []` で wipe → 先着 ICE 喪失 | epoch++ のみ。 旧 epoch (= 旧 dialog 由来) は flush で drop、 新 dialog の ICE は新 epoch で残る |
| R2: `flushPendingIce` await 合間に "bye"/"cancel" → `teardownCall` 割り込み | 旧 `buffered` 参照で続行 → hung-up PC に addIce で warn ノイズ | ループ先頭で `dialogEpoch !== currentEpoch` を見て即 return |

単一スレッド JS なので epoch の読み書きは torn read 不可能 (W3C HTML Living
Standard §8.1.4: 各 task / microtask は他 task と並行実行されない)。 Mutex
や Promise.race 風 lock は不要 — epoch snapshot で順序問題を完全に解決する。

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
| `a=ice-options:trickle` (session level) | trickle ICE | RFC 8838 §11 |

SSRC / CNAME / msid は `DtlsIceParams::with_ssrc()` / `with_cname()` /
`with_msid()` で呼び出し側が指定可能。 未指定なら `o=` の session-id 由来の
安定値 (CNAME は `"sabiden"`、 track id は `"audio0"`) が補われ、 同一 SDP に
対する変換は冪等 (二度かけても重複しない)。

`convert_savpf_to_avp` (ブラウザ SAVPF → NGN AVP) は逆方向で、 DTLS-SRTP /
ICE / msid / ssrc / extmap 等の NGN が解釈しない属性を全て剥がし、
`m=audio <port> RTP/AVP 0` + PCMU rtpmap だけに正規化する (RFC 5853 §3.2、
NGN 制約は CLAUDE.md §5)。

### SDP `Negotiator` (Phase R3、 Issue #272、 `src/sdp/negotiation.rs`)

`Negotiator` は NGN レッグへ流す SDP の **codec subset + WebRTC 属性剥離 +
NGN 媒体正規化** を一括で行うレイヤ (`docs/refactor-plan.md` §1.4 / §4.2)。
旧 `crate::sdp::builder::restrict_audio_to_pcmu` / `_with_dtmf` の 1 関数に
同居していた以下 4 つの責務を分割し、 設定可能な型に集約する:

| 責務 | 根拠 RFC | 設定 |
|---|---|---|
| Codec subset (PCMU / telephone-event) | RFC 3264 §6.1 / RFC 3551 §6 / RFC 4733 §3.2 | `allowed_audio` |
| WebRTC SAVPF 属性剥離 (DTLS-SRTP / ICE / BUNDLE / msid / ssrc / extmap / rtcp-mux / rtcp-fb / rtcp-xr 等) | RFC 5763 §5 / RFC 8839 §5.4 / RFC 8843 §7.2 / RFC 5576 §4 / RFC 8285 §6 / RFC 5761 §5 | `strip_webrtc_attrs` |
| NGN 媒体正規化 (`s=` / `a=ptime:20` / `a=rtcp:<port+1>` 補完) | RFC 4566 §5.3 / §6 / RFC 3605 §2.1 | `normalize_for_ngn` |
| 欠落 rtpmap / fmtp 補完 | RFC 3551 §6 / RFC 4733 §3.2 | `allowed_audio` の `rtpmap_value` / `fmtp_value` |

ファクトリ:

| Factory | allowed_audio | 用途 |
|---|---|---|
| `Negotiator::for_ngn()` | `[PCMU(0)]` | PCMU only INVITE (PR #264 までの 117 通話 / PWA→NGN 発信 SDP) |
| `Negotiator::for_ngn_with_dtmf()` | `[PCMU(0), TELEPHONE_EVENT(101)]` | NGN INVITE + in-band DTMF (Issue #69、 Re-INVITE 経路) |

API:

| メソッド | 入力 | 出力 | 用途 |
|---|---|---|---|
| `rewrite_offer(&[u8])` | offer SDP | 正規化 SDP | 内線 → NGN 発信 / PWA → NGN 発信 / Re-INVITE 伝搬 |
| `rewrite_answer(_ext_offer, ngn_answer)` | NGN 由来 answer (= 200 OK SDP) | 内線 relay 用 SDP | NGN inbound → 内線 relay (将来 intersection 計算と統合予定、 現状は PCMU only 正規化のみ) |

旧 `crate::sdp::builder::restrict_audio_to_pcmu` / `_with_dtmf` は本モジュールへの
薄い alias として残置 (backwards compat)。 production callsite は順次
`Negotiator::for_ngn().rewrite_offer(...)` に切替済 (`src/call/orchestrator.rs`
3 箇所 — PWA outbound INVITE / Re-INVITE 伝搬 / PWA INVITE 再構築)。

実機未検証で属性を追加 / 削除しないルール (CLAUDE.md §6.1) は引き続き適用される。
Negotiator の `strip_webrtc_attrs` 対象セットは `docs/asterisk-real-invite.md`
§2 の pcap 由来確定事項に基づく。

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

#### offerer 経路の audio_mid 先取り設定 (Bug A / Issue #268)

`Str0mPeerSession::create_offer` (= sabiden が **offerer**、 NGN→PWA 着信時に
使う) は str0m 0.19 の `change/sdp.rs:1180` の挙動により `Event::MediaAdded`
が **発火しない**:

```rust
// str0m 0.19 change/sdp.rs:1180
media.need_open_event = is_offer && !is_rejected;
```

ここで `is_offer` は **「リモートが offer を送ってきたか」** (= sabiden が
answerer のとき true)。 sabiden が **offerer** で remote answer を `apply_answer`
する経路では `is_offer=false` となり `need_open_event=false`。 そのため
`poll_event` が `MediaAdded` を fire せず、 run_loop の `audio_mid` は `None`
のままになる。 結果として `write_media` は「audio mid 未確定 → media drop」
で全 RTP を破棄する (実機 v7 で 60 秒 PWA `track.muted=true` 観測)。

対処 (`fn create_offer` の戻り値変更): `sdp_api().add_media(...)` が返す `Mid`
を呼出側 (run_loop の `Command::CreateOffer` 分岐) で取り出し、 `RunCtx.audio_mid`
に **即時セット**する。 `Event::MediaAdded` への依存を断つことで offerer 経路
でも `write_media` が writer を取得できる。 RFC 3264 §5 (offerer
responsibility): offerer は自身が出した m-line の状態を answer 受領前から
把握しており、 mid は自分で割り当てた値を使う。

回帰テスト: `webrtc::str0m_session::tests::rfc3264_5_send_media_works_when_
sabiden_is_offerer` (sabiden offerer + mock-browser answerer の loopback
ラウンドトリップで `Event::MediaData` が browser 側に届くまでを検証)。 既存
`rfc8825_send_media_after_connected_delivers_media_data` (sabiden answerer 経路)
と対称形なので、 二方向のレッグを両方守る。

副次的に PWA 側 `frontend/src/lib/webrtc.ts::addIce` も hardcode の
`sdpMid: "0"` から `remoteDescription` の `a=mid:<tag>` 抽出に修正した
(str0m offerer の mid は ASCII 3 文字のランダム ID `J9e` 等で固定 `"0"` と
合わないため、 chromium 124+ が `Cannot set ICE candidate for level=0 mid=0`
で reject していた)。 RFC 8838 §14 (sdpMid OR sdpMLineIndex 必須) 準拠。

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
   │ (2) payload をそのまま μ-law 列に       │ (2) OpusDecoder::decode → 48k PCM
   │ (3) RtpPacket{PT0, seq+=1, ts+=160}     │     (RFC 7587 §4.1: 2.5/5/10/20/40/60 ms)
   │                                         │ (3) OpusToPcmuAccum::push で 20 ms 境界に
   │                                         │     揃える (Issue #200; 短尺は次 packet で
   │                                         │     flush、 20/40/60 ms は即時 N chunk)
   │                                         │ (4) 各 chunk: DownsamplerWbToNb(48k→8k)
   │                                         │ (5) 各 chunk: encode_ulaw → 8k μ-law 列
   │                                         │ (6) 各 chunk: RtpPacket{PT0, seq+=1, ts+=160}
   ▼                                          ▼
  NGN UDP                                     NGN UDP (N packet)
```

##### `OpusToPcmuAccum`: 20 ms 境界 累積バッファ (Issue #200)

RFC 7587 §4.1: Opus は **6 種** のフレーム長 (2.5/5/10/20/40/60 ms = 120/240/480/
960/1920/2880 samples @ 48 kHz) を許す。 RFC 7587 §4.2: "the receiver SHOULD NOT
assume any particular frame size"。 sabiden の NGN 出口は PCMU **20 ms 固定**
(RFC 3551 §4.5.14) なので、 受信 Opus フレーム長と NGN フレーム長は一致しない:

| 受信 Opus | 累積後の挙動 | NGN 出力 PCMU |
|---|---|---|
| 2.5 ms (120 samples) | 累積 120 < 960 → 保持、 次 packet 待ち | 0 個 (即時) |
| 5 ms (240) | 累積 < 960 → 保持 | 0 個 (即時) |
| 10 ms (480) | 累積 < 960 → 保持 | 0 個 (即時) |
| 20 ms (960) | 累積 960 → 即時 emit | 1 個 (即時) |
| 40 ms (1920) | 累積 1920 → 2 chunk emit | 2 個 (即時) |
| 60 ms (2880) | 累積 2880 → 3 chunk emit | 3 個 (即時) |
| 短尺の連結 (例 2.5 ms × 8) | 累積 960 達成 → 1 chunk emit | 1 個 (8 packet 目で) |

`OpusToPcmuAccum` (`src/call/transcoder.rs`) は decoded WB 48 kHz サンプルを
内部 `Vec<i16>` に蓄積し、 `WB_FRAME_SAMPLES` (= 960) に達した時点で先頭 960
samples を切り出して [`DownsamplerWbToNb`] → μ-law encode → `Vec<u8>` chunk として
返す。 短尺フレームを単発で受け取った場合は空 `Vec<Vec<u8>>` を返し、 累積バッファ
に保持して次 packet で flush する。 旧実装 (PR #197 まで) は
`wb.samples.len() % 960 != 0` を silently drop していたため 2.5/5/10 ms 入力で
NGN レッグが無音になっていた。

`web_to_ngn_loop` (`TranscodingBridge`、 UDP↔UDP) と `peer_to_ngn_loop`
(`WebRtcAudioBridge`、 str0m mpsc↔UDP) の **両方** で同じ `OpusToPcmuAccum` を
使う。 状態は loop ローカル変数として持ち、 通話 lifetime 中ずっと存続する。

PCMU 直送モード (`direct_pcmu_passthrough = true`) では Opus decode 自体が無く、
受信 PCMU が既に 20 ms 単位なので accum は使わない。

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
- **SSRC collision detection** (Issue #182 (e) / RFC 3550 §8.2): transcoder
  の各 ingress (`ngn_to_web_loop` / `web_to_ngn_loop` / `ngn_to_peer_loop`) で
  受信した RTP packet の SSRC が egress SSRC と一致する場合、
  `RtpEgressState::check_and_rotate_on_collision` で egress SSRC を新規 random
  値に rotate する (旧 SSRC とは必ず異なる値)。 seq / timestamp は維持。
  検出時は `tracing::warn!` + `Metrics::add_ssrc_collision_detected` で観測。
  RFC §8.2 が併せて要求する「旧 SSRC からの RTCP BYE 送出」は transcoder
  経路で SR/RR/BYE を送出していない (Issue #182 (f) で別 PR) ため現状未実装。
  `peer_to_ngn_loop` は ingress が `MediaFrame` (SSRC を持たない、 str0m が
  WebRTC 側で割り当て) のため対象外。 また `ngn_to_peer_loop` での rotate は
  egress 先 (`peer.send_media(MediaFrame)`) が SSRC を消費せず str0m が独自に
  WebRTC レッグ上の SSRC を割り当てるため、 mutated 新 SSRC は実 RTP egress
  には載らず、 metrics 計上と warn ログのみが有効な observability 効果になる
  (collision 自体の検知は意味があるため rotate 処理は残置)。
  テスト: `rfc3550_8_2_*` 3 件。
- **Ingress→Egress loss propagation** (Issue #182 (b) / RFC 3550 §5.1 / §A.1):
  入力 RTP の seq gap を出力 RTP の seq に伝搬する。 `RtpEgressState` に
  `last_ingress_seq: Option<u16>` を持ち、 各 ingress 経路 (`ngn_to_web_loop` /
  `web_to_ngn_loop` / `ngn_to_peer_loop`) で `note_ingress_seq(pkt.sequence)` を
  呼ぶ。 `wrapping_sub(ingress_seq, last_ingress_seq)` で 16-bit wrap-around を
  吸収しつつ、 `MAX_INGRESS_GAP = 100` (RFC 3550 §A.1 `MAX_MISORDER` 相当) で
  clamp、 duplicate (gap=0) は skip しない (`gap=1` clamp)。 観測した gap-1 だけ
  `self.seq` を `wrapping_add` で前進させ、 続く `next` / `next_with_marker` で
  +1 されることで、 出力 seq は ingress と同じ gap だけ進む。 これにより受信側
  jitter buffer / NACK / FEC は **真の loss を観測可能** になり adaptive 制御が
  機能する (旧実装: transcoder が +1 連番で連結 → 受信側からは perfect stream に
  見えて loss が隠蔽されていた)。
  1 ingress packet が複数 chunk を emit する経路 (`web_to_ngn_loop` で Opus 40/60 ms
  → PCMU 2/3 chunk、 `OpusToPcmuAccum` 経由) では、 `note_ingress_seq` を chunk
  loop の外で 1 回だけ呼び、 ingress gap は最初の chunk にだけ反映する (後続
  chunk は通常通り +1 連番)。 短尺フレーム accum (Opus 10ms × 2 → PCMU 1 chunk)
  では note 自体は ingress packet ごとに呼ぶ (gap=1 連続性を維持) が、 emit が
  発生しない経路では egress seq が進まない (= accum 自体は loss ではないため
  false gap を出さない)。
  `peer_to_ngn_loop` は ingress が `MediaFrame` (seq を持たず、 str0m が WebRTC
  レッグから順序保証して mpsc に流す) のため対象外。 `ngn_to_peer_loop` は
  egress seq が wire に出ない (`peer.send_media(MediaFrame)` 経由で str0m が
  独自割当) が、 egress state の一貫性 / 観測性 (test / log) のため他経路と
  同様に `note_ingress_seq` を呼ぶ。
  テスト: `rfc3550_5_1_normal_no_loss_no_skip`、
  `rfc3550_5_1_ingress_loss_propagates_to_egress`、
  `rfc3550_5_1_ingress_wrap_around_handled`、 `rfc3550_5_1_large_gap_clamped`、
  `rfc3550_a_1_ingress_duplicate_seq_does_not_skip_egress`、 e2e
  `rfc3550_5_1_e2e_ingress_loss_propagates_to_egress_seq`。

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
| RR fraction_lost | `JitterStats::fraction_lost(last_expected, last_received)` で **直前 RR/SR 以降の interval** から算出 (RFC 3550 §6.4.1 / Appendix A.3)。 `RtpSession` が per-SSRC `(last_expected, last_received)` を保持し、 `build_report_blocks` 出力ごとに更新する | Issue #199 (PR #196 follow-up)。 旧実装は累積 `lost * 256 / expected` を返していたため初期 loss が永続化し §6.4.1 違反だった |
| UDP 受信バッファ | 9000 byte (`crate::rtp::RECV_BUF_SIZE`、 jumbo frame 上限) | RFC 3550 §5.1 (RTP fixed header + CSRC + RFC 5285/8285 extension) と §6.4 (compound RTCP) が 1500 byte IP MTU を超え得るため。 PCMU 20ms = 172 byte の常用パスには影響なし。 `n == RECV_BUF_SIZE` のとき truncate 疑いで warn ログ (`tokio` は Linux `MSG_TRUNC` を expose しない)。 Issue #96。 |

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

| ソース | 修正前の挙動 | 修正後 (Issue #89 / #200) |
|---|---|---|
| `OpusDecoder::decode` | 出力バッファ 960 固定、 40/60 ms は libopus エラー or truncate | `get_nb_samples` で必要量を取り、 5760 まで対応 |
| `TranscodingBridge::web_to_ngn_loop` | `len != 960` で silently drop | `OpusToPcmuAccum::push` で 20 ms 境界に累積後 N packet 送出 |
| `WebRtcAudioBridge::peer_to_ngn_loop` (non-passthrough) | 同上 | 同上 |
| 2.5 / 5 / 10 ms (短フレーム / RFC 7587 §4.2) | silently drop | `OpusToPcmuAccum` が 8/4/2 frame 単位に累積、 20 ms 揃いで PCMU 1 packet emit |
| PLC (packet.is_empty()) | 不変 | 不変 (RFC 7587 §6.2、 20 ms 固定で `OPUS_GET_LAST_PACKET_DURATION` 連動は将来) |

RFC 7587 §4.2 / RFC 6716 §3.2 が許す **全フレーム長 (2.5/5/10/20/40/60 ms)** を
`OpusToPcmuAccum` で一般化して処理する (Issue #200)。 20 ms 未満のフレームは
内部 buffer に蓄積し 20 ms 揃ったタイミングで PCMU を emit する。 buffer は
PCMU passthrough mode (`direct_pcmu_passthrough = true`) では一切経由しない (PR #149 透過パス無破壊)。

#### Talkspurt 境界の M ビット (Issue #84)

RFC 3550 §5.1 の RTP marker bit は profile 依存で解釈される。 RFC 3551 §4.1
(audio profile) と RFC 7587 §4.4 (Opus payload format) はいずれも **talkspurt
開始の最初の packet で M=1 を立てる** ことを規定する (silence suppression /
DTX 復帰直後)。 対向の adaptive jitter buffer は M=1 を talkspurt 境界として
受信深度をリセットし、 silence 後の playout 遅延を最小化する。

sabiden の RTP 送信パスは 2 系統:

| 経路 | コード | M=1 判定 |
|---|---|---|
| `RtpSession::send_ulaw` (低レベル UDP 送信) | `src/rtp/session.rs` | `last_send_time` 経過時間 ≥ `TALKSPURT_GAP_THRESHOLD` (= 30 ms) |
| `TranscodingBridge` / `WebRtcAudioBridge` (transcoder の RTP egress) | `src/call/transcoder.rs::RtpEgressState::next_with_marker` | 同上、 seq / ts 払い出しと同一 critical section |

30 ms 閾値は 20 ms (= 1 frame 周期) と 40 ms (= silence detector の最短窓) の
中間値で、 jitter による false positive と silence 検出漏れの両方を避ける。
Opus DTX 復帰 (RFC 7587 §3.7) は silence packet 4 個 = 80 ms 以上の gap を
伴うため、 30 ms 閾値で確実に拾える。

`WebRtcAudioBridge::ngn_to_peer_loop` は `MediaFrame` (str0m への mpsc) を
出力し、 marker は str0m が WebRTC レッグ上で割当てるため sabiden 側で扱わない。
`RtpBridge::forward_loop` (`src/call/bridge.rs` のバイト透過モード) は対向の
M ビットをそのまま forward する。

#### RTCP Sender Report の送出 (Issue #182 (f) / #112)

RFC 3550 §6.4.1 は「自送信中の participant は周期的に Sender Report (SR) を
送出して、 受信側に (a) sender SSRC、 (b) NTP 時刻 ↔ RTP timestamp の相関、
(c) 累積 packet/octet 数を伝える」ことを規定する。 受信側は SR の NTP timestamp
を用いて lip-sync (= RTP timestamp と wall clock の同期) と RTT 推定を行う。

transcoder の 3 egress 経路に対し、 5 秒間隔で SR を送出するタスクを
`rtcp_sr_sender_loop` (`src/call/transcoder.rs`) として spawn する (PR #242 で
導入)。

| egress 経路 | コード | SR 送出先 socket | SR 宛先 |
|---|---|---|---|
| `ngn_to_web_loop` (UDP→UDP transcode) | `TranscodingBridge::start` | `web_socket` | `web_state.peer` (WebRTC 側) |
| `web_to_ngn_loop` (UDP→UDP transcode) | `TranscodingBridge::start` | `ngn_socket` | `ngn_state.peer` (NGN P-CSCF) |
| `peer_to_ngn_loop` (str0m mpsc→UDP) | `WebRtcAudioBridge::start` | `ngn_socket` | `ngn_state.peer` (NGN P-CSCF) |

`ngn_to_peer_loop` (UDP→str0m mpsc) は egress 先が `MediaFrame` mpsc であり、
WebRTC レッグの RTCP は str0m 自身が SAVPF 経路 (RFC 8108 / RFC 8835) で扱う
ため、 sabiden 側で SR を組まない。

| 項目 | 値 | 根拠 |
|---|---|---|
| 送出間隔 | 5 秒固定 (`RTCP_SR_INTERVAL`) | RFC 3550 §6.2 minimum interval。 Adaptive interval (§6.3 `T_rr_interval`) と randomization (0.5x〜1.5x) は Phase R5/R6 で検討 |
| RTP/RTCP mux | 有効 (= 同 UDP socket / 同 port で SR を送出) | RFC 5761 §3.3。 NGN P-CSCF は port+1 への inbound 許可が不確実 (`docs/asterisk-real-invite.md` §5.2 で確証なし) のため mux を採用 |
| MissedTickBehavior | `Skip` | tick lag (上位 task busy 等) で複数 tick が溜まっても RFC 3550 §6.2 minimum interval = 5 秒を破らない |
| 初回 SR 送出 | bridge 起動から **5 秒後** | 起動直後の `interval.tick()` (immediate) を 1 回消費して 5 秒待つ。 packet_count=0 の空 SR を wire に出さない実装 |
| 送信統計 | `RtpEgressState.sent_packets` / `sent_octets` | 上位 loop が `to_socket.send_to` 成功時に `record_sent(payload_len, sent_rtp_ts)` を呼ぶ。 send 失敗時は集計しない (wire に出ていない packet を SR にカウントしないため) |
| RC (report count) | 0 | transcoder egress は受信側 jitter buffer 統計を共有しないため (入力レッグの SSRC ≠ 出力レッグの SSRC)。 入力 RR/SR の集計は別 PR で対応 |
| Peer 学習 | `LegState::peer` (late-binding) を周期 snapshot | 学習未了なら scheduling skip (次 tick で再判定)。 SDP 事前学習済なら最初の tick から送出 |
| シャットダウン | bridge Drop で `JoinHandle::abort` | 他 loop と同ライフサイクル管理 (`tokio::spawn` の慣用パターン) |
| 観測カウンタ | `Metrics::rtcp_sr_sent` (Prometheus `sabiden_rtcp_sr_sent_total`) | 全方向で集計 (将来 label 化で方向別に分解可) |

##### NTP/RTP timestamp anchor (Issue #182 (d))

`build_sr` が出す SR の `rtp_timestamp` は `RtpEgressState::rtp_timestamp_at`
(PR #245 で配線) によって anchor からの線形補間値を返す。 RFC 3550 §6.4.1
要件「NTP timestamp と RTP timestamp が **同じ wall-clock 瞬間** を指す」を
満たす:

| 方向 | sample_rate_hz | 初期化 | 根拠 |
|---|---|---|---|
| `TranscodingBridge::ngn_to_web_egress` | 48000 | `BridgeState::with_sample_rates(OPUS_SAMPLE_RATE, NARROW_BAND_RATE)` | RFC 7587 §4.1 (Opus 48 kHz) |
| `TranscodingBridge::web_to_ngn_egress` | 8000 | 同上 | RFC 3551 §4.5.14 (PCMU 8 kHz) |
| `WebRtcAudioBridge::ngn_to_web_egress` (PCMU 直送) | 8000 | `direct_pcmu_passthrough=true` で 8 k / 8 k | NGN→peer も PCMU 8 kHz そのまま |
| `WebRtcAudioBridge::ngn_to_web_egress` (Opus 変換) | 48000 | `direct_pcmu_passthrough=false` で 48 k / 8 k | str0m に Opus を渡すモード (将来) |
| `WebRtcAudioBridge::web_to_ngn_egress` | 8000 | 常に | peer→NGN 出力は常に PCMU |

anchor の semantics:
- **初回 `record_sent` 呼び出し** (= wire 送出成功時) で `anchor = Some((NtpTimestamp::now(), sent_rtp_ts))` を確定する。 caller (3 つの送信 loop) は `next` が返した RTP ts (= wire に乗せた packet の ts) を渡す。
- `next` (払い出し) 時点ではなく `record_sent` (wire 送出成功) で anchor を確定するのは、 wire 送出失敗時 (`to_socket.send_to` Err) に anchor だけ確定して NTP/RTP 線形性が 1 frame ずれる事故を避けるため (RFC 3550 §6.4.1 「NTP timestamp ↔ RTP timestamp の対応」 は実際に wire に出した packet を基準にすべき)。
- 2 回目以降の `record_sent` 呼び出しでは anchor は **不変** (上書きしない)。 これにより wall clock と RTP timestamp の relationship が long-running 通話でも線形に保持される。
- SSRC rotate (RFC 3550 §8.2 / PR #239 `check_and_rotate_on_collision`) は anchor を **保持** する。 anchor は wall clock と RTP ts の関係であり、 SSRC とは独立した量だから。
- `rtp_timestamp_at(now_ntp)` は anchor から線形補間で「now_ntp 瞬間に対応する RTP ts」を返す:

  ```text
  rtp_at_now = anchor_rtp + round( (now_ntp - anchor_ntp) * sample_rate_hz )
  ```

  `build_sr` 内で `let now_ntp = NtpTimestamp::now(); rtp_timestamp_at(now_ntp).unwrap_or(self.timestamp)` を呼んで埋め込む。 anchor 未確定 (= 1 packet も wire に出していない) の場合は `self.timestamp` fallback だが、 実運用では `record_sent` 後にしか SR を出さないため通常通過しない。

##### 完了 (Issue #182 全要件 — b/d/e/f)

- **(b) loss/reorder propagation** (RFC 3550 §5.1 / §A.1、 closes #182): ingress
  で観測した RTP seq の gap を egress seq に伝搬する。 `RtpEgressState`
  に `last_ingress_seq: Option<u16>` を追加し、 `note_ingress_seq(ingress_seq)`
  を 3 ingress 経路 (`ngn_to_web_loop` / `web_to_ngn_loop` / `ngn_to_peer_loop`)
  で呼ぶ。 入力 1 packet ロスは egress seq を +2 進める (受信側が真のロスを
  観測可能になり jitter buffer adaptive 制御が機能する)。 `MAX_INGRESS_GAP = 100`
  で clamp (RFC 3550 §A.1 `MAX_MISORDER` 相当)、 duplicate (gap=0) は skip しない
  (`gap=1` clamp)、 16-bit wrap-around は `wrapping_sub` で吸収。 reorder は
  jitter buffer (`src/rtp/jitter.rs`) が forward-only 順序を保証するため
  transcoder は forward-only 前提で実装。
- **(d) timestamp NTP 基準**: 出力 timestamp 初期値が random で NTP 同期計算
  の基準が不安定だった点は PR #245 (NTP anchor) で対応済 (Issue #182 (d) close)。
  SR の `rtp_timestamp` が NTP_now との関係で安定する。
- **(e) SSRC collision detection** (RFC 3550 §8.2): PR #239 で実装済
  (Issue #182 (e) close)。 `RtpEgressState::check_and_rotate_on_collision` が
  ingress SSRC == egress SSRC を検出して新規 random SSRC に rotate する。
- **(f) SR 送出** (RFC 3550 §6.4.1 / RFC 5761 §3.3): PR #242 で実装済
  (Issue #182 (f) close)。 5 秒周期で各方向の SR を対向 socket に送出する。

#### orchestrator 配線

```text
[NGN → PWA 着信 (Issue #145、 src/call/orchestrator.rs:799-815)]

  NGN INVITE (PCMU only)
   ▼
  UasEventHandler / NgnInboundHandler
   │ ext_answer = browser SAVPF answer (str0m PCMU only)
   │ pcmu_only = restrict_answer_to_ngn_offer_subset(ngn_offer, ext_answer)
   │   (Issue #108 / #212 / RFC 3264 §6.1: answer m= formats は
   │    **NGN offer formats ∩ ext_answer formats の真 intersection**。
   │    NGN offer の出現順を尊重 (RFC 3264 §6.1 "priority order")、
   │    intersection 空なら Err → 呼出側 502 / 488 相当。
   │    rtpmap / fmtp 行は intersection PT に対応する行のみ残す、
   │    WebRTC/ICE/DTLS 由来 attribute は剥がす)
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

**SDP 書換 (Issue #138 / Issue #77)**:

内線が出した Re-INVITE オファ SDP は **NGN へ転送する前に必ず** 初回 INVITE
経路と同じ NGN 制約フィルタを通す (CLAUDE.md §5):

- `force_rewrite_sdp_for_ngn`: `c=`/`o=` IP を eth1 IP (= sent-by) に強制書換
- `restrict_audio_to_pcmu_with_dtmf`: PCMU(0) + telephone-event(101) 以外を削除

これにより内線 UA が LAN private IP + Opus 等 multi-codec を載せた Re-INVITE
を出しても、 NGN レッグへは PCMU only + eth1 IP の sanitized SDP が流れる。
hold/un-hold (`a=sendonly` ↔ `a=sendrecv` 切替) や `a=ptime` 変更は保持される。

`rewrite_rtp_endpoint` は `o=` を書換える際 **RFC 3264 §8 準拠**で
`session_version` を入力値 + 1 する (Issue #77)。 同 Call-ID の Re-INVITE で
sess-version が変わらないとピア (NGN P-CSCF / 内線 UA) は「内容変更なし」と
判定し RTP socket 再 bind や direction 切替を反映しない。 `session_id` は
RFC 4566 §5.2 に従い session 内で不変 (32-bit 超過の場合のみ NGN 互換のため
UNIX epoch 秒へ正規化)。

**Min-SE / Retry-After relay (Issue #138)**:

NGN レッグの Re-INVITE 応答に **Min-SE** / **Retry-After** が乗っていた場合、
sabiden は内線への応答にも同値をコピーする:

- RFC 4028 §7.1 / §10: **422 Session Interval Too Small** には Min-SE 必須。
  内線 UA はこの値で Re-INVITE を再送するため、 中継を欠くと Session-Timer
  更新が失敗し続ける。
- RFC 3261 §20.33: 5xx (+ 404/413/480/486/600/603) の Retry-After は中継推奨。
  内線 UA が無駄な即時 retry を避けて backoff を取れる。

**NGN→sabiden 方向 Re-INVITE (Issue #138 / RFC 3261 §14.2)**:

sabiden は通常 `refresher=uac` で Session-Timer refresh を打つため NGN 由来の
Re-INVITE は稀だが、 NGN 側ピアが起こす hold / un-hold (RFC 3264 §8) や
NGN-initiated session refresh (RFC 4028 §7.4) を内線へ届けるため、 双方向
透過処理を実装:

```
NGN ──Re-INVITE (To-tag=existing)──► sabiden(UAS for NGN)
                                            │
                                            │ NgnInboundHandler::handle_invite
                                            │ → To に tag あり = in-dialog
                                            │ → outbound_forwarder.try_forward_ngn_reinvite
                                            │ → UasEventHandler::handle_ngn_reinvite
                                            │   (registry.lookup_by_ngn で entry を引く)
                                            │
sabiden(UAC for ext) ──Re-INVITE (新 SDP)──► 内線
                                            │
sabiden ◄──200 OK + 新 SDP answer── 内線
NGN ◄──200 OK + 新 SDP answer + Contact── sabiden
NGN ──ACK──► sabiden
```

該当 outbound 通話が registry に無ければ 481 Call/Transaction Does Not Exist
を返す (RFC 3261 §12.2.2)。

内線レッグ Re-INVITE の `send_request` が失敗した場合は失敗種別を分類して
NGN へ伝搬する (Issue #207):

- **408 Request Timeout** (RFC 3261 §13.3.1.1) — 内線 UAS が Timer B/F (= 64 * T1
  = 32s) 満了まで応答しない場合 (= callee silence semantic)。
- **500 Server Internal Error** (RFC 3261 §13.3.1.2) — UDP `send_to` の I/O
  失敗、 トランザクション層停止、 oneshot 中断、 ヘッダ欠落による
  `create_client` 失敗 等の「unexpected condition により request 履行不能」
  系統。

分類は `classify_ext_reinvite_send_error` ヘルパが anyhow error chain を辿って
"transaction timeout" を検出するか否かで行う。

**既知の制限** (Phase R3 で改善):

- RTP ブリッジ媒介時の Re-INVITE SDP 書換 (sabiden 側 RTP port 差替) は
  未実装。 現状は SDP 透過モードでの hold/un-hold / Session-Timer 更新のみ
  正しく動く。 ブリッジ媒介時の Re-INVITE 経路は `prepare_outbound_bridge` /
  `finalize_outbound_bridge` を `handle_ext_reinvite` / `handle_ngn_reinvite`
  にも結線する必要がある (`docs/refactor-plan.md` §1.4 / Phase R3 Negotiator)。
- PRACK / 100rel (RFC 3262)、 UPDATE (RFC 3311) は内線 UAS 側で **未対応**
  (Phase R2)。 NGN 側は Issue #110 で 481 default を返すよう整理済 (「NGN UAS
  メソッド ディスパッチ」セクション参照)。
- NGN 側 Re-INVITE が 4xx/5xx で失敗した場合は同コード + Min-SE / Retry-After
  を内線へ中継する (491 Request Pending を含む RFC 3261 §14.2 glare 解消は
  内線 UA の責務)。

### PWA hold / unhold (Issue #279、 RFC 3264 §8.4 + RFC 3261 §14.1)

PWA UI の「保留」 / 「再開」 ボタンは、 PWA→NGN 発信通話の NGN レッグに対し
Re-INVITE を発行して SDP direction を `a=sendrecv` ↔ `a=sendonly` 切替える
ことで実現する。 内線 UA 起点の Re-INVITE (前節) と違い、 sabiden は **発信
側 UAC** として Re-INVITE を NGN に投げる。

```
PWA browser ─── WS {"type":"hold","call_id":"ngn-call-...."} ──► sabiden
                                                                    │
                                                                    │ webrtc_outbound_active から entry を引く:
                                                                    │   entry あり → last_ngn_offer_sdp を sendrecv→sendonly に書換
                                                                    │   entry 無し → unknown_call_id error を WS 返却
                                                                    │
sabiden(UAC) ──Re-INVITE (CSeq+1、 SDP direction=sendonly)──► NGN
                                                                    │
sabiden ◄──200 OK + answer SDP── NGN
sabiden(UAC) ──ACK──► NGN (RFC 3261 §13.2.2.4: 2xx ACK は新 transaction)
                                                                    │
PWA browser ◄── WS {"type":"held","call_id":"..."} ── sabiden
[NGN 側 UA は sendonly を recvonly として解釈し、 sabiden への RTP 送信を停止]
[sabiden→NGN への RTP は継続 (透過モード、 PWA hold tone は将来 Issue)]
```

**Protocol** (`src/webrtc/signaling.rs::ClientMessage`):

| C→S 方向 | S→C 成功応答 | S→C 失敗応答 (code) |
|---|---|---|
| `{type:"hold", call_id:"<ngn-call-id>"}` | `{type:"held", call_id}` | `unknown_call_id` / `hold_rejected` / `hold_failed` / `hold_unavailable` |
| `{type:"unhold", call_id:"<ngn-call-id>"}` | `{type:"unheld", call_id}` | `unknown_call_id` / `unhold_rejected` / `unhold_failed` / `hold_unavailable` |

`call_id` は **NGN レッグの Call-ID** (= `webrtc_outbound_active` テーブルのキー、
= `UacDialog::dialog().id().call_id`)。 PWA UI は INVITE 確立時に `Answer` で
返ってきた SDP やシグナリングログから得るか、 別途 sabiden が outbound 確立時
に push する将来追加メッセージで取得する (現状の PWA UI は localState で保持)。

**実装責務** (`src/call/orchestrator.rs::UasEventHandler` の `PwaHoldHandler` 実装):

1. `webrtc_outbound_active` から `call_id` (NGN Call-ID) で entry 引き。
2. entry の `last_ngn_offer_sdp` を `apply_audio_direction(&sdp, MediaDirection::SendOnly|SendRecv)` で書換 (`src/sdp/negotiation.rs`)。
3. `UacDialog::send_reinvite(Some(&new_offer))` 呼出 (RFC 3261 §14.1: CSeq 単調増加 / Call-ID / From-tag / To-tag 不変)。
4. 2xx 受領で `entry.hold_state` / `entry.last_ngn_offer_sdp` を更新し WS に `Held` / `Unheld` push。 4xx/5xx は **state 変更せず** `HoldError::Rejected { status }` を返し WS に `Error` push (RFC 3264 §8: 失敗時 state 不変)。

**RTP 取扱**:

- 透過モード (Phase R3 完了前): NGN→PWA の RTP は **NGN 側 UA が** sendonly を recvonly 解釈で停止することを期待する。 sabiden 側で bridge を停止する path は持たない (= sabiden→NGN は引続き silence 相当の RTP を送る)。
- RFC 3264 §8.4 の `sendonly` semantics は「remote UA は sabiden 向けに RTP を送らない」 SHOULD/MUST 規定であり、 sabiden 側送信停止は MAY 動作 (省略可)。
- hold tone 注入 (`a=sendonly` + silence/comfort noise 以外の音源送出) は Issue #279 本 PR スコープ外、 将来 Issue で扱う。

**SDP `o=` session-version** (RFC 4566 §5.2 / RFC 3264 §8):

- 現状の `apply_audio_direction` は **direction 属性だけ** を書換える (= `o=` を触らない)。 厳密には RFC 3264 §8 は「offer が変わったら session-version +1」を要求するが、 NGN P-CSCF は Re-INVITE で session-version が同値でも direction 切替を accept する実機挙動を確認している (Re-INVITE は CSeq 単調増加で in-dialog request を識別する RFC 3261 §14.1 が支配的)。 将来別ピア (Asterisk 等) で互換性問題が出たら `apply_audio_direction` に session-version increment を入れる。

**並行性 / glare**:

- 同一 entry への並行 `set_hold` は `WebRtcOutboundEntry::ngn_dialog` mutex で直列化、 last-writer-wins。
- NGN 側からの逆方向 Re-INVITE (`handle_ngn_reinvite` 経路) との glare は、 NGN がそちらを先に処理して 491 を返した場合 `HoldError::Rejected { status: 491 }` で PWA へ伝搬。 PWA UI 側で RFC 3261 §14.1 retry-after backoff (T1 random) を実装するのが望ましい (本 PR スコープ外、 将来 PWA UI Issue)。

### SMS / RFC 3428 MESSAGE (Issue #299、 `src/call/message_log.rs`)

NGN / 内線 から受信した SIP `MESSAGE` (RFC 3428) 本文を ring buffer に保存し、
PWA UI から SMS タイムライン表示 / SMS 送信を行う機能。 旧実装 (PR #189 / #274)
は `MESSAGE` を一律 `200 OK` で受け流して body を破棄するだけだったが、 SOHO
での SMS 連携用途を満たすため、 受信本文の保存 + PWA 送信経路 + REST API を
追加した。

**受信 (incoming MESSAGE)**:

```
NGN / 内線 UA ──(MESSAGE)──► sabiden
       ▲                       │
       │                       ├─ message_log_extract::sms_from_inbound_message
       │                       │   (Content-Type 判定: text/plain* のみ受理)
       │                       │
       │◄────(200 OK)──────────┤   (RFC 3428 §7: 本文有無に関わらず 200 OK)
                               │
                               └─ MessageLog (Arc<Mutex<VecDeque>>)
                                  direction=Inbound + From/To/body/timestamp
```

- NGN 経路: `src/call/orchestrator.rs::NgnInboundHandler::handle_inbound` の
  `SipMethod::Message` arm で `message_log_clone()` → push。
- 内線経路: `src/sip/uas.rs::ExtensionUas::handle_request` の同 arm で
  `with_message_log` 注入時のみ push。
- text/plain 以外 (`message/cpim`、 `application/im-iscomposing+xml` 等) は
  ring buffer に push しない (= 200 OK のみ返す)。 PWA UI で render できない
  MIME を観測ログに混ぜないため。 CPIM サポートは別 Issue。

**送信 (outgoing MESSAGE、 PWA → NGN / 内線)**:

```
PWA browser
   │ ClientMessage::SendSms { to, body }  (WS)
   ▼
SignalingState (signaling.rs::process_client_message)
   │ to ホワイトリスト検証 ([0-9*#+]{1,32}) + body truncate (≤1024 byte, char_boundary)
   │ PwaSmsHandler trait
   ▼
UasEventHandler::send_sms (orchestrator.rs)
   │ normalize_request_uri_for_ngn (Request-URI = P-CSCF IP+port)
   │ Uac::build_message → Uac::send_message
   ▼
NGN P-CSCF / 内線 UA
   │
   ◄── 200 OK / 4xx / 5xx
       │
       └─ ring buffer に Outbound entry push (注入時のみ)
       └─ ServerMessage::SmsSent { status } / Error{ code:"sms_rejected" }
```

- `Uac::build_message` (`src/sip/uac.rs`): RFC 3428 §4 準拠の MESSAGE を組み立てる。
  - Via に `;rport`、 From に display-name `"Anonymous"` + tag (Asterisk 互換、
    INVITE と同形)、 To には tag を **付けない** (RFC 3261 §8.1.1.2 out-of-dialog)。
  - Content-Type = `text/plain;charset=utf-8` (RFC 3428 §10 IETF default)。
  - Allow に `MESSAGE` を含めて宣言、 `P-Preferred-Identity` / `Privacy` は
    付けない (CLAUDE.md §5 NGN 実機制約)。
- `Uac::send_message`: dialog を作らない (RFC 3428 §7) ので 200 OK を取得して
  単に `SipResponse` を返す (`invite` のような ACK 送信や `Dialog` 確立は無し)。

**REST API**:

- `GET /api/sms/recent?n=20` (Issue #299、 `src/health/mod.rs::sms_recent`):
  ring buffer を新しい順 JSON 配列で返す。 `[sms] enabled = false` のとき 503。
- `POST /api/sms` body `{"to":"117","body":"hi"}`: REST 経由送信。 ホワイトリスト
  違反は 400、 1024 byte 超は 413、 機能無効時は 503、 NGN 非 2xx は 502 +
  status 表示、 sabiden 内部エラーは 500。

**Wiring** (`src/main.rs`):

- 起動時 `[sms].enabled = true` で `Arc<MessageLog>` を作り、
  `NgnInboundHandler::set_message_log` + `UasEventHandler::set_message_log` +
  `ExtensionUas::with_message_log` の 3 経路に注入する。
- `SignalingState::with_pwa_sms` で WS dispatch handler を attach、
  `HealthState::with_sms` で REST endpoint を attach。 すべて同じ `Arc` を共有。

**設定**:

```toml
[sms]
enabled = true       # 既定 false (旧挙動互換)
max_history = 200    # ring buffer 容量 (件)
```

環境変数オーバライド: `SABIDEN_SMS_ENABLED` / `SABIDEN_SMS_MAX_HISTORY`。

**RFC 3428 と sabiden 実装の対応**:

| RFC 3428 §条 | 内容 | sabiden 実装 |
|---|---|---|
| §4 | MESSAGE method の定義、 任意で in-dialog / out-of-dialog | sabiden は out-of-dialog のみ生成 (pager-mode、 RFC 3428 §1)。 受信は dialog 状態を見ない |
| §6 | Header field rules (Contact 等は MUST ではない) | sabiden は `Contact` を広告 (Asterisk 互換) |
| §7 | UAS の応答 (200 OK 受領 ack、 配送保証は無し) | 受信側は 200 OK を返し本文を log に保存 |
| §8 | Aggregate size SHOULD NOT exceed 1300 bytes | body を 1024 byte で truncate (UTF-8 char boundary 保持) |
| §10 | Content-Type default は `text/plain;charset=utf-8` | 送信時は同 Content-Type を付ける。 受信は `text/plain*` のみ store、 それ以外は破棄 (PWA UI に渡せないため) |

## テスト基盤

### E2E SIP testbed (`tests/e2e_call_sequence/`)

`docs/test-strategy.md` §3 「E2E (orchestrator 全部繋ぐ)」の最上層として、
NGN P-CSCF と内線 UA を **両側 UDP socket** で立ち上げ、 sabiden の
**通話シーケンス全体** (INVITE → 100 → 180 → 200 → ACK → BYE → 200) を 1 test
で検証する。 既存 `src/call/inbound_e2e_tests.rs` は `LegInviter` の `ScriptedInviter`
ハーネスで内線レッグを「合成レスポンス返却」 で簡略化していたが、 本 testbed は
両側を生 UDP で駆動するため、 INVITE 経路上の Via / branch / To-tag / 順序保証
の取り違えが pcap でなくとも検出できる。

#### 構成 (Cargo `[[test]]` で `e2e_call_sequence` 名で登録):

| ファイル | 責務 |
|---|---|
| `tests/e2e_call_sequence/mod.rs` | エントリ。 サブモジュール宣言のみ。 |
| `tests/e2e_call_sequence/mock_ngn_carrier.rs` | NTT NGN P-CSCF 模擬。 080 着信風 INVITE 注入 (`Session-Expires` / `Min-SE` / `Supported: timer,100rel` / `Record-Route` / `P-Called-Party-ID` / anonymous From)、 100/180/200 受領、 ACK/BYE 送出。 2xx MUST/SHOULD 一括 assert DSL `expect_invite_2xx_with` (Allow / Date / Session-Expires / Require: timer / Contact / Content-Type / ptime)。 |
| `tests/e2e_call_sequence/mock_extension_ua.rs` | 内線 UA 模擬 (UDP)。 INVITE 受信 → 200 OK + SDP answer / 拒否 (busy / decline) / 内線側 BYE 等。 |
| `tests/e2e_call_sequence/leg_inviter.rs` | `sabiden::call::manager::LegInviter` の **テスト実装**。 sabiden の fork が呼ぶ `invite(target_uri, sdp_offer)` を、 mock UA の UDP addr に **生 SIP INVITE を送信して 200 を待つ** 経路で駆動する。 production 型 (`UacForker` / `Uac`) は mock しない (CLAUDE.md §6.3)。 |
| `tests/e2e_call_sequence/sabiden_harness.rs` | sabiden を in-process に組み立てるエントリ。 `wire_ngn_inbound` で `NgnInboundHandler` を spawn し、 NGN 側 UDP socket addr を返す。 WebRTC / 内線 UAS / RTP ブリッジ実体は持たない (SIP のみ精査)。 |
| `tests/e2e_call_sequence/scenarios.rs` | 初期 4 件のシナリオ + smoke test。 |

#### 初期シナリオ (RFC 引用付き):

| test 名 | 検証対象 RFC |
|---|---|
| `rfc3261_inbound_invite_full_sequence_succeeds` | RFC 3261 §13.2.2.4 / §17.2.1 / §13.3.1.4 / §15.1.1: 100 → 180 → 200 → ACK → BYE → 200 のフル経路。 |
| `rfc4028_inbound_invite_negotiates_session_timer` | RFC 4028 §7.1: 2xx で Session-Expires echo + Require: timer。 |
| `rfc4028_inbound_invite_below_min_se_returns_422` | RFC 4028 §10: SE < Min-SE は 422 + Min-SE で reject。 |
| `rfc3261_inbound_invite_sends_180_ringing_before_200` | RFC 3261 §13.3.1.4 + §12.1.1: 180 が 200 OK より前、 To-tag が同値 (early == confirmed dialog)。 |
| `rfc3264_inbound_invite_sdp_answer_subsets_offer` | RFC 3264 §6.1: PCMU+PCMA offer に対し PCMU のみ answer (intersection / subset)、 ptime echo。 |

#### `expect_invite_2xx_with` の検査範囲 (DSL):

- `Contact` (RFC 3261 §13.3.1.4): UAS が dialog target を確定するため MUST。
- `To` に tag (RFC 3261 §8.2.6.2 / §12.1.1): 2xx で MUST。
- `Allow` (RFC 3261 §20.5): SHOULD on 2xx。
- `Date` (RFC 3261 §20.17): SHOULD on responses。
- `Session-Expires` + `Require: timer` (RFC 4028 §7.1): INVITE に Session-Expires が
  乗っていれば echo MUST。
- `Content-Type: application/sdp` (RFC 3261 §20.15): SDP body 付き応答に MUST。
- `a=ptime:N` (RFC 4566 §6.10): offer 由来 ptime の echo。

`Expect2xx` フラグで個別 SHOULD は opt-out 可能。 sabiden の既存実装が満たして
いない SHOULD (例: `Date` / `Allow`) は audit fix 完了まで opt-out しておき、
fix が入ったら ON に戻して regression を縛る (= 「audit gap の regression
test 雛形」 として機能する)。

#### 設計原則:

- production 型 (`ServerTransaction` / `UAS` / `Uac`) を mock しない (CLAUDE.md §6.3)。
- mock は `tokio::net::UdpSocket` で生 SIP を読み書きする最小実装。
- timeout は `tokio::time` で deterministic に。 RNG (Call-ID / branch / tag) は
  `rand::thread_rng()` で発行するが各 test は独立 socket で独立動作するため
  flakiness は無い。
- WebRTC / 内線 UAS は本 testbed の scope 外。 PWA / RTP ブリッジは別 E2E が担当。

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

### NGN 直収 RTP port allocator (Issue #260 Phase 1-D Final、 PR #264)

NTT NGN P-CSCF / N-ACT は SDP `m=audio <port>` の **parity (even/odd) を入口で
hardcoded check** し、 **奇数 port を 500 Server Internal Error で reject** する。
RFC 3550 §11 は "RTP SHOULD use an even destination port" と SHOULD レベル、
RFC 3605 (`a=rtcp:<port>`) で explicit signal すれば §11 3 段目 "MAY disregard"
と規定されているが、 **NGN 実機 (2026-05-15 falsification test、 16/16 odd→500)
は RFC 3605 を honor しない** ことを実機 evidence で確認済 (memory
`project_ngn_500_FINAL.md`)。

#### sabiden 側の対応

`src/call/orchestrator.rs::bind_ngn_rtp_socket` で **even-only round-robin
allocator** (30000-30998、 `AtomicU32::fetch_add(2)` を span 1000 で modulo + even mask で even guarantee + last-resort
ephemeral も even のみ accept) を採用。 OS ephemeral (`UdpSocket::bind(*, 0)`)
は uniform random で 50% odd を引いていたのが過去 baseline 20-70% success rate
variance の真因。

#### Evidence

- 5/13-5/15 累積 13 pcap 横断、 mixed-parity 44 dial で完全相関:
  - even → 200 OK: 14/14 (100%)
  - odd  → 500   : 30/30 (100%)
  - p-value (null = parity 無関係): `1 / C(44, 14) ≈ 1e-10`
- 5/15 evenfix pcap (production fix deploy 後 10 dial): 全 even (30000-30018)、
  全 200 OK
- 5/15 falsification (odd + a=rtcp:port+1 明示) 16 INVITE: 全 500 = NGN は
  RFC 3605 を honor しない

#### 関連 RFC / 仕様

- RFC 3550 §11 (RTP over Network and Transport Protocols、 even-port SHOULD)
- RFC 3605 §2.1 (SDP `a=rtcp:<port>` 属性、 explicit RTCP port signaling)
- RFC 3261 §21.5.1 (500 Server Internal Error 用途)
- 3GPP TS 24.229 §6.1 (UE shall comply with RFC 3550)
- NTT 公開仕様 ひかり電話タイプ2 第13.1版 (2025-07-01) §2.6 (準拠規格に
  TTC JF-IETF-STD64 = RFC 3550、 ただし RFC 3605 は未掲載)

#### Sequence: NGN outbound INVITE (Phase 1-D 後)

```
sabiden                        NGN P-CSCF
  |                              |
  | bind_ngn_rtp_socket(eth1_ip) | (内部: even port 30000+2n を allocate)
  |                              |
  | INVITE sip:117@p-cscf:5060   |
  |   m=audio 30000 RTP/AVP 0 101| ← even port
  |   a=rtcp:30001               | ← RFC 3605 explicit (modern peer 互換)
  |   ...                        |
  |----------------------------->|
  |       100 Trying             |
  |<-----------------------------|
  |       200 OK                 | ← even なら通る
  |<-----------------------------|
  | ACK ...                      |
  |----------------------------->|
  | RTP (PCMU 20ms)              |
  |<================== bidir ===>|
```

奇数 port では 35-48ms 内に **500 Server Internal Error fast-fail**。 これは
RFC 3261 §21.5.1 の 500 用途 (internal failure) ではなく SDP shape reject、
NTT 自身の最新仕様 §4.2.3 が指す「488 + Warning」 の正しい code を使っていない。
client (sabiden) 側で even-only allocator が唯一の現実解。
