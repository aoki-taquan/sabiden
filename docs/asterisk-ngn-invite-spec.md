# Asterisk 実装レベルで見る NTT NGN 直収 INVITE の正しい構造

## 目的

sabiden が NGN P-CSCF (118.177.125.1) に内線→外線 INVITE を投げた際の
`403 Forbidden` を、推測ではなく **Asterisk のソースと実機 capture** から導いた
仕様で根本解決するためのリファレンス。

このドキュメントの値は (a) Qiita iwamazonjp 記事の実機 REGISTER capture、
(b) Asterisk 18 / master の `chan_sip.c` `res_pjsip_caller_id.c`
`res_pjsip_session.c` の実装、(c) 他の Asterisk + ひかり電話直収報告
(kawabata-eye、note.com/tsq、kmorimoto Qiita) を突き合わせて作成した。

凡例:
- `[Asterisk: file:line]` = Asterisk リポジトリのソースで確認した値・挙動
- `[Qiita iwamazonjp]` = Qiita iwamazonjp 記事の実機 capture
- `[推測]` = ソースで断定できなかった経験的事項

参考にしたソースは末尾 §7 にまとめた。

---

## §1 Qiita iwamazonjp 記事から抽出した発信設定・INVITE 例

URL: <https://qiita.com/iwamazonjp/items/15a66112e2d51ea56d6b>
著者: iwamazonjp、投稿: 2018-02-19。

### 1.1 NGN 環境前提
- 配布される IP は `/30`、デフォルトルートと DNS は配られない。
- SIP サーバアドレス (118.177.125.x) と static route 情報は DHCP で配布。
- v6 は電話に使われていない。
- 認証情報は不要 (= 回線認証ベース、`secret` を sip.conf に書かない)。

### 1.2 sip.conf (chan_sip)

```
register => 0480000000:@ntt-east.ne.jp/0480000000

[ntt]
type=peer
host=118.177.125.zzz
nat=never
canreinvite=no
caninvite=no
session-expires=300
defaultexpiry=3600
dtmfmode=inband
context=outsideline
qualify=yes
```

ポイント:
- `secret` 行 が **無い** (NGN 回線認証なので Asterisk 側に digest credential を持たせる必要が無い)。
- `nat=never` → Via に `;rport` を付けない、Contact を rewrite しない。
- `canreinvite=no` (= `directmedia=no` 相当) → Re-INVITE で RTP の direct メディア交換をしない。
- `session-expires=300` → RFC 4028 Session Timer の interval を 300 秒に固定。
- `defaultexpiry=3600` → REGISTER の Expires を 3600 秒。

### 1.3 extensions.conf (発信前の caller ID 操作)

```
[outsideline]
exten => _0.,1,Set(CALLERID(num)=${MYNUMBER})
exten => _0.,2,Set(CALLERID(name)=${MYNUMBER})
exten => _0.,n,Dial(SIP/${EXTEN}@ntt)
```

ここで CALLERID(num/name) を発信番号 `${MYNUMBER}` に強制してから Dial する。
chan_sip は CALLERID を **From ヘッダの user 部** にそのまま反映する
([Asterisk: chan_sip.c:14467] `connected_id.number.str`)。

### 1.4 実機 REGISTER capture (記事内に貼られている)

```
REGISTER sip:ntt-east.ne.jp SIP/2.0
Via: SIP/2.0/UDP 118.177.125.zzz:5060;branch=z9hG4bK1435901013
From: <sip:0480000000@ntt-east.ne.jp>;tag=2955143756
To: <sip:0480000000@ntt-east.ne.jp>
Call-ID: 688452033@118.177.14.xxx
CSeq: 1 REGISTER
Max-Forwards: 70
Contact: <sip:234590xxxx@[2408:123:bbb:aaaa:face:cafe:beef:1234]>,<sip:652483661@118.177.14.xxx>
Expires: 3600
Allow: INVITE,ACK,BYE,CANCEL,PRACK,UPDATE,MESSAGE
Supported: path
Content-Length: 0
```

注目点 (これは REGISTER だが、**Allow / Supported / Contact の流儀は INVITE でも同じ系統になる**):

| 項目 | 値 | 注 |
|---|---|---|
| Request-URI | `sip:ntt-east.ne.jp` (user 無し) | NGN ドメイン |
| Via | rport 無し、host=自局グローバル IP (P-CSCF が見る IP) | NGN は `;received=` を嫌う [VoIP-Info.jp] |
| From / To URI | `<sip:<phone>@ntt-east.ne.jp>` 揃い、display name **無し** | iwamazonjp は display 無しで通った |
| Call-ID | `<num>@<自局 IPv4>` 形式 | host 部に IPv4 文字列 (Asterisk 慣例) |
| Max-Forwards | `70` | RFC 3261 既定 |
| Contact | **2 個、ipv6 と ipv4 の両方をカンマ連結** | 記事は HGW のキャプチャ。Asterisk 単体だと 1 個でも通る (kmorimoto, kawabata-eye) |
| Allow | `INVITE,ACK,BYE,CANCEL,PRACK,UPDATE,MESSAGE` | **PRACK / UPDATE / MESSAGE まで含む**。OPTIONS / NOTIFY が 入っていない点に注意 |
| Supported | `path` | RFC 3327。`timer` / `replaces` は無い |
| User-Agent | **無い** | HGW (NTT 出荷) は User-Agent を出さないことがある |

### 1.5 INVITE 例 (記事には載っていない)
記事の capture は REGISTER のみで INVITE 全文は無い。INVITE 実例は他の
Asterisk + NGN 直収レポート (kawabata-eye, kmorimoto Qiita) を参照する。

そこから収集できた要点:
- `from_domain=ntt-east.ne.jp` を endpoint に書き、From URI host を `<phone>@ntt-east.ne.jp` に固定する [kmorimoto, kawabata-eye]。
- `send_pai=yes` で **P-Asserted-Identity** を発信のたびに乗せる [kawabata-eye]。
- さらに dialplan で `Set(PJSIP_HEADER(add,P-Preferred-Identity)=<sip:${phone}@ntt-east.ne.jp>)` を併用する記述がある [kawabata-eye]。
- `disable_rport=yes` (PJSIP) で rport 抑制 [tsq]。
- `dtmf_mode=inband, allow=ulaw` [kawabata-eye, tsq]。
- Privacy ヘッダは **明示しない** (chan_sip / pjsip いずれも、発番非通知でない限り出さないのが既定。§2.4 参照)。

---

## §2 Asterisk ソースから抽出した INVITE 構造

参照したのは Asterisk 18 系 (chan_sip.c はこのブランチで残っている) と master
(`channels/chan_pjsip.c`, `res/res_pjsip*`)。

### 2.1 INVITE のヘッダ追加順 (chan_sip)

`transmit_invite()` の構成順 [Asterisk: chan_sip.c:14765 〜 14926]:

1. `init>1` のとき **`initreqprep`** で Via / Max-Forwards / Route / From / To / Contact / Call-ID / CSeq / User-Agent を生成 [chan_sip.c:14420]。
2. `Date:` を追加 [chan_sip.c:14785]。
3. (条件付き) `Replaces` / `Require: replaces` for attended transfer。
4. **Session-Expires / Min-SE** を mode が `originate|accept` のときに追加 [chan_sip.c:14811-14831]。
5. **`Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE`** を追加 [chan_sip.c:14833, 定数 ALLOWED\_METHODS は sip.h:166]。
6. **`add_supported`** で `Supported: replaces[, timer][, path]` を追加 [chan_sip.c:11869]。
7. SIPADDHEADER (dialplan で追加された任意ヘッダ) があれば追加。
8. `SIP_SENDRPID` フラグが立っていれば **`add_rpid`** で RPID または PAI、必要なら Privacy を追加 [chan_sip.c:14880, 13006]。
9. INVITE 限定で `add_diversion` (転送発信時のみ Diversion) [chan_sip.c:14883, 14663]。
10. SDP (`add_sdp`) を本文として追加。

### 2.2 各ヘッダの厳密値

| ヘッダ | 値の組み立て | 出典 |
|---|---|---|
| Request-URI | `fullcontact` があればそれ、無ければ `sip:<username>@<tohost>[:<port>][;user=phone]` | chan_sip.c:14564-14587 |
| Via | `SIP/2.0/UDP <ourip>;branch=z9hG4bK<8桁hex>[;rport]` rport は SIP\_NAT\_FORCE\_RPORT or SIP\_NAT\_RPORT\_PRESENT 時のみ | chan_sip.c:3855-3865 |
| Max-Forwards | `70` (peer ごとに `dialog->maxforwards`、既定 70) | chan_sip.c:11911, sip.h:67 `DEFAULT_MAX_FORWARDS=70` |
| From | `[<displayname>] <sip:<l>@<d>[:port]>;tag=<p->tag>` 数字 only かつ `useragentphone=yes` のとき URI に `;user=phone` | chan_sip.c:14527-14530, 14438-14454 |
| To | `<<p->uri>>` (display 無し)。`SIP_NOTIFY` 以外は theirtag 無し | chan_sip.c:14615 |
| Contact | `<sip:<exten>@<ourip>>` (UDP)、 `<sip:<exten>@<ourip>;transport=tcp>` (TCP) | chan_sip.c:14409-14415 |
| Call-ID | `<rand>@<host>` host = `fromdomain or ourip` | chan_sip.c:8843 |
| CSeq | `<num> INVITE` 単調増加 | chan_sip.c:14629 |
| User-Agent | `global_useragent`、既定 `"Asterisk PBX <version>"` | chan_sip.c:14647, sip.h:233 |
| Allow | **`INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE`** 固定文字列 | chan_sip.c:14833, sip.h:166 |
| Supported | **`replaces`** + `, timer` (SESSION\_TIMER\_MODE\_REFUSE 以外) + `, path` (`SIP_USEPATH`) | chan_sip.c:11874-11876 |
| Session-Expires | `<interval>` (mode=ORIGINATE のとき) `;refresher=` は **付けない**。下層 pjsip が必要なら付ける | chan_sip.c:14824-14827 |
| Min-SE | `<min-se>` (既定 90 秒) | chan_sip.c:14829-14830 |
| Privacy | 既定では **乗らない**。`SIP_SENDRPID_PAI` で発番非通知なら `Privacy: id` | chan_sip.c:13062 |
| P-Asserted-Identity | `SIP_SENDRPID_PAI` のとき `"<name>" <sip:<num>@<fromdomain>>` | chan_sip.c:13073 |
| P-Preferred-Identity | **chan\_sip / pjsip いずれも自動では出さない**。dialplan の `SIPAddHeader` / `PJSIP_HEADER(add,...)` で明示挿入 | (該当生成コード無し。kawabata-eye / kmorimoto の dialplan 例) |

### 2.3 PJSIP (`res_pjsip*`) の差分

PJSIP は ヘッダ生成を pjproject に委譲しているため Asterisk のソース上に
リテラルの `Allow: ...` が出てこないが、`pjsip` 側のデフォルトで以下が
出る (`pjsip-perf` / pjsip ソース調査):

- `Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS` [推測: pjsip 既定。chan_pjsip.c から見える Asterisk 側の上書きは無い]。
- `Supported: replaces, 100rel, timer, norefersub, histinfo, outbound` [推測: pjsip 既定 + Asterisk が `100rel`, `timer` を pjsip module 経由で乗せる]。
- `User-Agent: Asterisk PBX <ver>` [Asterisk: res/res\_pjsip/config\_global.c:34, 738]。
- `Max-Forwards: 70` (pjsip 既定)。
- Session-Expires は session\_timers モジュール (pjproject) が `<sec>;refresher=uac` を付ける。
- From / Contact は `res_pjsip_session.c:1693-1738` の `update_initial_invite` で
  `endpoint->fromuser` / `endpoint->fromdomain` で上書き、または restricted のとき
  `anonymous@anonymous.invalid` に。Contact の user 部は `endpoint->contact_user` か caller-id number。
- `;user=phone` は `endpoint->usereqphone=yes` のとき URI user 部が数字 only なら追加 [Asterisk: res/res\_pjsip.c:924-956 `ast_sip_add_usereqphone`]。Request-URI / Remote-URI / From URI 全てに付く [res/res\_pjsip.c:1043-1046, 1407-1408]。

### 2.4 Privacy / PAI / PPI の自動生成ロジック

Asterisk PJSIP の `res_pjsip_caller_id.c` `add_id_headers` は、
`endpoint->id.send_pai` か `endpoint->id.send_rpid` が立っているときだけ
PAI / RPID ヘッダを乗せる [Asterisk: res/res\_pjsip\_caller\_id.c:541-547]。

`add_pai_header` の Privacy ヘッダ管理 [Asterisk: res/res\_pjsip\_caller\_id.c:316-333]:

```c
if ((ast_party_id_presentation(id) & AST_PRES_RESTRICTION) == AST_PRES_ALLOWED) {
    if (old_privacy) {
        pj_list_erase(old_privacy);          // ← Privacy ヘッダを **削除**
    }
} else if (!old_privacy) {
    /* 値は "id" 固定 (pj_privacy_value = "id") */
    pjsip_msg_add_hdr(tdata->msg, ... "Privacy: id" ...);
}
```

つまり Asterisk が自動で `Privacy: none` を付けることは **無い**。
- 発番通知あり (allowed) → Privacy ヘッダ自体を削除する。
- 発番非通知 (restricted) → `Privacy: id` を追加する。

`P-Preferred-Identity` を Asterisk が自動生成する経路は **存在しない**。
NGN で必要な場合は dialplan で `Set(PJSIP_HEADER(add,P-Preferred-Identity)=<sip:${num}@ntt-east.ne.jp>)`
を呼ぶか、chan\_sip なら `SIPAddHeader(P-Preferred-Identity: <sip:...>)`。

### 2.5 NGN / NTT / Japan に関する Asterisk ソースのコメント

`grep -i 'ntt|hikari|NGN|japan|ja-jp'` を Asterisk リポジトリで実施したが、
**ヒット 0 件**。NGN/ひかり電話のための Asterisk 内ハードコード分岐は無い
([Asterisk: chan_sip.c, res_pjsip*.c 調査結果])。
すべて `sip.conf` / `pjsip.conf` の設定 + dialplan の `SIPAddHeader` /
`PJSIP_HEADER` で対応されている。

---

## §3 sabiden が現状送信している INVITE と Asterisk の差分

sabiden の現状 (src/sip/uac.rs:89 `Uac::build_invite`):

```
INVITE sip:117@ntt-east.ne.jp SIP/2.0
Via: SIP/2.0/UDP <local_addr>;branch=<branch>
Max-Forwards: 70
From: <sip:0191349809@ntt-east.ne.jp>;tag=<tag>
To: <sip:117@ntt-east.ne.jp>
Call-ID: <call-id>
CSeq: <n> INVITE
Contact: <sip:0191349809@<local_addr>>
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY
Supported: timer
Session-Expires: 300;refresher=uac
Min-SE: 90
User-Agent: <user_agent>
P-Preferred-Identity: <sip:0191349809@ntt-east.ne.jp>
Privacy: none
Content-Type: application/sdp
```

差分表 (Asterisk 側を「正」として):

| 項目 | sabiden 現状 | Asterisk (chan_sip / pjsip) | 影響 |
|---|---|---|---|
| **Allow** | `INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY` | `INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE` (chan\_sip 固定) / pjsip 既定では PRACK, UPDATE 含む | NGN は `Allow` を厳しくチェックする説あり。**特に `UPDATE` (RFC 3311) が無いと session timer 更新方式と矛盾するので 403 / 488 を誘発しうる** [推測: NGN 仕様非公開]。iwamazonjp の REGISTER でも `PRACK,UPDATE,MESSAGE` まで含めている |
| **Supported** | `timer` のみ | `replaces, timer, path` (chan\_sip) / `replaces, 100rel, timer, ...` (pjsip) | NGN が `100rel` (PRACK) を要求する場合、Supported に無いと PRACK を送ってこず動作するが、`Supported` の構成検査で 403 になる説あり [推測] |
| **P-Preferred-Identity** | あり (`<sip:0191349809@ntt-east.ne.jp>`) | デフォルト無し。PJSIP では send\_pai / dialplan で **PAI を出すのが本流**。PPI を出すかは選択肢 | NGN 直収では 「PPI を出すと PAI を NGN 側で生成して下流へ」 = NGN の P-Asserted ベースが推奨 [kawabata-eye] |
| **P-Asserted-Identity** | **無し** | PJSIP `send_pai=yes` で `<sip:0191349809@ntt-east.ne.jp>` 形式で出す | NGN は **PAI も同時に来ることを許容** する。NGN によっては PPI ではなく PAI でないと 403 を返す実装が報告 [Asterisk Community 403 Forbidden 議論] |
| **Privacy** | `none` 固定 | 既定で出さない (allowed なら削除、restricted なら `id`) | RFC 3325 では Privacy ヘッダの値は `header / session / user / id / none / critical` のみ有効。`none` 自体は規格的に valid だが、NGN は Privacy ヘッダの **値** をパースして `none` のまま送られると拒否する個体差あり [推測] |
| **From URI** | `<sip:0191349809@ntt-east.ne.jp>` (display 無し) | 同じ (display 無しが既定) | OK |
| **Contact host** | `<local_addr>` = 自局 IP (auto-detect) | `<our_contact>` = 自局 IP (`p->ourip`) | OK。ただし NGN は **「DHCP で配布された /30 のグローバル IP (= P-CSCF から見えるアドレス)」** が host になっている必要あり。NAT 越え HGW なら HGW が rewrite するのが前提 |
| **Contact user** | `0191349809` (= 発信番号) | chan\_sip: `p->exten` (= 着信用 dialed extension)。pjsip: contact\_user か caller-id number | iwamazonjp の REGISTER capture は Contact user に **電話番号と乱数 ID の 2 個**。INVITE では電話番号が普通 |
| **Request-URI** | `sip:117@ntt-east.ne.jp` (user 部に dialed digit) | 同じ | OK |
| **Request-URI に `;user=phone`** | **無い** | `usereqphone=yes` の Asterisk endpoint で **数字 only のとき自動付加** [res_pjsip.c:944-955] | NGN は **`;user=phone` を要求する個体が報告されている** [Asterisk Community]。From URI 側にも付く |
| **`;user=phone` on From URI** | **無い** | `usereqphone=yes` で From / Request-URI / Remote-URI 全てに付く [res_pjsip.c:1043-1046] | 同上 |
| **User-Agent** | `<user_agent>` (config から) | `Asterisk PBX <ver>` | NGN が UA 文字列で振り分けるかは未確認だが、Yamaha RTX / Asterisk の文字列は許可されている経験則あり [kawabata-eye] |
| **`To` / `From` の URI 同一性** | OK (caller=callee=`0191349809@...`) | 同じ | OK |
| **Date** ヘッダ | 無し | chan\_sip は `add_date` で必ず付ける [chan\_sip.c:14785] | 重要度低 (RFC 3261 任意)。pjsip では既定で出さない |
| **Content-Length** | 自動付与 (現状コード未確認) | 必須 (RFC 3261)。SDP body あり時は実バイト数 | UDP では絶対必要 |

---

## §4 sabiden が追加・修正すべきヘッダ群 (最優先)

403 の根本原因仮説を、影響度の高い順に列挙する。

### 4.1 [最優先] Request-URI / From URI に `;user=phone` を付ける

NGN は電話番号を扱う SIP UA に対して `;user=phone` を厳しく要求する個体が
報告されている [Asterisk Community 403 Forbidden 議論]。
PJSIP の `usereqphone=yes` 相当の挙動を sabiden にも実装する。

`build_invite` で:
```text
INVITE sip:117@ntt-east.ne.jp;user=phone SIP/2.0
From: <sip:0191349809@ntt-east.ne.jp;user=phone>;tag=...
```

判定: From URI の user 部が空文字でなく、最初の文字が `+` または `0..9` の
うちのみ → `;user=phone` を URI param に追加 (`<...>` の **内側、`>` の前**)。
Asterisk PJSIP の `ast_sip_add_usereqphone` が full reference 実装。

### 4.2 [最優先] P-Asserted-Identity を併送する

PPI **だけ** だと NGN によっては 403 を返す実装がある。Asterisk が
`send_pai=yes` で送る形式 ([Asterisk: res_pjsip_caller_id.c:342-385]) を真似て
**PAI を必ず追加**:

```text
P-Asserted-Identity: <sip:0191349809@ntt-east.ne.jp>
```

display name が無いときは `"" <...>` ではなく単に `<...>`。
PPI と PAI を **両方** 載せても RFC 違反にならない (両方は推奨されないが、
Asterisk + dialplan 連携の現場では併用例が多数 [kawabata-eye, kmorimoto])。

### 4.3 [優先] Privacy: none を **やめる** (削るか、他の値にする)

Asterisk が自動で出す Privacy は `id` (restricted のとき) のみ。
発番通知ありの normal case では **Privacy ヘッダ自体を出さない** [Asterisk: res_pjsip_caller_id.c:316-333]。

sabiden の `Privacy: none` 固定は、たまたま RFC 3323 §4.2 で valid
(`none` はキーワード) だが、NGN の Privacy ヘッダの実装が **「値を見て none を rejected list に入れている」** 可能性がある (実機 capture が無く憶測の域)。

→ Privacy ヘッダは **発番通知時は完全に削除** が安全。
   発番非通知時のみ `Privacy: id` を追加する Asterisk 流に揃える。

### 4.4 [優先] Allow を Asterisk と等価に揃える

```
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
```

または、`UPDATE` を含めた pjsip 流:

```
Allow: INVITE, ACK, CANCEL, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, OPTIONS, MESSAGE, PRACK, UPDATE
```

**特に `UPDATE` を含める** → Session Timer の更新方式として UPDATE を使う場合、
`Allow` に UPDATE が無いと NGN は対応していないと判断する [RFC 4028 §7.4]。

### 4.5 [優先] Supported を `replaces, timer` (最低限 + 互換性) に拡張

```
Supported: replaces, timer
```

(`100rel` も後で検討する余地あり。`path` は REGISTER でのみ意味があるため
INVITE で乗せる必要は無い)。

### 4.6 [中] Contact の host が「DHCP で実際に配布された /30 IP」 になっているか確認

sabiden は `local_addr` を auto-detect しているが、これが **NGN P-CSCF
から見える同じグローバル IP** であることは必須 ([Asterisk: chan_sip.c:14409]
`p->ourip` を直接使う = 同じ前提)。NIC の primary IP と Contact host が
ズレていると 403 / 488 を誘発する。

sabiden の現状コードでは `expect_local_addr()` の結果がそのまま Contact に
入るので、`server_addr` 宛のダミー UDP socket 経由で取れる送信元 IP が
正しい /30 lease と一致しているか起動時に assert すること。

### 4.7 [低] User-Agent を `Asterisk PBX <ver>` 風にする実験

NGN 個体が UA 文字列で振り分けるかは未確認だが、`hikari-sip/0.1` よりは
`Asterisk PBX 18.x.x` の方が NGN の互換性 DB にヒットする可能性がある
[推測]。403 が PPI/PAI/user=phone の修正で解消しなかった場合の二次手段。

### 4.8 [低] Date ヘッダ

chan\_sip は `add_date` で `Date:` を必ず付ける [chan\_sip.c:14785] が、
RFC 3261 §20.17 では任意。NGN がこれを必要とする報告は見つけられなかった
ので、まず付けずに様子を見る。

---

## §5 `Uac::build_invite` を Asterisk と等価にする変更提案

src/sip/uac.rs:89 `build_invite` の修正案 (実装はしない、提案のみ)。

### 5.1 シグネチャ拡張

`UacConfig` に以下を追加 (config.toml 経由で構成):
```rust
pub struct UacConfig {
    // 既存...
    /// `;user=phone` を URI に付与する (NGN 必須)
    pub use_phone_uri: bool,        // 既定 true
    /// PAI / PPI に出すドメイン (空文字 = local_uri と同じ)
    pub asserted_identity_domain: String,
}
```

### 5.2 ヘルパ関数

`utils.rs` に追加:
```rust
/// URI が "sip:digits@host..." 形式で digits 部分が数字 only なら
/// "sip:digits@host;user=phone..." に書き換える (Asterisk PJSIP
/// `ast_sip_add_usereqphone` 互換)。"<...>" で囲まれていたら剥がして付け直す。
pub fn add_user_eq_phone(uri: &str) -> String { ... }
```

### 5.3 build_invite の差し替え

```rust
let request_uri = if cfg.use_phone_uri {
    add_user_eq_phone(target_uri)
} else {
    target_uri.to_string()
};
let from_uri = if cfg.use_phone_uri {
    add_user_eq_phone(self.config.local_addr_of_record())
} else {
    self.config.local_addr_of_record().to_string()
};

let mut req = SipRequest::new(SipMethod::Invite, request_uri.clone());
req.headers.set("Via", format!("SIP/2.0/UDP {};branch={}", self.config.sent_by(), branch));
req.headers.set("Max-Forwards", "70");
req.headers.set("From", format!("<{}>;tag={}", from_uri, local_tag));
req.headers.set("To", format!("<{}>", request_uri));   // user=phone も同じ
req.headers.set("Call-ID", &call_id);
req.headers.set("CSeq", format!("{} INVITE", cseq));
req.headers.set("Contact", format!("<{}>", self.config.contact_uri()));

// Allow / Supported は Asterisk と等価に
req.headers.set("Allow",
    "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE, UPDATE");
req.headers.set("Supported", "replaces, timer");

req.headers.set("Session-Expires", format!("{};refresher=uac", session_expires));
req.headers.set("Min-SE", MIN_SE.to_string());
req.headers.set("User-Agent", &self.config.user_agent);

// PAI と PPI の両方を載せる (NGN 互換性のため)
let pai_uri = format!("<sip:{}@{}>", phone_number, asserted_domain);
req.headers.set("P-Asserted-Identity", &pai_uri);
req.headers.set("P-Preferred-Identity", &pai_uri);

// Privacy は **設定しない** (デフォルトで出さない)。
// もし発番非通知の発信が来たら "Privacy: id" を追加する分岐をここに。
// req.headers.set("Privacy", "none");  // ← 削除する
```

### 5.4 Privacy 削除 / 条件付与

現状の `req.headers.set("Privacy", "none")` を削除し、将来の anonymous 発信
対応のため:
```rust
if anonymous_caller {
    req.headers.set("Privacy", "id");
    // From URI も "<sip:anonymous@anonymous.invalid>" に置換 (Asterisk 流)
}
```

### 5.5 テストの更新

既存の `invite_includes_p_preferred_identity_and_privacy_for_ngn` test は
`Privacy: none` を assert しているので、`Privacy` ヘッダが **無い** ことを
assert する形に書き換える。代わりに PAI / PPI が両方出ていることと
`;user=phone` が URI に付いていることを assert する。

### 5.6 段階的ロールアウト

PR を分けて順に検証:
1. **PR-A**: `;user=phone` 付与 + Allow/Supported 拡張。ここで 403 が消えるか。
2. **PR-B**: PAI 追加 / Privacy 削除。
3. **PR-C**: Privacy の条件分岐 (anonymous caller 対応)。

各段階で実機 (118.177.125.1) に向けて INVITE して 403 → 200 (or 18x) の遷移
ログを取り、`docs/asterisk-ngn-invite-spec.md` の §3 表を更新する。

---

## §6 残った不明点 (Asterisk ソースを見ても判らない NGN 専用挙動)

1. **403 の真の trigger**
   NGN P-CSCF (118.177.125.1) は 403 に Reason header を **付けない**。
   Asterisk のソースに NGN 固有分岐は無く、「どのヘッダの何が原因で 403 か」
   を特定するには NGN 側のログを見るしかないが、NTT は提供しない。
   → §4 の修正を **段階的に** 当て、403 → 200 の境界を観測するしかない。

2. **NGN が要求する `Supported` の最低集合**
   `path` は REGISTER 用、`100rel` は PRACK 必須要件、`timer` は Session
   Timer 必須要件。どれが必須か Asterisk ソースには書いて無い (NGN 仕様書
   が非公開のため)。経験則的に `timer` だけで通っている事例 (iwamazonjp)
   と `replaces, timer` 必須の事例 (kawabata-eye) が混在する。

3. **NGN が要求する `Allow` の最低集合**
   iwamazonjp の REGISTER は `PRACK, UPDATE, MESSAGE` を含むが、INVITE で
   何が必要かは個体差あり。OPTIONS / NOTIFY を必須とする報告は無いが、
   排除する根拠も無い。

4. **`;user=phone` がどの URI に必要か**
   - Request-URI: 必須説が強い
   - From URI: pjsip は `usereqphone=yes` で全 URI に乗せる
   - Contact URI: 乗らない
   sabiden では Request-URI と From URI に乗せ、Contact には付けない方針が
   Asterisk PJSIP 互換。

5. **Privacy ヘッダの存在自体を NGN が要求するか**
   Asterisk PJSIP は **発番通知時は Privacy を出さない** が、現状の sabiden の
   コメント「NGN は Privacy ヘッダの存在自体を要求するケースあり」 は
   ソース根拠が見つからない。**この仮説は誤りの可能性がある**。
   Privacy を削除するパターンを試して 403 が解消すれば Privacy 不要と確認できる。

6. **NGN の Re-INVITE 時の Contact 期待値**
   sabiden の `Re-INVITE` (Session Timer 更新) で Contact に何を入れるかは
   このドキュメントの範囲外だが、初回 INVITE で確立した Record-Route が
   無いとき Contact が rewrite されるかは Asterisk のソース調査では
   特定できなかった。

7. **NGN 上の SDP 制約**
   PCMU only / RTPMap / PT 番号などは別途 NGN 仕様書 (NTT 東日本 第三者接続
   インタフェース仕様書) が要る。本ドキュメントでは触れない。

---

## §7 参考にしたソース一覧

- **Qiita / iwamazonjp** 「NTT東のIP電話網にasteriskで直接Registした話」
  <https://qiita.com/iwamazonjp/items/15a66112e2d51ea56d6b> (2018-02-19)
  ローカル: `/tmp/sabiden-dev/iwamazonjp.html`
- **Qiita / kmorimoto** 「NTT光ネクストのひかり電話へAsteriskを直接接続する」
  <https://qiita.com/kmorimoto/items/d99cd9edcf7436eea7cc>
- **kawabata-eye** 「Asterisk / FreePBX に NTT西日本のひかり電話を直接収容」
  <https://kawabata-eye.jp/ntt%E8%A5%BF%E6%97%A5%E6%9C%AC%E3%81%AE%E3%81%B2%E3%81%8B%E3%82%8A%E9%9B%BB%E8%A9%B1%E3%82%92%E7%9B%B4%E6%8E%A5%E5%8F%8E%E5%AE%B9/>
- **note.com / Takao Takahashi (tsq)** 「Asterisk+RTXでひかり電話直収のはなし」
  <https://note.com/tsq/n/n54ffb5edf451>
- **VoIP-Info.jp** 「ひかり電話 プロトコル」
  <https://www.voip-info.jp/index.php/%E3%81%B2%E3%81%8B%E3%82%8A%E9%9B%BB%E8%A9%B1_%E3%83%97%E3%83%AD%E3%83%88%E3%82%B3%E3%83%AB>
- **Asterisk source (asterisk-18 branch)**
  - `channels/chan_sip.c` (`transmit_invite`, `initreqprep`, `add_supported`,
    `add_rpid`, `add_diversion`, `build_via`, `build_contact`)
  - `channels/sip/include/sip.h` (`ALLOWED_METHODS`, `DEFAULT_USERAGENT`,
    `DEFAULT_MAX_FORWARDS`)
- **Asterisk source (master)**
  - `res/res_pjsip.c` (`ast_sip_add_usereqphone`, `create_in_dialog_request`,
    `create_out_of_dialog_request`)
  - `res/res_pjsip_caller_id.c` (`add_pai_header`, `add_privacy_header`,
    `add_rpid_header`, `add_id_headers`)
  - `res/res_pjsip_session.c` (`update_initial_invite` 周辺の From / Contact
    生成)
  - `res/res_pjsip/config_global.c` (default user_agent)
  - `res/res_pjsip/pjsip_global_headers.c` (User-Agent module 登録)
- **Asterisk Community 403 Forbidden / NEC PABX 403 議論** 検索結果より
  <https://community.asterisk.org/t/403-forbidden-on-outbound-invite/84743>
  <https://community.asterisk.org/t/pjsip-registering-to-nec-pabx-fails-with-403-works-with-chan-sip/70539>

---

## 付録 A: Asterisk ALLOWED_METHODS の正確な定義

```c
/* channels/sip/include/sip.h:166 */
#define ALLOWED_METHODS "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE"
```

(注: `UPDATE` は **chan\_sip の ALLOWED\_METHODS には含まれていない**。
chan\_sip は session timer 更新を Re-INVITE で行う前提のため。pjsip は
pjproject 側がデフォルトで UPDATE を Allow に含める。)

## 付録 B: Asterisk DEFAULT_USERAGENT の正確な定義

```c
/* channels/sip/include/sip.h:233 */
#define DEFAULT_USERAGENT "Asterisk PBX"
/* 起動時に "Asterisk PBX <version>" に組み立てられる
   chan_sip.c:32696, res/res_pjsip/config_global.c:738 */
```

## 付録 C: chan_sip 流の Privacy / PAI 生成擬似コード

```c
/* chan_sip.c add_rpid() L13006 - 発番通知制御 */
if (!SIP_SENDRPID) return 0;
if (presentation == ALLOWED) {
    /* 通常: Privacy ヘッダは出さない / RPID/PAI は実値を載せる */
    add_header(req, "P-Asserted-Identity", "\"<name>\" <sip:<num>@<fromdomain>>");
} else if (presentation == RESTRICTED) {
    /* 非通知: Privacy: id を出して PAI は anonymous で出す */
    add_header(req, "Privacy", "id");
    add_header(req, "P-Asserted-Identity", "\"Anonymous\" <sip:anonymous@anonymous.invalid>");
}
/* "Privacy: none" を出す経路は存在しない */
```

## 付録 D: pjsip 流 user=phone 生成

```c
/* res/res_pjsip.c:924-956 */
void ast_sip_add_usereqphone(endpoint, pool, uri) {
    if (!endpoint->usereqphone) return;
    if (!is_sip_or_sips_uri(uri)) return;
    /* user 部が空なら何もしない */
    if (!user_len) return;
    /* "+" で始まれば飛ばす */
    /* 残り全文字が AST_DIGIT_ANY (0-9, ABCD#*) のうちの 0-9 系 → user_param = "phone" */
    /* 1 文字でも非数字なら付けない */
    sip_uri->user_param = "phone";
}
/* 呼ばれる箇所:
   - res_pjsip.c:1043-1046 (create_in_dialog_request)
   - res_pjsip.c:1407-1408 (out-of-dialog request の Request-URI)
   - res_pjsip_session.c:1717, 1738 (saved_from_hdr / dlg_info の From URI)
*/
```
