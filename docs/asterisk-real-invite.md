# Asterisk 実機で取得した NGN 直収 INVITE の解析

NTT NGN 直収回線で、内線→NGN INVITE が `403 Forbidden` で蹴られる sabiden の不具合
解明のため、同一 eth1 (HGW MAC spoof 済) で **Asterisk 20.6** を立て、`117` (時報) へ
発信して INVITE / 200 OK / ACK / RTP / BYE までフルでキャプチャした。

**結果: Asterisk からの発信は 200 OK で成立。RTP も双方向に流れた。**
`117` の応答音声は確認していない (Echo に流したのみ) が、SIP / RTP の
シグナリングは正常終了している。

すべて 2026-05-09 (UTC) に同一線で実施。

- pcap (成功): `/tmp/sabiden-dev/asterisk-ngn.pcap` (= `asterisk-ngn-3.pcap`)
- pcap (失敗 / port 5070): `/tmp/sabiden-dev/asterisk-ngn-2.pcap`
- 抽出済テキスト: `/tmp/sabiden-dev/asterisk-sip-text.txt`

## §1 セットアップ手順 (再現性ある形)

### 1.1 前提

- eth1 が NGN 直収側 (HGW WAN MAC `2C:FF:65:3E:67:86` を spoof 済み)
- eth1 に DHCPv4 で `118.177.72.242/30` を取得済み、P-CSCF 経路あり
  ```
  118.177.72.240/30 dev eth1 proto kernel scope link src 118.177.72.242
  118.177.125.1 via 118.177.72.241 dev eth1
  ```
- 自分の電話番号: `0191349809` / ドメイン: `ntt-east.ne.jp` / 認証なし

### 1.2 Asterisk インストール

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y asterisk asterisk-modules
# Ubuntu 24.04 の標準パッケージで Asterisk 20.6.0 が入る
asterisk -V
```

### 1.3 sabiden を停止 (5060 を空ける)

NGN は **送信元 UDP ポートが 5060 でなければ INVITE に応答しない** ことが
本検証で判明した (§3 参照)。sabiden を完全停止して 5060 を Asterisk に渡す。

```bash
sudo pkill -9 -f 'sabiden register'
sudo ss -ulnp | grep -E ':(5060|5070)'   # 何も出ないことを確認
```

### 1.4 Asterisk 設定

`/etc/asterisk/pjsip.conf` (バックアップを `pjsip.conf.orig.bak` に取った):

```ini
[transport-udp]
type=transport
protocol=udp
bind=118.177.72.242:5060
external_media_address=118.177.72.242
external_signaling_address=118.177.72.242

[ngn-endpoint]
type=endpoint
transport=transport-udp
context=outbound-ngn
disallow=all
allow=ulaw
direct_media=no
from_user=0191349809
from_domain=ntt-east.ne.jp
aors=ngn-aor
send_pai=yes
send_rpid=no
trust_id_outbound=yes
identify_by=ip

[ngn-aor]
type=aor
contact=sip:118.177.125.1:5060

[ngn-identify]
type=identify
endpoint=ngn-endpoint
match=118.177.125.1

[ngn-reg]
type=registration
transport=transport-udp
server_uri=sip:ntt-east.ne.jp
client_uri=sip:0191349809@ntt-east.ne.jp
contact_user=0191349809
expiration=3600
auth_rejection_permanent=no
retry_interval=30
line=yes
endpoint=ngn-endpoint
```

注意点:

- `outbound_auth=` を空文字で書くと `res_pjsip_outbound_registration` がパースに
  失敗するので、**行ごと省略** する (NGN は認証無し)。
- `endpoint=ngn-endpoint` を指定するなら **`line=yes` 必須** (Asterisk が
  「endpoint without enabling line support」で reject する)。

`/etc/asterisk/extensions.conf`:

```ini
[general]
static=yes
writeprotect=no

[outbound-ngn]
exten => _X.,1,NoOp(NGN dial: ${EXTEN})
 same => n,Set(PJSIP_HEADER(add,P-Preferred-Identity)=<sip:0191349809@ntt-east.ne.jp>)
 same => n,Dial(PJSIP/${EXTEN}@ngn-endpoint,30)
 same => n,Hangup()

[default]
exten => _X.,1,Goto(outbound-ngn,${EXTEN},1)
```

### 1.5 起動・キャプチャ・発信

```bash
# 1. tcpdump をバックグラウンドで起動
sudo tcpdump -i eth1 -nn -s0 -w /tmp/sabiden-dev/asterisk-ngn.pcap \
    'host 118.177.125.1' &

# 2. Asterisk 起動
sudo systemctl restart asterisk
sleep 4
sudo asterisk -rx "pjsip show transports"     # 118.177.72.242:5060 を確認

# 3. 117 (時報) へ発信。Echo に流して短時間で切る
sudo asterisk -rx "channel originate Local/117@outbound-ngn application Echo"
sleep 5
sudo asterisk -rx "channel request hangup all"

# 4. キャプチャ停止
sudo pkill -INT -f 'tcpdump.*asterisk-ngn'
```

### 1.6 確認コマンド

```bash
sudo asterisk -rx "pjsip show endpoints"
sudo asterisk -rx "pjsip show registrations"
sudo asterisk -rx "pjsip set logger on"
sudo asterisk -rx "pjsip show history"
sudo asterisk -rx "pjsip show history entry 0"
```

## §2 Asterisk が NGN に出した実 INVITE (キャプチャ全文)

`/tmp/sabiden-dev/asterisk-ngn.pcap` を `tcpdump -A` で展開した SIP メッセージの
ヘッダ部分。

```
INVITE sip:117@118.177.125.1:5060 SIP/2.0
Via: SIP/2.0/UDP 118.177.72.242:5060;rport;branch=z9hG4bKPjac6a0a13-425d-4c85-b117-1d893768383b
From: "Anonymous" <sip:0191349809@ntt-east.ne.jp>;tag=7e826d40-db17-4666-85e5-7a580b962429
To: <sip:117@118.177.125.1>
Contact: <sip:0191349809@118.177.72.242:5060>
Call-ID: 2fe2b037-4e09-4dbb-9f2a-87984af6a866
CSeq: 3424 INVITE
Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER
Supported: 100rel, timer, replaces, norefersub, histinfo
Session-Expires: 1800
Min-SE: 90
Max-Forwards: 70
User-Agent: Asterisk PBX 20.6.0~dfsg+~cs6.13.40431414-2build5
Content-Type: application/sdp
Content-Length:   239

v=0
o=- 397958033 397958033 IN IP4 118.177.72.242
s=Asterisk
c=IN IP4 118.177.72.242
t=0 0
m=audio 18082 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=ptime:20
a=maxptime:140
a=sendrecv
```

注意:

- `P-Preferred-Identity` は extensions.conf で `Set(PJSIP_HEADER(add,...))` を
  書いていたが、`Local/...,application Echo` で原チャネルが `Local` なので
  `Local/...;2` の Dial 時には Local チャネル側のヘッダを継承せず実際には
  **送信されていない**。それでも 200 OK が返ってきたので、**NGN 側は
  `P-Preferred-Identity` を必須としていない** (これは sabiden の現状実装が
  PPI / Privacy を入れても 403 で蹴られていた事実とも整合)。

## §3 NGN からの応答

### 3.1 成功シーケンス (port 5060 で送信)

```
06:25:40.012  118.177.72.242:5060 -> 118.177.125.1:5060  INVITE sip:117@118.177.125.1:5060
06:25:40.019  118.177.125.1:5060  -> 118.177.72.242:5060  100 Trying
06:25:40.121  118.177.125.1:5060  -> 118.177.72.242:5060  200 OK
06:25:40.122  118.177.72.242:5060 -> 118.177.125.1:5060  ACK sip:12455@118.177.125.1:5060
06:25:40.144                                              ←→ RTP PCMU 双方向 (約6秒)
06:25:46.036  118.177.72.242:5060 -> 118.177.125.1:5060  BYE
06:25:46.044  118.177.125.1:5060  -> 118.177.72.242:5060  200 OK (BYE)
```

200 OK のヘッダ:

```
SIP/2.0 200 OK
v: SIP/2.0/UDP 118.177.72.242:5060;branch=...;rport
i: 2fe2b037-4e09-4dbb-9f2a-87984af6a866
CSeq: 3424 INVITE
x: 300;refresher=uas             ; Session-Expires
Require: timer
Record-Route: <sip:118.177.125.1:5060;lr>
t: <sip:117@118.177.125.1>;tag=B76D2E
f: "Anonymous"<sip:0191349809@ntt-east.ne.jp>;tag=...
m: <sip:12455@118.177.125.1:5060>
Allow: INVITE,ACK,BYE,CANCEL,UPDATE
k: 100rel                        ; Supported
c: application/sdp
l: 184

v=0
o=- 85704 85704 IN IP4 118.177.125.1
s=-
c=IN IP4 118.177.125.1
t=0 0
m=audio 24252 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000/1
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
```

### 3.2 失敗シーケンス (port 5070 で送信、§参考)

最初は Asterisk transport を `bind=118.177.72.242:5070` で動かした (sabiden が
5060 を掴んでいたため)。同じ INVITE 内容にも関わらず:

```
06:24:13.314  118.177.72.242:5070 -> 118.177.125.1:5060  INVITE
06:24:13.321  118.177.125.1:5060  -> 118.177.72.242:5060  100 Trying  ← 5060 へ返ってくる
06:24:13.325  118.177.125.1:5060  -> 118.177.72.242:5060  403 Forbidden
```

- NGN は **応答先を Via の `:5070` ではなく、UDP ソース確認なしで自分が認識して
  いる port (この線では 5060)** へ送る。これは P-CSCF の挙動として
  Via ヘッダの `received`/`rport` を無視しており、回線単位で「何番に
  送り返すか」を保持しているように見える。
- 結果として 403 が返るが、応答が listening していない別ポートへ届くため
  Asterisk は到達不能、再送ループに陥った。

→ **NGN 直収では UDP ソースポートを 5060 に固定するのが必須条件**。

403 Forbidden 自体のヘッダは `Reason:` ヘッダ無し、`Content-Length: 0`。
追加情報なし。本文に NGN ベンダ依存の `Warning:` 等も無い。

## §4 sabiden 現状 INVITE との差分表

sabiden の最新 INVITE トレース
(`/tmp/sabiden-dev/trace/1778307228864_sent_INVITE_06f1d70fa02f0d48_hikari-sip.txt`):

```
INVITE sip:117@ntt-east.ne.jp SIP/2.0                                         ★
Via: SIP/2.0/UDP 118.177.72.242:5060;branch=z9hG4bK6e43a0fc8795c582            ★
Max-Forwards: 70
From: <sip:0191349809@ntt-east.ne.jp>;tag=6723e455
To: <sip:117@ntt-east.ne.jp>                                                   ★
Call-ID: 06f1d70fa02f0d48@hikari-sip
CSeq: 1 INVITE
Contact: <sip:0191349809@118.177.72.242:5060>
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY
Supported: timer
Session-Expires: 300;refresher=uac
Min-SE: 90
User-Agent: sabiden/0.1
P-Preferred-Identity: <sip:0191349809@ntt-east.ne.jp>                          ★
privacy: none                                                                  ★
Content-Type: application/sdp
Content-Length: 148

v=0
o=iphone 2246 1745 IN IP4 192.168.30.162                                       ★ private IP 漏洩
s=Talk
c=IN IP4 192.168.30.162                                                        ★ private IP 漏洩
t=0 0
m=audio 55120 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=rtcp:61858
```

| 項目 | Asterisk (200 OK) | sabiden (403) | 差分の重要度 |
| --- | --- | --- | --- |
| Request-URI host | `118.177.125.1:5060` (P-CSCF IP) | `ntt-east.ne.jp` (NGN ドメイン) | **致命的候補 1** |
| To URI host | `118.177.125.1` | `ntt-east.ne.jp` | **致命的候補 1** (Request-URI と連動) |
| Via に `rport` | あり | なし | 中 (rport 無しでも 200 OK は出る、ただし NAT 想定では推奨) |
| Via branch prefix | `z9hG4bKPj...` (Asterisk 流儀) | `z9hG4bK...` (RFC 3261 標準) | 影響なし |
| From display-name | `"Anonymous"` | なし | 影響なし (sabiden 側は明示しないが NGN は許容している) |
| P-Preferred-Identity | **なし** | あり | **無くても 200 OK が返る = 必須ではない** |
| Privacy | なし | `privacy: none` (小文字) | **必須ではない** |
| Allow | `OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER` | `INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, NOTIFY` | 影響なし |
| Supported | `100rel, timer, replaces, norefersub, histinfo` | `timer` | 影響なし |
| Session-Expires | `1800` (refresher 指定なし) | `300;refresher=uac` | 影響なし (Asterisk のは pjsip 既定値) |
| User-Agent | `Asterisk PBX 20.6.0~...` | `sabiden/0.1` | 影響なし |
| SDP `o=` username | `-` | `iphone` | 軽微 |
| SDP `o=` IP | `118.177.72.242` (eth1, NGN 側) | `192.168.30.162` (内線 LAN, 私設 IP) | **致命的候補 2** |
| SDP `c=` IP | `118.177.72.242` | `192.168.30.162` | **致命的候補 2** |
| SDP `m=audio` port | `18082` (Asterisk が確保) | `55120` (内線 UA が広告) | LAN 側 port を NGN 側 IP で広告するのは無効 |
| SDP `m=` フォーマット | `0 101` (PCMU + telephone-event) | `0` (PCMU のみ) | 影響なし |
| 送信元 UDP port | `5060` | `5060` | OK |

★ = sabiden で要修正候補

## §5 sabiden の `Uac::build_invite` に追加・修正すべき項目

優先度順:

### 5.1 [致命] Request-URI の host を NGN ドメインから P-CSCF IP に変更

`src/call/orchestrator.rs` の `normalize_request_uri_for_ngn`
(L539〜) は今、内線が出した URI が LAN IP の場合 `ngn_domain`
(`ntt-east.ne.jp`) に書き換えている。**これを `ngn_server_host`
(`118.177.125.1` + port `5060`) に書き換える** べき。

具体策:

```rust
fn normalize_request_uri_for_ngn(req_uri: &str, ngn_domain: &str, ngn_server_host: &str, ngn_server_port: u16) -> String {
    let Some(parts) = parse_sip_uri(req_uri) else {
        return req_uri.to_string();
    };
    let host_lower = parts.host.to_ascii_lowercase();
    let domain_lower = ngn_domain.to_ascii_lowercase();
    let server_lower = ngn_server_host.to_ascii_lowercase();
    if host_lower == server_lower {
        return req_uri.to_string();
    }
    // ドメイン宛も含め、すべて P-CSCF IP:port に正規化する
    // (NGN は Request-URI host に IP を要求する)
    rebuild_sip_uri(parts.scheme, parts.user, ngn_server_host, Some(&ngn_server_port.to_string()))
}
```

呼び出し側 (orchestrator L882) は `self.ngn_uac.server_addr()` から host と
port を渡す。`Uac::build_invite` 内の To ヘッダは target から組み立てる
ため、これだけで Request-URI と To が両方 `sip:117@118.177.125.1:5060` /
`<sip:117@118.177.125.1>` になる。

注: `To` には port を含めず host だけを書くのが Asterisk 流儀 (`<sip:117@118.177.125.1>`)。
`build_invite` は現在 `To: <{target}>` をそのまま使うので、Request-URI
には port を残しつつ To は host のみのバリアントが必要なら、To を別計算する。
ただし NGN 200 OK は Request-URI と一致する `;5060` を含む URI を `f:` に
echo back していたので、To 側に port を残しても問題ないと推測される (要検証)。

### 5.2 [致命] SDP の `c=` / `o=` の IP と `m=` audio port を NGN 側に書き換え

orchestrator は `prepare_outbound_bridge` で RTP ブリッジ用 socket を確保し
`sdp_for_ngn` を作っているが、トレースを見ると 192.168.30.162 (内線の LAN IP)
が NGN への INVITE にそのまま乗っている。**`prepare_outbound_bridge` の戻り
SDP がきちんと NGN 側 IP/port を反映しているか要検証**。

対処 (検証ポイント):

- `crate::sdp::builder` 系の関数で `c=` / `o=` を `eth1` IP
  (`118.177.72.242`) に書き換える
- `m=audio <port>` を sabiden が NGN 側に open した RTP socket port に書き換え
- これは既存実装で意図はされているが、現状トレースでは適用されていない様子。
  `prepare_outbound_bridge` が `Ok(None)` を返すケース (call_manager 未注入時等)
  に SDP 透過するパスが効いている可能性が高い。NGN モードでは透過パスを
  禁止するか、最低限 IP/port だけは強制的に書き換える。

### 5.3 [推奨] P-Preferred-Identity / Privacy を削除

sabiden は現状以下を入れているが、**Asterisk は両方無しで 200 OK を取得した**
ため、これらが原因で蹴られていた可能性は低い。RFC 3325 上は trusted
network 内で意味があるヘッダで、誤った値だと拒否される実装もある。差分を
減らすため、まずは削除して 5.1 / 5.2 だけで通るか確認する。

```rust
// uac.rs L131〜135 を削除
req.headers.set(
    "P-Preferred-Identity",
    format!("<{}>", self.config.local_addr_of_record()),
);
req.headers.set("Privacy", "none");
```

### 5.4 [推奨] Privacy ヘッダの大文字小文字

仮に残すなら `privacy: none` (小文字) ではなく `Privacy: none` (RFC 3323
の表記) に揃える。SipHeaders の set 実装が大文字/小文字をどう正規化して
いるかを確認した上で、case-insensitive でも揃えておくのが無難。

### 5.5 [推奨] Via に `rport` を付ける

uac.rs L102 の Via 構築。Asterisk は `rport` 付きで 200 OK 成立、sabiden は
無しでも 200 OK が出る個所もあるが、付けておくと P-CSCF が NAT 相当の
処理をするときに安全。

```rust
req.headers.set(
    "Via",
    format!("SIP/2.0/UDP {};rport;branch={}", self.config.sent_by(), branch),
);
```

(コメントの「Via に `rport` を付けない」という記述 (uac.rs L9) は実機検証で
逆だった旨を更新する。)

### 5.6 [調査] From display-name `"Anonymous"`

Asterisk は `from_user=0191349809` 設定なのに `From: "Anonymous" <...>` を
送っている。これは `pjsip_endpoint` の既定挙動 (発信者番号通知抑制
モード相当)。NGN は許容している。sabiden は display-name を入れていない
が、Asterisk と同じ動きにするなら `"Anonymous"` を入れることも検討
(必須ではない)。

## §6 まとめ / Next Action

1. **本タスクは成功**。Asterisk が NGN へ 200 OK を取れた INVITE / 200 / RTP /
   BYE 全文がキャプチャできている (`/tmp/sabiden-dev/asterisk-ngn.pcap`)。
2. **403 の根本原因 (最有力仮説)**: sabiden が Request-URI / To に NGN ドメイン
   `ntt-east.ne.jp` を使い、SDP に LAN private IP (192.168.30.162) を載せて
   いる。NGN は **Request-URI host を P-CSCF IP に**、**SDP IP を eth1
   グローバル IP に**揃える必要がある (Asterisk の成功 INVITE と一致させる)。
3. 修正は §5.1 (Request-URI 書換) と §5.2 (SDP 書換) を最優先で適用し、再現
   テスト。§5.3〜5.6 は差分を減らす最適化として後追い。
4. P-Preferred-Identity / Privacy は不要だった可能性が高い。一旦外して
   原因切り分けを単純化する。

### 残作業 / 注意

- Asterisk は今 `/etc/asterisk/pjsip.conf` を NGN 設定で上書きしてある。
  元に戻すには `sudo cp /etc/asterisk/pjsip.conf.orig.bak /etc/asterisk/pjsip.conf`
  および `sudo cp /etc/asterisk/extensions.conf.orig.bak /etc/asterisk/extensions.conf`
  → `sudo systemctl restart asterisk`。
- sabiden を再開するには Asterisk を停止してから起動: `sudo systemctl stop asterisk`
  → `sudo nohup /home/aoki/sabiden/target/debug/sabiden register --config /home/aoki/sabiden/config.toml &`
- pcap ファイル (`/tmp/sabiden-dev/asterisk-ngn.pcap`) は実電話番号
  (0191349809) と P-CSCF IP を含む。リポジトリにコミットしないこと。
