# sabiden 実機インストールガイド

このドキュメントは、フレッツ光ネクスト + ひかり電話 契約環境で sabiden を
HGW を介さず NGN 直収運用するためのセットアップ手順をまとめたもの。

## 前提環境

| 項目 | 要件 |
|------|------|
| 回線 | NTT 東日本 / 西日本 フレッツ光ネクスト (NGN 接続) |
| 契約 | ひかり電話 (アナログ電話 A 等含む) |
| 機器 | ONU と sabiden を動かす Linux ホストの間に L3 ルーターが無いこと |
| OS | Linux (kernel 4.x 以降、systemd または OpenRC) |
| 言語ランタイム | Rust 1.95 以降 (ソースからビルドする場合) |
| 必須プロトコル | IPv6 / DHCPv6-PD / DHCPv4 (Option 120) |
| ネットワーク | NGN 側に直結する物理 NIC / VLAN |

> HGW (PR-500/600/RT-500 等) を残したまま並列収容することはできない。
> 同一 NGN 上で SIP REGISTER は 1 端末しか維持できないため、HGW 側の
> ひかり電話設定を OFF にしてから sabiden を起動する。

---

## Step 1: ひかり電話契約と DHCPv6-PD の確認

1. 契約状態が「ひかり電話」または「ひかり電話 A」であることを My NTT 等で確認。
2. NGN 側 NIC で DHCPv6-PD が動いていること:
   ```sh
   sudo dhclient -6 -P -v eth0      # 取得テスト
   ip -6 addr show dev eth0
   ```
   `/56` のプレフィックスが取得でき、global IPv6 アドレス
   (`2400::/12` 等の NGN レンジ) が降ってくることを確認する。

---

## Step 2: DHCP Option 120 取得

NGN は DHCP Option 120 (RFC 3361) で SIP サーバ (P-CSCF) の IPv6 を払い出す。
sabiden 本体は `/run/sabiden/sip-servers` から読み取る前提。

1. hook スクリプト配置 (詳細は `deploy/dhcp/README.md`):
   ```sh
   sudo install -m 0755 deploy/dhcp/dhclient-exit-hooks.d/sabiden \
       /etc/dhcp/dhclient-exit-hooks.d/sabiden
   sudo cp deploy/dhcp/dhclient.conf.example /etc/dhcp/dhclient.d/sabiden.conf
   sudo sed -i 's/INTERFACE_PLACEHOLDER/eth0/' /etc/dhcp/dhclient.d/sabiden.conf
   ```
2. dhclient を再起動して取得確認:
   ```sh
   sudo systemctl restart isc-dhcp-client
   cat /run/sabiden/sip-servers
   cat /run/sabiden/ntt-vendor.json
   ```
   1 行に IPv6 アドレスが 1 つ以上出ていればよい。

---

## Step 3: ホストアドレス確認

sabiden は SIP REGISTER の Contact ヘッダに NGN 側 global IPv6 を入れる。
通常は **local_addr の設定を省略可能** で、起動時に
`server_addr` 宛のダミー UDP socket でカーネルが選ぶ source IP を
自動検出して Via/Contact に載せる (Issue #35)。

```sh
ip -6 addr show dev eth0 scope global
# 例: 2001:xxxx:xxxx::1/64
```

DHCPv6-PD で /56 を取得し、その中から /64 を切って NIC に設定する運用が一般的。
RA (Router Advertisement) を NGN 側が送ってこない構成では `radvd` 等で
自前生成する必要がある。

> **K8s デプロイ等で pod IP が動的に変わる場合は `local_addr` を空のまま
> にしておく**ことで、ノード固定 (nodeSelector) せずに動かせる。
> NAT 越しで外部 IP を Via に載せたいなど、明示指定が必要な場合のみ
> `config.toml` の `sip.local_addr` または環境変数 `SABIDEN_SIP_LOCAL_ADDR`
> で設定する。

---

## Step 4: 設定ファイル準備

```sh
sudo install -d -m 0755 -o root -g sabiden /etc/sabiden
sudo install -m 0640 -o root -g sabiden config.example.toml /etc/sabiden/config.toml
sudo $EDITOR /etc/sabiden/config.toml
```

最低限編集する項目:

- `sip.server_addr`: `/run/sabiden/sip-servers` の値、または起動時に DHCP モジュールで自動解決
- `sip.local_addr`: **省略可** (自動検出)。Step 3 で確認した自ホスト global IPv6 を
  明示したい場合のみ設定する
- `sip.bind_addr`: **省略可** (デフォルト `[::]:5060`)。listen ポートを変える場合のみ設定
- `sip.phone_number`: ひかり電話で割当てられた電話番号
- `sip.domain`: NTT 提供ドメイン (例: `ntt-east.ne.jp`)
- `password`: 環境変数 `SABIDEN_SIP_PASSWORD` 経由で渡すこと推奨 (Step 5a/5b 参照)

---

## Step 5a: systemd で起動する

```sh
sudo install -m 0644 deploy/systemd/sysusers.d/sabiden.conf \
    /usr/lib/sysusers.d/sabiden.conf
sudo systemd-sysusers

sudo install -m 0755 target/release/sabiden /usr/local/bin/sabiden
sudo install -m 0640 -o root -g sabiden \
    deploy/systemd/sabiden.env.example /etc/sabiden/sabiden.env
sudo $EDITOR /etc/sabiden/sabiden.env   # SABIDEN_SIP_PASSWORD を設定

sudo install -m 0644 deploy/systemd/sabiden.service \
    /etc/systemd/system/sabiden.service
sudo systemctl daemon-reload
sudo systemctl enable --now sabiden.service
```

詳細とハードニング項目は `deploy/systemd/README.md` を参照。

## Step 5b: Docker / docker compose で起動する

```sh
export SABIDEN_SIP_PASSWORD='****'
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml logs -f
```

`network_mode: host` を使うため、ホスト側の dhclient hook と
`/run/sabiden/` 配下を共有する。

## Step 5c: Kubernetes で起動する

`deploy/k8s/deployment.yaml` を `kubectl apply` する。
Secret は事前作成:

```sh
kubectl -n sabiden create secret generic sabiden-secrets \
    --from-literal=sip-password="$SABIDEN_SIP_PASSWORD" \
    --from-literal=phone-number="0xxxxxxxxxx"
kubectl apply -f deploy/k8s/deployment.yaml
```

Pod は `hostNetwork: true` で動くため、ノード自身が NGN に直結している必要がある。

---

## Step 6: 内線 SIP UA 登録 (Linphone iOS / Android)

sabiden の UAS (内線受付) 設定は `config.toml` の `[uas]` セクションと
`[[extensions]]` ブロック。

### Linphone (iOS / Android) の設定例

| 項目 | 値 |
|------|----|
| Username | `[[extensions]]` の `username` |
| Password | 同 `password` |
| Domain | sabiden ホストの IP / FQDN (LAN 内、例: `192.168.1.10`) |
| Transport | UDP |
| Port | 5061 (`uas.bind_addr` に合わせる) |
| Outbound proxy | sabiden ホストの IP |
| Register | ON |

> sabiden の `[uas]` は LAN 側 NIC (例: `0.0.0.0:5061`) に bind しておく。
> NGN 側からは内線受付しないこと。

登録成功すると Linphone の UI に "Connected" / 緑のチェックが出る。
sabiden 側のログでも `REGISTER 200 OK` が出ていることを確認:

```sh
journalctl -u sabiden -f | grep REGISTER
```

---

## Step 7: 動作確認

### ヘルスチェック
```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```
`readyz` は NGN への REGISTER が成功した後に 200 を返す。

### 発信テスト
1. Linphone で `117` (時報、NTT 提供) などに発信。
2. RTP が双方向で流れているかは `ss -u -n` や `tcpdump` で確認:
   ```sh
   sudo tcpdump -i eth0 -n udp port 5060 or 'udp portrange 16384-32768'
   ```
3. 発信履歴は `journalctl -u sabiden | grep INVITE`。

### 着信テスト
1. 別の電話 (携帯等) からひかり電話番号にかける。
2. Linphone を登録した複数台が同時に鳴ることを確認 (フォーク着信)。
3. 1 台が応答すると他はキャンセルされる。

---

## トラブルシューティング

### REGISTER が 401 → 401 を繰り返す
- `SABIDEN_SIP_PASSWORD` が誤り。HGW 設定の "ユーザ認証パスワード" と一致しているか確認。
- `From` ヘッダの SIP URI が `sip:<電話番号>@<domain>` の形式になっているか sabiden ログで確認。

### REGISTER が 403 / 404
- `domain` が NTT 払い出し値と異なる。`/run/sabiden/ntt-vendor.json` の `domain` を採用する。
- HGW のひかり電話設定が ON のままになっていないか確認 (両者排他)。

### REGISTER がそもそもタイムアウト
- IPv6 経路が無い: `ping6 <SIP server>` で確認。
- DSCP マーキングが必須: NGN は DSCP=32 でないと黙殺する事例がある (sabiden は実装済)。

### SIP トレース取得
```sh
sudo tcpdump -i eth0 -nn -s0 -w /tmp/sip.pcap 'udp port 5060'
# 別端末で再現後 Ctrl-C
wireshark /tmp/sip.pcap
```
Wireshark で `sip` フィルタを使うと REGISTER / 401 / INVITE のやり取りが追える。

### 内線が登録できない
- `uas.bind_addr` が LAN 側 NIC に bind されているか確認。
- ファイアウォール (ufw / firewalld / nftables) で 5061/udp が許可されているか確認。
- Linphone の Transport が TLS になっていないか (Phase 1 では UDP のみ)。

---

## NGN 直収モード (Issue #37 / home-ops PR #214)

HGW (PR-500/600/RT-500 等) を物理的に経由せず、sabiden を直接 NGN に
ぶら下げて運用するモード。home-ops issue #205 / PR #214 の検証で確定した
レシピに基づく。HGW の Digest 認証ではなく **NGN 側の回線認証
(WAN MAC + DHCPv4 vendor class)** で REGISTER を通すため、`SABIDEN_SIP_PASSWORD`
は不要になる。

### 確定レシピ

```
[初期化 一度きり]
HGW (RX-600KI) を 1 回起動 → NTT OSS-DB に WAN MAC を永続登録

[sabiden 常用]
1. eth1 を HGW WAN MAC に spoof (K8s NIC レベル)
2. init container が DHCPv4 with Vendor Class "RX-600KI"
   → /30 IPv4 lease + option 120 で SIP server IPv4 を取得
3. sabiden が SIP REGISTER (Authorization なし、回線認証ベース)
4. 200 OK 受信
```

詳細な検証ログは home-ops PR #214 を参照。

### sabiden 側の責務 (本ドキュメントの範囲)

sabiden は上記 (4) のみを担当する。**(1)-(3) は本リポジトリの実装範囲外**:

- **MAC spoof は K8s Pod の NIC レベルで対応する** (CNI / `macvlan` /
  `multus` + NetworkAttachmentDefinition 等)。本ドキュメントでは扱わない。
- **DHCPv4 と vendor class は init container で行う**。init container は
  `[ngn] vendor_class` の値 (デフォルト `RX-600KI`) を読んで DHCP option 60
  に乗せ、取得した lease IP / option 120 (SIP server) を環境変数で sabiden
  本体に渡す。本ドキュメントでは扱わない (別 issue で実装予定)。

### sabiden の設定

`config.toml` (または環境変数) を以下のようにする:

```toml
# NGN 直収モード (HGW なし、回線認証ベース)
[ngn]
direct_mode = true
vendor_class = "RX-600KI"   # NTT 東日本 HGW 機種、init container の DHCP vendor class に渡される

[sip]
# 直収モードでは password 不要 (回線認証)
# password = ""               # コメントアウト or 空文字
server_addr = "118.177.125.1:5060"   # init container の DHCP option 120 で取得した値
local_addr = "118.177.72.x:5060"     # init container の DHCP lease IP
phone_number = "0312345678"
domain = "ntt-east.ne.jp"
```

環境変数のみで起動する場合 (k8s ConfigMap + Secret 想定):

```sh
SABIDEN_NGN_DIRECT_MODE=true
SABIDEN_NGN_VENDOR_CLASS=RX-600KI
SABIDEN_SIP_SERVER_ADDR=118.177.125.1:5060
SABIDEN_SIP_LOCAL_ADDR=118.177.72.x:5060
SABIDEN_SIP_PHONE_NUMBER=0312345678
SABIDEN_SIP_DOMAIN=ntt-east.ne.jp
# SABIDEN_SIP_PASSWORD は未設定 or 空文字
```

### 動作上の差分

| 項目 | HGW Digest 認証 (従来) | NGN 直収モード (Issue #37) |
|------|------------------------|----------------------------|
| 認証 | Digest (password 必須) | 回線認証 (password 不要) |
| 401 受信時 | 1 回まで Digest 再送 | 即 bail (DHCP/MAC を疑う) |
| トランスポート | NGN IPv6 path | NGN IPv4 path (/30 lease) |
| DSCP | `IPV6_TCLASS` | `IP_TOS` (sabiden は両方セット) |

password を未設定にしたうえで `direct_mode = false` (デフォルト) のまま運用すると、
401 が返ってきた時点で bail し 30 秒後に再試行ループに入る (互換性のため
`direct_mode` フラグは挙動を変えない設計; 単に運用文脈を明示する目的)。

### トラブルシューティング (直収モード固有)

- **401 が返り続ける**: `register_with_retry` のエラーメッセージに
  `auth=none mode` と出ていれば、SIP 層は正しく動いている。MAC spoof の値が
  HGW WAN MAC と一致しているか / DHCP の vendor class が `RX-600KI` で
  送出されているかを確認する (`tcpdump -n udp port 67 or udp port 68`)。
- **DHCP lease が来ない**: NTT OSS-DB に MAC が登録されていない可能性。
  HGW を一度物理接続して通電し、回線認証を通す必要がある (初期化手順)。
- **REGISTER が IPv6 で送出されてしまう**: `server_addr` が IPv6 アドレスに
  なっていないか確認 (init container が `option 120` の IPv4 を渡せているか)。

---

## アンインストール

```sh
sudo systemctl disable --now sabiden.service
sudo rm -f /etc/systemd/system/sabiden.service /usr/local/bin/sabiden
sudo rm -rf /etc/sabiden /run/sabiden
sudo rm -f /etc/dhcp/dhclient-exit-hooks.d/sabiden \
           /etc/dhcp/dhclient.d/sabiden.conf \
           /usr/lib/sysusers.d/sabiden.conf
sudo userdel sabiden 2>/dev/null || true
sudo systemctl daemon-reload
```
