# DHCP Option 120 取得スクリプト

NTT NGN は接続時に DHCP Option 120 (RFC 3361) で SIP サーバ (P-CSCF) の
IPv6 アドレスを払い出す。sabiden 本体はこの値を `/run/sabiden/sip-servers`
から読み取る前提なので、dhclient / dhcpcd 側で hook スクリプトを動かして
ファイルに書き出す必要がある。

## ファイル一覧

| ファイル | 用途 |
|---------|------|
| `dhclient-exit-hooks.d/sabiden` | dhclient 用 exit hook (Debian/Ubuntu/RHEL 系) |
| `dhclient.conf.example` | dhclient.conf に追加する Option 宣言と request 行 |
| `dhcpcd.conf.example` | dhcpcd 用設定 (Alpine/OpenWrt 系の参考) |

## dhclient (ISC dhcp-client) を使う場合

1. hook スクリプトを配置:
   ```sh
   sudo install -m 0755 deploy/dhcp/dhclient-exit-hooks.d/sabiden \
       /etc/dhcp/dhclient-exit-hooks.d/sabiden
   ```
2. dhclient.conf を更新:
   ```sh
   sudo cp deploy/dhcp/dhclient.conf.example /etc/dhcp/dhclient.d/sabiden.conf
   sudo sed -i 's/INTERFACE_PLACEHOLDER/eth0/' /etc/dhcp/dhclient.d/sabiden.conf
   ```
   インタフェース名は実環境に合わせて差し替えること (`ip -6 addr` で確認)。
3. dhclient を再起動:
   ```sh
   sudo systemctl restart isc-dhcp-client
   ```
4. 取得確認:
   ```sh
   cat /run/sabiden/sip-servers
   cat /run/sabiden/ntt-vendor.json
   ```

## dhcpcd を使う場合 (Alpine / OpenWrt)

`dhcpcd.conf.example` を参考に `/etc/dhcpcd.conf` を編集する。
exit hook は `/lib/dhcpcd/dhcpcd-hooks/` に配置すれば dhclient hook と同様に
環境変数 (`$new_ip_sip_servers` など) が渡される。

## 出力ファイル仕様

### `/run/sabiden/sip-servers`
1 行 1 IP アドレス (IPv6/IPv4 どちらも可)。改行区切り。空ファイルもありうる。

例:
```
2001:A7FF:2101:6::F
2001:A7FF:2101:1::C
```

### `/run/sabiden/ntt-vendor.json`
NTT vendor info (Option 210) のパース結果を JSON で出力。

```json
{"number":"0312345678","domain":"ntt-east.ne.jp"}
```

## デバッグ

- hook が呼ばれているかは `journalctl -t sabiden-dhclient-hook` で確認。
- `dhclient -v` を直接実行すると Option 120 の生値が見える。
- shellcheck はリポジトリ内で次のように実行:
  ```sh
  shellcheck deploy/dhcp/dhclient-exit-hooks.d/sabiden
  ```

## セキュリティ注意

- `/run/sabiden/` 配下は world-readable (0644) で出すが、機密情報は含まない。
- パスワード等の Secret は systemd の `EnvironmentFile=` か K8s Secret 経由で注入する
  こと。DHCP 取得値とは混在させない。
