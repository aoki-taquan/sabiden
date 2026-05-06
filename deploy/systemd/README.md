# systemd ユニット

systemd で sabiden を常駐サービスとして動かすためのファイル群。

## ファイル一覧

| ファイル | 配置先 |
|----------|--------|
| `sabiden.service` | `/etc/systemd/system/sabiden.service` |
| `sabiden.env.example` | `/etc/sabiden/sabiden.env` (改名) |
| `sysusers.d/sabiden.conf` | `/usr/lib/sysusers.d/sabiden.conf` |

## セットアップ手順

```sh
# 1. ユーザ作成
sudo install -m 0644 deploy/systemd/sysusers.d/sabiden.conf \
    /usr/lib/sysusers.d/sabiden.conf
sudo systemd-sysusers

# 2. バイナリ配置 (cargo build --release 済みとして)
sudo install -m 0755 target/release/sabiden /usr/local/bin/sabiden

# 3. 設定ディレクトリ
sudo install -d -m 0755 -o root -g sabiden /etc/sabiden
sudo install -m 0640 -o root -g sabiden config.example.toml /etc/sabiden/config.toml
sudo install -m 0640 -o root -g sabiden \
    deploy/systemd/sabiden.env.example /etc/sabiden/sabiden.env
# /etc/sabiden/config.toml と sabiden.env を編集

# 4. unit ファイル
sudo install -m 0644 deploy/systemd/sabiden.service \
    /etc/systemd/system/sabiden.service

# 5. 起動
sudo systemctl daemon-reload
sudo systemctl enable --now sabiden.service
```

## 動作確認

```sh
sudo systemctl status sabiden.service
journalctl -u sabiden.service -f
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

## ハードニング項目

`sabiden.service` には以下の保護を入れている。

- `NoNewPrivileges=true`
- `PrivateTmp=true`, `PrivateDevices=true`
- `ProtectSystem=strict`, `ProtectHome=true`
- `ProtectKernelTunables/Modules/Logs=true`
- `RestrictNamespaces=true`, `RestrictRealtime=true`
- `MemoryDenyWriteExecute=true`
- `SystemCallFilter=@system-service` (危険な系を deny)
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK`
- 5060 などの低位ポート bind 用に
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` のみ付与

`systemd-analyze security sabiden.service` で点数確認推奨。

## トラブルシューティング

| 症状 | 原因と対処 |
|------|-----------|
| `Failed to bind 5060` | `CapabilityBoundingSet` から `CAP_NET_BIND_SERVICE` が外れている / SELinux で拒否されている |
| `permission denied: /run/sabiden/sip-servers` | DHCP hook が動いていない。`deploy/dhcp/README.md` を参照 |
| `EnvironmentFile not found` | `/etc/sabiden/sabiden.env` 未配置。`-` 接頭辞で起動失敗にはならないが Secret は注入されない |
| journald に何も出ない | `StandardOutput=journal` が上書きされていないか確認 |
