# OBSERVABILITY — sabiden メトリクス / Grafana / Prometheus

> ops 担当が sabiden を panel 1 枚で監視するための手引き。
> 関連ファイル:
>
> - [`observability/grafana/sabiden-dashboard.json`](../observability/grafana/sabiden-dashboard.json) — Grafana 10+ dashboard JSON
> - [`observability/prometheus/scrape-config.example.yml`](../observability/prometheus/scrape-config.example.yml) — Prometheus job 設定例 (bare metal / K8s SD)
> - [`src/observability/mod.rs`](../src/observability/mod.rs) — メトリクス実装本体 (`Metrics::render_prometheus`)
> - [`src/health/mod.rs`](../src/health/mod.rs) — `/metrics` HTTP endpoint

## 1. 概要

sabiden は `/metrics` を **Prometheus text exposition (v0.0.4)** 形式で公開する。

| 項目 | 値 |
|---|---|
| Endpoint | `GET /metrics` |
| 既定 listen address | `0.0.0.0:8080` (`[health] bind_addr` で変更可、 `config.example.toml`) |
| 認証 | なし (production では NetworkPolicy / oauth2-proxy を前置すること) |
| Scrape interval | 15s 推奨 (sabiden の counter は秒単位の rate 計算に十分な解像度) |
| 公開フォーマット | counter / gauge / summary (`# HELP` / `# TYPE` 行付き) |

すべての時系列は `sabiden_*` prefix。 他データソース (Node Exporter / cAdvisor 等) と
混在せずに 1 panel = 1 数値が決まる self-contained 設計。

## 2. メトリクス一覧

> ⚠ ここに載っているメトリクス名は `src/observability/mod.rs::Metrics::render_prometheus`
> の実装と 1:1 対応する。 追加 / 削除は同関数を grep して同期すること。
> 架空のメトリクス名を panel / alert に書かない。

### 2.1 SIP REGISTER

| メトリクス | type | label | 意味 |
|---|---|---|---|
| `sabiden_sip_registered` | gauge | — | 現在 NGN への REGISTER が成立しているか (1 / 0) |
| `sabiden_sip_register_total` | counter | `result` ∈ {`success`, `fail`} | REGISTER 試行累計 |

### 2.2 SIP INVITE

| メトリクス | type | label | 意味 |
|---|---|---|---|
| `sabiden_sip_invite_total` | counter | `direction` ∈ {`ngn`, `extension`, `pwa_outbound`} × `result` ∈ {`answered`, `busy`, `timeout`, `error`} | INVITE 結果別累計 |
| `sabiden_sip_invite_blocked_by_rate_limit_total` | counter | `direction` ∈ {`extension`, `pwa_outbound`} | TTC JJ-90.24 §5.7.1 連続発信抑制で 503 拒否した outbound INVITE 累計 |
| `sabiden_sip_invite_interval_seconds_sum` | summary | — | 連続 outbound INVITE 発射間隔の合計 (秒) |
| `sabiden_sip_invite_interval_seconds_count` | summary | — | 同サンプル数 |

`direction`:

- `ngn` — sabiden が UAC として NGN P-CSCF へ送る outbound (例: 内線→外線発信、 PWA→外線発信の NGN レッグ)
- `extension` — 内線スマホ / SIP UA へフォークする UAC レッグ
- `pwa_outbound` — WebRTC PWA からの発信専用カウンタ (Issue #145)

### 2.3 NGN 5xx / carrier retry

| メトリクス | type | label | 意味 |
|---|---|---|---|
| `sabiden_ngn_5xx_total` | counter | `status` ∈ {`500`, `503`, `other`} | NGN P-CSCF が返した 5xx 累計 (3GPP TS 24.229 §5.2.7 / RFC 3261 §21.5) |
| `sabiden_ngn_carrier_retry_total` | counter | `outcome` ∈ {`not_retried`, `succeeded`, `failed`, `aborted_by_cancel`} | NGN carrier intermittent reject (500/486/503) に対する 1 回 retry の結果別累計 (Issue #260 / RFC 3261 §20.33 / TTC JJ-90.24 §5.7.3) |

### 2.4 通話 / RTP

| メトリクス | type | label | 意味 |
|---|---|---|---|
| `sabiden_call_active` | gauge | — | 進行中の B2BUA 通話数 |
| `sabiden_extension_registered` | gauge | — | 現在登録中の内線数 |
| `sabiden_rtp_bridge_packets_total` | counter | `direction` ∈ {`ngn_to_ext`, `ext_to_ngn`} | RTP リレーが転送したパケット累計 |
| `sabiden_rtp_ssrc_collision_detected_total` | counter | — | RFC 3550 §8.2 SSRC 衝突検出で transcoder egress SSRC を rotate した累計 |
| `sabiden_rtcp_sr_sent_total` | counter | — | transcoder egress から送出した RTCP SR 累計 (RFC 3550 §6.4.1 / RFC 5761 §3.3) |

### 2.5 まだ未実装 (この dashboard に panel を作っていない)

`record_*` 関数が存在しない / `render_prometheus` で出力していないので、 panel
を作っていない。 将来 metrics を追加した時点で本 dashboard / 本 doc を更新する。

- intercom (内線間直通) の active calls / capacity rejection 件数
- call_log の outcome 別 (`Outcome::Answered`, `Outcome::NoAnswer`, ...) 数 — `src/observability/call_log.rs` は record しているが Prometheus には export していない
- transcription / voicemail (`record_voicemail_*`, `record_transcription_*` 等)

## 3. Prometheus scrape 設定

詳細は [`observability/prometheus/scrape-config.example.yml`](../observability/prometheus/scrape-config.example.yml)。 ファイル冒頭のコメント
通り `prometheus.yml` の `scrape_configs:` 配下にコピーすれば動く。

### 3.1 bare metal / systemd デプロイ

`static_configs.targets` を sabiden のホスト名 + `[health] bind_addr` ポートに
書き換える。

```yaml
- job_name: sabiden
  static_configs:
    - targets: ["sabiden.local:8080"]
      labels:
        service: sabiden
```

### 3.2 Kubernetes デプロイ

`deploy/k8s/` で Pod を作るときに annotation を付ければ自動 discover される。

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

scrape config 側の `sabiden-k8s` job は `prometheus.io/scrape=true` を keep する
relabel rule を持つ。 NetworkPolicy で Prometheus pod ↔ sabiden pod 間の 8080/tcp
ingress を許可することを忘れない (NGN 側は hostNetwork = true の場合、 NodeIP
経由になることに注意)。

## 4. Grafana dashboard import 手順

### 4.1 UI から import

1. Grafana → **Dashboards** → **New** → **Import**
2. **Upload JSON file** で [`observability/grafana/sabiden-dashboard.json`](../observability/grafana/sabiden-dashboard.json) を選択
3. データソース選択で **Prometheus** (sabiden を scrape している Prometheus) を選ぶ
4. **Import** をクリック

`instance` テンプレ変数で複数台 sabiden を絞り込める。 デフォルトは `All`。

### 4.2 Provisioning (file based / GitOps)

Grafana の `provisioning/dashboards/` 配下に YAML + JSON を配置する例:

```yaml
# /etc/grafana/provisioning/dashboards/sabiden.yaml
apiVersion: 1
providers:
  - name: sabiden
    orgId: 1
    folder: sabiden
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards/sabiden
```

```bash
# JSON をコピー
sudo install -d /var/lib/grafana/dashboards/sabiden
sudo install -m 0644 \
  observability/grafana/sabiden-dashboard.json \
  /var/lib/grafana/dashboards/sabiden/
sudo systemctl restart grafana-server
```

### 4.3 Panel 一覧 (panel ID 順)

| ID | Title | Type | 主クエリ |
|---|---|---|---|
| 1 | SIP Registered | stat | `max(sabiden_sip_registered)` |
| 2 | Active Calls | stat | `sum(sabiden_call_active)` + `sum(sabiden_extension_registered)` |
| 3 | REGISTER success rate (5m) | stat | `rate(sabiden_sip_register_total{result="success"}) / rate(total)` |
| 4 | INVITE answer rate (5m) | stat | direction 別 answered / total |
| 5 | INVITE rate by direction × result | timeseries (stacked) | `sum by (direction, result) (rate(sabiden_sip_invite_total))` |
| 6 | NGN 5xx response rate | timeseries (stacked) | `sum by (status) (rate(sabiden_ngn_5xx_total))` |
| 7 | NGN carrier retry outcome | timeseries (stacked) | `sum by (outcome) (rate(sabiden_ngn_carrier_retry_total{outcome!="not_retried"}))` |
| 8 | Rate-limit rejected INVITE | timeseries (stacked) | `sum by (direction) (rate(sabiden_sip_invite_blocked_by_rate_limit_total))` |
| 9 | RTP bridge throughput | timeseries | `sum by (direction) (rate(sabiden_rtp_bridge_packets_total))` |
| 10 | Outbound INVITE interval (avg) | timeseries | `rate(_interval_seconds_sum) / rate(_interval_seconds_count)` |
| 11 | RTP SSRC collisions / RTCP SR | timeseries | `rate(sabiden_rtp_ssrc_collision_detected_total)` ほか |

## 5. 推奨 alert rule

下記は Prometheus alerting rule の例。 `prometheus.rules.yml` 等にコピーして
そのまま使える。 閾値はホーム用途 (1 回線) を想定。 大量回線運用なら見直し。

```yaml
groups:
  - name: sabiden.rules
    interval: 30s
    rules:
      # NGN REGISTER が落ちている (REGISTER が成立していない状態が 2 分以上続く)。
      # NGN 経路 / DHCP option 120 / eth1 ARP 失敗の早期検知。
      - alert: SabidenRegisterDown
        expr: max(sabiden_sip_registered) < 1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "sabiden NGN REGISTER down"
          description: |
            sabiden_sip_registered=0 が 2 分以上継続。 NGN P-CSCF への到達性 /
            DHCP lease / eth1 経路を確認。 ログ: journalctl -u sabiden -n 200

      # 直近 10 分の REGISTER 成功率が 90% 未満。 P-CSCF 認証障害 / NTP ずれ等。
      - alert: SabidenRegisterFailRateHigh
        expr: |
          (
            sum(rate(sabiden_sip_register_total{result="fail"}[10m]))
            /
            clamp_min(sum(rate(sabiden_sip_register_total[10m])), 1e-9)
          ) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "sabiden REGISTER fail rate > 10%"
          description: |
            REGISTER 試行のうち 10% 超が失敗。 直近 10 分の rate で集計。
            sabiden_sip_register_total{result="fail"} を Grafana で確認。

      # NGN P-CSCF からの 5xx が突発的に増えた。 carrier 障害 / parity allocator
      # の退行 / 連続発信抑制超過 (TTC JJ-90.24) の検知。
      - alert: SabidenNgn5xxBurst
        expr: sum(rate(sabiden_ngn_5xx_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "sabiden NGN 5xx burst (>0.05/s for 5m)"
          description: |
            NGN から 5xx が 5m 平均で 0.05 件/秒を超えた。 status 別の内訳は
            Grafana panel "NGN 5xx response rate" を参照。 500 が支配的なら
            carrier intermittent (Issue #260)、 503 が支配的なら overload。

      # carrier retry が連続失敗。 parity allocator が effective でない /
      # 全て carrier 側の 5xx で救済できない状態。
      - alert: SabidenCarrierRetryAllFailing
        expr: |
          sum(rate(sabiden_ngn_carrier_retry_total{outcome="failed"}[10m]))
          /
          clamp_min(sum(rate(sabiden_ngn_carrier_retry_total{outcome=~"succeeded|failed|aborted_by_cancel"}[10m])), 1e-9)
          > 0.9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "sabiden carrier retry failure ratio > 90%"
          description: |
            Issue #260 carrier retry の outcome が 90% 以上 failed。 1 回 retry
            では救えていない = carrier 側障害 / parity allocator 退行の可能性。

      # 連続発信抑制で 503 拒否が発生 = loop / 自動発信 bug の早期検知。
      - alert: SabidenRateLimitTripped
        expr: sum(rate(sabiden_sip_invite_blocked_by_rate_limit_total[5m])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "sabiden outbound INVITE rate-limit tripped"
          description: |
            TTC JJ-90.24 §5.7.1 連続発信抑制で 503 拒否が発生。 PWA / 内線側で
            INVITE loop / 自動再発信 bug が動いていないか確認。
```

## 6. トラブルシューティング

### 6.1 `/metrics` が 404 / connection refused

- `sabiden register --config ...` で起動しているか (`/metrics` は health server
  経由で公開される。 `register` サブコマンドが health server を上げる)。
- `[health] bind_addr` が想定 IP / port にバインドしているか:
  ```sh
  ss -tlnp | grep ':8080'
  curl -sS http://127.0.0.1:8080/healthz
  curl -sS http://127.0.0.1:8080/metrics | head -20
  ```
- K8s で hostNetwork = true の場合、 NodeIP 経由で scrape する。
- Pod 単位で scrape したい場合は `prometheus.io/scrape: "true"` annotation 必須。

### 6.2 `/metrics` が空 / counter が動かない

- 起動直後は counter が 0 で正常。 INVITE / REGISTER が起きていない場合は値が
  入らない (Prometheus の counter は最初の sample が 0 でもよい)。
- それでも全 0 なら以下を確認:
  - `sabiden_sip_registered` が 1 になっているか (REGISTER 成立確認)
  - `RUST_LOG=sabiden=debug` でログを見て `record_register` / `record_invite_*`
    が呼ばれているか
  - test mode (`--dry-run` 等) で動いていないか — production 経路を通すと
    `Metrics::record_*` が呼ばれる

### 6.3 Prometheus 側で scrape されない

```sh
# Prometheus targets を見る
curl -sS http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="sabiden")'
```

- `health` が `up` でなければ scrape config の `targets:` のホスト名 / ポートを
  確認。
- K8s SD なら `relabel_configs` の `prometheus.io/scrape=true` keep rule が
  当たっているか (`__meta_kubernetes_pod_annotation_prometheus_io_scrape`
  ラベルが annotation 通り設定されているか)。
- NetworkPolicy で Prometheus pod → sabiden pod の 8080 が許可されているか。

### 6.4 Grafana 上で No data

- データソースが Prometheus を指しているか (dashboard import 時の選択)。
- `$instance` 変数が `All` ではなく特定値で絞られて空になっていないか。
- メトリクス名が古い (panel に `sabiden_invite_ngn_total` 等の旧名が残っている)
  — 本 dashboard は §2 の現行メトリクス名と一致。 自前に追加した panel は §2 と
  突合する。

## Assumptions

- 本書執筆時点 (Issue #318) の `src/observability/mod.rs::Metrics::render_prometheus`
  が出力するメトリクスは §2 に列挙した 13 系列。 将来追加された場合は本書 + dashboard
  を必ず同 PR で更新する (CLAUDE.md §13 / HLD 整合)。
- `/metrics` は CLAUDE.md §8 で「触らない領域」とされる `src/sip/register.rs`
  には影響しない (read-only な観測経路)。
- TLS / 認証は本 Issue の scope 外。 production hardening は別 Issue で扱う。
