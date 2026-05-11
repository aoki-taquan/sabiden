import { createSignal, For, Show, type Component } from "solid-js";

const KEYS = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"];

/**
 * Dialer の props (Issue #194 追補):
 *
 * - `rateLimitedSeconds`: backend が `ServerMessage::error{code:"rate_limited"|"outbound_failed"}`
 *   で押し戻してきた retry_after 残秒数。 `> 0` の間は発信ボタンを disable し、
 *   カウントダウンを表示する。 親 (App.tsx) が `setInterval` で 1 秒毎に
 *   デクリメントする (Date.now ベース、 WS 再接続後も有効期限が残れば継続)。
 *   `null` または `0` で通常状態に復帰。
 *   背景仕様: TTC JJ-90.24v2 §5.7.1 (連続抑制) / §5.7.3 (5xx 自動 retry 禁止) /
 *   RFC 3261 §20.33 Retry-After。 backend 側 `src/call/rate_limiter.rs` を参照。
 */
export const Dialer: Component<{
  extId: string;
  onCall: (number: string) => void;
  onLogout: () => void;
  status: string;
  statusOk: boolean;
  rateLimitedSeconds?: number | null;
}> = (props) => {
  const [num, setNum] = createSignal("");

  const append = (k: string) => setNum((n) => (n + k).slice(0, 32));
  const back = () => setNum((n) => n.slice(0, -1));

  /**
   * 発信ボタン disabled 判定:
   * - `statusOk` が false (= WS 未接続 / 認証失敗 / 再接続中) は従来通り disable
   * - `rateLimitedSeconds` が正値 (= NGN/自前 rate limiter で抑制中、 Issue #194)
   */
  const disabled = () => !props.statusOk || (props.rateLimitedSeconds ?? 0) > 0;

  /**
   * 発信ボタンの label。 通常は「発信」、 rate limit 中は残秒数を表示。
   * WAI-ARIA 1.2 §4.1.1 accessible name 経由で screen reader にも残秒数が届く。
   */
  const callLabel = () => {
    const sec = props.rateLimitedSeconds ?? 0;
    if (sec > 0) return `発信 (${sec}s)`;
    return "発信";
  };

  const call = () => {
    if (disabled()) return; // defense-in-depth: button disabled 中の keyboard 経由を弾く
    const n = num().trim();
    if (n.length === 0) return;
    props.onCall(n);
  };

  return (
    <div class="container">
      <div class="row" style={{ "justify-content": "space-between", "align-items": "center" }}>
        <div>
          <h2 style={{ margin: 0 }}>{props.extId}</h2>
          <span class={`status ${props.statusOk ? "ok" : "err"}`}>{props.status}</span>
        </div>
        <button onClick={props.onLogout} style={{ padding: "8px 12px" }}>
          ログアウト
        </button>
      </div>

      <input
        type="tel"
        inputmode="tel"
        value={num()}
        onInput={(e) => setNum(e.currentTarget.value.replace(/[^0-9*#+]/g, ""))}
        placeholder="番号を入力"
        style={{ "margin-top": "20px", "font-size": "22px", "text-align": "center" }}
      />

      <div class="dialer">
        <For each={KEYS}>{(k) => <button onClick={() => append(k)}>{k}</button>}</For>
      </div>

      {/*
       * Rate limit 抑制中の通知 (Issue #194):
       * WAI-ARIA 1.2 §5.4 / §6 (Live Region): `role="status"` + `aria-live="polite"`
       * で screen reader に「○ 秒お待ちください」を割り込みなしで読み上げさせる
       * (`alert` だと assertive で他の読み上げを遮るため、 単なる残秒数表示には不適)。
       * `aria-atomic="true"` で内容が変わるたびに全文を再読し、 「3」「2」「1」と
       * 数字だけ流れるのを防ぐ。
       */}
      <Show when={(props.rateLimitedSeconds ?? 0) > 0}>
        <div
          class="notice"
          role="status"
          aria-live="polite"
          aria-atomic="true"
          data-testid="rate-limited-notice"
          style={{ "margin-top": "12px" }}
        >
          発信制限中: あと {props.rateLimitedSeconds} 秒お待ちください
        </div>
      </Show>

      <div class="row">
        <button onClick={back} style={{ flex: 1 }}>
          ←
        </button>
        <button
          class="primary"
          onClick={call}
          style={{ flex: 2 }}
          disabled={disabled()}
          aria-disabled={disabled()}
          data-testid="call-button"
        >
          {callLabel()}
        </button>
      </div>
    </div>
  );
};
