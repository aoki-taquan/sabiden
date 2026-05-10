import { createMemo, createSignal, Show, type Component } from "solid-js";
import { saveSignalUrl, saveToken } from "../lib/storage";
import { resolveSignalingUrl } from "../lib/signaling";

/**
 * Login view に渡す再ログイン理由 (Issue #142, PR #141 follow-up)。
 *
 * `App.tsx::LoginReason` と同じ shape だが、 components 層が App 型に
 * 依存しないよう独立して export する (props 型の重複を避ける目的では
 * App 側 import でも OK だが、 Login 単体テスト容易性のため localize)。
 *
 * - `auth`:      永続認証失敗 (RFC 6455 §7.4.1 1008 / §7.4.2 4xxx)。
 *                token 失効 / 署名不一致 / Cloudflare Access 401 等。
 * - `exhausted`: transient close (1006/1011/...) が
 *                `maxReconnectAttempts` (約 8 分相当の累積遅延後) を
 *                使い切った。 ネットワーク途絶 / サーバ長期不在等。
 */
export type LoginReason = "auth" | "exhausted";

/**
 * Issue #142: 再ログインを促す理由を画面上部に可視化する Login 画面。
 *
 * a11y: WAI-ARIA 1.2 §5.4 の `role="alert"` で screen reader に即時告知
 * (live region 同等の assertive アナウンス)。 入力 validation エラー側は
 * 従来通り `role="alert"` を付与する。
 */
export const Login: Component<{
  onSubmit: (token: string) => void;
  /**
   * 直前に SignalingClient が永続的に閉じた理由 (auth/exhausted)。
   * `undefined` なら通常の Login 画面 (notice 非表示)。
   */
  reason?: LoginReason;
}> = (props) => {
  const [token, setToken] = createSignal("");
  const [signalUrl, setSignalUrl] = createSignal(resolveSignalingUrl());
  const [err, setErr] = createSignal<string | null>(null);

  /**
   * `props.reason` を表示文言に写像する。 createMemo で signal 化し、
   * SolidJS reactive 規約に従って props 変化に追従させる。
   */
  const reasonNotice = createMemo<string | null>(() => {
    switch (props.reason) {
      case "auth":
        return "認証に失敗しました。 トークンを発行し直して入力してください。";
      case "exhausted":
        return "サーバへの再接続を約 8 分試みましたが復旧しませんでした。 ネットワーク状況を確認のうえ再ログインしてください。";
      default:
        return null;
    }
  });

  const submit = (e: Event) => {
    e.preventDefault();
    const t = token().trim();
    if (!t || t.split(".").length !== 3) {
      setErr("トークン形式が正しくありません (ext.expiry.signature)");
      return;
    }
    saveToken(t);
    saveSignalUrl(signalUrl().trim());
    props.onSubmit(t);
  };

  return (
    <div class="container">
      <h1>sabiden</h1>
      <p class="muted">NTT ひかり電話 WebRTC クライアント</p>
      <Show when={reasonNotice()}>
        {(notice) => (
          <div class="notice error" role="alert" style={{ "margin-top": "16px" }}>
            {notice()}
          </div>
        )}
      </Show>
      <form class="stack" onSubmit={submit} style={{ "margin-top": "20px" }}>
        <label class="stack" style={{ gap: "6px" }}>
          <span class="muted">アクセストークン (HMAC)</span>
          <input
            type="password"
            // Issue #109: ブラウザ password manager の autofill / 候補提示で
            // HMAC token が UI に残るのを抑制する (`new-password` は WHATWG
            // HTML §autocomplete-detail で「password manager に保存させない /
            // 既存提案を出さない」 セマンティクス)。 完全には封じられない
            // が、 主要ブラウザの候補表示は止まる。
            autocomplete="new-password"
            // ARIA: パスワード入力 input に明示ラベル付け (WAI-ARIA 1.2 §6.7
            // labelling-by relation)。 同 label の <span> は visual で文字を
            // 出しているが「ext.expiry.signature 形式」という入力指示を
            // 補助テキストとして screen reader に届けるため aria-describedby
            // を併用する。
            aria-label="アクセストークン"
            aria-describedby="token-help"
            placeholder="ext.expiry.signature"
            value={token()}
            onInput={(e) => setToken(e.currentTarget.value)}
            required
          />
          <span id="token-help" class="muted" style={{ "font-size": "11px" }}>
            HMAC 形式: ext.expiry.signature
          </span>
        </label>
        <label class="stack" style={{ gap: "6px" }}>
          <span class="muted">シグナリング URL (任意)</span>
          <input
            type="url"
            placeholder="wss://example.com/signal"
            value={signalUrl()}
            onInput={(e) => setSignalUrl(e.currentTarget.value)}
          />
        </label>
        {err() && (
          <div class="notice error" role="alert">
            {err()}
          </div>
        )}
        <button class="primary" type="submit">
          接続
        </button>
        <p class="muted" style={{ "font-size": "12px" }}>
          URL の <code>#token=...</code> ハッシュからも自動取り込みされます。
        </p>
      </form>
    </div>
  );
};
