import { createSignal, type Component } from "solid-js";
import { saveSignalUrl, saveToken } from "../lib/storage";
import { resolveSignalingUrl } from "../lib/signaling";

export const Login: Component<{ onSubmit: (token: string) => void }> = (props) => {
  const [token, setToken] = createSignal("");
  const [signalUrl, setSignalUrl] = createSignal(resolveSignalingUrl());
  const [err, setErr] = createSignal<string | null>(null);

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
      <form class="stack" onSubmit={submit} style={{ "margin-top": "20px" }}>
        <label class="stack" style={{ gap: "6px" }}>
          <span class="muted">アクセストークン (HMAC)</span>
          <input
            type="password"
            autocomplete="off"
            placeholder="ext.expiry.signature"
            value={token()}
            onInput={(e) => setToken(e.currentTarget.value)}
            required
          />
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
        {err() && <div class="notice error">{err()}</div>}
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
