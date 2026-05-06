import { createSignal, onCleanup, onMount, Show, type Component } from "solid-js";

export type CallScreenProps = {
  peerLabel: string;
  state: "ringing" | "connecting" | "connected" | "ended";
  remoteStream: MediaStream | null;
  onHangup: () => void;
  onToggleMute: () => boolean; // returns new mute state
  onAccept?: () => void; // 着信時のみ
  incoming?: boolean;
};

export const CallScreen: Component<CallScreenProps> = (props) => {
  const [muted, setMuted] = createSignal(false);
  const [seconds, setSeconds] = createSignal(0);
  let audioEl: HTMLAudioElement | undefined;
  let timer: number | undefined;

  onMount(() => {
    if (audioEl) {
      // iOS Safari ではバックグラウンド再生に playsinline 属性が必須。
      // SolidJS の型に当該プロパティが無いので setAttribute で付ける。
      audioEl.setAttribute("playsinline", "true");
      if (props.remoteStream) {
        audioEl.srcObject = props.remoteStream;
        audioEl.play().catch((e) => console.warn("audio play blocked", e));
      }
    }
    timer = window.setInterval(() => {
      if (props.state === "connected") setSeconds((s) => s + 1);
    }, 1000);
  });

  onCleanup(() => {
    if (timer) clearInterval(timer);
  });

  const fmt = (s: number) => {
    const m = Math.floor(s / 60)
      .toString()
      .padStart(2, "0");
    const r = (s % 60).toString().padStart(2, "0");
    return `${m}:${r}`;
  };

  const toggleMute = () => setMuted(props.onToggleMute());

  return (
    <div class="call-screen">
      {/* 着信音/通話音はバックグラウンドでも継続させる autoplay 要素 */}
      <audio ref={audioEl} autoplay />
      <div>
        <p class="muted" style={{ margin: 0 }}>
          {props.incoming ? "着信中" : "通話"}
        </p>
        <h1 style={{ "margin-top": "8px" }}>{props.peerLabel}</h1>
        <Show when={props.state === "connected"}>
          <p class="muted">{fmt(seconds())}</p>
        </Show>
        <Show when={props.state === "connecting"}>
          <p class="muted">接続中...</p>
        </Show>
        <Show when={props.state === "ringing"}>
          <p class="muted">呼び出し中...</p>
        </Show>
        <Show when={props.state === "ended"}>
          <p class="muted">通話終了</p>
        </Show>
      </div>

      <div class="call-actions">
        <Show when={props.incoming && props.state === "ringing" && props.onAccept}>
          <button
            class="primary"
            onClick={props.onAccept}
            style={{ background: "var(--success)", "border-color": "var(--success)" }}
          >
            応答
          </button>
        </Show>
        <Show when={props.state === "connected"}>
          <button onClick={toggleMute}>{muted() ? "解除" : "ミュート"}</button>
        </Show>
        <button class="danger" onClick={props.onHangup}>
          {props.state === "ended" ? "閉じる" : "切断"}
        </button>
      </div>
    </div>
  );
};
