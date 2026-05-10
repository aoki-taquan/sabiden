import { createEffect, createSignal, onCleanup, onMount, Show, type Component } from "solid-js";

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
    }
    timer = window.setInterval(() => {
      if (props.state === "connected") setSeconds((s) => s + 1);
    }, 1000);
  });

  // `remoteStream` は ontrack で後から差し込まれる (特に着信経路では応答後)。
  // onMount 時点では null なことがあるので createEffect で props 変化に追従する。
  createEffect(() => {
    const stream = props.remoteStream;
    if (audioEl && stream && audioEl.srcObject !== stream) {
      const tracks = stream.getTracks();
      console.log("[PWA/audio] srcObject set", {
        track_count: tracks.length,
        tracks: tracks.map((t) => ({
          kind: t.kind,
          enabled: t.enabled,
          muted: t.muted,
          readyState: t.readyState,
        })),
      });
      audioEl.srcObject = stream;
      audioEl
        .play()
        .then(() =>
          console.log("[PWA/audio] play() ok", {
            paused: audioEl!.paused,
            muted: audioEl!.muted,
            volume: audioEl!.volume,
          }),
        )
        .catch((e) =>
          console.warn(
            "[PWA/audio] play() blocked",
            e,
            "← どこかクリックすると Firefox の autoplay restriction が解除されます",
          ),
        );

      // RTP が来てるかを 3 秒おきに統計確認 (デバッグ用)。
      // createEffect は `props.remoteStream` 変化で再走するため、 interval id を
      // onCleanup でこの effect run の終了 (= 次走 / unmount) 時に必ず clear する。
      // これがないと effect 再走毎に interval が累積し、 unmount しても leak する
      // (SolidJS reactivity guide: onCleanup inside an effect runs on re-execution
      // and on owner disposal).
      const id = window.setInterval(() => {
        if (!audioEl?.srcObject) {
          window.clearInterval(id);
          return;
        }
        const at = stream.getAudioTracks()[0];
        if (at) {
          console.log("[PWA/audio] track tick", {
            elapsed_s: audioEl.currentTime,
            paused: audioEl.paused,
            muted: at.muted,
            enabled: at.enabled,
            readyState: at.readyState,
          });
        }
      }, 3000);
      onCleanup(() => window.clearInterval(id));
    }
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

  const hangupLabel = (p: CallScreenProps): string => {
    if (p.state === "ended") return "閉じる";
    if (p.incoming && p.state === "ringing") return "拒否";
    return "切断";
  };

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
          {hangupLabel(props)}
        </button>
      </div>
    </div>
  );
};
