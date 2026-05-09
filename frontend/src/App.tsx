import { createSignal, Match, onMount, Switch, type Component } from "solid-js";
import { Login } from "./components/Login";
import { Dialer } from "./components/Dialer";
import { CallScreen } from "./components/CallScreen";
import {
  parseExtIdFromToken,
  resolveSignalingUrl,
  SignalingClient,
  type ServerMessage,
} from "./lib/signaling";
import { WebRtcCall } from "./lib/webrtc";
import {
  clearToken,
  consumeTokenFromHash,
  loadSignalUrl,
  loadToken,
  saveSignalUrl,
} from "./lib/storage";

type View =
  | { kind: "login" }
  | { kind: "dialer" }
  | {
      kind: "call";
      peerLabel: string;
      state: "ringing" | "connecting" | "connected" | "ended";
      stream: MediaStream | null;
      incoming: boolean;
      /** NGN 着信時 sabiden 側で採番された Call-ID。answer 送信時に必要。 */
      callId: string | null;
      /** 着信中で、応答前の生 offer SDP。応答ボタンで `acceptIncomingOffer` に渡す。 */
      pendingOfferSdp: string | null;
    };

export const App: Component = () => {
  const [view, setView] = createSignal<View>({ kind: "login" });
  const [extId, setExtId] = createSignal<string>("");
  const [status, setStatus] = createSignal("未接続");
  const [statusOk, setStatusOk] = createSignal(false);

  let signaling: SignalingClient | null = null;
  let call: WebRtcCall | null = null;

  const teardownCall = () => {
    call?.hangup();
    call = null;
  };

  const handleSignalMessage = async (msg: ServerMessage) => {
    switch (msg.type) {
      case "registered":
        setStatus(`登録済み (${msg.ext_id})`);
        setStatusOk(true);
        break;
      case "answer":
        try {
          await call?.applyAnswer(msg.sdp);
          setView((v) => (v.kind === "call" ? { ...v, state: "connected" } : v));
        } catch (e) {
          console.error("answer apply failed", e);
        }
        break;
      case "offer":
        // NGN 着信: sabiden が生成した offer をブラウザに push してきた。
        // ringing UI を出して、ユーザの応答ボタン待ち。
        // 多重着信は後勝ち (現行の View が単一通話前提なので).
        if (!signaling) break;
        teardownCall();
        // caller display name は Issue #41 のスコープ外: TODO で call_id を表示。
        setView({
          kind: "call",
          peerLabel: "着信",
          state: "ringing",
          stream: null,
          incoming: true,
          callId: msg.call_id,
          pendingOfferSdp: msg.sdp,
        });
        break;
      case "cancel":
        // 着信中に NGN 側がキャンセル → UI を閉じる。
        // call_id 不一致のものは無視 (古い着信のフラッシュ等).
        setView((v) => {
          if (v.kind !== "call") return v;
          if (v.callId !== null && v.callId !== msg.call_id) return v;
          return { ...v, state: "ended", stream: null };
        });
        teardownCall();
        break;
      case "ice":
        await call?.addIce(msg.candidate);
        break;
      case "error":
        console.error("signaling error", msg);
        setStatus(`エラー: ${msg.code}`);
        setStatusOk(false);
        break;
      case "bye":
        setView((v) => (v.kind === "call" ? { ...v, state: "ended", stream: null } : v));
        teardownCall();
        break;
    }
  };

  const connect = async (tok: string) => {
    const ext = parseExtIdFromToken(tok);
    if (!ext) {
      setStatus("トークンが不正です");
      setStatusOk(false);
      return;
    }
    setExtId(ext);
    setStatus("接続中...");
    setStatusOk(false);

    const url = loadSignalUrl() ?? resolveSignalingUrl();
    saveSignalUrl(url);

    signaling = new SignalingClient(url, tok, {
      onMessage: handleSignalMessage,
      onOpen: () => {
        // 接続確立 (初回 / 再接続いずれも) 直後に必ず Re-Register。
        // sabiden 側は WS セッション = 内線登録の lifetime なので、
        // 切断 → 再接続後は新セッションとして登録し直す必要がある (Issue #119)。
        setStatus("認証済み");
        signaling?.send({ type: "register", ext_id: ext });
      },
      onClose: () => {
        // SignalingClient が自動再接続を schedule する。 状態文言は
        // onStateChange で `reconnecting` に切替わるので、 ここでは
        // statusOk の二重打ちのみ。
        setStatusOk(false);
      },
      onError: () => {
        setStatusOk(false);
      },
      onStateChange: (s) => {
        switch (s) {
          case "idle":
            setStatus("未接続");
            setStatusOk(false);
            break;
          case "connecting":
            setStatus("接続中...");
            setStatusOk(false);
            break;
          case "open":
            // `registered` 受信時にさらに上書きするので一時的な文言。
            setStatus("認証済み");
            break;
          case "reconnecting":
            setStatus("再接続中...");
            setStatusOk(false);
            break;
          case "closed":
            setStatus("切断");
            setStatusOk(false);
            break;
        }
      },
    });
    try {
      await signaling.connect();
      setView({ kind: "dialer" });
    } catch (e) {
      console.error(e);
      // 初回 connect の resolve は失敗したが、 SignalingClient は内部で
      // backoff 再接続を継続している。 ユーザーには再接続中であることを
      // 示し、 dialer view には移行する (発信ボタンは statusOk で disable)。
      setStatus("再接続中...");
      setStatusOk(false);
      setView({ kind: "dialer" });
    }
  };

  onMount(async () => {
    // 1) URL ハッシュ #token=... を最優先で取り込み
    const hashTok = consumeTokenFromHash();
    const stored = hashTok ?? loadToken();
    if (stored) await connect(stored);
  });

  const handleLogin = async (tok: string) => {
    await connect(tok);
  };

  const handleLogout = () => {
    teardownCall();
    signaling?.close();
    signaling = null;
    clearToken();
    setStatus("未接続");
    setStatusOk(false);
    setView({ kind: "login" });
  };

  /** WebRtcCall を共通生成 (発信/着信で使い回す)。 */
  const newCall = (sig: SignalingClient): WebRtcCall =>
    new WebRtcCall(sig, {
      onRemoteTrack: (s) => {
        setView((v) => (v.kind === "call" ? { ...v, stream: s } : v));
      },
      onConnectionState: (s) => {
        if (s === "connected") {
          setView((v) => (v.kind === "call" ? { ...v, state: "connected" } : v));
        } else if (s === "failed" || s === "disconnected" || s === "closed") {
          setView((v) => (v.kind === "call" && v.state !== "ended" ? { ...v, state: "ended" } : v));
        }
      },
    });

  const placeCall = async (number: string) => {
    if (!signaling) return;
    setView({
      kind: "call",
      peerLabel: number,
      state: "connecting",
      stream: null,
      incoming: false,
      callId: null,
      pendingOfferSdp: null,
    });
    try {
      call = newCall(signaling);
      await call.acquireMic();
      await call.createOffer();
      // INVITE 送出はサーバ側 TODO (Issue #25 と協調). offer/answer 折返しのみ動作。
    } catch (e) {
      console.error("call setup failed", e);
      setView((v) => (v.kind === "call" ? { ...v, state: "ended" } : v));
      teardownCall();
    }
  };

  /** 着信応答: 保留中の offer SDP に対して answer を返送する。 */
  const acceptIncoming = async () => {
    const v = view();
    if (v.kind !== "call" || !v.incoming || !v.callId || !v.pendingOfferSdp || !signaling) {
      return;
    }
    setView({ ...v, state: "connecting", pendingOfferSdp: null });
    try {
      call = newCall(signaling);
      await call.acquireMic();
      await call.acceptIncomingOffer(v.callId, v.pendingOfferSdp);
    } catch (e) {
      console.error("accept incoming failed", e);
      setView((curr) => (curr.kind === "call" ? { ...curr, state: "ended" } : curr));
      teardownCall();
    }
  };

  const hangup = () => {
    try {
      signaling?.send({ type: "bye" });
    } catch {
      /* ignore */
    }
    teardownCall();
    setView({ kind: "dialer" });
  };

  /**
   * 着信を応答前に拒否する。
   *
   * `bye` は WS セッション (= 内線登録) ごと閉じる意味なので、
   * ringing 中に押されても送らない。ローカル UI をクリアするのみで、
   * サーバ側は browser 応答が来ないことを CANCEL タイムアウトで検出する。
   * (将来サーバが `reject` C→S に対応したらここで送信を追加する)
   */
  const rejectIncoming = () => {
    teardownCall();
    setView({ kind: "dialer" });
  };

  const toggleMute = (): boolean => call?.toggleMute() ?? false;

  return (
    <Switch>
      <Match when={view().kind === "login"}>
        <Login onSubmit={handleLogin} />
      </Match>
      <Match when={view().kind === "dialer"}>
        <Dialer
          extId={extId()}
          onCall={placeCall}
          onLogout={handleLogout}
          status={status()}
          statusOk={statusOk()}
        />
      </Match>
      <Match when={view().kind === "call"}>
        {(() => {
          const v = view() as Extract<View, { kind: "call" }>;
          // ringing 中の incoming は専用の「拒否」を出して bye で内線を落とさない。
          const onHangup = v.incoming && v.state === "ringing" ? rejectIncoming : hangup;
          return (
            <CallScreen
              peerLabel={v.peerLabel}
              state={v.state}
              remoteStream={v.stream}
              incoming={v.incoming}
              onHangup={onHangup}
              onToggleMute={toggleMute}
              onAccept={v.incoming && v.state === "ringing" ? acceptIncoming : undefined}
            />
          );
        })()}
      </Match>
    </Switch>
  );
};
