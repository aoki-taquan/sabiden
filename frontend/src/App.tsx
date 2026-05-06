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
        setStatus("認証済み");
        signaling?.send({ type: "register", ext_id: ext });
      },
      onClose: () => {
        setStatus("切断");
        setStatusOk(false);
      },
      onError: () => {
        setStatus("接続エラー");
        setStatusOk(false);
      },
    });
    try {
      await signaling.connect();
      setView({ kind: "dialer" });
    } catch (e) {
      console.error(e);
      setStatus("接続失敗 (トークン/URL を確認)");
      setStatusOk(false);
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

  const placeCall = async (number: string) => {
    if (!signaling) return;
    setView({
      kind: "call",
      peerLabel: number,
      state: "connecting",
      stream: null,
      incoming: false,
    });
    try {
      call = new WebRtcCall(signaling, {
        onRemoteTrack: (s) => {
          setView((v) => (v.kind === "call" ? { ...v, stream: s } : v));
        },
        onConnectionState: (s) => {
          if (s === "connected") {
            setView((v) => (v.kind === "call" ? { ...v, state: "connected" } : v));
          } else if (s === "failed" || s === "disconnected" || s === "closed") {
            setView((v) =>
              v.kind === "call" && v.state !== "ended" ? { ...v, state: "ended" } : v,
            );
          }
        },
      });
      await call.acquireMic();
      await call.createOffer();
      // INVITE 送出はサーバ側 TODO (Issue #25 と協調). offer/answer 折返しのみ動作。
    } catch (e) {
      console.error("call setup failed", e);
      setView((v) => (v.kind === "call" ? { ...v, state: "ended" } : v));
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
          return (
            <CallScreen
              peerLabel={v.peerLabel}
              state={v.state}
              remoteStream={v.stream}
              incoming={v.incoming}
              onHangup={hangup}
              onToggleMute={toggleMute}
            />
          );
        })()}
      </Match>
    </Switch>
  );
};
