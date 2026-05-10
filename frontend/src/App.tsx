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
  // Issue #91: NGN→PWA 着信フローで sabiden 側が trickle ICE で host
  // candidate を 1 つ push してくる (RFC 8839 §4 trickle ICE)。
  // ブラウザ PeerConnection は応答ボタン押下時に初めて生成されるため、
  // それ以前に届いた ICE candidate を捨てると ICE 確立が遅延 / 失敗する。
  // バッファに溜め、 acceptIncomingOffer / placeCall で call を生成した
  // 直後に flush する (W3C WebRTC §4.4.6: setRemoteDescription 前の
  // candidate は buffer 推奨)。
  let pendingIceCandidates: string[] = [];

  const teardownCall = () => {
    call?.hangup();
    call = null;
    pendingIceCandidates = [];
  };

  /** バッファ済 ICE candidate を call に流し込む (失敗は warn のみ). */
  const flushPendingIce = async () => {
    if (!call || pendingIceCandidates.length === 0) return;
    const buffered = pendingIceCandidates;
    pendingIceCandidates = [];
    for (const cand of buffered) {
      try {
        await call.addIce(cand);
      } catch (e) {
        console.warn("flushPendingIce: addIce failed", e);
      }
    }
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
        // Issue #91: 新着信受信時に古い ICE buffer は捨てる (teardownCall が
        // pendingIceCandidates をクリアする)。 ただし新着信に紐づく ICE は
        // この行以降に到達するので、 teardownCall は offer 受信時 1 回だけ。
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
        // Issue #91: call が無ければ buffer に積む (RFC 8839 §4 trickle ICE
        // のうち remote description / PeerConnection 未確立期間の candidate は
        // 受信側で buffer すべき)。 acceptIncomingOffer / placeCall 後に flush。
        if (call) {
          await call.addIce(msg.candidate);
        } else {
          pendingIceCandidates.push(msg.candidate);
        }
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
            // 文言は onClosedReason で reason 別に上書きされる。
            setStatusOk(false);
            break;
        }
      },
      onClosedReason: (reason) => {
        // Issue #127: 自動再接続を諦めた理由を UI に表示する。
        // `auth` / `exhausted` の場合 token を入れ直さない限り復旧できないため、
        // signaling 参照を破棄 + token を invalidate + login view に自動遷移
        // させる (review #2)。 そうしないと dialer view に居続けて
        // 「disposed な signaling instance を握ったまま」 race の温床になる。
        switch (reason) {
          case "normal":
            setStatus("切断");
            break;
          case "auth":
            setStatus("認証失敗 (token を入れ直してください)");
            // disposed instance race を防ぐため参照を切る。
            signaling = null;
            teardownCall();
            clearToken();
            setView({ kind: "login" });
            break;
          case "exhausted":
            setStatus("接続不可 (再ログインしてください)");
            signaling = null;
            teardownCall();
            // exhausted は token 自体は有効かもしれないが、 ネットワーク復旧
            // 後にユーザが明示的にログインし直す方が安全 (古い token で
            // 即再接続して 401 ループを再発させるリスク回避)。
            clearToken();
            setView({ kind: "login" });
            break;
        }
        setStatusOk(false);
      },
    });
    try {
      await signaling.connect();
      setView({ kind: "dialer" });
    } catch (e) {
      console.error(e);
      // Issue #127 review #2 race fix:
      //   onClosedReason は ws.onclose 内で同期的に発火し、 そこで signaling=null +
      //   setView({kind:"login"}) を済ませている可能性がある (auth / exhausted)。
      //   その後で connect() Promise が reject され、 ここの catch に入る。
      //   何もチェックせず setView({kind:"dialer"}) に上書きすると、 onClosedReason
      //   が決めた login view を握り潰してしまう (= ユーザが認証失敗時に dialer に
      //   戻されて再ログインの導線を失う)。 onClosedReason 側が既に終端状態を確定
      //   していたら (signaling 参照が null になっていたら) ここでは何もしない。
      if (signaling === null) {
        return;
      }
      // 初回 connect の resolve は失敗したが、 SignalingClient は内部で
      // backoff 再接続を継続している (transient close)。 ユーザーには再接続中で
      // あることを示し、 dialer view には移行する (発信ボタンは statusOk で disable)。
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
      // Issue #145: PWA→NGN 発信。 ダイアル番号を `target` で渡すと
      // sabiden は browser に SAVPF answer を返した上で AVP/PCMU SDP の
      // INVITE を NGN へ出す (RFC 3264 §5)。
      await call.createOffer(number);
      // Issue #91: call 生成前に届いた ICE candidate を flush。
      await flushPendingIce();
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
      // Issue #91: ringing 中に届いていた ICE candidate を flush。
      // setRemoteDescription 完了 (acceptIncomingOffer 内) 後に流す必要がある。
      await flushPendingIce();
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
