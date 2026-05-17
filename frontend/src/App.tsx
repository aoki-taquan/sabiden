import {
  createSignal,
  Match,
  onCleanup,
  onMount,
  Switch,
  type Component,
} from "solid-js";
import { Login, type LoginReason } from "./components/Login";
import { Dialer } from "./components/Dialer";
import { CallScreen } from "./components/CallScreen";
import {
  parseExtIdFromToken,
  parseRateLimitedRetryAfter,
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
import { enablePushNotifications } from "./lib/push";

/**
 * View 状態 (Issue #142): `login` は再ログイン理由 `reason` を optional で
 * 持てる discriminated union。 `auth`/`exhausted` 時に SignalingClient
 * `onClosedReason` で受け取った値をそのまま流す
 * (`./components/Login::LoginReason` を参照)。
 */
type View =
  | { kind: "login"; reason?: LoginReason }
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
  /**
   * Issue #194: backend rate limiter / NGN 503 Retry-After で発信抑制中の
   * 解除予定時刻 (epoch ms)。 `null` なら抑制なし。 Date.now ベースなので
   * WS が再接続しても期限が残っていれば適用継続する (Issue DoD)。
   */
  const [rateLimitedUntil, setRateLimitedUntil] = createSignal<number | null>(null);
  /** 1 秒毎にカウントダウンを更新する派生値 (now() を 1Hz で進める)。 */
  const [now, setNow] = createSignal<number>(Date.now());
  /**
   * UI に渡す「残り秒数」 (切り上げ)。 0 以下は `null` (= 抑制解除)。
   * カウントダウンは Date.now() ベース。 `setInterval` がブラウザ throttle で
   * 大幅遅延しても、 復帰時に Date.now で再計算するので「ボタンが N+α 秒残る」
   * バグを防ぐ。
   */
  const rateLimitedSeconds = (): number | null => {
    const until = rateLimitedUntil();
    if (until === null) return null;
    const remaining = Math.ceil((until - now()) / 1000);
    return remaining > 0 ? remaining : null;
  };
  let countdownTimer: number | undefined;

  /**
   * Issue #294: PWA Web Push 機能の状態。
   * - `pushAvailable`: backend が VAPID 公開鍵を返す (= 機能有効) かを起動時 probe
   * - `pushSubscribed`: 現在 push subscription を持っている (= 通知が来る) か
   */
  const [pushAvailable, setPushAvailable] = createSignal(false);
  const [pushSubscribed, setPushSubscribed] = createSignal(false);

  let signaling: SignalingClient | null = null;
  let call: WebRtcCall | null = null;
  // Issue #91: NGN→PWA 着信フローで sabiden 側が trickle ICE で host
  // candidate を 1 つ push してくる (RFC 8839 §4 trickle ICE)。
  // ブラウザ PeerConnection は応答ボタン押下時に初めて生成されるため、
  // それ以前に届いた ICE candidate を捨てると ICE 確立が遅延 / 失敗する。
  // バッファに溜め、 acceptIncomingOffer / placeCall で call を生成した
  // 直後に flush する (W3C WebRTC §4.4.6: setRemoteDescription 前の
  // candidate は buffer 推奨)。
  //
  // Issue #173 (race fix): 旧実装は `pendingIceCandidates: string[]` + `teardownCall`
  // で配列を空に再代入していたため、 以下 2 race を踏んでいた:
  //   (R1) WS が "offer" の前に新着信の "ice" を先送りしてくる順序差 (RFC 8839
  //        §4.2 trickle ICE は任意順序を許す) で、 buffer に積んだ ICE を
  //        後続 offer ハンドラ内 `teardownCall()` が wipe する → 新着信の ICE
  //        が消える。
  //   (R2) `flushPendingIce` ループの `await call.addIce(cand)` の合間に
  //        "bye"/"cancel" 受信 → `teardownCall()` で `call=null` + buffer 空、
  //        ループは古い `buffered` 参照で続行し、 hangup 済 PC への addIce で
  //        warn が出る (実害は無いが診断ノイズ)。
  //
  // 修正: ICE candidate を **dialog epoch (call 世代カウンタ)** でタグ付けする。
  //   - `teardownCall()` は epoch++ するだけ (buffer 配列再代入は不要)
  //   - "ice" 受信時は **その時点の epoch を snapshot** して push
  //   - `flushPendingIce()` は **現 epoch と一致するエントリだけ** addIce する
  //
  // これにより:
  //   - R1 解消: offer → teardownCall (epoch=N→N+1) → 以後の ICE は epoch=N+1 で
  //     buffer。 ringing 中に到達した ICE は新 epoch なので Accept 時 flush で
  //     正しく適用される。
  //   - R2 解消: bye 受信 → teardownCall (epoch++) → 進行中の flushPendingIce
  //     ループは次イテレーションで epoch 不一致になり addIce を skip する。
  //
  // 単一スレッド JS なので epoch の読み書きは torn read 不可能 (W3C HTML Living
  // Standard §8.1.4: 各タスク / microtask は他タスクと並行実行されない)。
  // Mutex / Promise.race 風の lock は不要。
  type PendingIce = { epoch: number; candidate: string };
  let pendingIceCandidates: PendingIce[] = [];
  let dialogEpoch = 0;

  const teardownCall = () => {
    call?.hangup();
    call = null;
    // epoch++ で在庫 ICE を「現役外」 にする。 配列は次回 flush または次回
    // teardown 時に世代不一致エントリを一括破棄するので、 ここでは触らない
    // (Issue #173 の race avoidance、 上記コメント R1 参照)。
    dialogEpoch += 1;
  };

  /** バッファ済 ICE candidate のうち **現 epoch と一致するもの** だけを
   * call に流し込む (失敗は warn のみ)。 不一致エントリ (= 過去 dialog 由来) は
   * 破棄する (Issue #173)。 */
  const flushPendingIce = async () => {
    if (!call) return;
    const currentEpoch = dialogEpoch;
    // 現 epoch 一致分を取り出す。 不一致 (= 古い) は drop。
    // 取り出した時点で buffer を空にして、 await 中に届く新着 ICE は
    // 新規エントリとして残る (= flush 後の取りこぼし無し: call は既に
    // 立ち上がっているので、 "ice" ハンドラの `if (call)` 分岐で直接
    // addIce される)。
    const buffered = pendingIceCandidates.filter((p) => p.epoch === currentEpoch);
    pendingIceCandidates = [];
    for (const { candidate } of buffered) {
      // ループ中に teardownCall が走った場合は epoch が進んで `call` も null。
      // 次イテレーションで両方を確認して即抜ける。
      if (!call || dialogEpoch !== currentEpoch) return;
      try {
        await call.addIce(candidate);
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
        // Issue #91/#173: 旧 dialog をクリーンアップする (teardownCall が
        // dialogEpoch++ で旧 dialog の在庫 ICE を「現役外」 にする)。 新 dialog
        // の ICE は この行以降に到達するため新 epoch でタグ付けされる
        // (= teardownCall に wipe されない、 race 修正の本丸)。
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
        //
        // Issue #173: buffer 時に **現 dialog epoch を snapshot** する。
        // 後続 teardownCall で epoch が進んでも、 epoch 一致しないので flush で
        // 適用されない (= 「次の dialog の ICE と勘違いされない」 保証)。
        //
        // 単一スレッド JS なので await 直前/直後で他 task が割り込んで epoch を
        // 変えても、 push 自体は同一 microtask 内で完結する。
        if (call) {
          await call.addIce(msg.candidate);
        } else {
          pendingIceCandidates.push({ epoch: dialogEpoch, candidate: msg.candidate });
        }
        break;
      case "error":
        console.error("signaling error", msg);
        setStatus(`エラー: ${msg.code}`);
        setStatusOk(false);
        // Issue #194 / PR #193: rate_limited / outbound_failed (NGN 503 +
        // Retry-After) を検出して発信ボタンを抑制する。 retry_after は backend
        // が `ServerMessage::error.message` 本文に埋めてくる (RFC 3261 §20.33,
        // TTC JJ-90.24v2 §5.7.1 / §5.7.3)。
        if (msg.code === "rate_limited" || msg.code === "outbound_failed") {
          const secs = parseRateLimitedRetryAfter(msg.message);
          if (secs !== null && secs > 0) {
            // 既存の解除予定時刻より遠い方を採用する (重複 error 受信で短縮
            // しないため: 一度長期抑制を受けたら短い後続値で上書きしない)。
            const candidate = Date.now() + secs * 1000;
            setRateLimitedUntil((prev) => (prev === null ? candidate : Math.max(prev, candidate)));
            setNow(Date.now()); // 即座に UI を更新
          }
        }
        break;
      case "bye":
        setView((v) => (v.kind === "call" ? { ...v, state: "ended", stream: null } : v));
        teardownCall();
        break;
      case "pushsubscribed":
        // Issue #294: backend が push 購読登録を受理した。 UI 上の「通知 ON」
        // 状態をサーバ側 ack で確定させる (= browser 内 race で button が
        // 一瞬戻るのを防ぐ defensive update)。
        setPushSubscribed(true);
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
            // Issue #219: 旧 session 由来の rate-limited deadline をリセット。
            // auth エラーで強制ログアウトされた後に別ユーザ (別 ext_id) が
            // login し直したとき、 前 session の deadline が UI に残ると
            // 「context 不明の待機中」 UX バグになる。 NGN bucket は AOR 共有
            // なので backend 的には継続中だが、 UI は新 session 開始時点で
            // 一旦クリアし、 次の `rate_limited` error 受信で正しく再構成する。
            setRateLimitedUntil(null);
            // Issue #142: Login コンポーネントに理由を伝えて画面に表示する。
            setView({ kind: "login", reason: "auth" });
            break;
          case "exhausted":
            setStatus("接続不可 (再ログインしてください)");
            signaling = null;
            teardownCall();
            // exhausted は token 自体は有効かもしれないが、 ネットワーク復旧
            // 後にユーザが明示的にログインし直す方が安全 (古い token で
            // 即再接続して 401 ループを再発させるリスク回避)。
            clearToken();
            // Issue #219: 同上。 reconnect 上限到達で session が終了したので
            // UI side の rate-limited deadline もリセットする。
            setRateLimitedUntil(null);
            // Issue #142: Login コンポーネントに理由を伝えて画面に表示する。
            setView({ kind: "login", reason: "exhausted" });
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
    // Issue #194: rate-limited 残秒数を 1Hz で再計算する。 Date.now ベースで
    // 計算しているので throttle 等で interval が遅延しても誤差を蓄積しない
    // (interval は単に「再描画契機」 を作るだけ)。 setInterval の callback は
    // SolidJS reactive tracking scope ではない (= createEffect 等ではない) ため
    // `solid/reactivity` lint warning が出るが、 ここではむしろ tracking させたく
    // ない (1Hz 固定で読み出すだけ、 シグナル変化で再走させない) ので意図的に抑制。
    // eslint-disable-next-line solid/reactivity
    countdownTimer = window.setInterval(() => {
      const until = rateLimitedUntil();
      if (until === null) return;
      const t = Date.now();
      setNow(t);
      if (t >= until) {
        // 期限切れ: 抑制解除 (interval は走らせ続ける = 次の rate_limited を即反映)。
        setRateLimitedUntil(null);
      }
    }, 1000);

    // 1) URL ハッシュ #token=... を最優先で取り込み
    const hashTok = consumeTokenFromHash();
    const stored = hashTok ?? loadToken();
    if (stored) await connect(stored);

    // Issue #294: backend が VAPID 公開鍵を配信できるか (= [push] enabled で
    // 鍵が設定されている) を probe する。 200 OK なら機能有効、 503 なら無効
    // (= ボタン非表示)。 失敗時は機能無効に倒す (= 既存挙動完全互換)。
    try {
      const res = await fetch("/api/push/vapid-public-key", {
        method: "GET",
        credentials: "same-origin",
      });
      setPushAvailable(res.ok);
    } catch (_e) {
      setPushAvailable(false);
    }
  });

  onCleanup(() => {
    if (countdownTimer !== undefined) {
      window.clearInterval(countdownTimer);
      countdownTimer = undefined;
    }
  });

  const handleLogin = async (tok: string) => {
    await connect(tok);
  };

  /**
   * Issue #294: 通知有効化ボタン押下時のハンドラ。
   * Service Worker 登録 + `Notification.requestPermission()` +
   * `PushManager.subscribe` + WS `pushsubscribe` 送信を直列実行する。
   * 失敗は status text に出す (UI は disable せず再試行可能)。
   */
  const handleEnablePush = async () => {
    if (!signaling) {
      setStatus("通知有効化失敗: 未接続");
      return;
    }
    try {
      const endpoint = await enablePushNotifications(signaling, "");
      console.info("push subscription registered", endpoint);
      setPushSubscribed(true);
      setStatus("通知を有効化しました");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("enable push failed", msg);
      setStatus(`通知有効化失敗: ${msg}`);
    }
  };

  const handleLogout = () => {
    teardownCall();
    signaling?.close();
    signaling = null;
    clearToken();
    setStatus("未接続");
    setStatusOk(false);
    // Issue #219: ユーザ明示ログアウト時に rate-limited deadline をリセット。
    // 別ユーザ (別 ext_id) が同 PWA で続けて login したとき、 前ユーザの
    // 抑制カウントダウンが残ると UI が「context 不明な待機中」 になる。
    // backend bucket は AOR 共有なので再 INVITE 即時には再 rate_limited が
    // 返ってくる可能性が高いが、 そのときは正規の error 受信経路で再構築する。
    setRateLimitedUntil(null);
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
    // Issue #194: rate-limited 中は WS にも投げず、 ローカルで弾く。
    // backend (`src/call/orchestrator.rs::handle_pwa_outbound_offer`) は
    // どのみち再度 `rate_limited` を返すだけなので無駄パケットになる。
    // NGN cooldown は backend rate limiter で完結しているため、 PWA から
    // 再投しなくても NGN 連鎖は起きないが、 UI 連発抑止 / WS 帯域節約のために
    // 早期弾きする (DoD「NGN cooldown を加速させない」 を満たす)。
    if ((rateLimitedSeconds() ?? 0) > 0) {
      console.warn("placeCall: 抑制中 (rate-limited) のためローカルで拒否");
      return;
    }
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
   * 着信を応答前に拒否する (Issue #107)。
   *
   * `bye` は WS セッション (= 内線登録) ごと閉じる別物なので押さない。
   * 個別の進行中着信のみ `decline{call_id}` で sabiden に通知する (RFC 3261
   * §21.6.2 603 Decline 相当)。 sabiden は対応する fork レッグを
   * `LegResult::Failed { status: 603 }` に倒し、 他フォーク先 (SIP 内線端末)
   * が居なければ NGN へ 603 Decline を即時返す。
   *
   * 旧挙動 (Issue #107 修正前) はここで何も送らず、 サーバ側は browser
   * 応答が来ないことを fork timeout (30 秒程度) で検出していた。 これにより
   * 「拒否したのに NGN 側で 30 秒鳴り続ける」 という UX 不具合が起きていた。
   *
   * call_id が無い (= NGN 着信ではない / pendingOfferSdp なし) ケースでは
   * 何も送らない。 ローカル UI のクリーンアップだけ行う。
   *
   * 送信失敗 (WS 切断中) は silent ignore: サーバ側の `cancel_all` (WS 切断
   * ハンドラ、 Issue #117) が waiter を起こすので、 fork は遅延なく Errored
   * で抜ける。 UI は teardownCall + setView で確実に閉じる。
   */
  const rejectIncoming = () => {
    const v = view();
    if (v.kind === "call" && v.incoming && v.callId && signaling) {
      try {
        signaling.send({ type: "decline", call_id: v.callId });
      } catch (e) {
        // WS 切断中等は送れないが、 サーバ側 `cancel_all` で代替されるので
        // UI を閉じる方を優先する (silent warn のみ)。
        console.warn("rejectIncoming: decline send failed (WS closed?)", e);
      }
    }
    teardownCall();
    setView({ kind: "dialer" });
  };

  const toggleMute = (): boolean => call?.toggleMute() ?? false;

  return (
    <Switch>
      <Match when={view().kind === "login"}>
        {(() => {
          const v = view() as Extract<View, { kind: "login" }>;
          return <Login onSubmit={handleLogin} reason={v.reason} />;
        })()}
      </Match>
      <Match when={view().kind === "dialer"}>
        <Dialer
          extId={extId()}
          onCall={placeCall}
          onLogout={handleLogout}
          status={status()}
          statusOk={statusOk()}
          rateLimitedSeconds={rateLimitedSeconds()}
          onEnablePush={pushAvailable() ? handleEnablePush : undefined}
          pushSubscribed={pushSubscribed()}
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
