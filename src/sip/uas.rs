//! 内線 UAS (User Agent Server)
//!
//! Linphone / Zoiper 等の SIP UA を内線として受け付けるサーバ。
//! NGN 側の `Registrar` (UAC) とは別ポート・別 [`TransactionLayer`]
//! インスタンスで動かすことで、内線網と NGN 網を L4 で分離する
//! (`ARCHITECTURE.md` 参照)。
//!
//! 本モジュールは以下を担う:
//! - REGISTER の Digest 認証 (`super::auth`) と
//!   [`ExtensionRegistrar`] への登録 (RFC 3261 §10)
//! - INVITE / BYE / CANCEL / ACK / OPTIONS の最低限の応答
//! - 上位層 (Call Manager, Issue #5) への INVITE/BYE 通知 (mpsc チャネル)
//!
//! Call Manager (`UasEvent` の受信側) が未接続なら INVITE/BYE は
//! それぞれ 503 / 481 で応答する。これにより UAS 単体でも CI 上で
//! 動作確認できる。
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time;
use tracing::{debug, info, info_span, warn, Instrument};

use super::auth::{build_www_authenticate, DigestAuthorization};
use super::message::{SipMethod, SipRequest, SipResponse};
use super::registrar::ExtensionRegistrar;
use super::transaction::{
    build_response_skeleton, InboundRequest, ServerTransaction, TransactionLayer,
};
use super::utils::{has_to_tag, new_call_id, new_tag};
use crate::config::{ExtensionConfig, UasConfig};
use crate::observability::Metrics;

/// 上位層 (Call Manager) に流すイベント。
///
/// UAS 自身は通話状態を持たない。INVITE を受け取ったら認証だけ済ませて
/// そのまま上位に流し、上位が応答とブリッジを組み立てる。
#[derive(Debug)]
pub enum UasEvent {
    /// 認証済みの内線からの新規 INVITE (To-tag 無し = dialog-creating)。
    ///
    /// RFC 3261 §12.1.1 / §13.3.1: 新規 INVITE は To-tag を持たず、UAS が
    /// 応答に新しい To-tag を付けて dialog を確立する。本イベントはその
    /// 経路を上位 (Call Manager) に通知する。
    /// `responder` 経由で 1xx/2xx/4xx 等を返す。
    Invite {
        /// 認証された AOR (内線ユーザ名)。
        from_aor: String,
        /// SIP リクエスト本体 (SDP オファ含む)。
        request: SipRequest,
        /// 送信元 (応答送信先)。
        remote: SocketAddr,
        /// レスポンスを送るためのハンドル。
        responder: ResponderHandle,
    },
    /// 既存ダイアログ内の Re-INVITE (To-tag 付き = mid-dialog).
    ///
    /// RFC 3261 §14.2 (UAS Behavior on Re-INVITE) / §12.2.2 に従い、To-tag が
    /// 付いた INVITE は **既存 dialog 内の SDP renegotiation 要求** であり、
    /// 新規 dialog として扱ってはならない。Linphone 等は session-timer
    /// (RFC 4028) や hold/un-hold で Re-INVITE を投げてくるため、これを
    /// 新規 INVITE として処理すると dialog が破綻する (Issue #94)。
    ///
    /// 上位 (B2BUA) は本イベント受信時に:
    /// - 既存 dialog (Call-ID + From-tag + To-tag で同定) を lookup する
    ///   - 見つからない、 かつ進行中 INVITE もない: 481 Call/Transaction
    ///     Does Not Exist (RFC 3261 §12.2.2)
    ///   - 見つからないが **進行中 INVITE がある** (初回 INVITE 完了前の
    ///     Re-INVITE 競合): 491 Request Pending (RFC 3261 §14.2)
    /// - 見つかれば NGN レッグへ Re-INVITE を伝搬し、200 OK を内線へ返す。
    ///   200 OK の To-tag は **既存 dialog の local-tag を保持** する
    ///   (= 受信 INVITE の To-tag をそのままエコーする)
    ///   (RFC 3261 §12.2.2)。
    Reinvite {
        /// SIP リクエスト本体 (新 SDP offer 含む)。
        request: SipRequest,
        /// 送信元。
        remote: SocketAddr,
        /// レスポンス送出ハンドル。
        responder: ResponderHandle,
    },
    /// 既存ダイアログに対する BYE。`responder` で 200 OK を返す。
    Bye {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
    /// 進行中 INVITE への CANCEL (RFC 3261 §9). `responder` は CANCEL 自身の
    /// 200 OK を返すために使う (元 INVITE は別途 487 で閉じる必要がある)。
    Cancel {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
    /// 内線からの ACK (2xx 確定後)。RFC 3261 §17.1.1.3 に従い応答は不要なので
    /// `responder` は持たず、上位層が必要なら通話状態を Connected に遷移させる
    /// マーカとして使う。
    Ack {
        request: SipRequest,
        remote: SocketAddr,
    },
    /// 既存ダイアログに対する INFO (RFC 6086)。
    ///
    /// 主用途は DTMF 中継 (Issue #69 / RFC 4733 + RFC 6086)。
    /// 内線 UA が `application/dtmf-relay` または `application/dtmf` body で
    /// DTMF を送る場合、上位層 (`UasEventHandler`) が NGN レッグへ
    /// RFC 4733 telephone-event RTP packet として変換する。
    ///
    /// `responder` は INFO 自身の 200 OK を返すために使う。本実装は INFO の
    /// 応答コードを上位層に委ねる (RFC 6086 §3 / §4)。
    Info {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
    /// 内線が登録抹消した (REGISTER expires=0、または期限切れ purge 検出)。
    /// RFC 3261 §10.2.1.1 / §10.3 に従う。Issue #68 の dialog 完全クローズ
    /// 連鎖のため、上位 (B2BUA) はこのイベントを受けたら `OutboundCallRegistry`
    /// 上の対応する通話を全て NGN へ BYE で閉じる責務を負う。
    /// 内線がサイレント切断 (BYE を送らずに居なくなる) してもダイアログ漏れを
    /// 防ぐためのフック。
    Unregister {
        /// 抹消された AOR (内線ユーザ名)。
        aor: String,
    },
    /// 内線からの **REFER** (call transfer 要求、 RFC 3515)。
    ///
    /// RFC 3515 §2.4.6: REFER は転送 (call transfer) を要求するメソッド。
    /// transferor (= REFER を送ってきた内線 A) が確立済み dialog 内で送信し、
    /// `Refer-To` ヘッダに転送先 (内線 B) の SIP URI を載せる。 RFC 3515 §2.4.4:
    /// > "Upon receipt of a REFER request, an implicit subscription is created
    /// >  to the 'refer' event package."
    ///
    /// 上位 (B2BUA) は本イベントを受けたら:
    /// 1. **202 Accepted** を返す (RFC 3515 §2.4.6)
    /// 2. implicit subscription を開始し、 `Event: refer` + sipfrag NOTIFY を
    ///    transferor へ送出 (RFC 3265 §3.1.2 + RFC 3515 §2.4.5)
    /// 3. Refer-To 内線へ新 INVITE を発信 (B2BUA 経路)
    /// 4. 新 INVITE の最終応答に応じて sipfrag NOTIFY (`SIP/2.0 200 OK` 等) を
    ///    transferor へ送出 + Subscription-State: terminated で subscription 終了
    /// 5. 新 INVITE が 2xx で確立した場合、 元 dialog (transferor ↔ NGN) を
    ///    BYE で終了 (RFC 3261 §15.1.1)
    ///
    /// NGN 側からの REFER (carrier 由来) は本実装の scope 外 (Issue #289)。
    Refer {
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    },
}

/// 1 リクエストに対応するサーバ トランザクションの操作ハンドル。
///
/// 内部で [`ServerTransaction`] を `Arc<Mutex>` 共有することで、
/// 上位層が複数回 (1xx → 2xx 等) 応答できるようにする。
#[derive(Clone)]
pub struct ResponderHandle {
    inner: Arc<Mutex<ServerTransaction>>,
}

impl std::fmt::Debug for ResponderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderHandle").finish_non_exhaustive()
    }
}

impl ResponderHandle {
    /// `ServerTransaction` から `ResponderHandle` を構築する。
    ///
    /// 通常経路では [`ExtensionUas::handle_request`] 内でしか作られないが、
    /// クレート内のテストハーネス (`crate::testing::builders`) からも
    /// 構築できるよう `pub(crate)` で公開する。production-side test hook
    /// (CLAUDE.md §6.3) ではなく、純粋なクレート内コンストラクタ。
    pub(crate) fn new(tx: ServerTransaction) -> Self {
        Self {
            inner: Arc::new(Mutex::new(tx)),
        }
    }

    /// 任意の応答を送信する。
    pub async fn respond(&self, response: SipResponse) -> Result<()> {
        let mut tx = self.inner.lock().await;
        tx.respond(response).await
    }

    /// 元リクエストから組み立てた簡易応答を送る。
    ///
    /// RFC 3261 §8.2.6.2 (Headers and Tags):
    /// > The To header field in a response (with the exception of the 100
    /// > (Trying) response, in which a tag is permitted but not required)
    /// > MUST contain a tag.
    ///
    /// initial INVITE / REGISTER などの「To に tag が無い」リクエストに対する
    /// final 応答 (200 OK / 4xx / 5xx / 6xx) と provisional 1xx (180 Ringing
    /// 等; 100 Trying は除外) は、UAS が新しい To-tag を付けて返す責務を負う
    /// (Issue #100)。`quick` は CANCEL 200 OK / REGISTER 403 / INVITE 4xx 5xx
    /// 等の **dialog を作らない final 応答** で多用されるため、ここで
    /// `ensure_to_tag` を通さないと strict UA (Asterisk pjsip 旧版 / Cisco /
    /// Polycom) が応答を silently drop する。100 Trying のみ §8.2.6.2 の
    /// 例外条項に従い tag 付与をスキップする (許容はされるが必須ではなく、
    /// `request()` 由来の To に既に tag が無いまま発射される)。
    ///
    /// 既に To に tag がある (in-dialog request への応答 = BYE 200 OK 等) は
    /// `ensure_to_tag` 内で no-op になるため副作用なし。
    pub async fn quick(&self, status: u16, reason: &str) -> Result<()> {
        let mut resp = {
            let tx = self.inner.lock().await;
            build_response_skeleton(tx.request(), status, reason)
        };
        if status != 100 {
            ensure_to_tag(&mut resp);
        }
        self.respond(resp).await
    }

    /// ボディ付き応答を送る。
    ///
    /// 200 OK + `application/sdp` で SDP answer を内線に返したい等、
    /// `quick` ではボディを乗せられない用途のためのヘルパ。
    /// To タグが未付与なら付与する (RFC 3261 §8.2.6.2)。
    pub async fn respond_with_body(
        &self,
        status: u16,
        reason: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<()> {
        let mut resp = {
            let tx = self.inner.lock().await;
            build_response_skeleton(tx.request(), status, reason)
        };
        if !body.is_empty() {
            resp.headers.set("Content-Type", content_type);
            resp.body = body;
        }
        ensure_to_tag(&mut resp);
        self.respond(resp).await
    }

    /// `Allow` ヘッダ付きの簡易応答を送る (RFC 3261 §8.2.1 / §20.5)。
    ///
    /// `405 Method Not Allowed` / `481 Call/Transaction Does Not Exist` /
    /// `489 Bad Event` 等の **拒否応答** では `Allow` ヘッダで UAS が処理可能な
    /// method を列挙するのが MUST (RFC 3261 §8.2.1: "MUST also generate an
    /// Allow header field listing the set of methods supported by the UAS")。
    /// `MESSAGE` の `200 OK` 受け流し (RFC 3428 §7) など、 拒否ではない応答でも
    /// capability 広告のため Allow を付けて返すのが推奨される (§20.5)。
    ///
    /// 内線側 UAS の method 別 default 応答 (Issue #273) で使う。
    /// 100 Trying 以外は `ensure_to_tag` で To-tag を保証する (§8.2.6.2)。
    pub async fn quick_with_allow(&self, status: u16, reason: &str, allow: &str) -> Result<()> {
        let mut resp = {
            let tx = self.inner.lock().await;
            build_response_skeleton(tx.request(), status, reason)
        };
        resp.headers.set("Allow", allow);
        if status != 100 {
            ensure_to_tag(&mut resp);
        }
        self.respond(resp).await
    }
}

/// RFC 3261 §8.2.1 / §20.5: 内線 UAS が **実装経路を持つ** method 列。
/// 405 / 481 / 489 等の拒否応答 (および MESSAGE の 200 OK 受け流し) に
/// 必ず添える `Allow` ヘッダ値。 §20.5 「a list of methods that the UA
/// implementing this header supports」に合わせ、 拒否 default を返すだけの
/// method (NOTIFY / SUBSCRIBE / PUBLISH / UPDATE / PRACK / MESSAGE)
/// は意図的に列挙から除外する。
///
/// Issue #289 で REFER (RFC 3515 §2.4.6) を実装したため、 内線 UAS の
/// `Allow` に REFER も追加する。 これにより内線 UA は capability ネゴ後に
/// REFER による call transfer を発行できる。
///
/// NGN inbound 側 (`src/call/orchestrator.rs::SUPPORTED_METHODS_ALLOW`) は
/// carrier から sabiden への REFER を実装しない (Issue #289 scope 外) ため
/// REFER を含めない。 内線/NGN で対応 method が違うので別定義で持つ
/// (Issue #273)。
const SUPPORTED_METHODS_ALLOW: &str = "INVITE, ACK, BYE, CANCEL, OPTIONS, REFER";

/// 設定済みの内線アカウント表 (username → password)。
type AuthDb = HashMap<String, String>;

/// 内線 UAS。`bind` でソケットを開き、`with_handler` で上位イベント送信先を
/// 渡してから `run` で受信ループに入る。
pub struct ExtensionUas {
    config: UasConfig,
    auth_db: AuthDb,
    socket: Arc<UdpSocket>,
    /// `TransactionLayer` の所有権を保持する。Drop されると内部 spawn の
    /// 受信ループが停止するため、UAS の生存期間中は手放さない。
    /// (将来 ServerTransaction の登録/再送制御で使う場合は public API を生やす。)
    _layer: Arc<TransactionLayer>,
    registrar: Arc<ExtensionRegistrar>,
    inbound_rx: mpsc::UnboundedReceiver<InboundRequest>,
    event_tx: Option<mpsc::UnboundedSender<UasEvent>>,
    /// 観測カウンタ。internal `extension_registered` gauge を更新する。
    metrics: Arc<Metrics>,
    /// Issue #299: 受信した MESSAGE 本文を保存する ring buffer。 `None` のとき
    /// MESSAGE は従来通り 200 OK で受け流すのみ (本文は破棄)、 `Some` のとき
    /// `text/plain` body を抽出して push する (RFC 3428 §10)。
    message_log: Option<Arc<crate::call::message_log::MessageLog>>,
}

impl ExtensionUas {
    /// UDP ソケットを bind して UAS を初期化する。
    pub async fn bind(config: UasConfig, extensions: &[ExtensionConfig]) -> Result<Self> {
        Self::bind_with_metrics(config, extensions, Metrics::new()).await
    }

    /// メトリクス付き bind。
    pub async fn bind_with_metrics(
        config: UasConfig,
        extensions: &[ExtensionConfig],
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind(config.bind_addr).await?);
        info!("内線 UAS bind: {}", config.bind_addr);
        let (layer, inbound_rx) = TransactionLayer::spawn(socket.clone());
        let auth_db = extensions
            .iter()
            .map(|e| (e.username.clone(), e.password.clone()))
            .collect();
        Ok(Self {
            config,
            auth_db,
            socket,
            _layer: layer,
            registrar: ExtensionRegistrar::new(),
            inbound_rx,
            event_tx: None,
            metrics,
            message_log: None,
        })
    }

    /// Call Manager (#5) との接続用 mpsc チャネルを設定する。
    /// 呼ばなければ INVITE は 503、BYE は 481 で応答する。
    pub fn with_handler(mut self, event_tx: mpsc::UnboundedSender<UasEvent>) -> Self {
        self.event_tx = Some(event_tx);
        self
    }

    /// Issue #299: 受信 MESSAGE 本文を保存する ring buffer を注入する (RFC 3428 §7)。
    /// 呼ばなければ MESSAGE は body 破棄して 200 OK で受け流すのみ (従来挙動)。
    pub fn with_message_log(mut self, log: Arc<crate::call::message_log::MessageLog>) -> Self {
        self.message_log = Some(log);
        self
    }

    /// 内線登録テーブルへの参照。Call Manager がフォーク先を引くのに使う。
    pub fn registrar(&self) -> Arc<ExtensionRegistrar> {
        self.registrar.clone()
    }

    /// 受信ソケットへの参照。テストや、内線網用 UAC の構築時に
    /// 同じ bind addr を使い回したいケースで利用する。
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// 受信ループを駆動している `TransactionLayer` への参照。
    /// 上位層 (B2BUA) が内線レッグへ in-dialog リクエスト (BYE 等) を
    /// `send_request` で送るために必要。
    pub fn layer(&self) -> Arc<TransactionLayer> {
        self._layer.clone()
    }

    /// 受信ループ。`Ctrl-C` などで中断されるまで終了しない。
    pub async fn run(mut self) -> Result<()> {
        // 期限切れエントリを掃除するタスクを並走させる。同時に
        // `extension_registered` gauge をスナップショット長で更新する。
        // Issue #68: 期限切れで失効した AOR は B2BUA 上位へ
        // `UasEvent::Unregister` を送って NGN レッグを BYE で閉じさせる
        // (内線がサイレント切断したケースの dialog 漏れ防止)。
        let registrar = self.registrar.clone();
        let metrics = self.metrics.clone();
        let event_tx = self.event_tx.clone();
        tokio::spawn(async move {
            let mut ticker = time::interval(Duration::from_secs(30));
            loop {
                ticker.tick().await;
                let removed_aors = registrar.purge_expired_returning_removed().await;
                if !removed_aors.is_empty() {
                    debug!(
                        "内線登録 {} 件を期限切れ削除: {:?}",
                        removed_aors.len(),
                        removed_aors
                    );
                    if let Some(tx) = &event_tx {
                        for aor in removed_aors {
                            let _ = tx.send(UasEvent::Unregister { aor });
                        }
                    }
                }
                let n = registrar.snapshot().await.len() as u64;
                metrics.set_extension_registered(n);
            }
        });

        while let Some(inbound) = self.inbound_rx.recv().await {
            self.handle_request(inbound).await;
        }
        Ok(())
    }

    async fn handle_request(&self, inbound: InboundRequest) {
        let InboundRequest { request, remote } = inbound;
        let method = request.method.clone();
        let call_id = request
            .headers
            .get("call-id")
            .map(str::to_string)
            .unwrap_or_else(|| "<no-call-id>".to_string());
        let span = info_span!(
            "uas_request",
            call_id = %call_id,
            method = %method,
            direction = "extension",
        );
        async move {
            debug!(?method, %remote, "内線リクエスト受信");

            // ServerTransaction を作成 (Via/branch から ID 生成失敗 = 不正パケット)
            let server_tx =
                match ServerTransaction::new(request.clone(), remote, self.socket.clone()) {
                    Ok(tx) => tx,
                    Err(e) => {
                        warn!(error=%e, "ServerTransaction 生成失敗");
                        return;
                    }
                };
            let responder = ResponderHandle::new(server_tx);

            match method {
                SipMethod::Register => {
                    if let Err(e) = self.handle_register(&request, remote, &responder).await {
                        warn!(error=%e, "REGISTER 処理エラー");
                    }
                }
                SipMethod::Invite => {
                    if let Err(e) = self.handle_invite(&request, remote, responder).await {
                        warn!(error=%e, "INVITE 処理エラー");
                    }
                }
                SipMethod::Bye => {
                    self.handle_bye(request.clone(), remote, responder).await;
                }
                SipMethod::Cancel => {
                    // CANCEL は元 INVITE と同じ branch を共有する。
                    // RFC 3261 §9.2: CANCEL 自体には 200 OK を返し、元 INVITE は
                    // 上位層 (B2BUA) が 487 Request Terminated で閉じる責務を負う。
                    let _ = responder.quick(200, "OK").await;
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(UasEvent::Cancel {
                            request,
                            remote,
                            responder,
                        });
                    }
                }
                SipMethod::Ack => {
                    // ACK 自体には応答しない (RFC 3261 §17.2.7)。
                    // 上位 (B2BUA) には通話状態の Confirmed 遷移マーカとして渡す。
                    debug!("ACK 受信 → 上位層へ転送");
                    if let Some(tx) = &self.event_tx {
                        let _ = tx.send(UasEvent::Ack { request, remote });
                    }
                }
                SipMethod::Options => {
                    // 単純な keep-alive 応答 (Linphone 等が定期送信する)
                    let _ = responder.quick(200, "OK").await;
                }
                SipMethod::Info => {
                    // RFC 6086 §3: INFO は既存ダイアログ内で送られる中間情報。
                    // 主用途は DTMF (Issue #69)。応答 (200 OK or 481) は上位層
                    // (`UasEventHandler`) に委ねる。Call Manager 未接続なら
                    // RFC 6086 §4 に従い 481 で返す (該当ダイアログ無しと同等)。
                    debug!("INFO 受信 → 上位層へ転送");
                    if let Some(tx) = &self.event_tx {
                        let event = UasEvent::Info {
                            request,
                            remote,
                            responder,
                        };
                        if tx.send(event).is_err() {
                            warn!("Call Manager 受信側が閉じている → INFO は dropped");
                        }
                    } else {
                        let _ = responder
                            .quick(481, "Call/Transaction Does Not Exist")
                            .await;
                    }
                }
                // RFC 3265 §3.2 / RFC 6665 §3.2: NOTIFY は事前に確立した
                // subscription dialog 内で送られるべき。 sabiden 内線 UAS は
                // SUBSCRIBE state machine を持たないため、 該当 subscription が
                // 存在しないとして **481 Subscription Does Not Exist** を返す。
                // 旧 catch-all 405 では IMS の reg-event NOTIFY をブロックし
                // UA 側の再送ストームを誘発していた band-aid (Issue #273、
                // CLAUDE.md §9)。 405 だと UA は「実装が無い」と判断して
                // dialog を畳むが、 481 を返すと UA は subscription state を
                // 整理して以降の NOTIFY 送信を止めるのが期待挙動。
                SipMethod::Notify => {
                    warn!("内線側 NOTIFY: 該当 subscription なし → 481 (RFC 3265 §3.2)");
                    let _ = responder
                        .quick_with_allow(
                            481,
                            "Subscription Does Not Exist",
                            SUPPORTED_METHODS_ALLOW,
                        )
                        .await;
                }
                // RFC 6665 §4.1.4 / RFC 3265 §7.2.4: SUBSCRIBE 受信時に
                // event package を実装していない UAS は **489 Bad Event** で
                // 拒否し、 `Allow-Events` ヘッダで対応 package を広告する
                // (sabiden は提供 0 個なので Allow-Events ヘッダは省略可)。
                // 内線 UA からの presence / dialog-info 等の subscribe を
                // 個別 status で reject する。
                SipMethod::Subscribe => {
                    warn!("内線側 SUBSCRIBE: 未対応 event package → 489 (RFC 6665 §4.1.4)");
                    let _ = responder
                        .quick_with_allow(489, "Bad Event", SUPPORTED_METHODS_ALLOW)
                        .await;
                }
                // RFC 3262 §4: PRACK は UAS が `Require: 100rel` 付きの 1xx を
                // 出した直後に届く ACK 相当。 内線側 UAS は 1xx を reliable で
                // 発行しないため (内線レッグは 180/183 unreliable + 200 OK のみ)、
                // PRACK が来るのは UA 側の誤実装か stale な dialog 残骸であり、
                // §4 / §7.1 に従い対応 transaction なし扱いで **481** を返す。
                SipMethod::Prack => {
                    warn!("内線側 PRACK: reliable 1xx 未発行 → 481 (RFC 3262 §4 / §7.1)");
                    let _ = responder
                        .quick_with_allow(
                            481,
                            "Call/Transaction Does Not Exist",
                            SUPPORTED_METHODS_ALLOW,
                        )
                        .await;
                }
                // RFC 3903 §6: PUBLISH は presence / event state を発行する
                // method。 sabiden 内線 UAS は EventStateCompositor を持たないが、
                // Issue #273 の方針 (受け流し) では UA の再送を止めるため
                // **200 OK** で素直に応答する (本文 = event state は破棄)。
                // RFC 3903 §6 は「UAS が PUBLISH を受け入れた場合 200 OK を
                // 返す」と規定しており、 SIP-Etag 等の補助ヘッダは optional な
                // ため省略可。
                SipMethod::Publish => {
                    debug!("内線側 PUBLISH: 200 OK で受け流し (RFC 3903 §6、 本文は破棄)");
                    let _ = responder
                        .quick_with_allow(200, "OK", SUPPORTED_METHODS_ALLOW)
                        .await;
                }
                // RFC 3311 §5.2: UPDATE は既存ダイアログの early / 確立後の
                // セッション情報更新に使う。 内線 UAS はダイアログ毎の
                // UPDATE 経路を持たない (Re-INVITE のみ対応、 §14.2 経路) ため、
                // 対応ダイアログ不在として **481** を返す。 §5.2 は
                // 「If a UAS receives an UPDATE for an existing dialog, it
                // must check ...」と規定するが、 そもそも UPDATE を解さない
                // 場合は RFC 3261 §12.2.2 に従い 481 で応答する。
                SipMethod::Update => {
                    warn!("内線側 UPDATE: 対応ダイアログ無し → 481 (RFC 3311 §5.2)");
                    let _ = responder
                        .quick_with_allow(
                            481,
                            "Call/Transaction Does Not Exist",
                            SUPPORTED_METHODS_ALLOW,
                        )
                        .await;
                }
                // RFC 3428 §7: UAS が MESSAGE をサポートしない場合でも、
                // **200 OK で受け流す** のが推奨される (UA の再送ストーム抑止)。
                // 内線 UA (Linphone / iPhone 系) は IM メッセージを発行する
                // ケースがあり、 405 で拒否すると UA 側の retry queue が
                // 詰まる band-aid 経路 (Issue #273 / CLAUDE.md §9) は維持する。
                //
                // Issue #299: `message_log` 注入時は body を抽出して ring buffer に
                // store する (RFC 3428 §10: text/plain;charset=utf-8 が IETF default)。
                // 200 OK 自体は本文の利用可否に関わらず常に返す (= 既存 UA への
                // backward compat: log 注入の有無で UA 観察動作が変わらない)。
                SipMethod::Message => {
                    if let Some(log) = self.message_log.as_ref() {
                        if let Some(sms) =
                            crate::call::message_log::sms_from_inbound_message(&request)
                        {
                            log.push(sms);
                        } else {
                            debug!(
                                "内線側 MESSAGE: text/plain でないため body 破棄 (RFC 3428 §10)"
                            );
                        }
                    }
                    debug!("内線側 MESSAGE: 200 OK (RFC 3428 §7)");
                    let _ = responder
                        .quick_with_allow(200, "OK", SUPPORTED_METHODS_ALLOW)
                        .await;
                }
                // RFC 3515 §2.4.6 / RFC 3265 §3.1.2: REFER は転送 (call
                // transfer) を要求する。 dialog 内 REFER 受信時、 上位 (B2BUA)
                // が 202 + implicit subscription + sipfrag NOTIFY + 新 INVITE
                // (Refer-To 内線へ) + 元 dialog BYE のフローを駆動する
                // (Issue #289)。 ここでは UAS は dialog state を持たないので、
                // request をそのまま `UasEvent::Refer` で上位に流す。
                //
                // 旧実装は 405 + Allow で拒否していたが (PR #274 / Issue #273)、
                // SOHO 用途で頻出する「外線通話中に内線 B につなぐ」 を実装する
                // ため 202 経路に置換した。 上位未接続のときだけ 405 で退行する
                // (call transfer は B2BUA 必須機能)。
                SipMethod::Refer => {
                    debug!("内線側 REFER → 上位 (B2BUA) へ転送");
                    if let Some(tx) = &self.event_tx {
                        let event = UasEvent::Refer {
                            request,
                            remote,
                            responder,
                        };
                        if tx.send(event).is_err() {
                            warn!("Call Manager 受信側が閉じている → REFER は dropped");
                        }
                    } else {
                        warn!("内線側 REFER: Call Manager 未接続 → 405 (RFC 3515 §4.5 fallback)");
                        let _ = responder
                            .quick_with_allow(405, "Method Not Allowed", SUPPORTED_METHODS_ALLOW)
                            .await;
                    }
                }
                // RFC 3261 §8.2.1: 未知メソッド (`SipMethod::Other`) には
                // **必ず** `Allow` ヘッダ付きの 405 で応答する義務がある。
                // Allow 欠落は §8.2.1 違反であり UA 側の実装によっては
                // 再送し続ける。 旧実装は Allow 無しで 405 を返していた
                // (Issue #273 で解消)。
                ref other => {
                    warn!(
                        ?other,
                        "内線側で未対応メソッド → 405 + Allow (RFC 3261 §8.2.1)"
                    );
                    let _ = responder
                        .quick_with_allow(405, "Method Not Allowed", SUPPORTED_METHODS_ALLOW)
                        .await;
                }
            }
        }
        .instrument(span)
        .await
    }

    /// REGISTER の Digest 認証と登録。
    ///
    /// フロー (RFC 3261 §10):
    /// 1. `Authorization` ヘッダなし → 401 + WWW-Authenticate (nonce 発行)
    /// 2. `Authorization` あり → 検証成功なら登録 + 200 OK / 失敗なら 401 (stale)
    async fn handle_register(
        &self,
        request: &SipRequest,
        remote: SocketAddr,
        responder: &ResponderHandle,
    ) -> Result<()> {
        // username は Authorization ヘッダ優先、なければ To から推測
        let auth_header = request.headers.get("authorization").map(str::to_string);

        let auth = match auth_header.as_deref() {
            Some(h) => match DigestAuthorization::parse(h) {
                Ok(a) => a,
                Err(e) => {
                    warn!(error=%e, "Authorization パース失敗");
                    return self.send_challenge(responder, "Bad Authorization").await;
                }
            },
            None => {
                return self.send_challenge(responder, "Unauthorized").await;
            }
        };

        let Some(password) = self.auth_db.get(&auth.username) else {
            warn!(user=%auth.username, "未登録ユーザの REGISTER → 403");
            return responder.quick(403, "Forbidden").await;
        };

        if !auth.verify("REGISTER", password) {
            warn!(user=%auth.username, "Digest 検証失敗 → 401");
            return self.send_challenge(responder, "Unauthorized").await;
        }

        // 認証成功 → 登録
        let aor = auth.username.clone();
        let contact_uri = request
            .headers
            .get("contact")
            .map(extract_uri_from_contact)
            .unwrap_or_else(|| format!("sip:{}@{}", aor, remote));
        let expires = parse_register_expires(request).min(self.config.max_expires);

        // RFC 3261 §10.2.1.1: expires=0 は登録抹消と等価。Issue #68 で
        // 内線サイレント切断 → NGN 側 dialog 残存 → 連続発信 486 の根因のため、
        // 抹消検出時は B2BUA 上位へ `UasEvent::Unregister` を送って通話を
        // 強制終了 (NGN へ BYE) させる。
        let is_unregister = expires == 0;
        self.registrar
            .register(
                &aor,
                contact_uri.clone(),
                remote,
                Duration::from_secs(expires.into()),
            )
            .await;
        // 観測: 登録直後に gauge を更新する (purge ループの 30 秒待たずに反映する)。
        let n = self.registrar.snapshot().await.len() as u64;
        self.metrics.set_extension_registered(n);
        if is_unregister {
            info!("内線 REGISTER 抹消: {} (expires=0)", aor);
            if let Some(tx) = &self.event_tx {
                let _ = tx.send(UasEvent::Unregister { aor: aor.clone() });
            }
        } else {
            info!(
                "内線 REGISTER 成功: {} → {} (expires={}s)",
                aor, contact_uri, expires
            );
        }

        // 200 OK + Contact + Expires
        let mut resp = build_response_skeleton(request, 200, "OK");
        ensure_to_tag(&mut resp);
        if let Some(c) = request.headers.get("contact") {
            // RFC 3261 §10.3: REGISTER の応答は登録された Contact 一覧を返す。
            // 内線用途では送ってきた値をそのまま expires 付きで返す。
            resp.headers
                .set("Contact", format!("{};expires={}", c, expires));
        }
        resp.headers.set("Expires", expires.to_string());
        responder.respond(resp).await
    }

    async fn send_challenge(&self, responder: &ResponderHandle, reason: &str) -> Result<()> {
        let nonce = new_call_id(); // 実用上十分にランダム
                                   // RFC 7616 §3.3: 初回 challenge は `stale=false`。 nonce ストア / 期限切れ
                                   // 検出は別 issue (#104 本文 §修正案) で対応するため、 現状は常に false。
                                   // `opaque` も server-side token の永続化が要るため別 issue で対応。
        let header = build_www_authenticate(&self.config.realm, &nonce, false, None);
        let mut resp = {
            let tx = responder.inner.lock().await;
            build_response_skeleton(tx.request(), 401, reason)
        };
        ensure_to_tag(&mut resp);
        resp.headers.set("WWW-Authenticate", header);
        responder.respond(resp).await
    }

    /// 内線からの INVITE を受け付ける。
    ///
    /// # 認証ポリシー (RFC 3261 §22 / Issue #62)
    ///
    /// REGISTER で確立した内線 binding を信用し、INVITE では Digest 認証を
    /// **要求しない**。RFC 3261 §22.1 は UAS が任意のリクエストに 401/407 を
    /// 返せるとしか規定しておらず、INVITE auth は実装依存。Asterisk / Kamailio /
    /// OpenSIPS など主要 OSS UAS の標準設定は「REGISTER で auth、 in-dialog や
    /// INVITE では binding を信用」であり、Linphone などのクライアントは
    /// INVITE 401 challenge に対し再 INVITE を送らない (REGISTER 済の AOR を
    /// 同じ Digest 認証で再認証する経路を持たない実装が多い)。
    ///
    /// 実機 trace (2026-05-09) で sabiden が INVITE に 401 を返したところ、
    /// Linphone は再 INVITE を送らず通話確立に失敗した。本実装は internal/VPN
    /// 信頼境界の前提 (内線網は L4 で分離、§ARCHITECTURE.md) のもと、INVITE
    /// では Authorization ヘッダの有無に関わらず検証せず、From URI のユーザ部
    /// が `ExtensionRegistrar` に登録済かどうかだけを binding 認可として用いる。
    ///
    /// - binding 有り: `UasEvent::Invite` を上位 (Call Manager) に流す
    /// - binding 無し: **403 Forbidden** で蹴る (401 challenge は意図的に出さない)
    /// - Authorization ヘッダ付きの INVITE: 検証せず無視する
    ///
    /// # Re-INVITE 分岐 (RFC 3261 §14.2 / §12.2.2 / Issue #94)
    ///
    /// 受信 INVITE の **To ヘッダに tag が付いている** 場合は in-dialog Re-INVITE
    /// (= 既存 dialog 内の SDP renegotiation / Session-Timer 更新) であり、
    /// 新規 INVITE と扱いが異なる:
    ///
    /// - 認証 (binding lookup) 済み dialog の継続なので REGISTER binding 検証を
    ///   再度行わない (in-dialog request は既存 dialog state で認可される)
    /// - From-AOR の取り出し / 未登録チェックを skip
    /// - `UasEvent::Reinvite` を上位 (B2BUA) に流す。 上位は既存 dialog を引いて
    ///   NGN レッグへ Re-INVITE を伝搬し、200 OK で答える責務を負う
    ///
    /// 100 Trying は新規 INVITE / Re-INVITE どちらも RFC 3261 §17.2.1 に従って
    /// 即時に返す。
    async fn handle_invite(
        &self,
        request: &SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) -> Result<()> {
        // RFC 3261 §14.2 / §12.2.2: To-tag 付きは in-dialog Re-INVITE。
        // 新規 INVITE 経路の binding 検証を skip し、上位 (B2BUA) に既存 dialog
        // 内 renegotiation として扱わせる。
        let is_reinvite = request.headers.get("to").map(has_to_tag).unwrap_or(false);

        if is_reinvite {
            debug!(
                "To-tag 付き INVITE = Re-INVITE → 上位へ既存 dialog 内 renegotiation として転送"
            );
            // 100 Trying を即返す (RFC 3261 §17.2.1, Re-INVITE も同様)
            responder.quick(100, "Trying").await?;
            if let Some(tx) = &self.event_tx {
                let event = UasEvent::Reinvite {
                    request: request.clone(),
                    remote,
                    responder,
                };
                if tx.send(event).is_err() {
                    warn!("Call Manager 受信側が閉じている → Re-INVITE は dropped");
                }
                return Ok(());
            } else {
                // 上位未接続 → RFC 3261 §12.2.2: 既存 dialog が引けないので
                // 481 Call/Transaction Does Not Exist で返す。
                warn!("Call Manager 未接続 → Re-INVITE 481");
                return responder
                    .quick(481, "Call/Transaction Does Not Exist")
                    .await;
            }
        }

        // From URI のユーザ部 = AOR を取り出す。取れない (壊れた From) なら
        // 4xx で蹴るしかない。RFC 3261 §8.1.1.3 で From は必須ヘッダ。
        let Some(from_aor) = request.headers.get("from").and_then(extract_user_from_addr) else {
            warn!("INVITE に From ユーザ部が無い → 400");
            return responder.quick(400, "Bad Request").await;
        };

        // REGISTER で確立した binding を信用する。未登録の AOR からの
        // INVITE は 403 で蹴る (challenge しない意図を 401 ではなく 403 で示す)。
        if self.registrar.lookup(&from_aor).await.is_none() {
            warn!(aor=%from_aor, "未登録 AOR からの INVITE → 403");
            return responder.quick(403, "Forbidden").await;
        }

        // 100 Trying を即返す (RFC 3261 §17.2.1)
        responder.quick(100, "Trying").await?;

        // 上位 (Call Manager) があれば渡す。なければ 503。
        if let Some(tx) = &self.event_tx {
            let event = UasEvent::Invite {
                from_aor,
                request: request.clone(),
                remote,
                responder,
            };
            if tx.send(event).is_err() {
                warn!("Call Manager 受信側が閉じている → 503");
                // ここでは responder は move 済みなので応答できない。
                // (Issue #5 が落ちた場合の縮退は将来課題)
            }
            Ok(())
        } else {
            warn!("Call Manager 未接続 → 503");
            responder.quick(503, "Service Unavailable").await
        }
    }

    async fn handle_bye(
        &self,
        request: SipRequest,
        remote: SocketAddr,
        responder: ResponderHandle,
    ) {
        // BYE は既存ダイアログ前提。UAS 自身は dialog テーブルを持たないので
        // 上位層 (B2BUA) に渡し、200 OK の送出は上位層に任せる。上位層が
        // 未接続のときは無害な 200 OK で閉じる (RFC 3261 §15.1.2 では
        // 「既知でなければ 481」だが、内線側 dialog 状態は B2BUA 側にしか
        // 無く、ここで 481 を返すと UA がリソース解放を後回しにする)。
        if let Some(tx) = &self.event_tx {
            if tx
                .send(UasEvent::Bye {
                    request,
                    remote,
                    responder,
                })
                .is_err()
            {
                warn!("Call Manager 受信側が閉じている → BYE は dropped");
            }
        } else {
            let _ = responder.quick(200, "OK").await;
        }
    }
}

/// REGISTER の expires を取り出す。Contact ヘッダ パラメータが優先で、
/// なければ Expires ヘッダを見る (RFC 3261 §10.2.1.1)。デフォルトは 3600。
fn parse_register_expires(request: &SipRequest) -> u32 {
    if let Some(contact) = request.headers.get("contact") {
        for part in contact.split(';') {
            if let Some(v) = part.trim().strip_prefix("expires=") {
                if let Ok(n) = v.trim_matches('"').parse::<u32>() {
                    return n;
                }
            }
        }
    }
    request
        .headers
        .get("expires")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(3600)
}

/// `From` / `To` 等の name-addr ヘッダ値から `sip:user@host` の `user` を取り出す。
///
/// RFC 3261 §20.20 / §20.39 によりヘッダ値は `name-addr` 形式
/// (`"Display" <sip:user@host>;tag=...`) または `addr-spec` 形式
/// (`sip:user@host;tag=...`) を取りうる。本ヘルパは双方を扱う。
///
/// `user` 部が無い (`sip:host` 形式) URI では `None` を返す。
fn extract_user_from_addr(value: &str) -> Option<String> {
    let trimmed = value.trim();
    // name-addr 形式なら `<...>` の中身、それ以外は先頭の `;` までを URI とする。
    let uri_part = if let Some(start) = trimmed.find('<') {
        let rest = &trimmed[start + 1..];
        rest.split_once('>').map(|x| x.0).unwrap_or(rest)
    } else if let Some((uri, _)) = trimmed.split_once(';') {
        uri
    } else {
        trimmed
    };
    // `sip:user@host` の `:` 後 → `@` 前を user とみなす。
    let after_scheme = uri_part.split_once(':').map(|x| x.1).unwrap_or(uri_part);
    after_scheme
        .split_once('@')
        .map(|(user, _)| user.to_string())
        .filter(|u| !u.is_empty())
}

/// `Contact: <sip:user@host:port>;expires=...` から URI 部分を抽出。
fn extract_uri_from_contact(contact: &str) -> String {
    let s = contact.trim();
    if let Some(start) = s.find('<') {
        if let Some(end) = s[start + 1..].find('>') {
            return s[start + 1..start + 1 + end].to_string();
        }
    }
    // `<>` 無しの場合: 先頭のセミコロンより前を URI とみなす
    s.split(';').next().unwrap_or(s).trim().to_string()
}

/// レスポンスの To に tag が無ければ付与する (RFC 3261 §8.2.6.2)。
///
/// 既存 tag の有無判定は [`has_to_tag`] (RFC 3261 §7.3.1 / §25.1 で
/// parameter name は case-insensitive) と同じヘルパに委ねる。 ナイーブに
/// `to.contains("tag=")` で判定すると、 `;TAG=existing` のような大文字
/// パラメータを「無し」と誤判定して `;tag=<new>` を末尾追加し、
/// `To: <sip:dest>;TAG=existing;tag=new` の **二重 tag** で 200 OK を返す
/// (RFC 3261 §12.2.2 違反; 内線 UA は ACK を送らず切断する) 罠がある。
/// 共通ヘルパ経由にすることで `has_to_tag` (in-dialog Re-INVITE 判定) と
/// `ensure_to_tag` (既存 tag 二重付与防止) の case-sensitivity を強制的に
/// 揃える。
fn ensure_to_tag(resp: &mut SipResponse) {
    if let Some(to) = resp.headers.get("to") {
        if !has_to_tag(to) {
            let new = format!("{};tag={}", to, new_tag());
            resp.headers.set("To", new);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::auth::{DigestChallenge, DigestCredentials};
    use crate::sip::message::{parse_message, SipMessage};
    use crate::testing::builders;
    use crate::testing::fixtures;

    /// 認証付き REGISTER の往復: クライアント側ソケットから REGISTER を送り、
    /// 401 → Authorization 付きで再送 → 200 OK を確認する。
    /// (RFC 3261 §10.2 / §22.4)
    #[tokio::test]
    async fn register_with_digest_succeeds() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();

        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        // テスト用クライアント
        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 1) 認証なし REGISTER
        let req1 = builders::register_from_phone(&local, "iphone", "z9hG4bKreg1", None);
        client.send_to(&req1.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("401 timeout")
            .unwrap();
        let resp1 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(resp1.status_code, 401);
        let www = resp1.headers.get("www-authenticate").unwrap().to_string();
        let challenge = DigestChallenge::parse(&www).unwrap();

        // 2) Authorization 付きで再送
        let creds = DigestCredentials::new("iphone", "secret");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req2 = builders::register_from_phone(
            &local,
            "iphone",
            "z9hG4bKreg2",
            Some(&auth.header_value),
        );
        client.send_to(&req2.to_bytes(), server_addr).await.unwrap();

        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("200 timeout")
            .unwrap();
        let resp2 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(resp2.status_code, 200);

        let bindings = registrar.snapshot().await;
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].0, "iphone");
    }

    /// 不正パスワードでは 401 が再度返り、登録されない。
    #[tokio::test]
    async fn register_with_wrong_password_rejected() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();

        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let req1 = builders::register_from_phone(&local, "iphone", "z9hG4bKbad1", None);
        client.send_to(&req1.to_bytes(), server_addr).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        let challenge =
            DigestChallenge::parse(resp.headers.get("www-authenticate").unwrap()).unwrap();

        let creds = DigestCredentials::new("iphone", "WRONG");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req2 = builders::register_from_phone(
            &local,
            "iphone",
            "z9hG4bKbad2",
            Some(&auth.header_value),
        );
        client.send_to(&req2.to_bytes(), server_addr).await.unwrap();

        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp2 = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(resp2.status_code, 401);
        assert!(registrar.snapshot().await.is_empty());
    }

    /// 未登録ユーザは 403。
    #[tokio::test]
    async fn unknown_user_gets_403() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 未登録ユーザで認証情報をでっち上げる
        let challenge = DigestChallenge {
            realm: "sabiden-test".into(),
            nonce: "fakenonce".into(),
            algorithm: "MD5".into(),
            qop: Some("auth".into()),
            opaque: None,
        };
        let creds = DigestCredentials::new("ghost", "anything");
        let auth = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let req = builders::register_from_phone(
            &local,
            "ghost",
            "z9hG4bKghost",
            Some(&auth.header_value),
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!(),
        };
        assert_eq!(resp.status_code, 403);
    }

    /// Issue #62 / RFC 3261 §22: 既登録 binding を持つ内線からの INVITE は
    /// Authorization ヘッダ無しでも 401 challenge せず、上位 (Call Manager) に
    /// 流す。本テストでは Call Manager 未接続のため、challenge 経由ではなく
    /// `100 Trying` に続いて `503 Service Unavailable` が返ることで確認する。
    #[tokio::test]
    async fn invite_with_existing_registration_passes_through_without_auth_challenge() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 事前に binding を直接挿入して REGISTER 往復を省略する。
        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", local),
                local,
                Duration::from_secs(60),
            )
            .await;

        // Authorization ヘッダ無し INVITE を 1 発送る (Linphone と同等の挙動)
        let req =
            builders::invite_from_phone(&local, "iphone", "sip:dest@sabiden", "z9hG4bKinv1", None);
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        // 上位層が UasEvent::Invite を受け取る (= 401 で蹴られていない)
        let event = time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("event timeout")
            .expect("event present");
        match event {
            UasEvent::Invite {
                from_aor,
                responder,
                ..
            } => {
                assert_eq!(from_aor, "iphone");
                // 上位層相当: 200 OK を返す
                responder.quick(200, "OK").await.unwrap();
            }
            other => panic!("unexpected event: {:?}", other),
        }

        // 100 Trying と 200 OK が来る (401 は来ない)
        let mut buf = vec![0u8; 4096];
        let mut saw_100 = false;
        let mut saw_2xx = false;
        for _ in 0..3 {
            match time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        assert_ne!(
                            r.status_code, 401,
                            "RFC 3261 §22 / Issue #62: 既登録 binding に対する INVITE で 401 を返してはならない"
                        );
                        match r.status_code {
                            100 => saw_100 = true,
                            s if (200..300).contains(&s) => saw_2xx = true,
                            _ => {}
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(saw_100, "100 Trying が届くべき (RFC 3261 §17.2.1)");
        assert!(saw_2xx, "200 OK が届くべき");
    }

    /// Issue #62: 未登録 AOR からの INVITE は 401 ではなく **403 Forbidden**。
    /// challenge しない意図を 401 と区別するため明示的に 403 を返す。
    #[tokio::test]
    async fn invite_without_registration_returns_403_not_401() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // REGISTER を挟まず (= binding 無し) でいきなり INVITE
        let req =
            builders::invite_from_phone(&local, "ghost", "sip:dest@sabiden", "z9hG4bKnoreg", None);
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(
            resp.status_code, 403,
            "未登録 AOR は 401 challenge ではなく 403 Forbidden"
        );
        assert!(
            resp.headers.get("www-authenticate").is_none(),
            "403 では WWW-Authenticate を付与しない (RFC 3261 §22 challenge せず)"
        );
    }

    /// Authorization ヘッダ付きの INVITE が来ても検証しない (透過)。binding 有り
    /// なら上位に流す。Issue #62 の「ヘッダは無視」要件の回帰確認。
    #[tokio::test]
    async fn invite_with_authorization_header_is_ignored_and_passes_through() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let registrar = uas.registrar();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        registrar
            .register(
                "iphone",
                format!("sip:iphone@{}", local),
                local,
                Duration::from_secs(60),
            )
            .await;

        // 検証されない (= 不正な値でも通る) ことを確認するためダミーの
        // Authorization ヘッダを乗せる。
        let bogus_auth = "Digest username=\"iphone\", realm=\"sabiden-test\", nonce=\"x\", \
                          uri=\"sip:dest@sabiden\", response=\"deadbeefdeadbeefdeadbeefdeadbeef\"";
        let req = builders::invite_from_phone(
            &local,
            "iphone",
            "sip:dest@sabiden",
            "z9hG4bKauth",
            Some(bogus_auth),
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let event = time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("event timeout")
            .expect("event present");
        assert!(matches!(event, UasEvent::Invite { .. }));
    }

    /// 既存挙動の回帰確認: BYE は元から auth 不要 (RFC 3261 §15.1.1 dialog 内
    /// request)。INVITE auth 撤廃で BYE 経路に副作用が出ないことを担保する。
    #[tokio::test]
    async fn bye_in_dialog_no_auth_challenge() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        // BYE は event_tx 未接続なら handle_bye 内で 200 OK を直接返す。
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let req = builders::bye(
            &local,
            "sip:caller@sabiden",
            "call-bye-1",
            "z9hG4bKbye",
            "from-tag",
            "to-tag",
        );
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        };
        assert_eq!(resp.status_code, 200, "BYE は 200 OK で閉じる");
        assert!(
            resp.headers.get("www-authenticate").is_none(),
            "BYE に対し challenge してはならない"
        );
    }

    #[test]
    fn extract_user_from_name_addr_with_tag() {
        // RFC 3261 §20.20 / §20.39 name-addr 形式
        assert_eq!(
            extract_user_from_addr("\"iPhone\" <sip:iphone@host>;tag=abc"),
            Some("iphone".to_string())
        );
    }

    #[test]
    fn extract_user_from_addr_spec() {
        // RFC 3261 §20.20 addr-spec 形式 (山括弧無し)
        assert_eq!(
            extract_user_from_addr("sip:iphone@host;tag=abc"),
            Some("iphone".to_string())
        );
    }

    #[test]
    fn extract_user_from_addr_without_user() {
        // ユーザ部無し → None
        assert_eq!(extract_user_from_addr("<sip:host>"), None);
    }

    #[test]
    fn parse_expires_from_contact_param() {
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers.set("Contact", "<sip:iphone@host>;expires=120");
        assert_eq!(parse_register_expires(&req), 120);
    }

    #[test]
    fn parse_expires_from_header_when_no_contact_param() {
        let mut req = SipRequest::new(SipMethod::Register, "sip:sabiden");
        req.headers.set("Contact", "<sip:iphone@host>");
        req.headers.set("Expires", "240");
        assert_eq!(parse_register_expires(&req), 240);
    }

    /// RFC 3261 §14.2 / §12.2.2 / Issue #94:
    /// 既存 dialog 内 Re-INVITE (To-tag 付き INVITE) は新規 INVITE 経路
    /// (= From-AOR 検証 + UasEvent::Invite) には流さず、`UasEvent::Reinvite`
    /// として上位へ転送する。 binding 検証も skip する (in-dialog request は
    /// 既存 dialog state で認可されるため、 REGISTER 抹消後でも Re-INVITE は
    /// 通る経路にする)。
    #[tokio::test]
    async fn rfc3261_14_2_invite_with_to_tag_dispatches_as_reinvite() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let uas = uas.with_handler(event_tx);
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // 「未登録」 AOR の Re-INVITE を流す。 既存 dialog 内 in-dialog request は
        // REGISTER binding に依らず通るのが正解 (RFC 3261 §12.2: dialog state で
        // 認可される)。 本テストでは「To-tag 付きなら from binding 検証を skip
        // する」ことを 403 が返らないことで確認する。
        let mut req =
            builders::invite_from_phone(&local, "ghost", "sip:dest@sabiden", "z9hG4bKreinv", None);
        // 既存 dialog の To-tag を付与 (mid-dialog Re-INVITE と等価)
        req.headers
            .set("To", "<sip:dest@sabiden>;tag=existing-uas-tag");

        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let event = time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("event timeout")
            .expect("event present");
        match event {
            UasEvent::Reinvite { request, .. } => {
                let to = request.headers.get("to").unwrap();
                assert!(
                    to.contains("tag=existing-uas-tag"),
                    "To-tag が保持されている"
                );
            }
            other => panic!("Re-INVITE であるべき: {:?}", other),
        }

        // 100 Trying は来る (RFC 3261 §17.2.1)。 401 / 403 は来てはいけない。
        let mut buf = vec![0u8; 4096];
        match time::timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                    assert_eq!(
                        r.status_code, 100,
                        "Re-INVITE への最初の応答は 100 Trying (RFC 3261 §17.2.1)"
                    );
                }
            }
            _ => panic!("100 Trying が来るべき"),
        }
    }

    /// 上位 (Call Manager) 未接続時の Re-INVITE は 481 Call/Transaction
    /// Does Not Exist で返す (RFC 3261 §12.2.2: 既存 dialog が引けない場合)。
    #[tokio::test]
    async fn rfc3261_12_2_2_reinvite_without_handler_returns_481() {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        // event_tx を結線せずに run (= Call Manager 未接続)
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let mut req = builders::invite_from_phone(
            &local,
            "iphone",
            "sip:dest@sabiden",
            "z9hG4bKreinv2",
            None,
        );
        req.headers
            .set("To", "<sip:dest@sabiden>;tag=stale-uas-tag");
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let mut saw_481 = false;
        for _ in 0..3 {
            match time::timeout(Duration::from_secs(1), client.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() {
                        if r.status_code == 481 {
                            saw_481 = true;
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_481,
            "Call Manager 未接続時の Re-INVITE は 481 Call/Transaction Does Not Exist (RFC 3261 §12.2.2)"
        );
    }

    #[test]
    fn extract_uri_brackets() {
        assert_eq!(
            extract_uri_from_contact("<sip:iphone@host>;expires=300"),
            "sip:iphone@host"
        );
    }

    #[test]
    fn extract_uri_no_brackets() {
        assert_eq!(
            extract_uri_from_contact("sip:iphone@host"),
            "sip:iphone@host"
        );
    }

    /// RFC 3261 §8.2.6.2 / §7.3.1 / §25.1 / §12.2.2 / PR #136 review fix:
    /// `ensure_to_tag` は既存 To-tag の有無判定を **case-insensitive** で
    /// 行わなければならない。 さもなくば内線が `;TAG=existing` 大文字で
    /// 送ってきた Re-INVITE に対し sabiden が「tag 無し」と誤判定し
    /// `;tag=<新規>` を末尾追加して `To: <sip:dest>;TAG=existing;tag=new`
    /// の二重 tag を返す → 内線 UA は RFC 3261 §12.2.2 違反として ACK を
    /// 送らず切断する。
    #[test]
    fn rfc3261_8_2_6_2_ensure_to_tag_is_case_insensitive_for_existing_tag() {
        // 大文字 `;TAG=existing` (既存 dialog から内線が送ってきた Re-INVITE
        // を sabiden が echo するケースを模擬)。 ensure_to_tag は既存 tag を
        // 検出して **何もしない** べき。
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: crate::sip::message::SipHeaders::new(),
            body: vec![],
        };
        resp.headers
            .set("To", "<sip:dest@sabiden>;TAG=existing-uas-tag");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert_eq!(
            to, "<sip:dest@sabiden>;TAG=existing-uas-tag",
            "case-insensitive に既存 tag を検出して二重付与してはならない: To={}",
            to
        );

        // mixed case `;tAg=` も同様
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: crate::sip::message::SipHeaders::new(),
            body: vec![],
        };
        resp.headers.set("To", "<sip:dest@sabiden>;tAg=mixed");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert_eq!(
            to, "<sip:dest@sabiden>;tAg=mixed",
            "mixed case の既存 tag を保持: To={}",
            to
        );

        // tag が本当に無いケース: ensure_to_tag が新規生成して付与するべき
        let mut resp = SipResponse {
            status_code: 200,
            reason: "OK".into(),
            headers: crate::sip::message::SipHeaders::new(),
            body: vec![],
        };
        resp.headers.set("To", "<sip:dest@sabiden>");
        ensure_to_tag(&mut resp);
        let to = resp.headers.get("to").unwrap();
        assert!(
            to.contains(";tag="),
            "tag 無しなら付与する (RFC 3261 §8.2.6.2): To={}",
            to
        );
        assert!(
            !to.contains(";tag=;") && !to.ends_with(";tag="),
            "値が空でない tag が付くべき: To={}",
            to
        );
    }

    /// テスト用ヘルパ: ローカル UDP ソケット 2 個を bind し、`SipRequest` を
    /// 1 通流して `ResponderHandle` (= ServerTransaction) を作る。 `quick` が
    /// 送信した応答パケットを受信側ソケットから読み出して [`SipResponse`] と
    /// して返す。
    ///
    /// `to_header` は `From` の To に対応する初期値 (例 `<sip:dest@sabiden>`).
    /// 通常 initial INVITE / REGISTER では tag 無し、in-dialog request では
    /// tag 付き。
    async fn quick_response_for_to(to_header: &str, status: u16, reason: &str) -> SipResponse {
        // `responder` 側の socket (応答送信元) と `client` 側 socket (応答受信)
        let server_sock = Arc::new(UdpSocket::bind(fixtures::loopback_any()).await.unwrap());
        let client_sock = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        // 最低限の INVITE-like SipRequest を組み立てる。 Via branch / CSeq /
        // Call-ID / From-tag は `ServerTransaction::new` の ID 計算に必要。
        let mut req = SipRequest::new(SipMethod::Invite, "sip:dest@sabiden");
        req.headers.set(
            "Via",
            format!(
                "SIP/2.0/UDP {};branch=z9hG4bK-test-{}",
                client_addr,
                new_call_id()
            ),
        );
        req.headers
            .set("From", "<sip:caller@sabiden>;tag=from-tag-1");
        req.headers.set("To", to_header);
        req.headers.set("Call-ID", new_call_id());
        req.headers.set("CSeq", "1 INVITE");
        req.headers.set("Max-Forwards", "70");
        req.headers.set("Content-Length", "0");

        let server_tx = ServerTransaction::new(req, client_addr, server_sock).unwrap();
        let responder = ResponderHandle::new(server_tx);
        responder.quick(status, reason).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
            .await
            .expect("response timeout")
            .unwrap();
        match parse_message(&buf[..n]).unwrap() {
            SipMessage::Response(r) => r,
            _ => panic!("response expected"),
        }
    }

    /// RFC 3261 §8.2.6.2 / Issue #100:
    /// `ResponderHandle::quick` は initial INVITE への final 応答 (4xx 等)
    /// で **必ず** To-tag を付与しなければならない。tag 無し To を持つ INVITE
    /// に 403 Forbidden を返した結果、To に `;tag=...` が含まれていることを
    /// 確認する。
    #[tokio::test]
    async fn rfc3261_8_2_6_2_quick_adds_to_tag_for_403_on_initial_invite() {
        let resp = quick_response_for_to("<sip:dest@sabiden>", 403, "Forbidden").await;
        assert_eq!(resp.status_code, 403);
        let to = resp.headers.get("to").unwrap();
        assert!(
            has_to_tag(to),
            "RFC 3261 §8.2.6.2: 403 final 応答に To-tag が必須: To={}",
            to
        );
    }

    /// RFC 3261 §8.2.6.2 / Issue #100:
    /// 200 OK (CANCEL / OPTIONS / BYE) でも To-tag 必須。 BYE のように元 To が
    /// 既に tag 付き (in-dialog) なケースは別テストで確認するので、 ここでは
    /// To-tag 無しの request (= initial CANCEL/OPTIONS 相当) に 200 OK を
    /// 返したケースを検証する。
    #[tokio::test]
    async fn rfc3261_8_2_6_2_quick_adds_to_tag_for_200_ok() {
        let resp = quick_response_for_to("<sip:dest@sabiden>", 200, "OK").await;
        assert_eq!(resp.status_code, 200);
        let to = resp.headers.get("to").unwrap();
        assert!(
            has_to_tag(to),
            "RFC 3261 §8.2.6.2: 200 OK 応答に To-tag が必須: To={}",
            to
        );
    }

    /// RFC 3261 §8.2.6.2 / Issue #100:
    /// 481 / 487 / 503 など UAS が `quick` で多用する非 2xx final 応答も
    /// To-tag 必須。 代表値 487 (Request Terminated; CANCEL→INVITE 経路) を
    /// 確認する。
    #[tokio::test]
    async fn rfc3261_8_2_6_2_quick_adds_to_tag_for_487_request_terminated() {
        let resp = quick_response_for_to("<sip:dest@sabiden>", 487, "Request Terminated").await;
        assert_eq!(resp.status_code, 487);
        let to = resp.headers.get("to").unwrap();
        assert!(
            has_to_tag(to),
            "RFC 3261 §8.2.6.2: 487 Request Terminated 応答に To-tag が必須: To={}",
            to
        );
    }

    /// RFC 3261 §8.2.6.2 例外条項 / Issue #100:
    /// > with the exception of the 100 (Trying) response, in which a tag is
    /// > permitted but not required
    ///
    /// 100 Trying では `quick` は To-tag を **付与しない** (例外条項に従い、
    /// 元 request の To をそのまま echo する)。 付与しても RFC 違反では
    /// ないが、 `quick` を経由する 100 Trying 経路 (`handle_invite` /
    /// `handle_invite` re-INVITE) の元 To が tag 無しなら、 そのまま tag 無し
    /// の 100 を返す挙動を保証する (Issue #100 完了条件)。
    #[tokio::test]
    async fn rfc3261_8_2_6_2_quick_skips_to_tag_for_100_trying() {
        let resp = quick_response_for_to("<sip:dest@sabiden>", 100, "Trying").await;
        assert_eq!(resp.status_code, 100);
        let to = resp.headers.get("to").unwrap();
        assert!(
            !has_to_tag(to),
            "RFC 3261 §8.2.6.2 例外: 100 Trying では quick が tag を付与しない: To={}",
            to
        );
    }

    /// RFC 3261 §8.2.6.2 / §12.2.2 / Issue #100:
    /// **既に To-tag が付いた** request (= in-dialog request、 例 BYE / Re-INVITE)
    /// への final 応答では既存 tag を保持し、 二重付与しない。 BYE 200 OK の
    /// dialog 整合性で重要 (元 dialog の local-tag を echo するのが正しい)。
    #[tokio::test]
    async fn rfc3261_12_2_2_quick_preserves_existing_to_tag() {
        let resp =
            quick_response_for_to("<sip:dest@sabiden>;tag=existing-uas-tag", 200, "OK").await;
        assert_eq!(resp.status_code, 200);
        let to = resp.headers.get("to").unwrap();
        assert!(
            to.contains("tag=existing-uas-tag"),
            "既存 To-tag が保持されている: To={}",
            to
        );
        // 二重 tag になっていないことを確認 (`tag=` が 1 個だけ)
        let tag_count = to
            .to_ascii_lowercase()
            .matches(";tag=")
            .count()
            // bare `tag=` (parameter 区切り無しで先頭) のケースもありうるが、
            // ここでは `;tag=` に限定して数える (本テストの to_header は `;tag=` 形)
            ;
        assert_eq!(
            tag_count, 1,
            "RFC 3261 §12.2.2: 二重 tag になってはならない: To={}",
            to
        );
    }

    // =========================================================================
    // Issue #273: 内線 UAS の method 別 default 応答 (CLAUDE.md §9 解消済)
    //
    // 旧 catch-all 405 が NOTIFY / MESSAGE 等で UA 側の再送ストームを誘発する
    // band-aid だったため、 RFC 引用付きで method 別 status に分解した。
    // NGN inbound 側 (Issue #110、 PR #154) と同じ方針を内線レッグにも適用。
    //
    // 各テストは ExtensionUas を bind → run し、 client UDP socket から
    // 該当 method の SIP リクエストを送り、 返ってくる status code と
    // Allow ヘッダ (RFC 3261 §8.2.1 MUST) を検証する。
    // =========================================================================

    /// `ExtensionUas` を bind して run し、 client socket から `method` の
    /// リクエストを送って **非 100 final 応答** を 1 つ受領するヘルパ。
    /// `expected_status` と一致しない / Allow ヘッダが欠落していると panic。
    async fn assert_ext_method_response(
        method: SipMethod,
        expected_status: u16,
        expect_allow_header: bool,
    ) {
        let extensions = vec![fixtures::extension_iphone()];
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap();
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let method_str = method.as_str().to_string();
        let req = builders::request_from_phone(
            &local,
            "iphone",
            method,
            "sip:sabiden",
            &format!("z9hG4bKext-{}", method_str.to_lowercase()),
        );
        let method_str = method_str.as_str();
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let mut got_response = None;
        for _ in 0..3 {
            match time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Ok(SipMessage::Response(r)) = parse_message(&buf[..n]) {
                        // RFC 3261 §17.1.1.1: 100 Trying は INVITE 系のみで
                        // 送出される。 非 INVITE method 経路 (NOTIFY 等の本
                        // helper 対象) に届くこと自体が異常 → 即 panic で
                        // silent fail を防ぐ (CLAUDE.md §7 flaky 禁止)。
                        assert_ne!(
                            r.status_code, 100,
                            "100 Trying は INVITE 系のみ。 非 INVITE method ({}) に届くのは異常",
                            method_str
                        );
                        got_response = Some(r);
                        break;
                    }
                }
                _ => break,
            }
        }
        let resp = got_response.unwrap_or_else(|| {
            panic!(
                "{} に対する応答が内線側に届くべき (期待 status={})",
                method_str, expected_status
            )
        });
        assert_eq!(
            resp.status_code, expected_status,
            "{} には status={} を返すべき (実際: {} {})",
            method_str, expected_status, resp.status_code, resp.reason,
        );
        if expect_allow_header {
            let allow = resp.headers.get("allow").unwrap_or_else(|| {
                panic!(
                    "{} 応答には `Allow` ヘッダが必須 (RFC 3261 §8.2.1 / §20.5)",
                    method_str
                )
            });
            // 旧 catch-all 405 は Allow を付けていなかった (Issue #273)。
            // 内線 UAS が処理経路を持つ method (INVITE / BYE 等) が
            // 含まれることを確認する。
            assert!(
                allow.contains("INVITE") && allow.contains("BYE"),
                "{} 応答の Allow に INVITE / BYE が含まれること: {}",
                method_str,
                allow
            );
        }
    }

    /// RFC 3265 §3.2 / RFC 6665 §3.2: 内線側から届いた NOTIFY は該当
    /// subscription が無いため `481 Subscription Does Not Exist` で応答する。
    /// 旧 catch-all 405 は IMS / reg-event 等の UA 再送を引き起こす
    /// band-aid だった (Issue #273)。
    #[tokio::test]
    async fn rfc3265_3_2_uas_returns_481_for_orphan_notify() {
        assert_ext_method_response(SipMethod::Notify, 481, true).await;
    }

    /// RFC 6665 §4.1.4 / RFC 3265 §7.2.4: 未対応 event package に対する
    /// SUBSCRIBE には `489 Bad Event` で返す。 sabiden 内線 UAS は
    /// presence / dialog-info 等の event package を提供しない。
    #[tokio::test]
    async fn rfc6665_4_1_4_uas_returns_489_for_subscribe() {
        assert_ext_method_response(SipMethod::Subscribe, 489, true).await;
    }

    /// RFC 3262 §4 / §7.1: PRACK は UAS が `Require: 100rel` 付きの
    /// 1xx を出した直後に届く ACK 相当。 内線 UAS は reliable 1xx を
    /// 発行しないため、 対応 transaction なし扱いで `481` を返す。
    #[tokio::test]
    async fn rfc3262_4_uas_returns_481_for_prack() {
        assert_ext_method_response(SipMethod::Prack, 481, true).await;
    }

    /// RFC 3311 §5.2: UPDATE 経路を持たない内線 UAS は、 対応ダイアログ
    /// 不在として `481 Call/Transaction Does Not Exist` で応答する
    /// (RFC 3261 §12.2.2)。
    #[tokio::test]
    async fn rfc3311_5_2_uas_returns_481_for_update() {
        assert_ext_method_response(SipMethod::Update, 481, true).await;
    }

    /// RFC 3428 §7: UAS が MESSAGE をサポートしない場合でも `200 OK` で
    /// 受け流す (UA 側の再送ストーム抑止)。 内線 UA (Linphone 等) が
    /// IM メッセージを発行するケースで 405 だと retry queue が詰まる
    /// 旧 band-aid を解消 (Issue #273、 CLAUDE.md §9)。
    #[tokio::test]
    async fn rfc3428_7_uas_returns_200_for_message() {
        assert_ext_method_response(SipMethod::Message, 200, true).await;
    }

    /// Issue #299 / RFC 3428 §7 / §10: `with_message_log` で注入した ring buffer
    /// に、 text/plain body の MESSAGE が **direction=Inbound** で push されること。
    /// 200 OK は本文有無に関わらず常に返る (= 旧 UA 動作互換)。
    #[tokio::test]
    async fn rfc3428_10_uas_pushes_text_plain_message_body_to_log() {
        use crate::call::message_log::{Direction, MessageLog};
        use crate::testing::{builders, fixtures};

        let extensions = vec![fixtures::extension_iphone()];
        let log = Arc::new(MessageLog::new(10));
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap()
            .with_message_log(log.clone());
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        // text/plain MESSAGE を組み立てる
        let mut req = builders::request_from_phone(
            &local,
            "iphone",
            SipMethod::Message,
            "sip:sabiden",
            "z9hG4bKsms-1",
        );
        req.headers.set("Content-Type", "text/plain;charset=utf-8");
        req.body = b"hello from iphone".to_vec();
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        // 200 OK が返ること
        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() else {
            panic!("expected response");
        };
        assert_eq!(r.status_code, 200);

        // 短いポーリングで push が完了するのを待つ (RFC 3428 §7 の処理は
        // 200 OK 後に行われる可能性があるため)。
        for _ in 0..20 {
            if !log.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let entries = log.recent(10);
        assert_eq!(entries.len(), 1, "MESSAGE 受信で 1 件 push されるべき");
        assert_eq!(entries[0].direction, Direction::Inbound);
        assert_eq!(entries[0].body, "hello from iphone");
        assert!(entries[0].from.contains("iphone"));
    }

    /// Issue #299 / RFC 3428 §10: `application/im-iscomposing+xml` 等 non-text body は
    /// ring buffer に push されない (200 OK のみ返す)。 PWA UI で render できない
    /// MIME を観測ログに混ぜないため。
    #[tokio::test]
    async fn rfc3428_10_uas_drops_non_text_plain_body_from_log() {
        use crate::call::message_log::MessageLog;
        use crate::testing::{builders, fixtures};

        let extensions = vec![fixtures::extension_iphone()];
        let log = Arc::new(MessageLog::new(10));
        let uas = ExtensionUas::bind(fixtures::uas_config(), &extensions)
            .await
            .unwrap()
            .with_message_log(log.clone());
        let server_addr = uas.socket.local_addr().unwrap();
        tokio::spawn(async move {
            uas.run().await.unwrap();
        });

        let client = UdpSocket::bind(fixtures::loopback_any()).await.unwrap();
        let local = client.local_addr().unwrap();

        let mut req = builders::request_from_phone(
            &local,
            "iphone",
            SipMethod::Message,
            "sip:sabiden",
            "z9hG4bKsms-2",
        );
        req.headers
            .set("Content-Type", "application/im-iscomposing+xml");
        req.body = b"<isComposing/>".to_vec();
        client.send_to(&req.to_bytes(), server_addr).await.unwrap();

        let mut buf = vec![0u8; 4096];
        let (n, _) = time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let SipMessage::Response(r) = parse_message(&buf[..n]).unwrap() else {
            panic!("expected response");
        };
        assert_eq!(r.status_code, 200, "non-text body でも 200 で受け流す");

        // ring buffer には push されていない (= 観測ログを汚染しない)。
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(log.len(), 0, "non-text body は ring buffer に push しない");
    }

    /// RFC 3903 §6: PUBLISH は presence / event state 発行 method。
    /// sabiden 内線 UAS は EventStateCompositor を持たないが、 Issue #273
    /// の方針 (受け流し) で `200 OK` を返し UA の再送を止める (本文破棄)。
    #[tokio::test]
    async fn rfc3903_6_uas_returns_200_for_publish() {
        assert_ext_method_response(SipMethod::Publish, 200, true).await;
    }

    /// RFC 3515 §4.5 / Issue #289 fallback: REFER は B2BUA 経路 (Issue #289)
    /// で 202 + NOTIFY を駆動するが、 **上位 (Call Manager) が未接続** の場合は
    /// `405 Method Not Allowed` + `Allow` ヘッダで縮退する (RFC 3515 §4.5)。
    /// 本テストは `assert_ext_method_response` が `with_handler` を呼ばないため
    /// 上位未接続経路を踏み、 405 fallback が機能していることを確認する。
    #[tokio::test]
    async fn rfc3515_4_5_uas_returns_405_for_refer_without_b2bua_handler() {
        assert_ext_method_response(SipMethod::Refer, 405, true).await;
    }

    /// RFC 3261 §8.2.1: 未知メソッド (`SipMethod::Other`) には **必ず**
    /// `Allow` ヘッダ付きの 405 で応答する。 旧実装は Allow 無しで 405 を
    /// 返していた (Issue #273 で解消)。
    #[tokio::test]
    async fn rfc3261_8_2_1_uas_returns_405_with_allow_for_unknown_method() {
        assert_ext_method_response(SipMethod::Other("FOO".to_string()), 405, true).await;
    }
}
