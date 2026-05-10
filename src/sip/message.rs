//! SIP メッセージ層 (RFC 3261 §7)
//!
//! - SIP Request / Response の共通モデル
//! - SIP Method の enum (PUBLISH/NOTIFY/PRACK/SUBSCRIBE まで個別バリアント)
//! - SipHeaders: 同名複数行 (Via, Route 等) を保持できるヘッダ表
//! - SIP-URI のパース (`SipUriParts` / [`parse_sip_uri`])
//!
//! ヘッダ名は内部的に "long form" の小文字 (例: `via`, `from`, `to`) で
//! 保持する。受信時に compact form (RFC 3261 §7.3.3 / §20:
//! `i=Call-ID`, `m=Contact`, `f=From`, `t=To`, `v=Via`, `c=Content-Type`,
//! `l=Content-Length`, `e=Content-Encoding`, `s=Subject`, `k=Supported`)
//! を long form へ展開し、書き出し時に [`canonical_header_name`] が
//! Title-Case 化する。

use std::fmt;

/// SIP method (RFC 3261 §7.1 + 拡張)。
///
/// RFC 3261 で定義される基本メソッドに加え、よく使われる拡張メソッド
/// (PUBLISH/NOTIFY/SUBSCRIBE/PRACK/UPDATE/MESSAGE/REFER) は専用バリアントを持ち、
/// 未知のメソッドは [`SipMethod::Other`] にフォールバックする。
///
/// 個別 variant 化の動機 (Issue #110): 上位ルータが
/// `Other(String)` を一律 405 で拒否すると、 IMS 経由の NOTIFY (reg-event) や
/// MESSAGE (SMS) が UA 側の再送ストームを引き起こす。 RFC ごとに
/// 適切な default 応答 (NOTIFY → 481、 MESSAGE → 200 OK 等) を返せるよう
/// パース側で区別しておく。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    /// RFC 6086 (旧 RFC 2976)
    Info,
    /// RFC 3265
    Notify,
    /// RFC 3265
    Subscribe,
    /// RFC 3262 (Reliable Provisional Responses)
    Prack,
    /// RFC 3903 (Event State Publication)
    Publish,
    /// RFC 3311 (UPDATE Method)
    Update,
    /// RFC 3428 (Instant Messaging)
    Message,
    /// RFC 3515 (Refer Method)
    Refer,
    /// 未知のメソッド名 (パース時に保持しておくが、ルータは 405 等で返す想定)。
    Other(String),
}

impl SipMethod {
    /// 文字列表現 (大文字)。`Other` は中身をそのまま返す。
    pub fn as_str(&self) -> &str {
        match self {
            SipMethod::Register => "REGISTER",
            SipMethod::Invite => "INVITE",
            SipMethod::Ack => "ACK",
            SipMethod::Bye => "BYE",
            SipMethod::Cancel => "CANCEL",
            SipMethod::Options => "OPTIONS",
            SipMethod::Info => "INFO",
            SipMethod::Notify => "NOTIFY",
            SipMethod::Subscribe => "SUBSCRIBE",
            SipMethod::Prack => "PRACK",
            SipMethod::Publish => "PUBLISH",
            SipMethod::Update => "UPDATE",
            SipMethod::Message => "MESSAGE",
            SipMethod::Refer => "REFER",
            SipMethod::Other(s) => s.as_str(),
        }
    }
}

impl fmt::Display for SipMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SipMethod {
    /// 任意の token を受け付け、未知メソッドは [`SipMethod::Other`] に
    /// 包む。空文字列だけはエラーとする。
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            anyhow::bail!("empty SIP method");
        }
        Ok(match s {
            "REGISTER" => SipMethod::Register,
            "INVITE" => SipMethod::Invite,
            "ACK" => SipMethod::Ack,
            "BYE" => SipMethod::Bye,
            "CANCEL" => SipMethod::Cancel,
            "OPTIONS" => SipMethod::Options,
            "INFO" => SipMethod::Info,
            "NOTIFY" => SipMethod::Notify,
            "SUBSCRIBE" => SipMethod::Subscribe,
            "PRACK" => SipMethod::Prack,
            "PUBLISH" => SipMethod::Publish,
            "UPDATE" => SipMethod::Update,
            "MESSAGE" => SipMethod::Message,
            "REFER" => SipMethod::Refer,
            other => SipMethod::Other(other.to_string()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SipRequest {
    pub method: SipMethod,
    pub uri: String,
    pub headers: SipHeaders,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SipResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: SipHeaders,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

/// 複数値を持てる SIP ヘッダ (Via 等は複数行になる)。
///
/// キーは long form の小文字で正規化される ([`normalize_header_name`])。
/// 書き出し時には [`canonical_header_name`] により Title-Case 化される。
#[derive(Debug, Clone, Default)]
pub struct SipHeaders {
    fields: Vec<(String, String)>,
}

impl SipHeaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let key = normalize_header_name(name);
        // 既存エントリを上書き (最初の1件のみ)
        if let Some(pos) = self.fields.iter().position(|(k, _)| k == &key) {
            self.fields[pos].1 = value.into();
        } else {
            self.fields.push((key, value.into()));
        }
    }

    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.fields
            .push((normalize_header_name(name), value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let key = normalize_header_name(name);
        self.fields
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let key = normalize_header_name(name);
        self.fields
            .iter()
            .filter(|(k, _)| k == &key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl SipRequest {
    pub fn new(method: SipMethod, uri: impl Into<String>) -> Self {
        Self {
            method,
            uri: uri.into(),
            headers: SipHeaders::new(),
            body: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("{} {} SIP/2.0\r\n", self.method, self.uri);
        for (k, v) in self.headers.iter() {
            let display_name = canonical_header_name(k);
            out.push_str(&format!("{}: {}\r\n", display_name, v));
        }
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        } else {
            out.push_str("Content-Length: 0\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

impl SipResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!("SIP/2.0 {} {}\r\n", self.status_code, self.reason);
        for (k, v) in self.headers.iter() {
            let display_name = canonical_header_name(k);
            out.push_str(&format!("{}: {}\r\n", display_name, v));
        }
        if !self.body.is_empty() {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        } else {
            out.push_str("Content-Length: 0\r\n");
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// ヘッダ名を内部キー (long-form, lowercase) に正規化する。
///
/// RFC 3261 §7.3.3 / §20 の compact form (`i`/`m`/`f`/`t`/`v`/`c`/`l`/
/// `e`/`s`/`k`/`b`/`o`/`r`/`u`) を long form の小文字へ展開する。
/// それ以外はそのまま小文字化する。
///
/// このヘルパが [`SipHeaders`] の唯一の正規化点で、書き出し時の
/// [`canonical_header_name`] と二重に大文字化ロジックを抱えないように
/// 「内部表現は常に long-form lowercase」を不変条件にする。
pub fn normalize_header_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        // RFC 3261 §20 compact form
        "i" => "call-id".into(),
        "m" => "contact".into(),
        "f" => "from".into(),
        "t" => "to".into(),
        "v" => "via".into(),
        "c" => "content-type".into(),
        "l" => "content-length".into(),
        "e" => "content-encoding".into(),
        "s" => "subject".into(),
        "k" => "supported".into(),
        "b" => "referred-by".into(),
        "o" => "event".into(),
        "r" => "refer-to".into(),
        "u" => "allow-events".into(),
        _ => lower,
    }
}

/// long-form lowercase キーから書き出し用の Title-Case 名を返す。
///
/// 既知のヘッダは RFC 互換の慣用 case (例: `Call-ID`, `CSeq`,
/// `WWW-Authenticate`) を使い、未知のヘッダは ハイフン区切りで
/// 各トークンを title-case する (`X-Foo-Bar` → `X-Foo-Bar`)。
pub fn canonical_header_name(lower: &str) -> String {
    match lower {
        "via" => "Via".into(),
        "from" => "From".into(),
        "to" => "To".into(),
        "call-id" => "Call-ID".into(),
        "cseq" => "CSeq".into(),
        "contact" => "Contact".into(),
        "content-type" => "Content-Type".into(),
        "content-length" => "Content-Length".into(),
        "content-encoding" => "Content-Encoding".into(),
        "max-forwards" => "Max-Forwards".into(),
        "authorization" => "Authorization".into(),
        "www-authenticate" => "WWW-Authenticate".into(),
        "proxy-authenticate" => "Proxy-Authenticate".into(),
        "proxy-authorization" => "Proxy-Authorization".into(),
        "expires" => "Expires".into(),
        "allow" => "Allow".into(),
        "allow-events" => "Allow-Events".into(),
        "supported" => "Supported".into(),
        "require" => "Require".into(),
        "session-expires" => "Session-Expires".into(),
        "min-se" => "Min-SE".into(),
        "p-preferred-identity" => "P-Preferred-Identity".into(),
        "p-asserted-identity" => "P-Asserted-Identity".into(),
        "user-agent" => "User-Agent".into(),
        "subject" => "Subject".into(),
        "event" => "Event".into(),
        "refer-to" => "Refer-To".into(),
        "referred-by" => "Referred-By".into(),
        "rseq" => "RSeq".into(),
        "rack" => "RAck".into(),
        "record-route" => "Record-Route".into(),
        "route" => "Route".into(),
        other => title_case_dashed(other),
    }
}

/// `x-foo-bar` → `X-Foo-Bar` のように "-" 区切り各トークンを Title Case。
fn title_case_dashed(s: &str) -> String {
    s.split('-')
        .map(|seg| {
            let mut chars = seg.chars();
            match chars.next() {
                Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// SIP-URI の最低限のパース結果 (RFC 3261 §19.1.1)。
///
/// 完全な URI BNF は実装せず、UAC/UAS が実用上参照する範囲に絞る:
///
/// ```text
/// sip:user:password@host:port;p1=v1;p2?h1=v1&h2=v2
/// |scheme|user_info|host|port|;params       |?headers
/// ```
///
/// - `scheme`: "sip" / "sips" / その他 (lower-case で保持)
/// - `user`: `@` の左側 (パスワード `:` は削除しユーザ名のみ)
/// - `host`: ホスト名 / IPv4 リテラル / **IPv6 リテラルは `[..]` brackets 込み**
///   (例: `"[2001:db8::1]"`)。 これは `parse_sip_uri` が IPv6 を識別する
///   `[..]:port` 構文を round-trip 可能な形で保持する契約 (Issue #133)。
///   `IpAddr` を作る側は `host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))`
///   で剥がしてから `parse::<IpAddr>()` する (例: `src/sip/uac.rs::resolve_next_hop_addr`)。
/// - `port`: 数値 (省略時 None)
/// - `params`: `;k=v` ペア (順序維持、値が無い `lr` は空文字列)
/// - `headers`: `?k=v&k=v` ペア
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SipUriParts {
    pub scheme: String,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

impl SipUriParts {
    /// 値の有無に関わらず特定パラメータを持つか?
    pub fn has_param(&self, name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        self.params.iter().any(|(k, _)| k.eq_ignore_ascii_case(&n))
    }

    /// パラメータの値を取得 (大文字小文字無視)。
    pub fn param(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&n))
            .map(|(_, v)| v.as_str())
    }
}

/// SIP/SIPS URI をパースする。
///
/// 入力例:
/// - `sip:bob@example.com`
/// - `sip:bob:secret@example.com:5060;transport=udp;lr?Subject=Hi`
/// - `sips:[2001:db8::1]:5061`
///
/// `<sip:..>` の山かっこは付いていない前提。display name 付きの
/// name-addr は呼び出し側で剥がしてから渡す。
pub fn parse_sip_uri(input: &str) -> anyhow::Result<SipUriParts> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("empty SIP-URI");
    }

    // scheme
    let (scheme, rest) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("missing scheme: {}", s))?;
    let scheme_lc = scheme.to_ascii_lowercase();
    if scheme_lc != "sip" && scheme_lc != "sips" {
        // 未知スキームでも構造解析は続けるが、scheme は保持する。
    }

    // ?headers 部
    let (rest, headers_part) = match rest.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };

    // ;params 部
    let (rest, params_part) = match rest.split_once(';') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };

    // user@host[:port]
    let (user_part, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };

    let user = user_part.map(|u| {
        // user[:password] のうちユーザ名だけ取る
        u.split(':').next().unwrap_or(u).to_string()
    });

    // hostport: IPv6 リテラルは [..]:port
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        // "[host]:port" or "[host]"
        let end = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 literal: {}", hostport))?;
        let host = stripped[..end].to_string();
        let after = &stripped[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("bad port: {}", p))?,
            )
        } else {
            None
        };
        (format!("[{}]", host), port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        // host:port (host に : が無い前提 = IPv4 / FQDN)
        let port = p
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("bad port: {}", p))?;
        (h.to_string(), Some(port))
    } else {
        (hostport.to_string(), None)
    };

    if host.is_empty() {
        anyhow::bail!("empty host: {}", input);
    }

    let params = match params_part {
        Some(p) => parse_kv_list(p, ';'),
        None => Vec::new(),
    };
    let headers = match headers_part {
        Some(h) => parse_kv_list(h, '&'),
        None => Vec::new(),
    };

    Ok(SipUriParts {
        scheme: scheme_lc,
        user,
        host,
        port,
        params,
        headers,
    })
}

fn parse_kv_list(s: &str, sep: char) -> Vec<(String, String)> {
    s.split(sep)
        .filter(|p| !p.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
            None => (part.trim().to_ascii_lowercase(), String::new()),
        })
        .collect()
}

/// SIP メッセージ パース失敗の分類 (RFC 3261 §16 / §21.4.1).
///
/// 受信 datagram が SIP メッセージとして整合しない場合のエラー種別。
/// `recv_loop` (UAS 側) はここで返った種別を参照して、 RFC 3261 §21.4.1
/// "400 Bad Request" 応答を組み立てるか silent drop するかを決める。
///
/// - 上位層が応答先 (Via / source address) を特定できる程度に「壊れていない」
///   メッセージ (= 本 enum のうち [`ParseError::Truncated`] /
///   [`ParseError::DuplicateContentLength`] /
///   [`ParseError::NonNumericContentLength`] のように、 ヘッダ部は
///   読めるが Content-Length 整合のみ崩れているケース) は 400 を返す
///   候補。
/// - [`ParseError::NoCrlfCrlf`] / [`ParseError::Empty`] /
///   [`ParseError::MalformedRequestLine`] / [`ParseError::BadStatusCode`] /
///   [`ParseError::UnknownMethod`] のように **ヘッダ部すら読めない**
///   ケースは応答先 (Via / 必須ヘッダ) を抽出できないので silent drop
///   (RFC 3261 §16.3: malformed request の応答先が決まらない場合は
///   応答送信不能)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// 入力 datagram が空。
    Empty,
    /// CRLFCRLF (header / body 境界) が見つからない。 ヘッダ部の終端
    /// すら確定できないので応答不能。 RFC 3261 §7.5。
    NoCrlfCrlf,
    /// `Content-Length: N` で実本文が N 未満 (truncate)。 RFC 3261 §18.3。
    /// `recv_loop` の 8192 byte buf を超えた INVITE / 200 OK で発生しうる。
    Truncated { declared: usize, actual: usize },
    /// `Content-Length` が同 datagram 内に **2 件以上** 出現 (request
    /// smuggling 風)。 RFC 3261 §7.3.1 / §20.14 違反。
    DuplicateContentLength { count: usize },
    /// `Content-Length` の値が 10 進整数として解釈できない。 RFC 3261 §20.14。
    NonNumericContentLength { value: String },
    /// Request line がスペース区切りでメソッド + URI を取り出せない (3xx に
    /// fall-back する応答先も特定できないので silent drop)。
    MalformedRequestLine { line: String },
    /// Status line の status-code が 3 桁整数として解釈できない (応答に対する
    /// 応答は出さないので silent drop で実害は少ない)。
    BadStatusCode { value: String },
    /// メソッドトークンが空 (`SipMethod::from_str` 由来)。
    UnknownMethod { token: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty SIP message"),
            ParseError::NoCrlfCrlf => write!(f, "malformed SIP message: no CRLFCRLF"),
            ParseError::Truncated { declared, actual } => write!(
                f,
                "Content-Length {} exceeds available body bytes {}",
                declared, actual
            ),
            ParseError::DuplicateContentLength { count } => write!(
                f,
                "duplicate Content-Length header (count={}): possible request smuggling",
                count
            ),
            ParseError::NonNumericContentLength { value } => {
                write!(f, "malformed Content-Length header value: {:?}", value)
            }
            ParseError::MalformedRequestLine { line } => {
                write!(f, "malformed SIP request line: {}", line)
            }
            ParseError::BadStatusCode { value } => {
                write!(f, "malformed SIP status code: {:?}", value)
            }
            ParseError::UnknownMethod { token } => {
                write!(f, "empty/unknown SIP method: {:?}", token)
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    /// 「ヘッダ部は読めるので 400 Bad Request を返せる候補」なら true。
    ///
    /// RFC 3261 §21.4.1: "The request could not be understood due to
    /// malformed syntax." の応答は、 応答先 (Via) と 1st-hop の必須ヘッダ
    /// (From/To/Call-ID/CSeq) が 取れる場合のみ意味を持つ。 truncate /
    /// 重複 CL / 非数値 CL はヘッダ自体は parse 可能なので応答候補。
    /// CRLFCRLF が無い等のケースはヘッダの末端が確定できないので応答不能
    /// (silent drop)。
    pub fn is_header_recoverable(&self) -> bool {
        matches!(
            self,
            ParseError::Truncated { .. }
                | ParseError::DuplicateContentLength { .. }
                | ParseError::NonNumericContentLength { .. }
        )
    }
}

/// 不正メッセージから 400 Bad Request 応答を組み立てるための「素材」。
///
/// `recv_loop` で [`parse_message_classified`] が
/// [`ParseError::is_header_recoverable`] な error を返したとき、
/// 同 datagram から best-effort で抽出する。 不正な Content-Length を
/// 信じて body を切り出さず、 ヘッダ部だけを lossy 化して読む点が
/// [`parse_message`] との差。
#[derive(Debug, Clone)]
pub struct MalformedRequestSkeleton {
    pub method: SipMethod,
    pub uri: String,
    /// 必須ヘッダのみ抽出 (Via / From / To / Call-ID / CSeq)。
    /// 一つでも欠けたら抽出失敗 (Option ではなく [`extract_request_skeleton_for_400`]
    /// 全体が `None` を返す)。
    pub headers: SipHeaders,
}

/// 不正メッセージから 400 Bad Request 応答用の必須ヘッダ skeleton を抽出する。
///
/// RFC 3261 §8.2.6.2 (Headers and Tags): 応答は request の Via / From /
/// To / Call-ID / CSeq をそのまま反映する必要がある。 これらが揃わない
/// malformed message には 400 を返せない (応答先が決まらない / 応答が
/// 上流で stateless rejection される)。
///
/// 失敗ケース:
/// - CRLFCRLF が無い → header 終端不明
/// - 1 行目が request line に見えない (= response かそれ以下)
/// - Via / From / To / Call-ID / CSeq のいずれかが欠落
pub fn extract_request_skeleton_for_400(data: &[u8]) -> Option<MalformedRequestSkeleton> {
    // CRLFCRLF が無い場合はヘッダ終端不明。 「最後の \r\n まで」を試すと
    // body 部が継ぎ足された garbage を header と誤認するので採用しない。
    let header_end = find_subslice(data, b"\r\n\r\n")?;
    let header_text = String::from_utf8_lossy(&data[..header_end]);

    let mut lines = header_text.split("\r\n");
    let first_line = lines.next()?;

    // Response (`SIP/2.0 ...`) の場合は応答に対する応答を出さないので skip。
    if first_line.starts_with("SIP/2.0 ") {
        return None;
    }

    // Request line: METHOD URI SIP/2.0 (RFC 3261 §7.1).
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let method: SipMethod = parts[0].parse().ok()?;
    let uri = parts[1].to_string();

    let mut headers = SipHeaders::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.add(k.trim(), v.trim());
        }
    }

    // RFC 3261 §8.1.1: minimal essential headers.
    if headers.get("via").is_none()
        || headers.get("from").is_none()
        || headers.get("to").is_none()
        || headers.get("call-id").is_none()
        || headers.get("cseq").is_none()
    {
        return None;
    }

    Some(MalformedRequestSkeleton {
        method,
        uri,
        headers,
    })
}

/// SIP メッセージのパーサ (anyhow ラッパ)。
///
/// 旧来の `Result<_, anyhow::Error>` API を維持するため、 内部で
/// [`parse_message_classified`] を呼んで [`ParseError`] を anyhow に
/// 持ち上げる。 エラー種別を見たい呼び出し側 (UAS の 400 応答経路) は
/// [`parse_message_classified`] を直接使う。
///
/// 詳細仕様は [`parse_message_classified`] の docstring 参照。
pub fn parse_message(data: &[u8]) -> anyhow::Result<SipMessage> {
    parse_message_classified(data).map_err(anyhow::Error::from)
}

/// SIP メッセージのパーサ (分類済 error 版)。
///
/// 入力は **生バイト列**として扱い、ヘッダ部 (start-line + headers)
/// だけを文字列化する。本文 (message-body) は
/// RFC 3261 §7.4 に従い **opaque な octet 列**として扱うため、
/// メッセージ全体に UTF-8 妥当性は要求しない。
///
/// # 切出し規則 (RFC 3261 §18.3 / §20.14)
///
/// - `\r\n\r\n` (CRLFCRLF) でヘッダと本文を分離する (RFC 3261 §7)。
/// - `Content-Length` (RFC 3261 §20.14) がある場合:
///   - `N == 0` → 本文は空 (CRLFCRLF 以降のバイトは無視。
///     UDP 1 datagram = 1 message 前提だが SBC が違反した場合の予防)。
///   - `N <= body_len` → `body[..N]` のみ採用。残余は drop
///     (1 datagram 内の余剰バイトは別 SIP メッセージまたは garbage と見なす。
///     RFC 3261 §18.3)。
///   - `N > body_len` → [`ParseError::Truncated`]。 UAS 側で
///     RFC 3261 §21.4.1 `400 Bad Request` 応答候補。
///   - 同名複数値 (重複) は [`ParseError::DuplicateContentLength`]。
///     RFC 3261 §7.3.1 では同名複数値の合成は `,` 連結で意味が同じ場合のみ
///     許容され、`Content-Length` のような単一値ヘッダで重複が現れた場合は
///     protocol violation。 attacker が
///     `Content-Length: 0\r\nContent-Length: 999\r\n` のような request
///     smuggling 風の食い違いを仕込んでも 1 件目だけ採用して silent に通る
///     ことを防ぐ。
///   - 値が 10 進整数として解釈できなければ
///     [`ParseError::NonNumericContentLength`] (RFC 3261 §20.14)。
/// - `Content-Length` ヘッダが無い場合は datagram 末尾までを本文とする
///   (RFC 3261 §18.3: UDP は datagram 長から決まる)。
///
/// # 文字コード (RFC 3261 §7.3.1 / §7.4 / §25.1 `UTF-8-NONASCII`)
///
/// SIP message-body は任意の octet 列で、media-type に拠る (RFC 3261 §7.4)。
/// 本パーサは `from_utf8` をメッセージ全体に適用しないので、
/// SDP 拡張 (binary `k=` 等) や S/MIME 等の binary body も受理できる。
/// ヘッダ行は **UTF-8** で、`TEXT-UTF8-TRIM` BNF (RFC 3261 §25.1) により
/// display-name や Subject に多バイト文字が許容される。 安全側で
/// `from_utf8_lossy` を使い、不正バイトは U+FFFD に置換してパースを
/// 継続する (header 行に non-UTF8 が混入しても全 datagram drop には
/// しない: §7.4 の body opaque 性と整合し、ヘッダ経路の DoS も塞ぐ)。
pub fn parse_message_classified(data: &[u8]) -> Result<SipMessage, ParseError> {
    if data.is_empty() {
        return Err(ParseError::Empty);
    }

    // ヘッダ末尾境界 (CRLFCRLF) を **生バイト** で検索する。
    // RFC 3261 §7.5 で header-body 区切りは厳密に CRLFCRLF と規定。
    let header_end = find_subslice(data, b"\r\n\r\n").ok_or(ParseError::NoCrlfCrlf)?;
    let header_bytes = &data[..header_end];
    let body_bytes = &data[header_end + 4..];

    // ヘッダ部を **lossy** 変換。RFC 3261 §7.3.1 / §25.1 (TEXT-UTF8-TRIM)
    // で UTF-8 が想定だが、不正バイトを 1 個混ぜただけで全 SIP メッセージ
    // が drop されると DoS 経路になるため、U+FFFD 置換でパースを継続する
    // (上位層が必要なら 400 Bad Request を返す機会を残す)。
    let header_text = String::from_utf8_lossy(header_bytes);

    let mut lines = header_text.split("\r\n");
    let first_line = lines.next().ok_or(ParseError::Empty)?;

    let mut headers = SipHeaders::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.add(k.trim(), v.trim());
        }
    }

    // RFC 3261 §20.14 / §7.3.1: Content-Length は単一値の 10 進バイト数。
    // 受信時は値に従って本文を切り出し、不整合 (truncate / 重複 / 非数値)
    // は parser error を返す。
    let cl_values = headers.get_all("content-length");
    let body = match cl_values.len() {
        0 => {
            // Content-Length 欠落時は datagram 末尾まで (UDP) を本文とする。
            // TCP 経路では §20.14 で MUST だが、UDP fallback の互換のため bail せず採用。
            body_bytes.to_vec()
        }
        1 => {
            // `headers.add` の段階で v.trim() 済みなので追加 trim は不要 (RFC 3261 §7.3.1)。
            let raw = cl_values[0];
            let n: usize = raw
                .parse()
                .map_err(|_| ParseError::NonNumericContentLength {
                    value: raw.to_string(),
                })?;
            if n > body_bytes.len() {
                // RFC 3261 §18.3: 宣言サイズより datagram の本文部が短い場合、
                // 切詰め (truncation) として扱う。 UDP では `recv_loop` の
                // 8192 byte buf を超えた INVITE で発生しうる。
                return Err(ParseError::Truncated {
                    declared: n,
                    actual: body_bytes.len(),
                });
            }
            // n <= body_bytes.len(): 余剰は別 datagram 扱い (drop)
            body_bytes[..n].to_vec()
        }
        _ => {
            // RFC 3261 §7.3.1: 同名複数値の合成は `,` 連結で意味が同じ場合のみ。
            // Content-Length は単一値ヘッダ (§20.14) なので、重複は protocol
            // violation として `Err` で drop する (request smuggling 経路を遮断)。
            return Err(ParseError::DuplicateContentLength {
                count: cl_values.len(),
            });
        }
    };

    if let Some(rest) = first_line.strip_prefix("SIP/2.0 ") {
        let (code_str, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        let status_code: u16 = code_str.parse().map_err(|_| ParseError::BadStatusCode {
            value: code_str.to_string(),
        })?;
        Ok(SipMessage::Response(SipResponse {
            status_code,
            reason: reason.to_string(),
            headers,
            body,
        }))
    } else {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(ParseError::MalformedRequestLine {
                line: first_line.to_string(),
            });
        }
        let method: SipMethod = parts[0].parse().map_err(|_| ParseError::UnknownMethod {
            token: parts[0].to_string(),
        })?;
        let uri = parts[1].to_string();
        Ok(SipMessage::Request(SipRequest {
            method,
            uri,
            headers,
            body,
        }))
    }
}

/// `haystack` 内から `needle` (固定パターン) の先頭 byte 位置を返す。
///
/// `slice::windows` ベースの素朴探索で、SIP メッセージ最大 64 KB 程度では
/// 性能上問題にならない。生バイト列のままパースするため、UTF-8 妥当性を
/// メッセージ全体に求めない方針 ([`parse_message`] docstring 参照)。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_401() {
        let msg = b"SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"ntt-east.ne.jp\", nonce=\"abc123\"\r\nCall-ID: test@example\r\n\r\n";
        let parsed = parse_message(msg).unwrap();
        match parsed {
            SipMessage::Response(r) => {
                assert_eq!(r.status_code, 401);
                assert!(r.headers.get("www-authenticate").is_some());
            }
            _ => panic!("expected response"),
        }
    }

    #[test]
    fn test_request_serialization() {
        let mut req = SipRequest::new(SipMethod::Register, "sip:ntt-east.ne.jp");
        req.headers
            .set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=abc");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "1 REGISTER");
        let bytes = req.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("REGISTER sip:ntt-east.ne.jp SIP/2.0\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn test_compact_header_form_normalized() {
        // RFC 3261 §7.3.3: compact form は long form と等価。
        // 受信側で `i=foo\r\nm=bar` を long form で取り出せること。
        let raw = b"INVITE sip:bob@x SIP/2.0\r\nv: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\nf: <sip:a@x>;tag=1\r\nt: <sip:b@x>\r\ni: 123@x\r\nCSeq: 1 INVITE\r\nm: <sip:a@x:5060>\r\nl: 0\r\n\r\n";
        let parsed = parse_message(raw).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert!(req.headers.get("via").is_some(), "v -> via");
                assert!(req.headers.get("from").is_some(), "f -> from");
                assert!(req.headers.get("to").is_some(), "t -> to");
                assert!(req.headers.get("call-id").is_some(), "i -> call-id");
                assert!(req.headers.get("contact").is_some(), "m -> contact");
                // get でも compact form を解決できる
                assert_eq!(req.headers.get("v"), req.headers.get("via"));
            }
            _ => panic!("expected request"),
        }
    }

    #[test]
    fn test_canonical_header_for_unknown() {
        assert_eq!(canonical_header_name("x-my-header"), "X-My-Header");
        assert_eq!(canonical_header_name("call-id"), "Call-ID");
        assert_eq!(canonical_header_name("cseq"), "CSeq");
    }

    #[test]
    fn test_method_other_for_unknown() {
        // 既知の RFC 拡張 (REFER/MESSAGE/UPDATE/NOTIFY 等) は Issue #110 で
        // 専用バリアント化済み。 真に未知のメソッドのみ `Other` に入る。
        let m: SipMethod = "FOOBAR".parse().unwrap();
        assert_eq!(m, SipMethod::Other("FOOBAR".to_string()));
        assert_eq!(m.as_str(), "FOOBAR");
        assert_eq!(format!("{}", m), "FOOBAR");
    }

    #[test]
    fn test_method_publish_prack_explicit() {
        // RFC 3262 / RFC 3903: PRACK / PUBLISH は専用バリアント。
        let p: SipMethod = "PRACK".parse().unwrap();
        let pub_: SipMethod = "PUBLISH".parse().unwrap();
        assert_eq!(p, SipMethod::Prack);
        assert_eq!(pub_, SipMethod::Publish);
    }

    /// Issue #110 / RFC 3311 / RFC 3428 / RFC 3515: UPDATE / MESSAGE / REFER は
    /// 上位ルータが個別 default 応答 (UPDATE → 481、 MESSAGE → 200 OK、
    /// REFER → 405 等) を返せるよう専用バリアントを持つ。
    /// `Other(String)` に落ちると一律 405 になり IMS 経由の MESSAGE 再送
    /// ストーム等を引き起こすため、 パース時に区別しておく。
    #[test]
    fn rfc3311_3428_3515_method_update_message_refer_have_explicit_variants() {
        let u: SipMethod = "UPDATE".parse().unwrap();
        let msg: SipMethod = "MESSAGE".parse().unwrap();
        let r: SipMethod = "REFER".parse().unwrap();
        assert_eq!(u, SipMethod::Update);
        assert_eq!(msg, SipMethod::Message);
        assert_eq!(r, SipMethod::Refer);
        assert_eq!(u.as_str(), "UPDATE");
        assert_eq!(msg.as_str(), "MESSAGE");
        assert_eq!(r.as_str(), "REFER");
    }

    #[test]
    fn test_parse_sip_uri_basic() {
        let u = parse_sip_uri("sip:bob@example.com").unwrap();
        assert_eq!(u.scheme, "sip");
        assert_eq!(u.user.as_deref(), Some("bob"));
        assert_eq!(u.host, "example.com");
        assert!(u.port.is_none());
        assert!(u.params.is_empty());
        assert!(u.headers.is_empty());
    }

    #[test]
    fn test_parse_sip_uri_with_port_and_params() {
        let u = parse_sip_uri("sip:alice@host.example:5061;transport=tls;lr").unwrap();
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.host, "host.example");
        assert_eq!(u.port, Some(5061));
        assert!(u.has_param("lr"));
        assert_eq!(u.param("transport"), Some("tls"));
        assert_eq!(u.param("LR"), Some("")); // case-insensitive lookup
    }

    #[test]
    fn test_parse_sip_uri_with_headers() {
        let u = parse_sip_uri("sip:bob@x.example?Subject=Hi&Priority=urgent").unwrap();
        assert_eq!(u.headers.len(), 2);
        assert_eq!(u.headers[0].0, "subject");
        assert_eq!(u.headers[0].1, "Hi");
        assert_eq!(u.headers[1].0, "priority");
    }

    #[test]
    fn test_parse_sip_uri_ipv6() {
        let u = parse_sip_uri("sips:[2001:db8::1]:5061;transport=tls").unwrap();
        assert_eq!(u.scheme, "sips");
        assert_eq!(u.host, "[2001:db8::1]");
        assert_eq!(u.port, Some(5061));
        assert!(u.user.is_none());
    }

    #[test]
    fn test_parse_sip_uri_with_password_strips_password() {
        let u = parse_sip_uri("sip:alice:secret@x.example").unwrap();
        assert_eq!(u.user.as_deref(), Some("alice"));
    }

    #[test]
    fn test_parse_sip_uri_rejects_empty() {
        assert!(parse_sip_uri("").is_err());
        assert!(parse_sip_uri("bob@x.example").is_err());
    }

    /// RFC 3261 §20.14 / §18.3: `Content-Length: 0` のとき、
    /// CRLFCRLF 以降に余剰バイトがあっても本文は空でなければならない。
    /// (1 datagram に 2 メッセージを詰めるケースの保険)
    #[test]
    fn rfc3261_20_14_content_length_zero_ignores_trailing_body() {
        let mut msg = Vec::new();
        msg.extend_from_slice(
            b"OPTIONS sip:bob@x SIP/2.0\r\n\
              Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
              From: <sip:a@x>;tag=1\r\n\
              To: <sip:b@x>\r\n\
              Call-ID: 123@x\r\n\
              CSeq: 1 OPTIONS\r\n\
              Content-Length: 0\r\n\
              \r\n",
        );
        // 余剰データ (別の SIP メッセージ片の混入を模擬)
        msg.extend_from_slice(b"GARBAGE-EXTRA-DATA");
        let parsed = parse_message(&msg).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert!(
                    req.body.is_empty(),
                    "Content-Length: 0 のとき body は空でなければならない"
                );
            }
            _ => panic!("expected request"),
        }
    }

    /// RFC 3261 §20.14: `Content-Length: N` で実本文が N より短い場合、
    /// truncate と見なして parse error を返す。
    /// (UDP `recv_loop` の固定バッファ 8192 を超えた INVITE で起きうる)
    #[test]
    fn rfc3261_20_14_content_length_exceeds_body_returns_err() {
        let msg = b"INVITE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 INVITE\r\n\
                    Content-Length: 100\r\n\
                    \r\n\
                    short body";
        let result = parse_message(msg);
        assert!(
            result.is_err(),
            "Content-Length が body より大きい場合は parse 失敗 (truncate 検知)"
        );
        let err_text = format!("{}", result.unwrap_err());
        assert!(
            err_text.contains("Content-Length"),
            "エラーメッセージは Content-Length 起因と分かること: {}",
            err_text
        );
    }

    /// RFC 3261 §20.14: `Content-Length: N` で実本文が N より長い場合、
    /// 本文は先頭 N バイトのみ採用。残余は次 datagram 扱い (drop)。
    #[test]
    fn rfc3261_20_14_content_length_shorter_than_body_takes_prefix() {
        let mut msg = Vec::new();
        msg.extend_from_slice(
            b"INVITE sip:bob@x SIP/2.0\r\n\
              Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
              From: <sip:a@x>;tag=1\r\n\
              To: <sip:b@x>\r\n\
              Call-ID: 123@x\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Type: application/sdp\r\n\
              Content-Length: 5\r\n\
              \r\n",
        );
        msg.extend_from_slice(b"HELLO" /* 5 bytes */);
        // 後続の余剰 ASCII (= 別メッセージ片を模擬)
        msg.extend_from_slice(b"TRAILING-EXTRA");
        let parsed = parse_message(&msg).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.body, b"HELLO".to_vec());
            }
            _ => panic!("expected request"),
        }
    }

    /// RFC 3261 §7.4: message-body は任意 octet 列。 UTF-8 妥当性を
    /// メッセージ全体に要求する parser はバイナリ body を受理できず
    /// 不正。 ここでは body に non-UTF8 バイトを混ぜて受理されることを保証。
    #[test]
    fn rfc3261_7_4_non_utf8_body_is_accepted() {
        let mut msg = Vec::new();
        msg.extend_from_slice(
            b"INVITE sip:bob@x SIP/2.0\r\n\
              Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
              From: <sip:a@x>;tag=1\r\n\
              To: <sip:b@x>\r\n\
              Call-ID: 123@x\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Type: application/octet-stream\r\n\
              Content-Length: 4\r\n\
              \r\n",
        );
        // 不正 UTF-8 シーケンス (lone 0xFF, 続く 0xFE はサロゲートではない非 ASCII)
        msg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x80]);
        let parsed = parse_message(&msg).expect("non-UTF8 body must be accepted");
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.body, vec![0xFF, 0xFE, 0x00, 0x80]);
            }
            _ => panic!("expected request"),
        }
    }

    /// RFC 3261 §18.3: `Content-Length` ヘッダが欠落した UDP datagram は
    /// CRLFCRLF 以降を全て body として採用 (datagram 末尾で確定)。
    /// 既存の `test_parse_response_401` 等が体感する後方互換性を保証。
    #[test]
    fn rfc3261_18_3_no_content_length_uses_remaining_bytes() {
        let raw = b"BYE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>;tag=2\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 2 BYE\r\n\
                    \r\n\
                    SDP-LIKE-PAYLOAD";
        let parsed = parse_message(raw).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.body, b"SDP-LIKE-PAYLOAD".to_vec());
            }
            _ => panic!("expected request"),
        }
    }

    /// RFC 3261 §20.14: Content-Length の compact form `l` も同様に解釈される。
    /// `l: 0` で trailing data が drop されること。
    #[test]
    fn rfc3261_20_14_compact_content_length_form_works() {
        let mut msg = Vec::new();
        msg.extend_from_slice(
            b"OPTIONS sip:bob@x SIP/2.0\r\n\
              v: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
              f: <sip:a@x>;tag=1\r\n\
              t: <sip:b@x>\r\n\
              i: 123@x\r\n\
              CSeq: 1 OPTIONS\r\n\
              l: 0\r\n\
              \r\n",
        );
        msg.extend_from_slice(b"EXTRA");
        let parsed = parse_message(&msg).unwrap();
        match parsed {
            SipMessage::Request(req) => {
                assert!(req.body.is_empty());
            }
            _ => panic!("expected request"),
        }
    }

    /// 不正な Content-Length 値 (非数値) は parse error。
    #[test]
    fn rfc3261_20_14_malformed_content_length_value_is_err() {
        let raw = b"OPTIONS sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 OPTIONS\r\n\
                    Content-Length: abc\r\n\
                    \r\n";
        assert!(parse_message(raw).is_err());
    }

    /// RFC 3261 §7.3.1 / §20.14: 同名複数値の合成は `,` 連結で意味が同じ場合のみ
    /// 許容される。 `Content-Length` のような単一値ヘッダで重複が現れた場合は
    /// protocol violation として `Err` を返す (request smuggling 風の食い違いを
    /// 1 件目だけ採用して silent に通すのを防ぐ)。
    #[test]
    fn rfc3261_7_3_1_duplicate_content_length_is_err() {
        let mut msg = Vec::new();
        msg.extend_from_slice(
            b"INVITE sip:bob@x SIP/2.0\r\n\
              Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
              From: <sip:a@x>;tag=1\r\n\
              To: <sip:b@x>\r\n\
              Call-ID: 123@x\r\n\
              CSeq: 1 INVITE\r\n\
              Content-Type: application/sdp\r\n\
              Content-Length: 0\r\n\
              Content-Length: 999\r\n\
              \r\n",
        );
        msg.extend_from_slice(b"v=0\r\n");
        let result = parse_message(&msg);
        assert!(
            result.is_err(),
            "重複 Content-Length は protocol violation で Err"
        );
        let err_text = format!("{}", result.unwrap_err());
        assert!(
            err_text.contains("duplicate Content-Length"),
            "重複検知メッセージが含まれること: {}",
            err_text
        );
    }

    /// RFC 3261 §7.3.1 / §25.1: ヘッダ中に non-UTF8 バイトが 1 個混入しても、
    /// `from_utf8_lossy` で U+FFFD 置換してパースを継続する。
    /// (旧実装は strict `from_utf8` でメッセージ全体を drop していた DoS 経路を遮断)
    #[test]
    fn rfc3261_7_3_1_non_utf8_in_header_is_lossy_tolerated() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"OPTIONS sip:bob@x SIP/2.0\r\n");
        msg.extend_from_slice(b"Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n");
        // Subject 中に lone 0xFF (非 UTF-8 シーケンス)
        msg.extend_from_slice(b"Subject: hello-");
        msg.extend_from_slice(&[0xFF, 0xFE]);
        msg.extend_from_slice(b"-world\r\n");
        msg.extend_from_slice(b"From: <sip:a@x>;tag=1\r\n");
        msg.extend_from_slice(b"To: <sip:b@x>\r\n");
        msg.extend_from_slice(b"Call-ID: 123@x\r\n");
        msg.extend_from_slice(b"CSeq: 1 OPTIONS\r\n");
        msg.extend_from_slice(b"Content-Length: 0\r\n");
        msg.extend_from_slice(b"\r\n");
        let parsed = parse_message(&msg).expect("non-UTF8 in header must be lossy-tolerated");
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.method, SipMethod::Options);
                // Subject は U+FFFD 置換済で取得できる
                let subject = req.headers.get("subject").expect("subject preserved");
                assert!(subject.starts_with("hello-"));
                assert!(subject.ends_with("-world"));
                assert!(req.body.is_empty());
            }
            _ => panic!("expected request"),
        }
    }

    /// 実機 NGN pcap 由来の Asterisk → NGN INVITE (`docs/asterisk-real-invite.md` §2)
    /// を round-trip パースして、 主要ヘッダと SDP body が正しく分離されることを
    /// 検証する。 SDP は §20.14 `Content-Length: 239` (header の余分空白あり)
    /// で切り出されること。
    #[test]
    fn rfc3261_20_14_real_ngn_invite_pcap_roundtrip() {
        // docs/asterisk-real-invite.md §2 の実 INVITE (CRLF 化 + `Content-Length: 239`
        // でヘッダ余分空白を保持)。 SDP 本体は 239 byte。
        let sdp = b"v=0\r\n\
                    o=- 397958033 397958033 IN IP4 118.177.72.242\r\n\
                    s=Asterisk\r\n\
                    c=IN IP4 118.177.72.242\r\n\
                    t=0 0\r\n\
                    m=audio 18082 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=fmtp:101 0-16\r\n\
                    a=ptime:20\r\n\
                    a=maxptime:140\r\n\
                    a=sendrecv\r\n";
        assert_eq!(sdp.len(), 239, "fixture SDP は 239 byte (CL と一致)");

        let mut msg = Vec::new();
        msg.extend_from_slice(b"INVITE sip:117@118.177.125.1:5060 SIP/2.0\r\n");
        msg.extend_from_slice(b"Via: SIP/2.0/UDP 118.177.72.242:5060;rport;branch=z9hG4bKPjac6a0a13-425d-4c85-b117-1d893768383b\r\n");
        msg.extend_from_slice(b"From: \"Anonymous\" <sip:0191349809@ntt-east.ne.jp>;tag=7e826d40-db17-4666-85e5-7a580b962429\r\n");
        msg.extend_from_slice(b"To: <sip:117@118.177.125.1>\r\n");
        msg.extend_from_slice(b"Contact: <sip:0191349809@118.177.72.242:5060>\r\n");
        msg.extend_from_slice(b"Call-ID: 2fe2b037-4e09-4dbb-9f2a-87984af6a866\r\n");
        msg.extend_from_slice(b"CSeq: 3424 INVITE\r\n");
        msg.extend_from_slice(b"Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, INFO, MESSAGE, REFER\r\n");
        msg.extend_from_slice(b"Supported: 100rel, timer, replaces, norefersub, histinfo\r\n");
        msg.extend_from_slice(b"Session-Expires: 1800\r\n");
        msg.extend_from_slice(b"Min-SE: 90\r\n");
        msg.extend_from_slice(b"Max-Forwards: 70\r\n");
        msg.extend_from_slice(b"User-Agent: Asterisk PBX 20.6.0~dfsg+~cs6.13.40431414-2build5\r\n");
        msg.extend_from_slice(b"Content-Type: application/sdp\r\n");
        // pcap では `Content-Length:   239` (3 連空白)。 RFC 3261 §7.3.1 の LWS 許容を確認
        msg.extend_from_slice(b"Content-Length:   239\r\n");
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(sdp);

        let parsed = parse_message(&msg).expect("real NGN INVITE must parse");
        match parsed {
            SipMessage::Request(req) => {
                assert_eq!(req.method, SipMethod::Invite);
                assert_eq!(req.uri, "sip:117@118.177.125.1:5060");
                assert_eq!(
                    req.headers.get("call-id"),
                    Some("2fe2b037-4e09-4dbb-9f2a-87984af6a866")
                );
                assert_eq!(req.headers.get("cseq"), Some("3424 INVITE"));
                assert_eq!(req.headers.get("content-length"), Some("239"));
                assert!(req
                    .headers
                    .get("from")
                    .unwrap()
                    .contains("0191349809@ntt-east.ne.jp"));
                assert_eq!(req.headers.get("to"), Some("<sip:117@118.177.125.1>"));
                // SDP body が full-fidelity で復元されていること
                assert_eq!(req.body, sdp.to_vec());
            }
            _ => panic!("expected request"),
        }
    }

    /// 実機 NGN pcap 由来の NGN → Asterisk 200 OK (`docs/asterisk-real-invite.md` §3.1)
    /// を round-trip パースする。 200 OK は **compact form** (`v`/`f`/`t`/`i`/`m`/`l`/`k`)
    /// で来るので、 normalize_header_name 経由で long form として取得できること、
    /// `l: 184` で SDP 184 byte を切り出せることを確認する。
    #[test]
    fn rfc3261_20_14_real_ngn_200ok_compact_form_roundtrip() {
        let sdp = b"v=0\r\n\
                    o=- 85704 85704 IN IP4 118.177.125.1\r\n\
                    s=-\r\n\
                    c=IN IP4 118.177.125.1\r\n\
                    t=0 0\r\n\
                    m=audio 24252 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000/1\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=fmtp:101 0-15\r\n";
        assert_eq!(sdp.len(), 184, "fixture SDP は 184 byte (l: と一致)");

        let mut msg = Vec::new();
        msg.extend_from_slice(b"SIP/2.0 200 OK\r\n");
        msg.extend_from_slice(
            b"v: SIP/2.0/UDP 118.177.72.242:5060;branch=z9hG4bKPjac6a0a13;rport=5060\r\n",
        );
        msg.extend_from_slice(b"i: 2fe2b037-4e09-4dbb-9f2a-87984af6a866\r\n");
        msg.extend_from_slice(b"CSeq: 3424 INVITE\r\n");
        msg.extend_from_slice(b"Session-Expires: 300;refresher=uas\r\n");
        msg.extend_from_slice(b"Require: timer\r\n");
        msg.extend_from_slice(b"Record-Route: <sip:118.177.125.1:5060;lr>\r\n");
        msg.extend_from_slice(b"t: <sip:117@118.177.125.1>;tag=B76D2E\r\n");
        msg.extend_from_slice(b"f: \"Anonymous\"<sip:0191349809@ntt-east.ne.jp>;tag=7e826d40-db17-4666-85e5-7a580b962429\r\n");
        msg.extend_from_slice(b"m: <sip:12455@118.177.125.1:5060>\r\n");
        msg.extend_from_slice(b"Allow: INVITE,ACK,BYE,CANCEL,UPDATE\r\n");
        msg.extend_from_slice(b"k: 100rel\r\n");
        msg.extend_from_slice(b"c: application/sdp\r\n");
        msg.extend_from_slice(b"l: 184\r\n");
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(sdp);

        let parsed = parse_message(&msg).expect("real NGN 200 OK must parse");
        match parsed {
            SipMessage::Response(resp) => {
                assert_eq!(resp.status_code, 200);
                assert_eq!(resp.reason, "OK");
                // compact form がすべて long form に展開されていること
                assert_eq!(
                    resp.headers.get("call-id"),
                    Some("2fe2b037-4e09-4dbb-9f2a-87984af6a866")
                );
                assert_eq!(resp.headers.get("cseq"), Some("3424 INVITE"));
                assert_eq!(resp.headers.get("content-length"), Some("184"));
                assert_eq!(resp.headers.get("content-type"), Some("application/sdp"));
                assert!(resp
                    .headers
                    .get("via")
                    .unwrap()
                    .contains("118.177.72.242:5060"));
                assert!(resp.headers.get("to").unwrap().contains("tag=B76D2E"));
                assert!(resp
                    .headers
                    .get("contact")
                    .unwrap()
                    .contains("12455@118.177.125.1"));
                // SDP body が full-fidelity で復元されていること
                assert_eq!(resp.body, sdp.to_vec());
            }
            _ => panic!("expected response"),
        }
    }

    /// RFC 3261 §21.4.1 (400 Bad Request): truncate (Content-Length 宣言値が
    /// datagram 本文長を上回る) は分類済 [`ParseError::Truncated`] を返し、
    /// 抽出された宣言/実バイト長で診断できる。
    #[test]
    fn rfc3261_21_4_1_truncate_classified_as_truncated_variant() {
        let raw = b"INVITE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 INVITE\r\n\
                    Content-Length: 100\r\n\
                    \r\n\
                    short body";
        let err = parse_message_classified(raw).expect_err("truncate must error");
        assert!(
            matches!(
                err,
                ParseError::Truncated {
                    declared: 100,
                    actual: 10
                }
            ),
            "Truncated 種別で declared=100 actual=10 を持つこと: {:?}",
            err
        );
        assert!(err.is_header_recoverable(), "truncate は 400 候補");
    }

    /// RFC 3261 §7.3.1 / §20.14: 重複 `Content-Length` は分類済
    /// [`ParseError::DuplicateContentLength`] を返し、 件数を保持する。
    #[test]
    fn rfc3261_7_3_1_duplicate_content_length_classified_variant() {
        let raw = b"INVITE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 INVITE\r\n\
                    Content-Length: 0\r\n\
                    Content-Length: 999\r\n\
                    \r\n";
        let err = parse_message_classified(raw).expect_err("duplicate CL must error");
        assert!(
            matches!(err, ParseError::DuplicateContentLength { count: 2 }),
            "DuplicateContentLength 種別で count=2 を持つこと: {:?}",
            err
        );
        assert!(err.is_header_recoverable(), "重複 CL は 400 候補");
    }

    /// RFC 3261 §20.14: 非数値 `Content-Length` は分類済
    /// [`ParseError::NonNumericContentLength`] を返す。
    #[test]
    fn rfc3261_20_14_non_numeric_content_length_classified_variant() {
        let raw = b"OPTIONS sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 OPTIONS\r\n\
                    Content-Length: abc\r\n\
                    \r\n";
        let err = parse_message_classified(raw).expect_err("non-numeric CL must error");
        match &err {
            ParseError::NonNumericContentLength { value } => {
                assert_eq!(value, "abc");
            }
            other => panic!("NonNumericContentLength 期待: {:?}", other),
        }
        assert!(err.is_header_recoverable(), "非数値 CL は 400 候補");
    }

    /// RFC 3261 §7.5: CRLFCRLF が無い datagram は header 終端不明で
    /// [`ParseError::NoCrlfCrlf`]。 応答先抽出不能なので `is_header_recoverable`
    /// は false。
    #[test]
    fn rfc3261_7_5_no_crlfcrlf_classified_variant_is_not_recoverable() {
        // \r\n\r\n が一切含まれない断片 (recv buffer 切れ等)
        let raw = b"INVITE sip:bob@x SIP/2.0\r\nVia: SIP/2.0/UDP h:5060;branch=z9hG4bKa";
        let err = parse_message_classified(raw).expect_err("no CRLFCRLF must error");
        assert!(matches!(err, ParseError::NoCrlfCrlf));
        assert!(!err.is_header_recoverable(), "header 終端不明は応答不能");
    }

    /// RFC 3261 §21.4.1 (400 Bad Request): truncate された malformed request
    /// から、 必須ヘッダ (Via/From/To/Call-ID/CSeq) を best-effort で抽出
    /// できること。 抽出結果は 400 応答の組み立て素材になる。
    #[test]
    fn rfc3261_21_4_1_extract_skeleton_from_truncated_request() {
        let raw = b"INVITE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKabc\r\n\
                    From: <sip:a@x>;tag=alice\r\n\
                    To: <sip:b@x>\r\n\
                    Call-ID: skel-call-id@x\r\n\
                    CSeq: 42 INVITE\r\n\
                    Content-Length: 9999\r\n\
                    \r\n\
                    body";
        let skel = extract_request_skeleton_for_400(raw).expect("skeleton must extract");
        assert_eq!(skel.method, SipMethod::Invite);
        assert_eq!(skel.uri, "sip:bob@x");
        assert_eq!(
            skel.headers.get("via"),
            Some("SIP/2.0/UDP h:5060;branch=z9hG4bKabc")
        );
        assert_eq!(skel.headers.get("from"), Some("<sip:a@x>;tag=alice"));
        assert_eq!(skel.headers.get("to"), Some("<sip:b@x>"));
        assert_eq!(skel.headers.get("call-id"), Some("skel-call-id@x"));
        assert_eq!(skel.headers.get("cseq"), Some("42 INVITE"));
    }

    /// RFC 3261 §8.1.1: Via/From/To/Call-ID/CSeq のいずれかを欠く request
    /// からは skeleton を抽出しない (応答先 / 応答ヘッダが組み立てられない)。
    #[test]
    fn rfc3261_8_1_1_extract_skeleton_rejects_missing_required_headers() {
        // Call-ID 欠落
        let raw = b"INVITE sip:bob@x SIP/2.0\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKabc\r\n\
                    From: <sip:a@x>;tag=alice\r\n\
                    To: <sip:b@x>\r\n\
                    CSeq: 42 INVITE\r\n\
                    \r\n";
        assert!(extract_request_skeleton_for_400(raw).is_none());
    }

    /// 応答 (Status line) からは skeleton を抽出しない (応答に対する応答は
    /// 出さない、 RFC 3261 §8.2.6)。
    #[test]
    fn rfc3261_8_2_6_extract_skeleton_rejects_response() {
        let raw = b"SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\n\
                    From: <sip:a@x>;tag=1\r\n\
                    To: <sip:b@x>;tag=2\r\n\
                    Call-ID: 123@x\r\n\
                    CSeq: 1 INVITE\r\n\
                    \r\n";
        assert!(extract_request_skeleton_for_400(raw).is_none());
    }

    /// CRLFCRLF が無いと header 終端が不明で skeleton 抽出不能。
    #[test]
    fn rfc3261_7_5_extract_skeleton_rejects_no_crlfcrlf() {
        let raw = b"INVITE sip:bob@x SIP/2.0\r\nVia: SIP/2.0/UDP h:5060;branch=z9hG4bKa\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: 123@x\r\nCSeq: 1 INVITE\r\n";
        assert!(extract_request_skeleton_for_400(raw).is_none());
    }
}
