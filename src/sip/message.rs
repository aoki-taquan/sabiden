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
/// (PUBLISH/NOTIFY/SUBSCRIBE/PRACK) は専用バリアントを持ち、未知の
/// メソッドは [`SipMethod::Other`] にフォールバックする。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Info,
    /// RFC 3265
    Notify,
    /// RFC 3265
    Subscribe,
    /// RFC 3262 (Reliable Provisional Responses)
    Prack,
    /// RFC 3903 (Event State Publication)
    Publish,
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
/// - `host`: ホスト or `[v6]`
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

/// SIP メッセージのパーサ
pub fn parse_message(data: &[u8]) -> anyhow::Result<SipMessage> {
    let text = std::str::from_utf8(data)?;
    let (header_part, body_part) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed SIP message: no CRLFCRLF"))?;

    let mut lines = header_part.split("\r\n");
    let first_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty SIP message"))?;

    let mut headers = SipHeaders::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.add(k.trim(), v.trim());
        }
    }

    let body = body_part.as_bytes().to_vec();

    if let Some(rest) = first_line.strip_prefix("SIP/2.0 ") {
        let (code_str, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        let status_code: u16 = code_str.parse()?;
        Ok(SipMessage::Response(SipResponse {
            status_code,
            reason: reason.to_string(),
            headers,
            body,
        }))
    } else {
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            anyhow::bail!("malformed SIP request line: {}", first_line);
        }
        let method: SipMethod = parts[0].parse()?;
        let uri = parts[1].to_string();
        Ok(SipMessage::Request(SipRequest {
            method,
            uri,
            headers,
            body,
        }))
    }
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
        // RFC 3428 (MESSAGE) など未対応メソッドは Other に入る
        let m: SipMethod = "MESSAGE".parse().unwrap();
        assert_eq!(m, SipMethod::Other("MESSAGE".to_string()));
        assert_eq!(m.as_str(), "MESSAGE");
        assert_eq!(format!("{}", m), "MESSAGE");
    }

    #[test]
    fn test_method_publish_prack_explicit() {
        // RFC 3262 / RFC 3903: PRACK / PUBLISH は専用バリアント。
        let p: SipMethod = "PRACK".parse().unwrap();
        let pub_: SipMethod = "PUBLISH".parse().unwrap();
        assert_eq!(p, SipMethod::Prack);
        assert_eq!(pub_, SipMethod::Publish);
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
}
