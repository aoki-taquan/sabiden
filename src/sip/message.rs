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

/// SIP メッセージのパーサ。
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
///   - `N > body_len` → `400 Bad Request` 相当の `Err`
///     (UDP 切詰め検知、TCP では §18.3 上必須エラー)。
///   - 同名複数値 (重複) は **`Err`**。 RFC 3261 §7.3.1 では同名複数値の
///     合成は `,` 連結で意味が同じ場合のみ許容され、`Content-Length` のような
///     単一値ヘッダで重複が現れた場合は protocol violation。 attacker が
///     `Content-Length: 0\r\nContent-Length: 999\r\n` のような request
///     smuggling 風の食い違いを仕込んでも 1 件目だけ採用して silent に通る
///     ことを防ぐ。
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
pub fn parse_message(data: &[u8]) -> anyhow::Result<SipMessage> {
    // ヘッダ末尾境界 (CRLFCRLF) を **生バイト** で検索する。
    // RFC 3261 §7.5 で header-body 区切りは厳密に CRLFCRLF と規定。
    let header_end = find_subslice(data, b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed SIP message: no CRLFCRLF"))?;
    let header_bytes = &data[..header_end];
    let body_bytes = &data[header_end + 4..];

    // ヘッダ部を **lossy** 変換。RFC 3261 §7.3.1 / §25.1 (TEXT-UTF8-TRIM)
    // で UTF-8 が想定だが、不正バイトを 1 個混ぜただけで全 SIP メッセージ
    // が drop されると DoS 経路になるため、U+FFFD 置換でパースを継続する
    // (上位層が必要なら 400 Bad Request を返す機会を残す)。
    let header_text = String::from_utf8_lossy(header_bytes);

    let mut lines = header_text.split("\r\n");
    let first_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty SIP message"))?;

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
                .map_err(|_| anyhow::anyhow!("malformed Content-Length header value: {:?}", raw))?;
            if n > body_bytes.len() {
                // RFC 3261 §18.3: 宣言サイズより datagram の本文部が短い場合、
                // 切詰め (truncation) として扱う。 UDP では `recv_loop` の
                // 8192 byte buf を超えた INVITE で発生しうる。
                anyhow::bail!(
                    "Content-Length {} exceeds available body bytes {}",
                    n,
                    body_bytes.len()
                );
            }
            // n <= body_bytes.len(): 余剰は別 datagram 扱い (drop)
            body_bytes[..n].to_vec()
        }
        _ => {
            // RFC 3261 §7.3.1: 同名複数値の合成は `,` 連結で意味が同じ場合のみ。
            // Content-Length は単一値ヘッダ (§20.14) なので、重複は protocol
            // violation として `Err` で drop する (request smuggling 経路を遮断)。
            anyhow::bail!(
                "duplicate Content-Length header (count={}): possible request smuggling",
                cl_values.len()
            );
        }
    };

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
}
