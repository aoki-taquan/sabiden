use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Info,
    Notify,
    Subscribe,
}

impl fmt::Display for SipMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipMethod::Register => write!(f, "REGISTER"),
            SipMethod::Invite => write!(f, "INVITE"),
            SipMethod::Ack => write!(f, "ACK"),
            SipMethod::Bye => write!(f, "BYE"),
            SipMethod::Cancel => write!(f, "CANCEL"),
            SipMethod::Options => write!(f, "OPTIONS"),
            SipMethod::Info => write!(f, "INFO"),
            SipMethod::Notify => write!(f, "NOTIFY"),
            SipMethod::Subscribe => write!(f, "SUBSCRIBE"),
        }
    }
}

impl std::str::FromStr for SipMethod {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "REGISTER" => Ok(SipMethod::Register),
            "INVITE" => Ok(SipMethod::Invite),
            "ACK" => Ok(SipMethod::Ack),
            "BYE" => Ok(SipMethod::Bye),
            "CANCEL" => Ok(SipMethod::Cancel),
            "OPTIONS" => Ok(SipMethod::Options),
            "INFO" => Ok(SipMethod::Info),
            "NOTIFY" => Ok(SipMethod::Notify),
            "SUBSCRIBE" => Ok(SipMethod::Subscribe),
            _ => anyhow::bail!("unknown SIP method: {}", s),
        }
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

/// 複数値を持てる SIP ヘッダ (Via 等は複数行になる)
#[derive(Debug, Clone, Default)]
pub struct SipHeaders {
    // 小文字キーで保持
    fields: Vec<(String, String)>,
}

impl SipHeaders {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let key = name.to_lowercase();
        // 既存エントリを上書き (最初の1件のみ)
        if let Some(pos) = self.fields.iter().position(|(k, _)| k == &key) {
            self.fields[pos].1 = value.into();
        } else {
            self.fields.push((key, value.into()));
        }
    }

    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.fields.push((name.to_lowercase(), value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let key = name.to_lowercase();
        self.fields
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let key = name.to_lowercase();
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

fn canonical_header_name(lower: &str) -> &str {
    match lower {
        "via" => "Via",
        "from" => "From",
        "to" => "To",
        "call-id" => "Call-ID",
        "cseq" => "CSeq",
        "contact" => "Contact",
        "content-type" => "Content-Type",
        "content-length" => "Content-Length",
        "max-forwards" => "Max-Forwards",
        "authorization" => "Authorization",
        "www-authenticate" => "WWW-Authenticate",
        "expires" => "Expires",
        "allow" => "Allow",
        "supported" => "Supported",
        "session-expires" => "Session-Expires",
        "min-se" => "Min-SE",
        "p-preferred-identity" => "P-Preferred-Identity",
        "p-asserted-identity" => "P-Asserted-Identity",
        "user-agent" => "User-Agent",
        other => other,
    }
}

/// 簡易 SIP URI 分解結果。RFC 3261 §19.1 完全準拠ではなく、
/// `sip:user@host[:port][;params][?headers]` の主要部分のみを抜き出す。
/// `<>` などの display-name angle-brackets は含めずに渡すこと。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUriParts<'a> {
    /// "sip" / "sips" / "tel" 等のスキーム (小文字化はしない)。
    pub scheme: &'a str,
    /// `@` の左側 (ユーザ部)。`None` なら `host` のみ。
    pub user: Option<&'a str>,
    /// host (IPv4 / IPv6 リテラル `[..]` / FQDN)。port やパラメータは除外済み。
    pub host: &'a str,
    /// `:port` 部 (省略可)。
    pub port: Option<&'a str>,
}

/// `sip:user@host[:port][;params]` 形式の SIP URI を分解する。
///
/// - `<sip:..>` の山括弧は事前に剥がしてから渡すこと
/// - `;params` `?headers` は捨てる
/// - IPv6 リテラル `[2001:db8::1]:5060` を扱える
///
/// 失敗時は `None`。本格的な RFC 3261 §19.1 パーサは用意しない。
pub fn parse_sip_uri(uri: &str) -> Option<SipUriParts<'_>> {
    let uri = uri.trim();
    // angle-brackets が残っている場合は剥がす
    let uri = uri
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(uri);
    let (scheme, rest) = uri.split_once(':')?;
    // パラメータ / ヘッダ部を捨てる
    let rest = rest.split(';').next()?;
    let rest = rest.split('?').next()?;

    let (user, hostport) = match rest.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };

    // IPv6 リテラル `[..]` を考慮した host:port 分離
    let (host, port) = if let Some(rest_after_bracket) = hostport.strip_prefix('[') {
        let (h, after) = rest_after_bracket.split_once(']')?;
        // `[host]:port` または `[host]` のみ
        let port = after.strip_prefix(':');
        // host 部に `[]` を含めて返す形にもできるが、比較しやすさを優先して中身のみ。
        (h, port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        // ":" を 1 つ含む通常の IPv4/FQDN
        (h, Some(p))
    } else {
        (hostport, None)
    };

    if host.is_empty() {
        return None;
    }
    Some(SipUriParts {
        scheme,
        user,
        host,
        port,
    })
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
        if let Some((k, v)) = line.split_once(": ") {
            headers.add(k.trim(), v.trim());
        } else if let Some((k, v)) = line.split_once(":") {
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
    fn parse_sip_uri_user_host() {
        let p = parse_sip_uri("sip:117@192.168.20.239").unwrap();
        assert_eq!(p.scheme, "sip");
        assert_eq!(p.user, Some("117"));
        assert_eq!(p.host, "192.168.20.239");
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_sip_uri_strips_params_and_port() {
        let p = parse_sip_uri("sip:117@192.168.20.239:5060;transport=udp").unwrap();
        assert_eq!(p.user, Some("117"));
        assert_eq!(p.host, "192.168.20.239");
        assert_eq!(p.port, Some("5060"));
    }

    #[test]
    fn parse_sip_uri_strips_angle_brackets() {
        let p = parse_sip_uri("<sip:0312345678@ntt-east.ne.jp>").unwrap();
        assert_eq!(p.user, Some("0312345678"));
        assert_eq!(p.host, "ntt-east.ne.jp");
    }

    #[test]
    fn parse_sip_uri_ipv6_literal() {
        let p = parse_sip_uri("sip:bob@[2001:db8::1]:5060").unwrap();
        assert_eq!(p.user, Some("bob"));
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, Some("5060"));
    }

    #[test]
    fn parse_sip_uri_no_user() {
        let p = parse_sip_uri("sip:ntt-east.ne.jp").unwrap();
        assert_eq!(p.user, None);
        assert_eq!(p.host, "ntt-east.ne.jp");
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
}
