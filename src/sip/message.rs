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
    /// RFC 3262 (PRACK), RFC 3265 (NOTIFY/SUBSCRIBE), RFC 3311 (UPDATE),
    /// RFC 3428 (MESSAGE), RFC 3515 (REFER), RFC 3903 (PUBLISH) など、
    /// 個別ハンドラを持たないメソッドを横断で受ける。Linphone は presence で
    /// PUBLISH を流すので、本バリアントが無いとメッセージ全体が drop される。
    Other(String),
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
            SipMethod::Other(name) => write!(f, "{}", name),
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
            // 既知 SIP メソッド名 (大文字 ASCII) ならば Other に格納し、
            // UAS 側で 405 Method Not Allowed として応答する。
            other if !other.is_empty() && other.bytes().all(|b| b.is_ascii_uppercase()) => {
                Ok(SipMethod::Other(other.to_string()))
            }
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
        let key = normalize_header_key(name);
        // 既存エントリを上書き (最初の1件のみ)
        if let Some(pos) = self.fields.iter().position(|(k, _)| k == &key) {
            self.fields[pos].1 = value.into();
        } else {
            self.fields.push((key, value.into()));
        }
    }

    pub fn add(&mut self, name: &str, value: impl Into<String>) {
        self.fields.push((normalize_header_key(name), value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let key = normalize_header_key(name);
        self.fields
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let key = normalize_header_key(name);
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

/// SIP ヘッダ名の格納キーを生成する。
/// 大文字小文字差を吸収しつつ、RFC 3261 §7.3.3 のコンパクト形式 (`v`, `f`, `t`, `i`,
/// `m`, `l`, `s`, `c`, `k`, `e` 等) を完全形に展開する。NTT NGN の P-CSCF は
/// 200 OK 等のレスポンスでコンパクト形式を多用するため、入口で正規化しないと
/// `headers.get("via")` 等で取り損なう。
fn normalize_header_key(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    let full = match lower.as_str() {
        // RFC 3261 §7.3.3
        "v" => "via",
        "f" => "from",
        "t" => "to",
        "i" => "call-id",
        "m" => "contact",
        "l" => "content-length",
        "s" => "subject",
        "c" => "content-type",
        "k" => "supported",
        "e" => "content-encoding",
        // 拡張 (RFC 3265 / 3515 / 4028 / 4474 / 4538 等)
        "o" => "event",
        "u" => "allow-events",
        "r" => "refer-to",
        "b" => "referred-by",
        "x" => "session-expires",
        "y" => "identity",
        "n" => "identity-info",
        "a" => "accept-contact",
        "j" => "reject-contact",
        "d" => "request-disposition",
        other => return other.to_string(),
    };
    full.to_string()
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
    fn test_parse_response_compact_headers_ngn_200ok() {
        // NTT NGN P-CSCF が REGISTER 200 OK で実際に使うコンパクトヘッダ形式
        // (v=Via, f=From, t=To, i=Call-ID, m=Contact, l=Content-Length)。
        // 実機 pcap (118.177.125.1 → 118.177.72.242) から取得した形そのまま。
        let msg = b"SIP/2.0 200 OK\r\n\
v: SIP/2.0/UDP 118.177.72.242:5060;branch=z9hG4bK1a56953e6a112f02\r\n\
f: <sip:0191349809@ntt-east.ne.jp>;tag=956a3a90\r\n\
t: <sip:0191349809@ntt-east.ne.jp>;tag=3987286122\r\n\
i: afa66bea0b3de7c1@hikari-sip\r\n\
CSeq: 1 REGISTER\r\n\
m: <sip:0191349809@118.177.72.242:5060>;q=0;expires=3600\r\n\
l: 0\r\n\
\r\n";
        let parsed = parse_message(msg).unwrap();
        match parsed {
            SipMessage::Response(r) => {
                assert_eq!(r.status_code, 200);
                assert!(r.headers.get("via").is_some(), "via が compact 'v' から拾えない");
                assert!(r.headers.get("from").is_some());
                assert!(r.headers.get("to").is_some());
                assert!(r.headers.get("call-id").is_some());
                assert!(r.headers.get("contact").is_some());
                assert_eq!(r.headers.get("content-length"), Some("0"));
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
}
