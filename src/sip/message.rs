use std::fmt;

#[derive(Debug, Clone, PartialEq)]
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
        self.fields.iter().find(|(k, _)| k == &key).map(|(_, v)| v.as_str())
    }

    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let key = name.to_lowercase();
        self.fields.iter().filter(|(k, _)| k == &key).map(|(_, v)| v.as_str()).collect()
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

/// SIP メッセージのパーサ
pub fn parse_message(data: &[u8]) -> anyhow::Result<SipMessage> {
    let text = std::str::from_utf8(data)?;
    let (header_part, body_part) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed SIP message: no CRLFCRLF"))?;

    let mut lines = header_part.split("\r\n");
    let first_line = lines.next().ok_or_else(|| anyhow::anyhow!("empty SIP message"))?;

    let mut headers = SipHeaders::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(": ") {
            headers.add(k.trim(), v.trim());
        } else if let Some((k, v)) = line.split_once(":") {
            headers.add(k.trim(), v.trim());
        }
    }

    let body = body_part.as_bytes().to_vec();

    if first_line.starts_with("SIP/2.0 ") {
        let rest = &first_line["SIP/2.0 ".len()..];
        let (code_str, reason) = rest
            .split_once(' ')
            .unwrap_or((rest, ""));
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
        req.headers.set("From", "<sip:0312345678@ntt-east.ne.jp>;tag=abc");
        req.headers.set("To", "<sip:0312345678@ntt-east.ne.jp>");
        req.headers.set("Call-ID", "callid@host");
        req.headers.set("CSeq", "1 REGISTER");
        let bytes = req.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("REGISTER sip:ntt-east.ne.jp SIP/2.0\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
    }
}
