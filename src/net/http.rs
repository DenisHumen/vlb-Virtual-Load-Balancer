//! Minimal HTTP/1.1 client whose TCP socket can be bound to a specific
//! provider via `SO_MARK`.
//!
//! Why not `reqwest`/`hyper`: we need two things no general-purpose client
//! gives us easily.
//!
//!  1. **`SO_MARK` on the connecting socket.** Every probe must leave
//!     through a chosen uplink regardless of which provider currently owns
//!     the default route. That means setting the mark *before* `connect`,
//!     which needs access to the raw fd.
//!  2. **A pre-resolved destination IP.** The hostname must be resolved
//!     through that same provider's marked DNS, not the system resolver.
//!     We pass the resolved IP in and still send the correct `Host:` header
//!     and TLS SNI, so virtual hosting and certificate validation work.
//!
//! The surface is deliberately small: one request, one response, connection
//! closed. No keep-alive, no pooling, no cookies.

use anyhow::{Context, Result, anyhow, bail};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Hard ceiling on any response body we will buffer. Probe bodies are a few
/// hundred bytes; release tarballs are a few MiB. Anything past the caller's
/// own `max_body` is dropped, and this constant stops a hostile/broken peer
/// from streaming forever even if a caller passes something silly.
pub const ABSOLUTE_MAX_BODY: usize = 64 * 1024 * 1024;

/// Parsed subset of a URL. We only ever speak `http` and `https` to an
/// explicit host, so a full RFC 3986 parser would be dead weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Path plus query, ready to be put on the request line. Always starts
    /// with `/`.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

impl Url {
    /// Parse `scheme://host[:port][/path][?query]`.
    ///
    /// Rejects anything we cannot faithfully reproduce on the wire:
    /// non-http(s) schemes, userinfo (`user@host` — a classic phishing
    /// vector we have no use for), empty hosts, and out-of-range ports.
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
            (Scheme::Https, r)
        } else if let Some(r) = raw.strip_prefix("http://") {
            (Scheme::Http, r)
        } else {
            bail!("url {raw:?} must start with http:// or https://");
        };

        // Split authority from path. A `#fragment` is client-side only and
        // never goes on the wire, so it is dropped here.
        let rest = rest.split('#').next().unwrap_or("");
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };

        if authority.contains('@') {
            bail!("url {raw:?} contains userinfo, which is not supported");
        }
        if authority.starts_with('[') {
            bail!("url {raw:?} uses an IPv6 literal host, which is not supported");
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| anyhow!("url {raw:?} has an invalid port {p:?}"))?;
                if port == 0 {
                    bail!("url {raw:?} has port 0");
                }
                (h, port)
            }
            None => (authority, scheme.default_port()),
        };

        if host.is_empty() {
            bail!("url {raw:?} has an empty host");
        }
        // Keep the host strictly to characters valid in a DNS name or an
        // IPv4 literal — this value ends up in the `Host:` header and in TLS
        // SNI, so a stray CR/LF here would be request splitting.
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            bail!("url {raw:?} has an invalid host {host:?}");
        }

        let path = if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };
        if path.chars().any(|c| c == '\r' || c == '\n' || c == ' ') {
            bail!("url {raw:?} has whitespace or control characters in the path");
        }

        Ok(Url {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// `host` or `host:port`, matching what a browser would send. The port
    /// is omitted when it is the scheme default, because some virtual-host
    /// setups key on the exact header value.
    pub fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Whether the host is an IPv4 literal — those need no DNS resolution
    /// and cannot be validated against a normal TLS certificate.
    pub fn host_as_ip(&self) -> Option<Ipv4Addr> {
        self.host.parse().ok()
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme.as_str(),
            self.host_header(),
            self.path
        )
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    /// Header names are lowercased; values keep their original casing.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// True when the body hit the caller's `max_body` cap and was cut short.
    pub truncated: bool,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        let want = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == want)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }
}

/// One HTTP request, fully specified.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: Url,
    /// Where to actually connect. Callers resolve the hostname themselves —
    /// through the provider's marked DNS — so we never touch the system
    /// resolver (which would use whichever provider owns the default route).
    pub connect_ip: Ipv4Addr,
    /// `SO_MARK` value, or `None` to use the default route.
    pub mark: Option<u32>,
    /// Bound on the whole exchange: connect, TLS handshake, write, read.
    pub timeout: Duration,
    pub max_body: usize,
    /// Sent verbatim as the `User-Agent` header.
    pub user_agent: String,
}

/// Perform the request and return the parsed response.
///
/// The entire exchange — connect, TLS handshake, write, read-to-EOF — sits
/// under a single `timeout`. Partial reads are not salvaged: a response we
/// could not finish reading is an error, never a half-body we might
/// mistakenly validate as canary content.
pub async fn fetch(req: &HttpRequest) -> Result<HttpResponse> {
    let max_body = req.max_body.min(ABSOLUTE_MAX_BODY);
    tokio::time::timeout(req.timeout, fetch_inner(req, max_body))
        .await
        .map_err(|_| {
            anyhow::Error::new(Timeout {
                url: req.url.to_string(),
                budget: req.timeout,
            })
        })?
}

/// The request ran out of time.
///
/// A distinct type rather than a message, because callers need to act on it
/// differently: for the throughput probe, "did not finish inside a budget
/// sized for a working link" is itself a statement about speed, while any
/// other failure is not. Matching on error text to make that distinction
/// would break the moment the wording changed.
#[derive(Debug, Clone)]
pub struct Timeout {
    pub url: String,
    pub budget: Duration,
}

impl std::fmt::Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "request to {} timed out after {:?}",
            self.url, self.budget
        )
    }
}

impl std::error::Error for Timeout {}

/// Did this error come from the request exceeding its budget?
pub fn is_timeout(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Timeout>().is_some()
}

async fn fetch_inner(req: &HttpRequest, max_body: usize) -> Result<HttpResponse> {
    let addr = SocketAddr::from((req.connect_ip, req.url.port));
    let stream = connect_marked(addr, req.mark)
        .await
        .with_context(|| format!("connect to {addr} failed"))?;

    let wire = build_request(req);

    match req.url.scheme {
        Scheme::Http => {
            let mut stream = stream;
            stream.write_all(&wire).await.context("write failed")?;
            stream.flush().await.ok();
            let raw = read_to_cap(&mut stream, max_body).await?;
            parse_response(&raw, max_body)
        }
        Scheme::Https => {
            let connector = tokio_rustls::TlsConnector::from(tls_config());
            // SNI and certificate validation both use the *hostname*, not
            // the IP we dialled. A transparent MITM proxy therefore cannot
            // satisfy this handshake without a certificate for the real
            // name — which is exactly the signal we want.
            let server_name = rustls_pki_types::ServerName::try_from(req.url.host.clone())
                .map_err(|_| anyhow!("host {:?} is not valid for TLS SNI", req.url.host))?;
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .context("TLS handshake failed")?;
            tls.write_all(&wire).await.context("write failed")?;
            tls.flush().await.ok();
            let raw = read_to_cap(&mut tls, max_body).await?;
            parse_response(&raw, max_body)
        }
    }
}

fn build_request(req: &HttpRequest) -> Vec<u8> {
    // `Connection: close` makes read-to-EOF a correct body terminator for
    // every response shape, which keeps the parser small.
    let text = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {ua}\r\n\
         Accept: */*\r\n\
         Accept-Encoding: identity\r\n\
         Cache-Control: no-cache, no-store\r\n\
         Pragma: no-cache\r\n\
         Connection: close\r\n\r\n",
        path = req.url.path,
        host = req.url.host_header(),
        ua = sanitize_header_value(&req.user_agent),
    );
    text.into_bytes()
}

/// Strip anything that could terminate a header line. The user-agent is the
/// only caller-supplied header value we emit, and it comes from config.
fn sanitize_header_value(v: &str) -> String {
    v.chars()
        .filter(|c| *c != '\r' && *c != '\n' && !c.is_control())
        .take(200)
        .collect()
}

/// Open a TCP connection with `SO_MARK` applied before `connect`, so the
/// kernel's `ip rule fwmark` lookup selects the provider's routing table for
/// the SYN itself.
async fn connect_marked(addr: SocketAddr, mark: Option<u32>) -> Result<tokio::net::TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4().context("failed to create socket")?;

    #[cfg(target_os = "linux")]
    if let Some(m) = mark {
        use std::os::fd::AsRawFd;
        let val: libc::c_int = m as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            // Failing open here would silently send the probe out of the
            // wrong uplink and report a healthy result for a dead provider.
            bail!(
                "setsockopt(SO_MARK, {m}) failed: {} — probe would leave via the \
                 wrong provider, refusing",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    if mark.is_some() {
        bail!("SO_MARK-bound probing is only supported on Linux");
    }

    let stream = socket.connect(addr).await?;
    // Probe payloads are single small writes; Nagle would only add latency.
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Read until EOF or until we have `max_body` bytes of body.
///
/// The cap is applied generously (headers + body) — `parse_response` does
/// the precise body-level truncation. Stopping early on a giant response is
/// what matters here.
async fn read_to_cap<S>(stream: &mut S, max_body: usize) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    // Headers are bounded separately in `parse_response`; 16 KiB of slack is
    // plenty for any real response head.
    let ceiling = max_body.saturating_add(16 * 1024);
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut chunk).await.context("read failed")?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= ceiling {
            break;
        }
    }
    if buf.is_empty() {
        bail!("peer closed the connection without sending a response");
    }
    Ok(buf)
}

/// Split the head from the body, parse the status line and headers, then
/// decode the body according to `Transfer-Encoding` / `Content-Length`.
pub fn parse_response(raw: &[u8], max_body: usize) -> Result<HttpResponse> {
    const MAX_HEAD: usize = 64 * 1024;

    let head_end = find_subslice(&raw[..raw.len().min(MAX_HEAD + 4)], b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| find_subslice(&raw[..raw.len().min(MAX_HEAD + 2)], b"\n\n").map(|i| i + 2))
        .ok_or_else(|| anyhow!("malformed response: no header terminator in the first 64 KiB"))?;

    let head = std::str::from_utf8(&raw[..head_end])
        .map_err(|_| anyhow!("malformed response: header block is not valid UTF-8"))?;
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r'));

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("malformed response: empty status line"))?;
    let mut sl = status_line.split_whitespace();
    let version = sl
        .next()
        .ok_or_else(|| anyhow!("malformed status line {status_line:?}"))?;
    if !version.starts_with("HTTP/") {
        bail!("malformed status line {status_line:?}: not an HTTP response");
    }
    let status: u16 = sl
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("malformed status line {status_line:?}: no status code"))?;

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Fold obs-fold continuation lines onto the previous value rather
        // than treating them as a new (nameless) header.
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }

    let raw_body = &raw[head_end..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));

    let (body, mut truncated) = if chunked {
        dechunk(raw_body, max_body)?
    } else {
        let content_length: Option<usize> = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        let end = match content_length {
            Some(n) => n.min(raw_body.len()),
            None => raw_body.len(),
        };
        let slice = &raw_body[..end];
        if slice.len() > max_body {
            (slice[..max_body].to_vec(), true)
        } else {
            (slice.to_vec(), false)
        }
    };

    if body.len() >= max_body {
        truncated = true;
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
        truncated,
    })
}

/// Decode `Transfer-Encoding: chunked`. Stops cleanly at the terminating
/// zero-length chunk, at `max_body`, or at the end of the available bytes.
fn dechunk(mut input: &[u8], max_body: usize) -> Result<(Vec<u8>, bool)> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let Some(nl) = find_subslice(input, b"\r\n") else {
            // Ran out of data mid-header: return what we decoded and mark it
            // truncated rather than pretending the body is complete.
            return Ok((out, true));
        };
        let size_line = std::str::from_utf8(&input[..nl]).unwrap_or("");
        // A chunk size may carry `;ext=value` extensions we ignore.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| anyhow!("malformed chunk size {size_hex:?}"))?;
        input = &input[nl + 2..];
        if size == 0 {
            return Ok((out, false));
        }
        if size > input.len() {
            out.extend_from_slice(input);
            return Ok((out, true));
        }
        out.extend_from_slice(&input[..size]);
        if out.len() >= max_body {
            out.truncate(max_body);
            return Ok((out, true));
        }
        // Skip the chunk's trailing CRLF.
        input = &input[size..];
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Shared rustls client config: webpki trust roots, safe defaults, built
/// once. Building it per request would re-parse the whole root store on
/// every probe tick.
fn tls_config() -> Arc<rustls::ClientConfig> {
    use std::sync::OnceLock;
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parse_basic() {
        let u = Url::parse("https://raw.githubusercontent.com/a/b/main/f.txt").unwrap();
        assert_eq!(u.scheme, Scheme::Https);
        assert_eq!(u.host, "raw.githubusercontent.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/a/b/main/f.txt");
        assert_eq!(u.host_header(), "raw.githubusercontent.com");

        let u = Url::parse("http://example.com").unwrap();
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/");

        let u = Url::parse("http://example.com:8080/x?y=1").unwrap();
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/x?y=1");
        assert_eq!(u.host_header(), "example.com:8080");
    }

    #[test]
    fn url_parse_normalises_and_rejects() {
        // Scheme and host are case-insensitive; host is lowercased so the
        // TLS SNI value is stable.
        assert_eq!(
            Url::parse("http://EXAMPLE.com/A").unwrap().host,
            "example.com"
        );
        // Fragments never go on the wire.
        assert_eq!(Url::parse("http://e.com/p#frag").unwrap().path, "/p");

        for bad in [
            "ftp://example.com/x",
            "example.com/x",
            "http://",
            "http://user@example.com/",
            "http://example.com:0/",
            "http://example.com:99999/",
            "http://[::1]/",
            "http://ex ample.com/",
        ] {
            assert!(
                Url::parse(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn url_host_as_ip() {
        assert_eq!(
            Url::parse("http://1.1.1.1/gen_204").unwrap().host_as_ip(),
            Some(Ipv4Addr::new(1, 1, 1, 1))
        );
        assert_eq!(
            Url::parse("http://example.com/").unwrap().host_as_ip(),
            None
        );
    }

    #[test]
    fn parse_content_length_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello-and-then-some-garbage";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert!(!r.truncated);
        assert_eq!(r.header("content-type"), Some("text/plain"));
        assert_eq!(r.header("Content-Type"), Some("text/plain"));
        assert!(!r.is_redirect());
    }

    #[test]
    fn parse_response_without_content_length_reads_to_eof() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nsuccess\n";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.body, b"success\n");
    }

    #[test]
    fn parse_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.body, b"hello world");
        assert!(!r.truncated);
    }

    #[test]
    fn parse_chunked_with_extension_and_truncation() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5;ext=1\r\nhello\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw, 1024).unwrap().body, b"hello");

        // Body larger than the cap must come back truncated, never silently
        // shortened — a canary comparison on a cut body would be wrong.
        let r = parse_response(raw, 3).unwrap();
        assert_eq!(r.body, b"hel");
        assert!(r.truncated);
    }

    #[test]
    fn parse_chunked_missing_terminator_is_truncated() {
        // Connection died mid-chunk: we keep what arrived but flag it.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        let r = parse_response(raw, 1024).unwrap();
        assert!(r.truncated);
    }

    #[test]
    fn parse_redirect_is_detected() {
        // The signature of a captive portal / paywall intercept.
        let raw = b"HTTP/1.1 302 Found\r\nLocation: http://portal.isp.example/pay\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.status, 302);
        assert!(r.is_redirect());
        assert_eq!(r.header("location"), Some("http://portal.isp.example/pay"));
    }

    #[test]
    fn parse_204_no_content() {
        let raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[test]
    fn parse_folded_header() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Long: part-one\r\n  part-two\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw, 1024).unwrap();
        assert_eq!(r.header("x-long"), Some("part-one part-two"));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_response(b"not http at all", 1024).is_err());
        assert!(parse_response(b"GARBAGE/1.1 200 OK\r\n\r\n", 1024).is_err());
        assert!(parse_response(b"HTTP/1.1 notanumber OK\r\n\r\n", 1024).is_err());
    }

    #[test]
    fn request_line_is_well_formed_and_injection_safe() {
        let req = HttpRequest {
            url: Url::parse("https://example.com/p?q=1").unwrap(),
            connect_ip: Ipv4Addr::new(93, 184, 216, 34),
            mark: Some(0x200),
            timeout: Duration::from_secs(5),
            max_body: 1024,
            // A user-agent carrying CRLF must not be able to inject headers.
            user_agent: "vlb/1.0\r\nX-Injected: yes".into(),
        };
        let wire = String::from_utf8(build_request(&req)).unwrap();
        assert!(wire.starts_with("GET /p?q=1 HTTP/1.1\r\n"));
        assert!(wire.contains("Host: example.com\r\n"));
        assert!(wire.ends_with("\r\n\r\n"));

        // The CRLF is stripped, so the attacker's text collapses into the
        // User-Agent *value* instead of becoming a header of its own. Assert
        // on line starts — a substring check would match the folded value.
        let lines: Vec<&str> = wire.trim_end_matches("\r\n\r\n").split("\r\n").collect();
        assert!(
            !lines.iter().any(|l| l.starts_with("X-Injected")),
            "CRLF injection produced a new header: {lines:?}"
        );
        assert!(
            lines.contains(&"User-Agent: vlb/1.0X-Injected: yes"),
            "user-agent not folded as expected: {lines:?}"
        );
    }

    #[test]
    fn tls_config_builds() {
        // Guards against a rustls feature-flag regression (e.g. no crypto
        // provider enabled), which would otherwise only surface at runtime
        // on the first HTTPS canary probe.
        let cfg = tls_config();
        assert!(!cfg.alpn_protocols.iter().any(|p| p.is_empty()));
    }
}
