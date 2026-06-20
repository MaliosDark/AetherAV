//! A tiny, dependency-free HTTP/1.1 request reader and response writer.
//!
//! Just enough to serve a JSON API: parse the request line, read headers, honor
//! `Content-Length`, and write a single response. No async runtime, no
//! framework - appropriate for a local control-plane endpoint.

use std::io::{self, BufRead, Write};

/// A parsed HTTP request.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Read and parse a single HTTP request. Returns `Ok(None)` on a clean EOF
/// (client closed without sending anything).
pub fn parse_request<R: BufRead>(reader: &mut R) -> io::Result<Option<Request>> {
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break; // end of headers
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(Request { method, path, body }))
}

/// Write a JSON response with the given status code.
pub fn write_response<W: Write>(writer: &mut W, status: u16, json_body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{json_body}",
        json_body.len()
    )?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_get_with_no_body() {
        let raw = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut c = Cursor::new(raw.as_bytes());
        let req = parse_request(&mut c).unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/health");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parses_post_with_body() {
        let raw = "POST /scan HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let mut c = Cursor::new(raw.as_bytes());
        let req = parse_request(&mut c).unwrap().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn writes_well_formed_response() {
        let mut out = Vec::new();
        write_response(&mut out, 200, "{\"ok\":true}").unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 11\r\n"));
        assert!(s.ends_with("{\"ok\":true}"));
    }
}
