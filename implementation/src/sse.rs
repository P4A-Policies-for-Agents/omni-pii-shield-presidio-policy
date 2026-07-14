//! Minimal Server-Sent Events parser / serializer for MCP + A2A
//! Streamable HTTP responses.
//!
//! The PDK delivers the buffered response body as one byte slice. This
//! module parses it into [`SseEvent`]s, lets the caller mutate the JSON
//! `data:` payload of any event, then re-emits the same structure.
//! Byte-perfect round-trip is a hard invariant when no `data:` is
//! mutated, so a clean pass-through never perturbs a frame.

/// One parsed SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub preamble: Vec<String>,
    pub data: Option<String>,
    pub uses_crlf: bool,
    pub terminator: String,
}

pub fn parse(body: &[u8]) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        let (event, consumed) = parse_one(&body[cursor..]);
        cursor += consumed;
        events.push(event);
    }
    events
}

fn parse_one(body: &[u8]) -> (SseEvent, usize) {
    let (term_offset, term_len) = find_event_terminator(body);
    let event_slice = &body[..term_offset];
    let terminator =
        String::from_utf8_lossy(&body[term_offset..term_offset + term_len]).into_owned();

    let mut preamble = Vec::new();
    let mut data_lines: Vec<String> = Vec::new();
    let mut uses_crlf = false;
    let mut line_start = 0usize;

    while line_start <= event_slice.len() {
        let (line_end, sep_len, is_crlf) = find_line_end(event_slice, line_start);
        if is_crlf {
            uses_crlf = true;
        }
        let line = &event_slice[line_start..line_end];
        if line.is_empty() && sep_len == 0 {
            break;
        }
        if let Some(payload) = line.strip_prefix(b"data:") {
            let payload = if payload.first() == Some(&b' ') {
                &payload[1..]
            } else {
                payload
            };
            data_lines.push(String::from_utf8_lossy(payload).into_owned());
        } else {
            preamble.push(String::from_utf8_lossy(line).into_owned());
        }
        line_start = line_end + sep_len;
        if sep_len == 0 {
            break;
        }
    }

    let data = if data_lines.is_empty() {
        None
    } else {
        Some(data_lines.join("\n"))
    };

    (
        SseEvent {
            preamble,
            data,
            uses_crlf,
            terminator,
        },
        term_offset + term_len,
    )
}

fn find_event_terminator(body: &[u8]) -> (usize, usize) {
    let mut i = 0usize;
    while i < body.len() {
        if i + 4 <= body.len() && &body[i..i + 4] == b"\r\n\r\n" {
            return (i, 4);
        }
        if i + 2 <= body.len() && &body[i..i + 2] == b"\n\n" {
            return (i, 2);
        }
        i += 1;
    }
    (body.len(), 0)
}

fn find_line_end(slice: &[u8], start: usize) -> (usize, usize, bool) {
    let mut i = start;
    while i < slice.len() {
        if i + 2 <= slice.len() && &slice[i..i + 2] == b"\r\n" {
            return (i, 2, true);
        }
        if slice[i] == b'\n' {
            return (i, 1, false);
        }
        i += 1;
    }
    (slice.len(), 0, false)
}

pub fn serialize(events: &[SseEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    for ev in events {
        let sep: &[u8] = if ev.uses_crlf { b"\r\n" } else { b"\n" };
        let mut lines: Vec<Vec<u8>> = Vec::with_capacity(ev.preamble.len() + 4);
        for line in &ev.preamble {
            lines.push(line.as_bytes().to_vec());
        }
        if let Some(data) = &ev.data {
            for line in data.split('\n') {
                let mut buf = Vec::with_capacity(6 + line.len());
                buf.extend_from_slice(b"data: ");
                buf.extend_from_slice(line.as_bytes());
                lines.push(buf);
            }
        }
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(sep);
            }
            out.extend_from_slice(line);
        }
        out.extend_from_slice(ev.terminator.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_byte_perfect() {
        let inputs: Vec<Vec<u8>> = vec![
            b"event: message\ndata: {\"x\":1}\n\n".to_vec(),
            b"event: message\r\ndata: {\"x\":1}\r\n\r\n".to_vec(),
            b": ping\nretry: 3000\nevent: message\ndata: {}\n\n".to_vec(),
        ];
        for input in inputs {
            let parsed = parse(&input);
            assert_eq!(serialize(&parsed), input);
        }
    }

    #[test]
    fn mutate_data_preserves_structure() {
        let input = b"event: message\ndata: {\"tools\":[]}\n\n".to_vec();
        let mut parsed = parse(&input);
        parsed[0].data = Some(r#"{"tools":[1]}"#.into());
        let out = serialize(&parsed);
        let reparsed = parse(&out);
        assert_eq!(reparsed[0].preamble, vec!["event: message".to_string()]);
        assert_eq!(reparsed[0].data.as_deref(), Some(r#"{"tools":[1]}"#));
    }
}
