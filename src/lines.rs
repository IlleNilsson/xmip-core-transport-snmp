//! The one-line text form of a variable binding, `oid=value`, that a
//! Stream of bindings is made of — one line each, newline-terminated.
//!
//! Numbers are digits, identifiers are dotted, text is as it is, other
//! octets are `0x` hex and NULL is nothing. Reading goes the other way with
//! one ambiguity accepted: text that happens to be digits or dotted numbers
//! reads back as an INTEGER or an OBJECT IDENTIFIER.

use crate::ber::{self, Value};
use crate::pdu::Binding;
use transport::error::{Result, protocol_error};

/// A value as a Stream line writes it.
#[must_use]
pub fn render_value(value: &Value) -> String {
    match value {
        Value::Integer(n) => n.to_string(),
        Value::Unsigned(_, n) => n.to_string(),
        Value::Null => String::new(),
        Value::Oid(arcs) => ber::oid_text(arcs),
        Value::IpAddress(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        Value::Exception(0x80) => "noSuchObject".to_string(),
        Value::Exception(0x81) => "noSuchInstance".to_string(),
        Value::Exception(_) => "endOfMibView".to_string(),
        Value::OctetString(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) if !text.is_empty() && !text.chars().any(char::is_control) => text.to_string(),
            _ => hex(bytes),
        },
        other => hex(&ber::to_bytes(other)),
    }
}

/// The value a Stream line means.
#[must_use]
pub fn parse_value(text: &str) -> Value {
    let text = text.trim_end_matches('\r');
    if text.is_empty() {
        return Value::Null;
    }
    if let Ok(n) = text.parse::<i64>() {
        return Value::Integer(n);
    }
    if let Some(bytes) = text
        .strip_prefix("0x")
        .and_then(|digits| codec::hex::decode(digits).ok())
    {
        return Value::OctetString(bytes);
    }
    if let Some(arcs) = ber::parse_oid(text).filter(|_| text.contains('.')) {
        return Value::Oid(arcs);
    }
    Value::OctetString(text.as_bytes().to_vec())
}

/// Octets a line cannot show as text: `0x` and the pairs.
fn hex(bytes: &[u8]) -> String {
    format!("0x{}", codec::hex::encode(bytes))
}

/// `bindings` as the Stream: one `oid=value` line each, newline-terminated.
#[must_use]
pub fn render(bindings: &[Binding]) -> Vec<u8> {
    let mut out = String::new();
    for binding in bindings {
        out.push_str(&binding.line());
        out.push('\n');
    }
    out.into_bytes()
}

/// The bindings a Stream of `oid=value` lines names; blank lines skipped.
///
/// # Errors
/// A line that is not UTF-8 or not a binding.
pub fn parse_lines(bytes: &[u8]) -> Result<Vec<Binding>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| protocol_error("bindings that are not UTF-8 text"))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(Binding::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_shape_writes_and_reads() {
        assert_eq!(render_value(&Value::IpAddress([10, 0, 0, 1])), "10.0.0.1");
        assert_eq!(render_value(&Value::Exception(0x82)), "endOfMibView");
        assert_eq!(render_value(&Value::Sequence(vec![])), "0x3000");
        assert_eq!(render_value(&Value::OctetString(vec![0, 1])), "0x0001");
        assert_eq!(render_value(&Value::Unsigned(0x41, 7)), "7");
        assert_eq!(parse_value(""), Value::Null);
        assert_eq!(parse_value("-3\r"), Value::Integer(-3));
        assert_eq!(parse_value("0x00ff"), Value::OctetString(vec![0, 0xff]));
        assert_eq!(parse_value("0xzz"), Value::OctetString(b"0xzz".to_vec()));
        assert_eq!(parse_value("1.3.6"), Value::Oid(vec![1, 3, 6]));
        assert_eq!(parse_value("up"), Value::OctetString(b"up".to_vec()));
        let bindings = parse_lines(b"1.3=a\n\n1.4=2\r\n").expect("lines");
        assert_eq!(bindings.len(), 2);
        assert_eq!(render(&bindings), b"1.3=a\n1.4=2\n");
        assert!(parse_lines(&[0xff, b'=']).is_err(), "not text");
        assert!(parse_lines(b"1.3").is_err(), "no equals");
    }
}
