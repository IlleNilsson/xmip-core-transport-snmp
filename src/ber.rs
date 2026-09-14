//! The BER values SNMP is made of, on the capability's X.690 tag-length-value
//! (`transport::ber`, shared with iec-61850 under ADR-0044): INTEGER, OCTET
//! STRING, NULL, OBJECT IDENTIFIER, SEQUENCE, the constructed context tags a
//! PDU wears, the four unsigned application types, `IpAddress` and the three
//! exceptions a response carries where a value would be. What is here is the
//! dialect — which tags, and what their contents mean; the framing, the
//! length forms and the INTEGER encoding are the capability's, and the
//! indefinite length form is refused there, as SNMP requires.

use transport::ber::{self, INTEGER, NULL, OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE};
use transport::error::{Result, protocol_error};

pub const TAG_IP_ADDRESS: u8 = 0x40;
pub const TAG_COUNTER32: u8 = 0x41;
pub const TAG_GAUGE32: u8 = 0x42;
pub const TAG_TIME_TICKS: u8 = 0x43;
pub const TAG_COUNTER64: u8 = 0x46;

/// One BER value as SNMP uses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    Oid(Vec<u32>),
    Sequence(Vec<Value>),
    /// A constructed context-specific value — a PDU, tagged 0xA0 to 0xA8.
    Context(u8, Vec<Value>),
    /// Counter32, Gauge32, `TimeTicks` or Counter64, told apart by the tag.
    Unsigned(u8, u64),
    IpAddress([u8; 4]),
    /// noSuchObject 0x80, noSuchInstance 0x81, endOfMibView 0x82.
    Exception(u8),
}

impl Value {
    /// The integer this is.
    ///
    /// # Errors
    /// Where it is anything else.
    pub fn integer(&self) -> Result<i64> {
        match self {
            Self::Integer(n) => Ok(*n),
            other => Err(protocol_error(format!(
                "expected an INTEGER, found {other:?}"
            ))),
        }
    }

    /// The octets this is.
    ///
    /// # Errors
    /// Where it is anything else.
    pub fn octets(&self) -> Result<&[u8]> {
        match self {
            Self::OctetString(bytes) => Ok(bytes),
            other => Err(protocol_error(format!(
                "expected an OCTET STRING, found {other:?}"
            ))),
        }
    }

    /// The object identifier this is.
    ///
    /// # Errors
    /// Where it is anything else.
    pub fn oid(&self) -> Result<&[u32]> {
        match self {
            Self::Oid(arcs) => Ok(arcs),
            other => Err(protocol_error(format!(
                "expected an OBJECT IDENTIFIER, found {other:?}"
            ))),
        }
    }

    /// The items of the SEQUENCE this is.
    ///
    /// # Errors
    /// Where it is anything else.
    pub fn items(self) -> Result<Vec<Self>> {
        match self {
            Self::Sequence(items) => Ok(items),
            other => Err(protocol_error(format!(
                "expected a SEQUENCE, found {other:?}"
            ))),
        }
    }
}

/// Append `value` to `out`.
pub fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Integer(n) => ber::write_tlv(out, INTEGER, &ber::integer(*n)),
        Value::OctetString(bytes) => ber::write_tlv(out, OCTET_STRING, bytes),
        Value::Null => ber::write_tlv(out, NULL, &[]),
        Value::Oid(arcs) => ber::write_tlv(out, OBJECT_IDENTIFIER, &oid_bytes(arcs)),
        Value::Sequence(items) => constructed(out, SEQUENCE, items),
        Value::Context(tag, items) => constructed(out, *tag, items),
        Value::Unsigned(tag, n) => ber::write_tlv(out, *tag, &unsigned_bytes(*n)),
        Value::IpAddress(address) => ber::write_tlv(out, TAG_IP_ADDRESS, address),
        Value::Exception(tag) => ber::write_tlv(out, *tag, &[]),
    }
}

/// `value` on its own.
#[must_use]
pub fn to_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode(value, &mut out);
    out
}

fn constructed(out: &mut Vec<u8>, tag: u8, items: &[Value]) {
    let mut body = Vec::new();
    for item in items {
        encode(item, &mut body);
    }
    ber::write_tlv(out, tag, &body);
}

/// The fewest bytes, a leading zero where the top bit would read as a sign.
fn unsigned_bytes(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut out = Vec::with_capacity(9);
    if bytes[skip] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// The first two arcs folded into one, the rest base 128.
fn oid_bytes(arcs: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let first = arcs.first().copied().unwrap_or(0) * 40 + arcs.get(1).copied().unwrap_or(0);
    base128(&mut out, first);
    for arc in arcs.iter().skip(2) {
        base128(&mut out, *arc);
    }
    out
}

fn base128(out: &mut Vec<u8>, mut arc: u32) {
    let mut stack = [0u8; 5];
    let mut count = 0;
    loop {
        stack[count] = u8::try_from(arc & 0x7f).unwrap_or(0);
        count += 1;
        arc >>= 7;
        if arc == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        let more = if index == 0 { 0 } else { 0x80 };
        out.push(stack[index] | more);
    }
}

/// Exactly one value, nothing after it.
///
/// # Errors
/// Anything [`read`] refuses, or bytes after the value.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let (value, next) = read(bytes, 0)?;
    if next != bytes.len() {
        return Err(protocol_error("bytes after the value"));
    }
    Ok(value)
}

/// The value at `at`, and where the next one starts.
///
/// # Errors
/// A tag this file does not know, a length that runs past the end or is
/// indefinite, an INTEGER over eight bytes, an arc over what `u32` holds.
pub fn read(bytes: &[u8], at: usize) -> Result<(Value, usize)> {
    let element = bytes
        .get(at..)
        .ok_or_else(|| protocol_error("a value shorter than its length"))?;
    let (tag, body, rest) = ber::read(element)?;
    let end = bytes.len() - rest.len();
    let value = match tag {
        INTEGER => Value::Integer(ber::read_integer(body)?),
        OCTET_STRING => Value::OctetString(body.to_vec()),
        NULL => Value::Null,
        OBJECT_IDENTIFIER => Value::Oid(read_oid(body)?),
        SEQUENCE => Value::Sequence(read_items(body)?),
        0xA0..=0xAF => Value::Context(tag, read_items(body)?),
        TAG_IP_ADDRESS => {
            let octets: [u8; 4] = body
                .try_into()
                .map_err(|_| protocol_error("an IpAddress that is not four bytes"))?;
            Value::IpAddress(octets)
        }
        TAG_COUNTER32 | TAG_GAUGE32 | TAG_TIME_TICKS | TAG_COUNTER64 => {
            Value::Unsigned(tag, read_unsigned(body)?)
        }
        0x80..=0x82 => Value::Exception(tag),
        other => {
            return Err(protocol_error(format!(
                "a tag SNMP does not use: {other:#04x}"
            )));
        }
    };
    Ok((value, end))
}

fn read_unsigned(body: &[u8]) -> Result<u64> {
    let digits = body.strip_prefix(&[0]).unwrap_or(body);
    if digits.len() > 8 {
        return Err(protocol_error("an unsigned over eight bytes"));
    }
    Ok(digits
        .iter()
        .fold(0u64, |acc, digit| (acc << 8) | u64::from(*digit)))
}

fn read_oid(body: &[u8]) -> Result<Vec<u32>> {
    if body.is_empty() {
        return Err(protocol_error("an empty OBJECT IDENTIFIER"));
    }
    let mut arcs = Vec::new();
    let mut arc: u32 = 0;
    for byte in body {
        if arc >= (1 << 25) {
            return Err(protocol_error("an arc over what u32 holds"));
        }
        arc = (arc << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if arcs.is_empty() {
                let (first, second) = if arc < 80 {
                    (arc / 40, arc % 40)
                } else {
                    (2, arc - 80)
                };
                arcs.push(first);
                arcs.push(second);
            } else {
                arcs.push(arc);
            }
            arc = 0;
        }
    }
    if body.last().is_some_and(|b| b & 0x80 != 0) {
        return Err(protocol_error("an arc that does not end"));
    }
    Ok(arcs)
}

fn read_items(body: &[u8]) -> Result<Vec<Value>> {
    let mut items = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let (item, next) = read(body, at)?;
        items.push(item);
        at = next;
    }
    Ok(items)
}

/// `1.3.6.1.2.1.1.3.0`.
#[must_use]
pub fn oid_text(arcs: &[u32]) -> String {
    arcs.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The arcs of `1.3.6.1.2.1.1.3.0`, `None` where any part is not a number.
#[must_use]
pub fn parse_oid(text: &str) -> Option<Vec<u32>> {
    let text = text.strip_prefix('.').unwrap_or(text);
    text.split('.').map(|arc| arc.parse().ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: &Value) {
        let bytes = to_bytes(value);
        assert_eq!(&decode(&bytes).expect("decode"), value, "{bytes:02x?}");
    }

    #[test]
    fn every_shape_round_trips() {
        for n in [0, 1, 127, 128, 255, 256, -1, -128, -129, i64::MAX, i64::MIN] {
            round_trip(&Value::Integer(n));
        }
        assert_eq!(to_bytes(&Value::Integer(128)), [2, 2, 0, 0x80]);
        assert_eq!(to_bytes(&Value::Integer(-129)), [2, 2, 0xff, 0x7f]);
        for n in [0, 127, 128, u64::from(u32::MAX), u64::MAX] {
            round_trip(&Value::Unsigned(TAG_COUNTER64, n));
        }
        assert_eq!(
            to_bytes(&Value::Unsigned(TAG_GAUGE32, 200)),
            [0x42, 2, 0, 200]
        );
        round_trip(&Value::OctetString(vec![0; 300]));
        assert_eq!(
            to_bytes(&Value::OctetString(vec![0; 300]))[..4],
            [4, 0x82, 1, 44]
        );
        round_trip(&Value::Null);
        round_trip(&Value::Oid(vec![1, 3, 6, 1, 4, 1, 9, 9, 1, 0, 70_000]));
        round_trip(&Value::Oid(vec![2, 999, 3]));
        assert_eq!(to_bytes(&Value::Oid(vec![1, 3, 6, 1])), [6, 3, 0x2b, 6, 1]);
        round_trip(&Value::IpAddress([10, 0, 0, 1]));
        round_trip(&Value::Exception(0x80));
        round_trip(&Value::Context(
            0xA7,
            vec![
                Value::Integer(5),
                Value::Sequence(vec![Value::Sequence(vec![
                    Value::Oid(vec![1, 3]),
                    Value::Unsigned(TAG_TIME_TICKS, 12),
                ])]),
            ],
        ));
        assert_eq!(oid_text(&[1, 3, 6]), "1.3.6");
        assert_eq!(parse_oid(".1.3.6"), Some(vec![1, 3, 6]));
        assert_eq!(parse_oid("1.x"), None);
    }

    #[test]
    fn what_is_not_ber_is_refused() {
        assert!(decode(&[]).is_err(), "nothing");
        assert!(decode(&[2, 5, 1]).is_err(), "short");
        assert!(decode(&[2, 0x80, 1, 0, 0]).is_err(), "indefinite");
        assert!(decode(&[2, 0]).is_err(), "empty integer");
        assert!(decode(&[2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err(), "nine");
        assert!(decode(&[6, 0]).is_err(), "empty oid");
        assert!(decode(&[6, 1, 0x81]).is_err(), "arc that does not end");
        assert!(decode(&[6, 6, 0x2b, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err());
        assert!(decode(&[0x40, 3, 1, 2, 3]).is_err(), "three-byte address");
        assert!(decode(&[0x13, 1, b'a']).is_err(), "PrintableString");
        assert!(decode(&[5, 0, 5, 0]).is_err(), "trailing bytes");
        assert!(Value::Null.integer().is_err());
        assert!(Value::Null.octets().is_err());
        assert!(Value::Null.oid().is_err());
        assert!(Value::Null.items().is_err());
    }
}
