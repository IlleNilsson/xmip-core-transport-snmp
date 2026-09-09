//! RFC 3416: the SNMP v2c message and the PDU inside it.
//!
//! A message is `SEQUENCE { version, community, PDU }`; a PDU is a context
//! tag over `request-id, error-status, error-index, SEQUENCE OF binding`,
//! and a binding is `SEQUENCE { name OBJECT IDENTIFIER, value }`. A v2c
//! trap and an inform carry `sysUpTime.0` and `snmpTrapOID.0` as their
//! first two bindings; this file puts them there.

use crate::ber::{self, TAG_TIME_TICKS, Value};
use crate::lines::{parse_value, render_value};
use transport::error::{Result, protocol_error};

/// `version` as SNMP v2c writes it.
pub const VERSION_2C: i64 = 1;
/// `version` as SNMP v3 writes it.
pub const VERSION_3: i64 = 3;
/// `sysUpTime.0`, the first binding of every notification.
pub const SYS_UPTIME: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];
/// `snmpTrapOID.0`, the second.
pub const SNMP_TRAP_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
/// `zeroDotZero`, RFC 2578: what a notification names when nobody named one.
pub const ZERO_DOT_ZERO: [u32; 2] = [0, 0];

/// The six PDU types this transport speaks, by their context tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PduType {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    InformRequest,
    Trap,
}

impl PduType {
    /// The context tag on the wire.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::GetRequest => 0xA0,
            Self::GetNextRequest => 0xA1,
            Self::GetResponse => 0xA2,
            Self::SetRequest => 0xA3,
            Self::InformRequest => 0xA6,
            Self::Trap => 0xA7,
        }
    }

    /// The type wearing `tag`.
    ///
    /// # Errors
    /// A tag that is none of the six — a v1 trap, a bulk request.
    pub fn from_tag(tag: u8) -> Result<Self> {
        Ok(match tag {
            0xA0 => Self::GetRequest,
            0xA1 => Self::GetNextRequest,
            0xA2 => Self::GetResponse,
            0xA3 => Self::SetRequest,
            0xA6 => Self::InformRequest,
            0xA7 => Self::Trap,
            other => {
                return Err(protocol_error(format!(
                    "a PDU type not spoken: {other:#04x}"
                )));
            }
        })
    }

    /// The name an origin URI writes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GetRequest => "get",
            Self::GetNextRequest => "get-next",
            Self::GetResponse => "response",
            Self::SetRequest => "set",
            Self::InformRequest => "inform",
            Self::Trap => "trap",
        }
    }
}

/// One variable binding: a name and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub oid: Vec<u32>,
    pub value: Value,
}

impl Binding {
    #[must_use]
    pub fn new(oid: &[u32], value: Value) -> Self {
        Self {
            oid: oid.to_vec(),
            value,
        }
    }

    /// `oid=value`, the line a Stream carries.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}={}", ber::oid_text(&self.oid), render_value(&self.value))
    }

    /// The binding written as `oid=value`.
    ///
    /// # Errors
    /// No `=`, or a name that is not dotted numbers.
    pub fn parse(line: &str) -> Result<Self> {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| protocol_error(format!("a binding without =: {line:?}")))?;
        let oid = ber::parse_oid(name.trim())
            .ok_or_else(|| protocol_error(format!("a name that is not an OID: {name:?}")))?;
        Ok(Self {
            oid,
            value: parse_value(value),
        })
    }

    fn to_value(&self) -> Value {
        Value::Sequence(vec![Value::Oid(self.oid.clone()), self.value.clone()])
    }

    fn from_value(value: Value) -> Result<Self> {
        let mut items = value.items()?.into_iter();
        let oid = items
            .next()
            .ok_or_else(|| protocol_error("a binding without a name"))?
            .oid()?
            .to_vec();
        let value = items
            .next()
            .ok_or_else(|| protocol_error("a binding without a value"))?;
        Ok(Self { oid, value })
    }
}

/// One PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    pub kind: PduType,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub bindings: Vec<Binding>,
}

impl Pdu {
    #[must_use]
    pub const fn new(kind: PduType, request_id: i32, bindings: Vec<Binding>) -> Self {
        Self {
            kind,
            request_id,
            error_status: 0,
            error_index: 0,
            bindings,
        }
    }

    /// A trap or inform: `sysUpTime.0` and `snmpTrapOID.0` first, unless
    /// `bindings` already opens with them.
    #[must_use]
    pub fn notification(
        kind: PduType,
        request_id: i32,
        trap_oid: &[u32],
        uptime: u64,
        mut bindings: Vec<Binding>,
    ) -> Self {
        if bindings.first().is_none_or(|b| b.oid != SYS_UPTIME) {
            bindings.insert(
                0,
                Binding::new(&SYS_UPTIME, Value::Unsigned(TAG_TIME_TICKS, uptime)),
            );
        }
        if bindings.get(1).is_none_or(|b| b.oid != SNMP_TRAP_OID) {
            bindings.insert(
                1,
                Binding::new(&SNMP_TRAP_OID, Value::Oid(trap_oid.to_vec())),
            );
        }
        Self::new(kind, request_id, bindings)
    }

    /// The response to `self`: same id and bindings, `error_status` set.
    #[must_use]
    pub fn response(&self, error_status: i32) -> Self {
        Self {
            kind: PduType::GetResponse,
            request_id: self.request_id,
            error_status,
            error_index: 0,
            bindings: self.bindings.clone(),
        }
    }

    /// What `snmpTrapOID.0` names, where it is bound.
    #[must_use]
    pub fn trap_oid(&self) -> Option<&[u32]> {
        self.bindings
            .iter()
            .find(|b| b.oid == SNMP_TRAP_OID)
            .and_then(|b| b.value.oid().ok())
    }

    /// The PDU as its BER value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Context(
            self.kind.tag(),
            vec![
                Value::Integer(i64::from(self.request_id)),
                Value::Integer(i64::from(self.error_status)),
                Value::Integer(i64::from(self.error_index)),
                Value::Sequence(self.bindings.iter().map(Binding::to_value).collect()),
            ],
        )
    }

    /// The PDU a BER value is.
    ///
    /// # Errors
    /// Not a context tag this transport speaks, or the four fields missing
    /// or mistyped.
    pub fn from_value(value: Value) -> Result<Self> {
        let Value::Context(tag, items) = value else {
            return Err(protocol_error("a PDU that is not context-tagged"));
        };
        let kind = PduType::from_tag(tag)?;
        let mut items = items.into_iter();
        let mut field = |name: &str| -> Result<i32> {
            let raw = items
                .next()
                .ok_or_else(|| protocol_error(format!("a PDU without {name}")))?
                .integer()?;
            i32::try_from(raw).map_err(|_| protocol_error(format!("{name} outside i32")))
        };
        let request_id = field("request-id")?;
        let error_status = field("error-status")?;
        let error_index = field("error-index")?;
        let bindings = items
            .next()
            .ok_or_else(|| protocol_error("a PDU without bindings"))?
            .items()?
            .into_iter()
            .map(Binding::from_value)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            kind,
            request_id,
            error_status,
            error_index,
            bindings,
        })
    }
}

/// An SNMP v2c message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub version: i64,
    pub community: Vec<u8>,
    pub pdu: Pdu,
}

impl Message {
    #[must_use]
    pub fn v2c(community: &str, pdu: Pdu) -> Self {
        Self {
            version: VERSION_2C,
            community: community.as_bytes().to_vec(),
            pdu,
        }
    }
}

/// `message` on the wire.
#[must_use]
pub fn encode(message: &Message) -> Vec<u8> {
    ber::to_bytes(&Value::Sequence(vec![
        Value::Integer(message.version),
        Value::OctetString(message.community.clone()),
        message.pdu.to_value(),
    ]))
}

/// The version a message opens with, before deciding how to read the rest.
///
/// # Errors
/// Not a SEQUENCE opening with an INTEGER.
pub fn version_of(bytes: &[u8]) -> Result<i64> {
    let (outer, _) = ber::read(bytes, 0)?;
    outer
        .items()?
        .first()
        .ok_or_else(|| protocol_error("an empty message"))?
        .integer()
}

/// One v2c message.
///
/// # Errors
/// Not BER, not `SEQUENCE { INTEGER, OCTET STRING, PDU }`, or a version
/// that is 3 — that one is read by the `v3` module.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    let mut items = ber::decode(bytes)?.items()?.into_iter();
    let version = items
        .next()
        .ok_or_else(|| protocol_error("a message without a version"))?
        .integer()?;
    if version == VERSION_3 {
        return Err(protocol_error("a v3 message read as v2c"));
    }
    let community = items
        .next()
        .ok_or_else(|| protocol_error("a message without a community"))?
        .octets()?
        .to_vec();
    let pdu = Pdu::from_value(
        items
            .next()
            .ok_or_else(|| protocol_error("a message without a PDU"))?,
    )?;
    Ok(Message {
        version,
        community,
        pdu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lines::{parse_lines, render, render_value};

    #[test]
    fn a_trap_round_trips_and_its_bindings_read_as_lines() {
        let bindings = parse_lines(
            b"1.3.6.1.4.1.9.9.1.0=link down\n\n1.3.6.1.4.1.9.9.2.0=3\r\n\
              1.3.6.1.4.1.9.9.3.0=0x00ff\n1.3.6.1.4.1.9.9.4.0=\n1.3.6.1.4.1.9.9.5.0=1.3.6",
        )
        .expect("lines");
        assert_eq!(bindings[0].value, Value::OctetString(b"link down".to_vec()));
        assert_eq!(bindings[1].value, Value::Integer(3));
        assert_eq!(bindings[2].value, Value::OctetString(vec![0, 0xff]));
        assert_eq!(bindings[3].value, Value::Null);
        assert_eq!(bindings[4].value, Value::Oid(vec![1, 3, 6]));
        let pdu = Pdu::notification(PduType::Trap, 7, &[1, 3, 6, 1, 4, 1, 9, 0, 1], 42, bindings);
        assert_eq!(pdu.bindings[0].oid, SYS_UPTIME);
        assert_eq!(pdu.trap_oid(), Some(&[1, 3, 6, 1, 4, 1, 9, 0, 1][..]));
        let message = Message::v2c("public", pdu);
        let bytes = encode(&message);
        assert_eq!(version_of(&bytes).expect("version"), VERSION_2C);
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, message);
        let text = String::from_utf8(render(&back.pdu.bindings)).expect("utf8");
        assert_eq!(
            text,
            "1.3.6.1.2.1.1.3.0=42\n1.3.6.1.6.3.1.1.4.1.0=1.3.6.1.4.1.9.0.1\n\
             1.3.6.1.4.1.9.9.1.0=link down\n1.3.6.1.4.1.9.9.2.0=3\n\
             1.3.6.1.4.1.9.9.3.0=0x00ff\n1.3.6.1.4.1.9.9.4.0=\n1.3.6.1.4.1.9.9.5.0=1.3.6\n"
        );
        let again = Pdu::notification(
            PduType::InformRequest,
            8,
            &ZERO_DOT_ZERO,
            0,
            back.pdu.bindings,
        );
        assert_eq!(again.bindings.len(), 7, "already opens with the two");
        let response = again.response(0);
        assert_eq!(response.kind, PduType::GetResponse);
        assert_eq!(response.request_id, 8);
        assert_eq!(render_value(&Value::IpAddress([10, 0, 0, 1])), "10.0.0.1");
        assert_eq!(render_value(&Value::Exception(0x82)), "endOfMibView");
        assert_eq!(render_value(&Value::Sequence(vec![])), "0x3000");
        assert_eq!(PduType::from_tag(0xA1).expect("tag").name(), "get-next");
    }

    #[test]
    fn what_is_not_a_v2c_message_is_refused() {
        assert!(decode(b"hello").is_err(), "not BER");
        assert!(decode(&[0x30, 0]).is_err(), "empty");
        let v1_trap = ber::to_bytes(&Value::Sequence(vec![
            Value::Integer(0),
            Value::OctetString(b"public".to_vec()),
            Value::Context(0xA4, vec![]),
        ]));
        assert!(decode(&v1_trap).is_err(), "a v1 trap PDU");
        let v3 = ber::to_bytes(&Value::Sequence(vec![Value::Integer(3)]));
        assert!(decode(&v3).is_err(), "v3 is not v2c");
        assert_eq!(version_of(&v3).expect("version"), 3);
        let no_bindings = ber::to_bytes(&Value::Sequence(vec![
            Value::Integer(1),
            Value::OctetString(vec![]),
            Value::Context(0xA7, vec![Value::Integer(1), Value::Integer(0)]),
        ]));
        assert!(decode(&no_bindings).is_err());
        assert!(Binding::parse("no equals").is_err());
        assert!(Binding::parse("x.y=1").is_err());
        assert!(parse_lines(&[0xff, b'=']).is_err(), "not text");
        assert!(PduType::from_tag(0xA5).is_err(), "bulk");
    }
}
