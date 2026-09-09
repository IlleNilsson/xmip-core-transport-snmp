//! RFC 3412 and RFC 3414: the SNMP v3 message with User-based Security
//! Model parameters, at noAuthNoPriv.
//!
//! `SEQUENCE { version 3, msgGlobalData, msgSecurityParameters, ScopedPDU }`
//! where the global data is `msgID, msgMaxSize, msgFlags, msgSecurityModel`,
//! the security parameters are an OCTET STRING wrapping a BER `SEQUENCE {
//! engineID, engineBoots, engineTime, userName, authParameters,
//! privParameters }`, and the scoped PDU is `contextEngineID, contextName,
//! PDU`. Authentication (HMAC over the whole message) and privacy (an
//! encrypted scoped PDU) stay open: a message with either flag set is
//! refused rather than half-read, and engine id discovery — the report
//! exchange a real manager runs before it authenticates — is not needed
//! until they land.

use crate::ber::{self, Value};
use crate::pdu::{Pdu, VERSION_3};
use transport::error::{Result, protocol_error};

/// The message is authenticated.
pub const FLAG_AUTH: u8 = 0x01;
/// The scoped PDU is encrypted.
pub const FLAG_PRIV: u8 = 0x02;
/// The receiver may answer with a Report.
pub const FLAG_REPORTABLE: u8 = 0x04;
/// The User-based Security Model, `msgSecurityModel` 3.
pub const SECURITY_USM: i64 = 3;
/// `msgMaxSize`: what a datagram carries.
pub const MAX_SIZE: i64 = 65_507;

/// One SNMP v3 message, noAuthNoPriv.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3Message {
    pub msg_id: i32,
    pub max_size: i64,
    pub flags: u8,
    pub engine_id: Vec<u8>,
    pub engine_boots: i64,
    pub engine_time: i64,
    pub user: String,
    pub context_engine_id: Vec<u8>,
    pub context_name: String,
    pub pdu: Pdu,
}

impl V3Message {
    /// A message from `user` at the engine `engine_id`, reportable unless it
    /// is a trap — nobody answers a trap, so nobody should report on one.
    #[must_use]
    pub fn new(msg_id: i32, engine_id: &[u8], user: &str, pdu: Pdu) -> Self {
        let flags = if pdu.kind == crate::pdu::PduType::Trap {
            0
        } else {
            FLAG_REPORTABLE
        };
        Self {
            msg_id,
            max_size: MAX_SIZE,
            flags,
            engine_id: engine_id.to_vec(),
            engine_boots: 0,
            engine_time: 0,
            user: user.to_string(),
            context_engine_id: engine_id.to_vec(),
            context_name: String::new(),
            pdu,
        }
    }

    /// The answer to `self` carrying `pdu`: same id, engine and user, not
    /// reportable.
    #[must_use]
    pub fn answering(&self, pdu: Pdu) -> Self {
        Self {
            flags: 0,
            pdu,
            ..self.clone()
        }
    }
}

/// `message` on the wire.
#[must_use]
pub fn encode(message: &V3Message) -> Vec<u8> {
    let usm = ber::to_bytes(&Value::Sequence(vec![
        Value::OctetString(message.engine_id.clone()),
        Value::Integer(message.engine_boots),
        Value::Integer(message.engine_time),
        Value::OctetString(message.user.as_bytes().to_vec()),
        Value::OctetString(Vec::new()),
        Value::OctetString(Vec::new()),
    ]));
    ber::to_bytes(&Value::Sequence(vec![
        Value::Integer(VERSION_3),
        Value::Sequence(vec![
            Value::Integer(i64::from(message.msg_id)),
            Value::Integer(message.max_size),
            Value::OctetString(vec![message.flags]),
            Value::Integer(SECURITY_USM),
        ]),
        Value::OctetString(usm),
        Value::Sequence(vec![
            Value::OctetString(message.context_engine_id.clone()),
            Value::OctetString(message.context_name.as_bytes().to_vec()),
            message.pdu.to_value(),
        ]),
    ]))
}

/// One v3 message.
///
/// # Errors
/// Not a v3 message, a security model that is not USM, or the auth or priv
/// flag set — those stay open, and are refused rather than half-read.
pub fn decode(bytes: &[u8]) -> Result<V3Message> {
    let mut outer = Fields::new(ber::decode(bytes)?.items()?, "message");
    if outer.next()?.integer()? != VERSION_3 {
        return Err(protocol_error("a message that is not version 3"));
    }
    let mut global = Fields::new(outer.next()?.items()?, "msgGlobalData");
    let msg_id = i32::try_from(global.next()?.integer()?)
        .map_err(|_| protocol_error("msgID outside i32"))?;
    let max_size = global.next()?.integer()?;
    let flags = *global
        .next()?
        .octets()?
        .first()
        .ok_or_else(|| protocol_error("msgFlags of no bytes"))?;
    if flags & (FLAG_AUTH | FLAG_PRIV) != 0 {
        return Err(protocol_error(
            "an authenticated or encrypted message; only noAuthNoPriv is spoken",
        ));
    }
    if global.next()?.integer()? != SECURITY_USM {
        return Err(protocol_error("a security model that is not USM"));
    }
    let mut usm = Fields::new(
        ber::decode(outer.next()?.octets()?)?.items()?,
        "msgSecurityParameters",
    );
    let engine_id = usm.next()?.octets()?.to_vec();
    let engine_boots = usm.next()?.integer()?;
    let engine_time = usm.next()?.integer()?;
    let user = String::from_utf8_lossy(usm.next()?.octets()?).into_owned();
    let mut scoped = Fields::new(outer.next()?.items()?, "ScopedPDU");
    let context_engine_id = scoped.next()?.octets()?.to_vec();
    let context_name = String::from_utf8_lossy(scoped.next()?.octets()?).into_owned();
    let pdu = Pdu::from_value(scoped.next()?)?;
    Ok(V3Message {
        msg_id,
        max_size,
        flags,
        engine_id,
        engine_boots,
        engine_time,
        user,
        context_engine_id,
        context_name,
        pdu,
    })
}

/// The items of one SEQUENCE, each missing one named for what it was.
struct Fields {
    items: std::vec::IntoIter<Value>,
    of: &'static str,
}

impl Fields {
    fn new(items: Vec<Value>, of: &'static str) -> Self {
        Self {
            items: items.into_iter(),
            of,
        }
    }

    fn next(&mut self) -> Result<Value> {
        self.items
            .next()
            .ok_or_else(|| protocol_error(format!("a {} with a field missing", self.of)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::{Binding, PduType, ZERO_DOT_ZERO};

    fn inform() -> V3Message {
        let pdu = Pdu::notification(
            PduType::InformRequest,
            5,
            &ZERO_DOT_ZERO,
            10,
            vec![Binding::new(&[1, 3, 6, 1, 4, 1, 1, 0], Value::Integer(1))],
        );
        V3Message::new(77, b"\x80\x00\x00\x00\x04xmip", "ops", pdu)
    }

    #[test]
    fn a_noauthnopriv_message_round_trips_and_its_answer_is_not_reportable() {
        let message = inform();
        assert_eq!(message.flags, FLAG_REPORTABLE);
        let bytes = encode(&message);
        assert_eq!(crate::pdu::version_of(&bytes).expect("version"), 3);
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, message);
        let answer = back.answering(back.pdu.response(0));
        assert_eq!(answer.flags, 0);
        assert_eq!(answer.msg_id, 77);
        assert_eq!(answer.pdu.kind, PduType::GetResponse);
        let trap = V3Message::new(1, b"e", "u", Pdu::new(PduType::Trap, 1, vec![]));
        assert_eq!(trap.flags, 0, "a trap is not reportable");
    }

    #[test]
    fn authenticated_encrypted_or_other_models_are_refused() {
        let mut message = inform();
        message.flags = FLAG_AUTH | FLAG_REPORTABLE;
        let refused = decode(&encode(&message)).expect_err("auth");
        assert!(refused.message.contains("noAuthNoPriv"));
        assert!(!refused.retryable);
        message.flags = FLAG_PRIV;
        assert!(decode(&encode(&message)).is_err(), "priv");
        let v2c = crate::pdu::encode(&crate::pdu::Message::v2c("public", inform().pdu));
        assert!(decode(&v2c).is_err(), "v2c is not v3");
        let bare = ber::to_bytes(&Value::Sequence(vec![Value::Integer(3)]));
        assert!(decode(&bare).is_err(), "global data missing");
        let other_model = ber::to_bytes(&Value::Sequence(vec![
            Value::Integer(3),
            Value::Sequence(vec![
                Value::Integer(1),
                Value::Integer(484),
                Value::OctetString(vec![0]),
                Value::Integer(1),
            ]),
        ]));
        assert!(decode(&other_model).is_err(), "SNMPv1 security model");
    }
}
