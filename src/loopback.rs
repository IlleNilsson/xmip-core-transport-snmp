//! Both ends of one SNMP exchange on this machine (ADR-0051): an agent at
//! an ephemeral local port takes the one SET that binds an object to the
//! Stream as an OCTET STRING, answers it, and the response is what the
//! manager waited for. The manager the transport binds hands bindings up
//! as `oid=value` lines, and a line is a view of the bytes, not the bytes;
//! the agent is the far end a SET has, and the transport's own codec reads
//! the request and writes the response.
//!
//! The ceiling is a fact about the protocol: one SET goes in one datagram,
//! and what the v2c envelope, the PDU and the binding take around the
//! OCTET STRING is what the datagram cannot carry of the Stream. A payload
//! over it is refused before anything waits on it.

use std::net::UdpSocket;
use std::sync::OnceLock;

use transport::error::{Result, classify, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Transport};

use crate::{Binding, Envelope, MAX_DATAGRAM, Message, Pdu, PduType, SnmpTransport, Value, ber};

/// The object one SET binds: a scratch object under enterprise 0.
pub const OID: [u32; 9] = [1, 3, 6, 1, 4, 1, 0, 1, 0];
/// The community the loopback speaks under.
const COMMUNITY: &str = "private";

/// The most one SET carries: the datagram less what the v2c envelope, the
/// PDU and the binding take around the OCTET STRING, measured through the
/// transport's own codec once at a size where every length is already in
/// its long form, as it is near the ceiling; the request id is the 1 a
/// fresh transport starts at.
#[must_use]
pub fn ceiling() -> usize {
    static CEILING: OnceLock<usize> = OnceLock::new();
    *CEILING.get_or_init(|| {
        let probe = 300;
        let binding = Binding::new(&OID, Value::OctetString(vec![0; probe]));
        let set = Pdu::new(PduType::SetRequest, 1, vec![binding]);
        let wire = Envelope::V2c(Message::v2c(COMMUNITY, set)).encode();
        MAX_DATAGRAM - (wire.len() - probe)
    })
}

impl SnmpTransport {
    /// Both ends on this machine: an agent at an ephemeral local port, a
    /// manager speaking v2c under [`COMMUNITY`], the loopback timeout on
    /// both.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", COMMUNITY).timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound agent waiting for its one SET.
struct Agent {
    socket: UdpSocket,
    address: String,
}

impl FarEnd for Agent {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let (read, peer) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|e| classify("receiving the request", &e))?;
        let request = Envelope::decode(&buffer[..read])?;
        let pdu = request.pdu();
        if pdu.kind != PduType::SetRequest {
            return Err(protocol_error(format!(
                "a {} where a set was due",
                pdu.kind.name()
            )));
        }
        let binding = pdu
            .bindings
            .first()
            .ok_or_else(|| protocol_error("a set binding nothing"))?;
        let bytes = binding.value.octets()?.to_vec();
        self.socket
            .send_to(&request.answering(pdu.response(0)).encode(), peer)
            .map_err(|e| classify("answering the set", &e))?;
        let origin = format!(
            "snmp://{peer}?{}&oid={}&pdu={}",
            request.credential(),
            ber::oid_text(&binding.oid),
            pdu.kind.name()
        );
        Ok(Arrived::new(origin, bytes))
    }
}

impl Loopback for SnmpTransport {
    fn ceiling(&self) -> Option<usize> {
        Some(ceiling())
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (socket, address) = self.bind_udp()?;
        Ok(Box::new(Agent { socket, address }))
    }

    /// A fresh manager SETs [`OID`] at the agent to the payload; the
    /// request id is the 1 the ceiling was measured with.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        if payload.len() > ceiling() {
            return Err(protocol_error(format!(
                "{} bytes is over the {} one SET carries in a datagram",
                payload.len(),
                ceiling()
            )));
        }
        let target = format!("snmp+set://{address}/{}", ber::oid_text(&OID));
        Self::loopback().send(&target, payload)
    }

    fn unblock(&self, _address: &str) {
        // The receive has its own timeout; there is no listener to poke.
    }
}
