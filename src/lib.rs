#![forbid(unsafe_code)]

//! Streams that arrive as SNMP notifications. One trap or inform is one
//! Stream: its variable bindings, one `oid=value` line each, and the
//! community or user, version and trap identifier in the origin.
//!
//! SNMP is how the estate's equipment says what happened: a switch whose
//! link went down, a UPS on battery, an appliance past a threshold — every
//! one raises a trap at a manager on UDP port 162. A Receive Location is
//! that manager, taking traps and acknowledging informs; a Send Location
//! raises a trap or an inform of its own, or sets one object on an agent.
//! v2c with a community, and v3 with a user at noAuthNoPriv — the
//! authentication and privacy of RFC 3414 stay open (`v3.rs` says why), and
//! join with identity (ADR-0019).
//!
//! The origin URI carries what the message header knew:
//! `snmp://peer?community=public&version=2c&trap-oid=1.3.6.1.4.1.9.0.1&pdu=trap`,
//! or `user=ops&version=3` for v3.
//!
//! A send goes to `snmp://host:162?community=public&trap-oid=…` as a trap,
//! `snmp+inform://host:162` as an inform that waits for its acknowledgement,
//! `snmp+set://host:161/1.3.6.1.4.1.9.9.1.0?community=private` as a SET of
//! the bytes as one OCTET STRING that waits for the response, or a bare
//! `host:port` as a trap with everything as configured. A trap's bindings
//! are the bytes' `oid=value` lines; `sysUpTime.0` and `snmpTrapOID.0` are
//! put first when the lines do not open with them.

pub mod ber;
pub mod lines;
pub mod loopback;
pub mod pdu;
pub mod target;
pub mod v3;

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

pub use ber::Value;
pub use pdu::{Binding, Message, Pdu, PduType};
pub use target::{Action, SnmpTarget};
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};
pub use v3::V3Message;

/// The largest datagram an SNMP entity must take, and then some: what UDP
/// over IPv4 carries.
pub const MAX_DATAGRAM: usize = 65_507;
/// `genErr`, the error status an unwanted request is answered with.
pub const GEN_ERR: i32 = 5;

/// A message as it came, whichever version wrapped it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    V2c(Message),
    V3(V3Message),
}

impl Envelope {
    /// Read `bytes` by the version they open with.
    ///
    /// # Errors
    /// Not BER, not a version spoken, or anything `pdu` and `v3` refuse.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if pdu::version_of(bytes)? == pdu::VERSION_3 {
            v3::decode(bytes).map(Self::V3)
        } else {
            pdu::decode(bytes).map(Self::V2c)
        }
    }

    /// On the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::V2c(message) => pdu::encode(message),
            Self::V3(message) => v3::encode(message),
        }
    }

    #[must_use]
    pub const fn pdu(&self) -> &Pdu {
        match self {
            Self::V2c(message) => &message.pdu,
            Self::V3(message) => &message.pdu,
        }
    }

    /// The same wrapping around `pdu`, answering this message.
    #[must_use]
    pub fn answering(&self, pdu: Pdu) -> Self {
        match self {
            Self::V2c(message) => Self::V2c(Message {
                version: message.version,
                community: message.community.clone(),
                pdu,
            }),
            Self::V3(message) => Self::V3(message.answering(pdu)),
        }
    }

    /// `community=public&version=2c` or `user=ops&version=3`.
    #[must_use]
    pub fn credential(&self) -> String {
        match self {
            Self::V2c(message) => format!(
                "community={}&version=2c",
                String::from_utf8_lossy(&message.community)
            ),
            Self::V3(message) => format!("user={}&version=3", message.user),
        }
    }
}

pub struct SnmpTransport {
    bind: String,
    community: String,
    user: String,
    version: i64,
    engine_id: Vec<u8>,
    timeout: Option<Duration>,
    started: Instant,
    next_id: AtomicI32,
}

impl SnmpTransport {
    /// Listen at `bind`, `0.0.0.0:162` being the standard port; send v2c
    /// under `community`.
    #[must_use]
    pub fn new(bind: impl Into<String>, community: &str) -> Self {
        Self {
            bind: bind.into(),
            community: community.to_string(),
            user: "xmip".to_string(),
            version: pdu::VERSION_2C,
            engine_id: b"\x80\x00\x00\x00\x04xmip".to_vec(),
            timeout: None,
            started: Instant::now(),
            next_id: AtomicI32::new(1),
        }
    }

    /// Send v3 as `user` at noAuthNoPriv unless a target says otherwise.
    #[must_use]
    pub fn speaking_v3(mut self, user: &str) -> Self {
        self.user = user.to_string();
        self.version = pdu::VERSION_3;
        self
    }

    /// The engine id v3 messages name; the default is the text form of
    /// `xmip` under enterprise 0.
    #[must_use]
    pub fn as_engine(mut self, engine_id: &[u8]) -> Self {
        self.engine_id = engine_id.to_vec();
        self
    }

    /// Give up waiting for a message or an answer after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the UDP socket and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_udp(&self) -> Result<(UdpSocket, String)> {
        socket::bind_udp(&self.bind, self.timeout)
    }

    /// Take one trap or inform from an already-bound socket. An inform is
    /// acknowledged; a get or set aimed at this manager is answered `genErr`
    /// and skipped, and a stray response is skipped.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not SNMP.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Arrived> {
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .map_err(|e| classify("receiving a datagram", &e))?;
            let envelope = Envelope::decode(&buffer[..read])?;
            let pdu = envelope.pdu();
            match pdu.kind {
                PduType::Trap => return Ok(arrived(peer, &envelope)),
                PduType::InformRequest => {
                    let answer = envelope.answering(pdu.response(0)).encode();
                    socket
                        .send_to(&answer, peer)
                        .map_err(|e| classify("acknowledging an inform", &e))?;
                    return Ok(arrived(peer, &envelope));
                }
                PduType::GetResponse => {}
                _ => {
                    let answer = envelope.answering(pdu.response(GEN_ERR)).encode();
                    socket
                        .send_to(&answer, peer)
                        .map_err(|e| classify("refusing a request", &e))?;
                }
            }
        }
    }

    /// Hundredths of a second since this transport was built: `sysUpTime`.
    #[must_use]
    pub fn uptime(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis() / 10).unwrap_or(u64::MAX)
    }

    /// The message `target` asks for, carrying `pdu`.
    fn wrap(&self, target: &SnmpTarget, pdu: Pdu) -> Envelope {
        if target.version.unwrap_or(self.version) == pdu::VERSION_3 {
            let user = target.user.as_deref().unwrap_or(&self.user);
            Envelope::V3(V3Message::new(pdu.request_id, &self.engine_id, user, pdu))
        } else {
            let community = target.community.as_deref().unwrap_or(&self.community);
            Envelope::V2c(Message::v2c(community, pdu))
        }
    }

    /// Send `request` to `address` and take the response to it.
    fn exchange(&self, address: &str, request: &Envelope) -> Result<Option<Envelope>> {
        let sender =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| classify("binding the sending socket", &e))?;
        sender
            .set_read_timeout(self.timeout)
            .map_err(|e| classify("setting the answer timeout", &e))?;
        sender
            .send_to(&request.encode(), address)
            .map_err(|e| classify("sending the message", &e))?;
        if request.pdu().kind == PduType::Trap {
            return Ok(None);
        }
        let mut buffer = vec![0u8; MAX_DATAGRAM];
        let read = sender
            .recv(&mut buffer)
            .map_err(|e| classify("awaiting the response", &e))?;
        let response = Envelope::decode(&buffer[..read])?;
        let answer = response.pdu();
        if answer.request_id != request.pdu().request_id || answer.kind != PduType::GetResponse {
            return Err(protocol_error("a response to another request"));
        }
        if answer.error_status != 0 {
            return Err(protocol_error(format!(
                "the agent answered error status {} at index {}",
                answer.error_status, answer.error_index
            )));
        }
        Ok(Some(response))
    }
}

fn arrived(peer: SocketAddr, envelope: &Envelope) -> Arrived {
    let pdu = envelope.pdu();
    let trap_oid = pdu.trap_oid().map(ber::oid_text).unwrap_or_default();
    Arrived::new(
        format!(
            "snmp://{peer}?{}&trap-oid={trap_oid}&pdu={}",
            envelope.credential(),
            pdu.kind.name()
        ),
        lines::render(&pdu.bindings),
    )
}

impl Transport for SnmpTransport {
    fn name(&self) -> &'static str {
        "snmp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (socket, _) = self.bind_udp()?;
        Ok(vec![self.receive_datagram(&socket)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let target = SnmpTarget::parse(target)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let trap_oid = target
            .trap_oid
            .clone()
            .unwrap_or(pdu::ZERO_DOT_ZERO.to_vec());
        let pdu = match &target.action {
            Action::Set(oid) => Pdu::new(
                PduType::SetRequest,
                id,
                vec![Binding::new(oid, Value::OctetString(bytes.to_vec()))],
            ),
            Action::Trap | Action::Inform => {
                let kind = if target.action == Action::Trap {
                    PduType::Trap
                } else {
                    PduType::InformRequest
                };
                Pdu::notification(
                    kind,
                    id,
                    &trap_oid,
                    self.uptime(),
                    lines::parse_lines(bytes)?,
                )
            }
        };
        self.exchange(&target.address, &self.wrap(&target, pdu))
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::loopback::Loopback;
    use transport::payload::{edge_payloads, patterned};

    fn node() -> SnmpTransport {
        SnmpTransport::new("127.0.0.1:0", "public").timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn a_stream_rounds_as_one_set_the_agent_answers() {
        let loopback = SnmpTransport::loopback();
        let opaque: &[u8] = b"\x00line\r\nbreak \xff";
        let arrived = loopback.round(opaque).expect("opaque");
        assert_eq!(arrived.bytes, opaque);
        assert!(
            arrived.origin_uri.starts_with("snmp://127.0.0.1:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived
                .origin_uri
                .ends_with("?community=private&version=2c&oid=1.3.6.1.4.1.0.1.0&pdu=set"),
            "{}",
            arrived.origin_uri
        );
        let long = vec![0x2a; 5000];
        assert_eq!(loopback.round(&long).expect("long").bytes, long);
        assert!(loopback.round(b"").expect("empty").bytes.is_empty());
        assert_eq!(loopback.ceiling(), Some(loopback::ceiling()));
        assert!(loopback.refuses(opaque).is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole_and_refuses_over_the_ceiling() {
        let ceiling = loopback::ceiling();
        assert!((65_000..MAX_DATAGRAM).contains(&ceiling), "{ceiling}");
        let loopback = SnmpTransport::loopback();
        let mut edges = edge_payloads();
        edges.push(("brim", patterned(ceiling)));
        for (name, payload) in edges {
            assert_eq!(
                loopback.round(&payload).expect(name).bytes,
                payload,
                "{name}"
            );
        }
        let over = loopback.round(&vec![0; ceiling + 1]).expect_err("over");
        assert!(over.message.starts_with("send failed:"), "{over}");
        assert!(over.message.contains("one SET carries"), "{over}");
    }

    #[test]
    fn a_trap_arrives_as_its_bindings_with_the_header_in_the_origin() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        node()
            .send(
                &format!("snmp://{address}?community=ops&trap-oid=1.3.6.1.4.1.9.0.1"),
                b"1.3.6.1.4.1.9.9.1.0=link down\n1.3.6.1.2.1.2.2.1.1.3=3\n",
            )
            .expect("sending");
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert!(
            arrived
                .origin_uri
                .ends_with("?community=ops&version=2c&trap-oid=1.3.6.1.4.1.9.0.1&pdu=trap"),
            "{}",
            arrived.origin_uri
        );
        let text = String::from_utf8(arrived.bytes).expect("text");
        assert!(text.starts_with("1.3.6.1.2.1.1.3.0="), "{text}");
        assert!(text.ends_with(
            "1.3.6.1.6.3.1.1.4.1.0=1.3.6.1.4.1.9.0.1\n\
             1.3.6.1.4.1.9.9.1.0=link down\n1.3.6.1.2.1.2.2.1.1.3=3\n"
        ));
        node().send(&address, b"").expect("bare target");
        let bare = far_end.receive_datagram(&socket).expect("receiving");
        assert!(
            bare.origin_uri
                .contains("community=public&version=2c&trap-oid=0.0")
        );
    }

    #[test]
    fn an_inform_is_acknowledged_and_a_set_waits_for_the_agent() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        let informer = std::thread::spawn(move || {
            let near = node();
            near.send(&format!("snmp+inform://{address}"), b"1.3.6.1.4.1.1.0=1\n")?;
            near.send(
                &format!("snmp+inform://{address}?version=3&user=ops"),
                b"1.3.6.1.4.1.1.0=2\n",
            )
        });
        let v2c = far_end.receive_datagram(&socket).expect("v2c inform");
        assert!(
            v2c.origin_uri
                .contains("community=public&version=2c&trap-oid=0.0&pdu=inform")
        );
        let v3 = far_end.receive_datagram(&socket).expect("v3 inform");
        assert!(
            v3.origin_uri
                .contains("user=ops&version=3&trap-oid=0.0&pdu=inform")
        );
        assert!(v3.bytes.ends_with(b"1.3.6.1.4.1.1.0=2\n"));
        informer.join().expect("thread").expect("both acknowledged");

        let agent = UdpSocket::bind("127.0.0.1:0").expect("agent");
        agent
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let address = agent.local_addr().expect("address");
        let setter = std::thread::spawn(move || {
            let near = node();
            near.send(
                &format!("snmp+set://{address}/1.3.6.1.4.1.9.9.1.0?community=private"),
                b"new value",
            )?;
            near.send(&format!("snmp+set://{address}/1.3.6.1.4.1.9.9.1.0"), b"x")
        });
        let mut buffer = [0u8; 512];
        for (turn, status) in [(0, 0), (1, 17)] {
            let (read, peer) = agent.recv_from(&mut buffer).expect("request");
            let envelope = Envelope::decode(&buffer[..read]).expect("decode");
            let Envelope::V2c(message) = &envelope else {
                panic!("v2c expected")
            };
            let expected = if turn == 0 {
                b"private".to_vec()
            } else {
                b"public".to_vec()
            };
            assert_eq!(message.community, expected);
            assert_eq!(message.pdu.kind, PduType::SetRequest);
            assert_eq!(message.pdu.bindings[0].oid, [1, 3, 6, 1, 4, 1, 9, 9, 1, 0]);
            let answer = envelope.answering(message.pdu.response(status)).encode();
            agent.send_to(&answer, peer).expect("answering");
        }
        let refused = setter.join().expect("thread").expect_err("wrongValue");
        assert!(refused.message.contains("error status 17"));
        assert!(!refused.retryable);
    }

    #[test]
    fn what_is_not_snmp_is_refused_and_a_request_is_answered_generr() {
        let far_end = node().timing_out_after(Duration::from_millis(300));
        let (socket, address) = far_end.bind_udp().expect("binding");
        let manager = UdpSocket::bind("127.0.0.1:0").expect("sender");
        manager
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        manager.send_to(b"not snmp", &address).expect("junk");
        let error = far_end.receive_datagram(&socket).expect_err("junk");
        assert!(!error.retryable);
        let get = Pdu::new(
            PduType::GetRequest,
            9,
            vec![Binding::new(&[1, 3], Value::Null)],
        );
        let request = Envelope::V2c(Message::v2c("public", get)).encode();
        manager.send_to(&request, &address).expect("get");
        let timed_out = far_end.receive_datagram(&socket).expect_err("then nothing");
        assert!(timed_out.retryable);
        let mut buffer = [0u8; 512];
        let read = manager.recv(&mut buffer).expect("genErr");
        let answer = Envelope::decode(&buffer[..read]).expect("decode");
        assert_eq!(answer.pdu().kind, PduType::GetResponse);
        assert_eq!(answer.pdu().error_status, GEN_ERR);
        assert_eq!(answer.pdu().request_id, 9);
        let mut authenticated = V3Message::new(1, b"e", "u", Pdu::new(PduType::Trap, 1, vec![]));
        authenticated.flags = v3::FLAG_AUTH;
        manager
            .send_to(&v3::encode(&authenticated), &address)
            .expect("auth");
        let refused = far_end
            .receive_datagram(&socket)
            .expect_err("noAuthNoPriv only");
        assert!(refused.message.contains("noAuthNoPriv"));
        assert!(node().send("http://x", b"").is_err());
        assert!(node().claims().is_none());
        assert_eq!(node().name(), "snmp");
        assert!(node().speaking_v3("ops").as_engine(b"e").uptime() < 100);
    }
}
