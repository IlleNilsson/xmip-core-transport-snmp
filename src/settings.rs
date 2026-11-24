//! The settings an SNMP Location takes, declared once and read through
//! (ADR-0064, amendment 2026-09-26).

use transport::Configured;
use transport::error::Result;
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

use crate::{SnmpTransport, TEXT_ENGINE};

impl Configured for SnmpTransport {
    /// The address is where a Receive Location listens as the manager,
    /// `0.0.0.0:162`; a send's target is each send's own.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The user a Send Location speaks v3 as, at noAuthNoPriv, unless a \
                          target says otherwise; v2c when left out.",
                applies: Applies::Send,
            },
            Setting {
                name: "engine",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The text an engine id v3 messages name carries, in its text form \
                          under enterprise 0; `xmip` when left out.",
                applies: Applies::Send,
            },
            transport::configured::timeout(
                Applies::Both,
                None,
                "How long a receive waits for a notification and a send for its \
                 answer; unbounded when left out.",
            ),
        ],
    };

    /// The schemes a Location's address is entered with to choose this technology.
    const SCHEMES: &'static [&'static str] = crate::target::SCHEMES;

    /// The whole address: its scheme says what a send does at the far end,
    /// a trap, an inform or a set (`target::SnmpTarget`), so a Send
    /// Location's sends do what its address says; a Receive Location binds
    /// the address in its own terms.
    fn own_target(address: &str) -> &str {
        address
    }

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    /// The community is a shared secret and comes through the Location's
    /// credentials, not a setting; until it is given, a v2c send names none.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address, "");
        if let Some(user) = settings.optional_text("user") {
            transport = transport.speaking_v3(user);
        }
        if let Some(engine) = settings.optional_text("engine") {
            transport = transport.as_engine(&[&TEXT_ENGINE[..], engine.as_bytes()].concat());
        }
        Ok(transport)
    }

    /// The socket every receive takes from, bound where a Receive Location
    /// listens for notifications.
    fn listening(&self) -> Result<Option<&str>> {
        self.receiving.listening(|| self.bind_udp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xcore::settings::Given;

    #[test]
    fn snmp_declares_its_settings_and_reads_through_them() {
        assert_eq!(SnmpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("user".to_string(), Given::Text("ops".to_string())),
            ("engine".to_string(), Given::Text("node7".to_string())),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built = SnmpTransport::open("0.0.0.0:162", Applies::Send, &given).expect("sent");
        assert_eq!(built.user, "ops");
        assert_eq!(built.version, crate::pdu::VERSION_3);
        assert_eq!(built.engine_id, [&TEXT_ENGINE[..], b"node7"].concat());
        assert_eq!(built.timeout, Some(Duration::from_secs(2)));
        let plain = SnmpTransport::open("0.0.0.0:162", Applies::Receive, &[]).expect("plain");
        assert_eq!(plain.version, crate::pdu::VERSION_2C);
        let Err(refused) = SnmpTransport::open("0.0.0.0:162", Applies::Receive, &given) else {
            panic!("a Receive Location speaks as no user");
        };
        assert!(refused.message.contains("\"user\""), "{refused}");
    }

    /// A Send Location as a node builds it, from its address, does what its
    /// address says at the far end: its own target is the whole address, so
    /// `snmp+set://` sets the object it names (the owner, 2026-11-24: *go
    /// through each item and sort it*). Until 2026-11-24 its target was the
    /// address without its scheme, a bare `host:port`, read as a trap.
    #[test]
    fn a_send_location_does_what_its_address_says() {
        use transport::{Loopback, Transport};
        let far = SnmpTransport::loopback().far_end().expect("a far end");
        let object: Vec<String> = crate::loopback::OID.iter().map(u32::to_string).collect();
        let address = format!("snmp+set://{}/{}", far.address(), object.join("."));
        let sending = SnmpTransport::open(&address, Applies::Send, &[])
            .expect("sending")
            .timing_out_after(transport::LOOPBACK_TIMEOUT);
        let taking = std::thread::spawn(move || far.take_one());

        let sent = sending.send(SnmpTransport::own_target(&address), b"order");

        let taken = taking.join().expect("the far end");
        sent.expect("set as its address says");
        assert_eq!(taken.expect("taken").bytes, b"order");
    }
}
