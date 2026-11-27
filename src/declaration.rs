//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens as the manager, `0.0.0.0:162`; a send's target
/// is each send's own.
pub const SETTINGS: &Settings = &Settings {
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

/// The schemes a Location's address, and a send's target, is entered with:
/// a trap, `snmp://` or `snmp+trap://`; an inform; and a set.
pub const SCHEMES: &[&str] = &["snmp", "snmp+trap", "snmp+inform", "snmp+set"];
