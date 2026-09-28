//! Where a send is going, read out of the target string.

use crate::pdu::{VERSION_2C, VERSION_3};
use net::Target;
use transport::error::{Result, protocol_error};

/// The schemes a target may open with: a trap, `snmp://` or
/// `snmp+trap://`; an inform; and a set.
const SCHEMES: &[&str] = &["snmp", "snmp+trap", "snmp+inform", "snmp+set"];

/// What a send does at the far end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Raise a trap: fire and forget.
    Trap,
    /// Raise an inform: a trap the far end acknowledges.
    Inform,
    /// Set the named object to the bytes as an OCTET STRING.
    Set(Vec<u32>),
}

/// A parsed `snmp://`, `snmp+inform://` or `snmp+set://` target, or a bare
/// `host:port` that raises a trap with everything else as configured.
///
/// The query carries `community`, `version` (`2c` or `3`), `user` for v3
/// and `trap-oid`; whichever is absent falls back to the transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnmpTarget {
    pub address: String,
    pub action: Action,
    pub community: Option<String>,
    pub version: Option<i64>,
    pub user: Option<String>,
    pub trap_oid: Option<Vec<u32>>,
}

impl SnmpTarget {
    /// # Errors
    /// A scheme that is not SNMP's, a set without an object, an object or
    /// trap-oid that is not dotted numbers, a version that is neither.
    pub fn parse(target: &str) -> Result<Self> {
        let named = if target.contains("://") {
            Target::under(SCHEMES, target)
                .ok_or_else(|| protocol_error(format!("not an snmp target: {target}")))?
        } else {
            Target::bare(target)
        };
        let (address, path) = (named.authority(), named.path());
        if address.is_empty() {
            return Err(protocol_error(format!(
                "an snmp target with no host: {target}"
            )));
        }
        let action =
            if named.is(&["snmp+set"]) {
                let oid = asn1::read_dotted(path).filter(|arcs| arcs.len() >= 2);
                Action::Set(oid.ok_or_else(|| {
                    protocol_error(format!("snmp+set needs /<oid> to set: {target}"))
                })?)
            } else if named.is(&["snmp+inform"]) {
                Action::Inform
            } else {
                Action::Trap
            };
        let value = |key: &str| named.query_value(key);
        let version = match value("version").as_deref() {
            None => None,
            Some("2c" | "2" | "1") => Some(VERSION_2C),
            Some("3") => Some(VERSION_3),
            Some(other) => {
                return Err(protocol_error(format!("a version not spoken: {other}")));
            }
        };
        let trap_oid = match value("trap-oid") {
            None => None,
            Some(text) => Some(
                asn1::read_dotted(&text)
                    .ok_or_else(|| protocol_error(format!("a trap-oid not dotted: {text}")))?,
            ),
        };
        Ok(Self {
            address: address.to_string(),
            action,
            community: value("community"),
            version,
            user: value("user"),
            trap_oid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_reads() {
        let trap = SnmpTarget::parse("snmp://nms:162?community=ops&trap-oid=1.3.6.1.4.1.9.0.1")
            .expect("trap");
        assert_eq!(trap.address, "nms:162");
        assert_eq!(trap.action, Action::Trap);
        assert_eq!(trap.community.as_deref(), Some("ops"));
        assert_eq!(trap.trap_oid, Some(vec![1, 3, 6, 1, 4, 1, 9, 0, 1]));
        assert_eq!(trap.version, None);
        let set = SnmpTarget::parse("snmp+set://agent:161/1.3.6.1.4.1.9.9.1.0?community=private")
            .expect("set");
        assert_eq!(set.action, Action::Set(vec![1, 3, 6, 1, 4, 1, 9, 9, 1, 0]));
        let inform =
            SnmpTarget::parse("snmp+inform://nms:162?version=3&user=xmip").expect("inform");
        assert_eq!(inform.action, Action::Inform);
        assert_eq!(inform.version, Some(VERSION_3));
        assert_eq!(inform.user.as_deref(), Some("xmip"));
        let bare = SnmpTarget::parse("127.0.0.1:162").expect("bare");
        assert_eq!(bare.address, "127.0.0.1:162");
        assert_eq!(bare.action, Action::Trap);
    }

    #[test]
    fn what_is_not_an_snmp_target_is_refused() {
        assert!(SnmpTarget::parse("http://nms").is_err());
        assert!(SnmpTarget::parse("snmp://").is_err());
        assert!(SnmpTarget::parse("snmp+set://agent:161").is_err(), "no oid");
        assert!(SnmpTarget::parse("snmp+set://agent:161/x").is_err());
        assert!(SnmpTarget::parse("snmp://nms?version=4").is_err());
        assert!(SnmpTarget::parse("snmp://nms?trap-oid=x").is_err());
    }
}
