//! A message as it came, whichever version wrapped it: v2c's community
//! message or v3's.

use transport::error::Result;

use crate::pdu::{self, Message, Pdu};
use crate::v3::{self, V3Message};

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
