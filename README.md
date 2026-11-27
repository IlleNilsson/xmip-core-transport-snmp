# xmip-core-transport-snmp

SNMP transport: v2c and v3 noAuthNoPriv over UDP with a hand-rolled BER — traps and informs arrive as one Stream of bindings, a Send Location raises a trap or sets an object. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A trap's or an inform's Stream is UTF-8 `oid=value` lines, one binding each; bytes that are not UTF-8, or a line that is not a binding, are refused. A SET carries its bytes as they are.

A datagram's BER is read to 64 nested SEQUENCEs and PDUs at most (`codec::depth`), so a trap of nested SEQUENCEs is refused rather than read down the stack; it is read by the BER reader of `xmip-core-library-asn1` (`asn1::ber`), which takes a definite length in any form, as SNMP agents write them, and holds an INTEGER to its fewest bytes.

A Send Location's request and its answer go through one socket per address family, bound on the first send and kept by the transport (`transport::sender::Sender`), whatever came late read off before the next request, so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16) (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

## Acknowledgement

An inform is confirmed, so its Response waits for the whole receive cycle: on
Accepted the Response goes back with `noError`. On Refused it goes back with an
error status (RFC 3416 section 3): `authorizationError` for a sender not
identified or not permitted, `genErr` for content refused; a Response ends the
originator's retransmissions (RFC 3416 section 4.2.7), so it is not sent again,
and a send of this transport answered an error status fails as permanent. On
Failed the inform goes unanswered, and its originator sends it again when its
timeout passes (RFC 3413 3.3.6). A trap is
unconfirmed (its agent sends it once and waits for nothing), so acceptance is
at-most-once there. Each notification arrives whole.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which
`Configured` reads (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `user`, `engine` and `timeout`, and `SCHEMES`,
`snmp`, `snmp+trap`, `snmp+inform` and `snmp+set`, by which a send's target
is read as well. Built with its `declaration` feature alone
(`--no-default-features --features declaration`), the crate is those and
nothing more: its code and every crate the code is built on are behind the
default feature. So the library the surfaces load carries it without the
code, through the gathering crate xmip-core-declaration (open problem 48),
and the language server and the desktop suggest and check an SNMP Location's
settings though no node in their process loaded the technology.
`test/Declaration.Test.ps1` in the estate holds that the declaration builds
nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
