# xmip-core-transport-snmp

SNMP transport: v2c and v3 noAuthNoPriv over UDP with a hand-rolled BER — traps and informs arrive as one Stream of bindings, a Send Location raises a trap or sets an object. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A trap's or an inform's Stream is UTF-8 `oid=value` lines, one binding each; bytes that are not UTF-8, or a line that is not a binding, are refused. A SET carries its bytes as they are.

A Send Location's request and its answer go through one socket per address family, bound on the first send and kept by the transport (`transport::sender::Sender`), whatever came late read off before the next request, so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound on the first receive (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
