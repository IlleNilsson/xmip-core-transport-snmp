# xmip-core-transport-snmp

SNMP transport: v2c and v3 noAuthNoPriv over UDP with a hand-rolled BER — traps and informs arrive as one Stream of bindings, a Send Location raises a trap or sets an object. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
