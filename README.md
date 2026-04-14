# go-sam-bridge

[![Go Reference](https://pkg.go.dev/badge/github.com/go-i2p/go-sam-bridge.svg)](https://pkg.go.dev/github.com/go-i2p/go-sam-bridge)

A pure Go implementation of the SAMv3.3 (Simple Anonymous Messaging) bridge for I2P networking.

## Overview

`go-sam-bridge` provides a complete SAM bridge server that allows applications to communicate over the I2P network using the SAM protocol. This implementation uses native Go I2P libraries instead of wrapping the Java I2P router, enabling lightweight and efficient I2P integration.

**Key Features:**

- Full SAMv3.3 protocol support
- STREAM sessions (virtual TCP-like connections)
- DATAGRAM sessions (repliable/authenticated datagrams)
- RAW sessions (anonymous datagrams)
- DATAGRAM2/DATAGRAM3 support (new formats)
- PRIMARY sessions with multiplexed subsessions
- Modern cryptography (Ed25519 signatures, ECIES-X25519 encryption)
- Offline signature support
- B32 address resolution; B33 blinded resolution delegated to go-i2cp (unverified)

## Architecture

This bridge is built on pure Go I2P libraries:

- **[go-i2cp](https://github.com/go-i2p/go-i2cp)** - I2CP protocol implementation for tunnel management
- **[go-streaming](https://github.com/go-i2p/go-streaming)** - Reliable ordered streams over I2P
- **[go-datagrams](https://github.com/go-i2p/go-datagrams)** - Datagram support (repliable, raw, and new formats)

Unlike other SAM implementations that require a separate I2P router, `go-sam-bridge` directly embeds I2P routing in Go. If no I2CP listener is detected on the configured address, an embedded I2P router will be started automatically when using the library API (`embedding.New()`).

> **Note for binary users:** The `sam-bridge` binary currently requires a running I2P/I2CP daemon (`routers` port 7654). Automatic embedded-router fallback is available only via the library API (`lib/embedding`). Start `i2pd` or Java I2P first, then run `sam-bridge`.

Also, `go-sam-bridge` is capable of detecting an I2P router on the host and determining if it has a SAM API enabled. If an I2CP port is available on port 7654 but a SAM API is not available on the configured port(`7656` by default), then `go-sam-bridge` launches attached to the I2CP port provided by the host.

## Status

✅ **Core Implementation Complete** - All SAMv3.3 protocol features are implemented.

**Implemented Features:**

- Full SAM command parsing with UTF-8 support
- HELLO handshake with version negotiation and optional authentication
- SESSION CREATE/ADD/REMOVE for all session styles
- STREAM CONNECT/ACCEPT/FORWARD operations
- DATAGRAM, DATAGRAM2, DATAGRAM3 send/receive
- RAW anonymous datagram support
- PRIMARY sessions with multiplexed subsessions
- DEST GENERATE with Ed25519/ECIES-X25519 key generation
- NAMING LOOKUP with B32/B33 address resolution and .i2p hostname lookup (requires I2CP connection)
- PING/PONG keepalive
- AUTH commands for authentication management
- Utility commands (QUIT, STOP, EXIT, HELP)

**Note:** SAM 3.3 send options (SEND_TAGS, TAG_THRESHOLD, EXPIRES, SEND_LEASESET) are parsed and forwarded to go-datagrams; full support depends on upstream library.

## Quick Start

```bash
# Install
go get github.com/go-i2p/go-sam-bridge

# Run the bridge (when implemented)
go run cmd/sam-bridge/main.go
```

## SAM Protocol

The SAM (Simple Anonymous Messaging) protocol allows applications to communicate over I2P without implementing the full I2P stack. Applications connect to the SAM bridge via TCP and issue text-based commands to:

- Create I2P destinations
- Establish virtual streams
- Send/receive datagrams
- Look up I2P addresses
- Manage sessions

For the complete SAM specification, see [SAMv3.md](SAMv3.md).

## Use Cases

- **Anonymous messaging** - Chat applications over I2P
- **Hidden services** - Web servers, APIs accessible only via I2P
- **File sharing** - BitTorrent and other P2P protocols
- **VoIP** - Voice/video over I2P
- **Databases** - Distributed databases over I2P
- **IoT** - Anonymous sensor networks

## Recommended Configuration

For optimal performance and compatibility with both Java I2P and i2pd routers:

```text
SIGNATURE_TYPE=7                    # Ed25519
i2cp.leaseSetEncType=4,0           # ECIES-X25519 + ElGamal fallback
inbound.quantity=3                  # Balanced tunnel count
outbound.quantity=3
```

## Limitations

- **DATAGRAM/RAW/DATAGRAM2/DATAGRAM3 send requires I2CP** — Datagram and raw session send operations require a running I2P/I2CP daemon. Sessions can be created without I2CP, but send operations will fail until the DatagramConn is wired via an active I2CP session. In embedded router mode (library API), wiring happens automatically when the router becomes ready.
- **DEST GENERATE only supports Ed25519 (signature type 7).** Clients requesting other SAM signature types (0–6, 8) will receive an error. This is the recommended signature type for modern I2P usage.
- **B33 blinded address resolution** is delegated to go-i2cp and has not been verified against a router that supports encrypted LeaseSets.
- **SAM 3.3 send options** (SEND_TAGS, TAG_THRESHOLD, EXPIRES, SEND_LEASESET) are parsed and forwarded to go-datagrams; actual behavioral effect depends on upstream library support.

## Contributing

Contributions are welcome!

Areas where help is needed:

- Testing against Java I2P and i2pd routers
- Integration testing with SAM client libraries
- Documentation and usage examples
- Performance optimization
- Bug reports and feature requests

## References

- [SAMv3 Specification](https://geti2p.net/spec/sam)
- [I2CP Specification](https://geti2p.net/spec/i2cp)
- [I2P Project](https://geti2p.net/)
- [i2pd Router](https://i2pd.website/)

## License

See [LICENSE](LICENSE) file for details.

## Related Projects

- [go-sam-go](https://github.com/eyedeekay/go-sam-go) - Modern SAM 3.3 client library
- [gosam](https://github.com/eyedeekay/goSam) - SAM 3.2 client library
- [sam3](https://github.com/eyedeekay/sam3) - Legacy SAM 3.3 client library
- [i2p-rs](https://github.com/i2p/i2p-rs) - Rust SAM implementation
