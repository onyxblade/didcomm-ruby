# didcomm-ruby

Ruby implementation of the [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) messaging protocol.

## Disclaimer

This project was developed with the assistance of Claude and GPT, referencing the DIDComm v2 specification and the Python and Rust reference implementations listed below. The author does not have the ability to verify the correctness of this implementation. **Use at your own risk.** It is not recommended for production use without independent review and thorough testing.

## Features

- **Pack/Unpack** — plaintext, signed (JWS), and encrypted (JWE) message packing
- **Authenticated & Anonymous Encryption** — ECDH-ES and ECDH-1PU key agreement with A256CBC-HS512 / XC20P content encryption
- **Signed Messages** — EdDSA signing
- **Forward Protocol** — routing / mediator support
- **From Prior** — DID rotation via `from_prior` JWT
- **Pluggable Resolvers** — bring your own DID resolver and secrets resolver

## Requirements

- Ruby >= 4.0 (requires OpenSSL with AES-256-wrap support)
- libsodium

## Installation

```ruby
gem "didcomm"
```

## Usage

```ruby
require "didcomm"

# Implement DIDComm::DIDDoc::DIDResolver and DIDComm::Secrets::SecretsResolver,
# or use the provided in-memory variants for testing.

resolver = DIDComm::DIDDoc::DIDResolverInMemory.new(did_docs)
secrets  = DIDComm::Secrets::SecretsResolverInMemory.new(secrets)

# Pack an encrypted message
result = DIDComm::PackEncrypted.new(message, to: recipient_did, from: sender_did,
                                    did_resolver: resolver, secrets_resolver: secrets).pack

# Unpack a received message
unpack = DIDComm::Unpack.new(result.packed_msg,
                             did_resolver: resolver, secrets_resolver: secrets).unpack
```

## Reference

This project was implemented following:

- [DIDComm Messaging v2.1 Specification](https://identity.foundation/didcomm-messaging/spec/v2.1/)
- [sicpa-dlab/didcomm-python](https://github.com/sicpa-dlab/didcomm-python)
- [sicpa-dlab/didcomm-rust](https://github.com/sicpa-dlab/didcomm-rust)

## License

[MIT](LICENSE)
