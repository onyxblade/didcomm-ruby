# DIDWell

Ruby toolkit for Decentralized Identifiers (DIDs).

## Components

- **[did](did/)** — [W3C DID Core](https://www.w3.org/TR/did-1.1/) types (DID Document, Verification Method, Resolvers)
- **[didcomm](didcomm/)** — [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/v2.1/) messaging (pack/unpack, encryption, signing, routing)

## Requirements

- Ruby >= 4.0
- libsodium

## Installation

```ruby
gem "didwell"
```

```ruby
require "didwell"
```

## License

[MIT](LICENSE)
