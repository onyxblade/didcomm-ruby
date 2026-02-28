# Changelog

## 0.1.0

- Initial implementation of DIDComm v2 messaging protocol
- Plaintext, signed (JWS), and encrypted (JWE) message packing/unpacking
- ECDH-ES (anoncrypt) and ECDH-1PU (authcrypt) key agreement
- A256CBC-HS512 and XC20P content encryption
- EdDSA signing
- Forward routing protocol support
- `from_prior` JWT packing/unpacking for DID rotation
- Pluggable DID resolver and secrets resolver interfaces
- In-memory resolver implementations for testing
- DID validation aligned with W3C DID grammar
- Encryption and message consistency validation
