#!/usr/bin/env ruby
# frozen_string_literal: true

# Authenticated encryption (ECDH-1PU): Alice encrypts a message to Bob.
# Bob can decrypt it AND verify that Alice was the sender.
#
# Both parties need Ed25519 (signing) + X25519 (encryption) keys.
#
# Run:
#   ruby -I lib examples/authcrypt.rb

require_relative "helpers"

alice = build_full_identity
bob   = build_full_identity

puts "Alice: #{alice[:did]}"
puts "Bob:   #{bob[:did]}"
puts

# ── Alice packs with authenticated encryption ────────────────────────────

message = DIDComm::Message.new(
  type: "https://example.com/protocols/hello/1.0/ping",
  from: alice[:did],
  to:   [bob[:did]],
  body: { "text" => "Hey Bob, this is Alice! (authenticated)" }
)

alice_config = DIDComm::ResolversConfig.new(
  did_resolver:     DID::ResolverInMemory.new([alice[:did_doc], bob[:did_doc]]),
  secrets_resolver: DID::SecretsResolverInMemory.new(alice[:secrets])
)

# Providing `from:` triggers ECDH-1PU (authcrypt) instead of ECDH-ES (anoncrypt).
pack_result = DIDComm.pack_encrypted(
  message,
  to:   bob[:did],
  from: alice[:did],
  resolvers_config: alice_config,
  pack_config: DIDComm::PackEncryptedConfig.new(forward: false)
)

puts "── Packed (authcrypt) message ──"
puts pack_result.packed_msg[0, 120] + "..."
puts "From key: #{pack_result.from_kid}"
puts

# ── Bob unpacks ──────────────────────────────────────────────────────────

bob_config = DIDComm::ResolversConfig.new(
  did_resolver:     DID::ResolverInMemory.new([alice[:did_doc], bob[:did_doc]]),
  secrets_resolver: DID::SecretsResolverInMemory.new(bob[:secrets])
)

unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: bob_config)

puts "── Unpacked message ──"
puts "Type: #{unpack_result.message.type}"
puts "From: #{unpack_result.message.from}"
puts "Body: #{unpack_result.message.body}"
puts
puts "── Metadata ──"
puts "Encrypted:        #{unpack_result.metadata.encrypted}"
puts "Authenticated:    #{unpack_result.metadata.authenticated}"
puts "Anonymous sender: #{unpack_result.metadata.anonymous_sender}"
puts "Encrypted from:   #{unpack_result.metadata.encrypted_from}"
