#!/usr/bin/env ruby
# frozen_string_literal: true

# Anonymous encryption (ECDH-ES): Alice encrypts a message to Bob.
# Bob can decrypt it but cannot verify who sent it.
#
# Run:
#   ruby -I lib examples/basic.rb

require_relative "helpers"

alice = build_x25519_identity(RbNaCl::PrivateKey.generate)
bob   = build_x25519_identity(RbNaCl::PrivateKey.generate)

puts "Alice: #{alice[:did]}"
puts "Bob:   #{bob[:did]}"
puts

# ── Alice packs ──────────────────────────────────────────────────────────

message = DIDComm::Message.new(
  type: "https://example.com/protocols/hello/1.0/ping",
  from: alice[:did],
  to:   [bob[:did]],
  body: { "text" => "Hey Bob, this is Alice!" }
)

alice_config = DIDComm::ResolversConfig.new(
  did_resolver:     DID::ResolverInMemory.new([alice[:did_doc], bob[:did_doc]]),
  secrets_resolver: DID::SecretsResolverInMemory.new(alice[:secrets])
)

pack_result = DIDComm.pack_encrypted(
  message,
  to: bob[:did],
  resolvers_config: alice_config,
  pack_config: DIDComm::PackEncryptedConfig.new(forward: false)
)

puts "── Packed (encrypted) message ──"
puts pack_result.packed_msg[0, 120] + "..."
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
puts "To:   #{unpack_result.message.to}"
puts "Body: #{unpack_result.message.body}"
puts
puts "── Metadata ──"
puts "Encrypted:        #{unpack_result.metadata.encrypted}"
puts "Anonymous sender: #{unpack_result.metadata.anonymous_sender}"
puts "Authenticated:    #{unpack_result.metadata.authenticated}"
