#!/usr/bin/env ruby
# frozen_string_literal: true

# Signed + encrypted message: provides non-repudiation.
# The message is first signed with EdDSA, then encrypted.
# Bob can decrypt AND prove to a third party that Alice sent it.
#
# Run:
#   ruby -I lib examples/signed_encrypted.rb

require_relative "helpers"

alice = build_full_identity
bob   = build_full_identity

puts "Alice: #{alice[:did]}"
puts "Bob:   #{bob[:did]}"
puts

# ── Alice signs and encrypts ─────────────────────────────────────────────

message = DIDComm::Message.new(
  type: "https://example.com/protocols/hello/1.0/ping",
  from: alice[:did],
  to:   [bob[:did]],
  body: { "text" => "This is signed — you can prove I sent it." }
)

alice_config = DIDComm::ResolversConfig.new(
  did_resolver:     DID::ResolverInMemory.new([alice[:did_doc], bob[:did_doc]]),
  secrets_resolver: DID::SecretsResolverInMemory.new(alice[:secrets])
)

# `sign_from:` adds an EdDSA signature (JWS) before encryption.
pack_result = DIDComm.pack_encrypted(
  message,
  to:        bob[:did],
  from:      alice[:did],
  sign_from: alice[:did],
  resolvers_config: alice_config,
  pack_config: DIDComm::PackEncryptedConfig.new(forward: false)
)

puts "── Packed (signed + encrypted) message ──"
puts pack_result.packed_msg[0, 120] + "..."
puts "Sign key: #{pack_result.sign_from_kid}"
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
puts "Encrypted:         #{unpack_result.metadata.encrypted}"
puts "Authenticated:     #{unpack_result.metadata.authenticated}"
puts "Non-repudiation:   #{unpack_result.metadata.non_repudiation}"
puts "Sign from:         #{unpack_result.metadata.sign_from}"
puts "Sign algorithm:    #{unpack_result.metadata.sign_alg}"
