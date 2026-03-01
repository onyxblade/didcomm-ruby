#!/usr/bin/env ruby
# frozen_string_literal: true

# Plaintext message: no encryption, no signing.
# Useful for understanding the DIDComm message structure.
#
# Run:
#   ruby -I lib examples/plaintext.rb

require_relative "helpers"

alice = build_x25519_identity(RbNaCl::PrivateKey.generate)
bob   = build_x25519_identity(RbNaCl::PrivateKey.generate)

puts "Alice: #{alice[:did]}"
puts "Bob:   #{bob[:did]}"
puts

# ── Pack plaintext ───────────────────────────────────────────────────────

message = DIDComm::Message.new(
  type: "https://example.com/protocols/hello/1.0/ping",
  from: alice[:did],
  to:   [bob[:did]],
  body: { "text" => "Hey Bob, this is Alice!" }
)

config = DIDComm::ResolversConfig.new(
  did_resolver:     DID::ResolverInMemory.new([alice[:did_doc], bob[:did_doc]]),
  secrets_resolver: DID::SecretsResolverInMemory.new([])
)

result = DIDComm.pack_plaintext(message, resolvers_config: config)

puts "── Packed (plaintext) message ──"
puts JSON.pretty_generate(JSON.parse(result.packed_msg))
