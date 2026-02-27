#!/usr/bin/env ruby
# frozen_string_literal: true

# DID Rotation via from_prior: Alice informs Bob that she rotated
# from an old DID to a new one, using a signed JWT in the message.
#
# Run:
#   ruby -I lib examples/did_rotation.rb

require_relative "helpers"

alice_old = build_full_identity
alice_new = build_full_identity
bob       = build_full_identity

puts "Alice (old): #{alice_old[:did]}"
puts "Alice (new): #{alice_new[:did]}"
puts "Bob:         #{bob[:did]}"
puts

# ── Alice sends a message from her new DID, with from_prior ──────────────

# from_prior is a JWT proving that alice_new was previously alice_old.
# iss = old DID, sub = new DID.
from_prior = DIDComm::FromPrior.new(
  iss: alice_old[:did],
  sub: alice_new[:did]
)

message = DIDComm::Message.new(
  type:       "https://example.com/protocols/hello/1.0/ping",
  from:       alice_new[:did],
  to:         [bob[:did]],
  body:       { "text" => "Hi Bob, I rotated my DID!" },
  from_prior: from_prior
)

# Alice needs the old identity's secret (to sign from_prior)
# and the new identity's secret (to encrypt the message).
alice_config = DIDComm::ResolversConfig.new(
  did_resolver: DIDComm::DIDResolverInMemory.new([
    alice_old[:did_doc], alice_new[:did_doc], bob[:did_doc]
  ]),
  secrets_resolver: DIDComm::SecretsResolverInMemory.new(
    alice_old[:secrets] + alice_new[:secrets]
  )
)

pack_result = DIDComm.pack_encrypted(
  message,
  to:   bob[:did],
  from: alice_new[:did],
  resolvers_config: alice_config,
  pack_config: DIDComm::PackEncryptedConfig.new(forward: false)
)

puts "── Packed message ──"
puts pack_result.packed_msg[0, 120] + "..."
puts "from_prior signed by: #{pack_result.from_prior_issuer_kid}"
puts

# ── Bob unpacks and sees the DID rotation ────────────────────────────────

bob_config = DIDComm::ResolversConfig.new(
  did_resolver: DIDComm::DIDResolverInMemory.new([
    alice_old[:did_doc], alice_new[:did_doc], bob[:did_doc]
  ]),
  secrets_resolver: DIDComm::SecretsResolverInMemory.new(bob[:secrets])
)

unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: bob_config)

puts "── Unpacked message ──"
puts "From: #{unpack_result.message.from}"
puts "Body: #{unpack_result.message.body}"
puts
puts "── DID Rotation ──"
puts "from_prior JWT present:  #{!unpack_result.metadata.from_prior_jwt.nil?}"
puts "from_prior issuer kid:   #{unpack_result.metadata.from_prior_issuer_kid}"

fp = unpack_result.message.from_prior
puts "Old DID (iss):           #{fp.iss}"
puts "New DID (sub):           #{fp.sub}"
