# frozen_string_literal: true

require "json"

module DIDComm
  PackPlaintextResult = Struct.new(:packed_msg, :from_prior_issuer_kid, keyword_init: true)

  def self.pack_plaintext(message, resolvers_config:)
    msg_hash = message.is_a?(Message) ? message.to_hash : message

    from_prior_issuer_kid = FromPriorModule.pack_from_prior(msg_hash, resolvers_config)
    packed_msg = JSON.generate(msg_hash)

    PackPlaintextResult.new(packed_msg: packed_msg, from_prior_issuer_kid: from_prior_issuer_kid)
  end
end
