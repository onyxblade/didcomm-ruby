# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module PackPlaintext
      Result = Data.define(:packed_msg, :from_prior_issuer_kid)

      def self.call(message, resolvers_config:)
        msg_hash = message.is_a?(Message) ? message.to_hash : message

        from_prior_issuer_kid = FromPrior.pack(msg_hash, resolvers_config)
        packed_msg = JSON.generate(msg_hash)

        Result.new(packed_msg: packed_msg, from_prior_issuer_kid: from_prior_issuer_kid)
      end
    end
  end
end
