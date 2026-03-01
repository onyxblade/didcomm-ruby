# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module PackSigned
      Result = Data.define(:packed_msg, :sign_from_kid, :from_prior_issuer_kid)

      def self.call(message, sign_from:, resolvers_config:)
        raise ValueError, "'sign_from' is not a valid DID or DID URL" unless DID::Utils.is_did(sign_from)

        msg_hash = message.is_a?(Message) ? message.to_hash : message

        # from_prior packing
        from_prior_issuer_kid = FromPrior.pack(msg_hash, resolvers_config)

        sign_result = Crypto::Sign.pack(msg_hash, sign_from, resolvers_config)

        packed_msg = JSON.generate(sign_result[:msg])

        Result.new(
          packed_msg: packed_msg,
          sign_from_kid: sign_result[:sign_frm_kid],
          from_prior_issuer_kid: from_prior_issuer_kid
        )
      end
    end
  end
end
