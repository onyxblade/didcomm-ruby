# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module Crypto
      module Sign
        def self.pack(msg_hash, sign_frm, resolvers_config)
          msg_bytes = JSON.generate(msg_hash).encode("UTF-8")

          secret = Keys::SignKeysSelector.find_signing_key(sign_frm, resolvers_config)
          key_info = KeyUtils.extract_key(secret)
          alg = KeyUtils.extract_sign_alg(secret)

          jws = JWSEnvelope.sign(msg_bytes, key_info, secret.kid, alg)

          { msg: jws, sign_frm_kid: secret.kid, alg: alg }
        end

        def self.unpack(msg_hash, resolvers_config)
          Validation.validate_jws(msg_hash)

          sign_frm_kid = msg_hash["signatures"][0]["header"]["kid"]

          vm = Keys::SignKeysSelector.find_verification_key(sign_frm_kid, resolvers_config)
          key_info = KeyUtils.extract_key(vm)
          alg = KeyUtils.extract_sign_alg(vm)

          payload_bytes = JWSEnvelope.verify(msg_hash, key_info, alg)

          { msg: payload_bytes.force_encoding("UTF-8"), sign_frm_kid: sign_frm_kid, alg: alg }
        end
      end
    end
  end
end
