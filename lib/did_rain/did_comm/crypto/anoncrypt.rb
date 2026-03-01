# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module Crypto
      module Anoncrypt
        def self.pack(msg_hash, to_did_or_kid, alg, resolvers_config)
          recipient_vms = Keys::AnoncryptKeysSelector.find_pack_recipient_public_keys(
            to_did_or_kid, resolvers_config
          )

          recipient_keys = recipient_vms.map do |vm|
            key_info = KeyUtils.extract_key(vm)
            key_info[:kid] = vm.id
            key_info
          end

          plaintext = JSON.generate(msg_hash)
          jwe = JWEEnvelope.encrypt_es(plaintext, recipient_keys, alg)

          {
            msg: jwe,
            to_kids: recipient_keys.map { |k| k[:kid] },
            to_keys: recipient_keys
          }
        end

        def self.unpack(msg_hash, resolvers_config, decrypt_by_all_keys: false)
          Validation.validate_anoncrypt_jwe(msg_hash)

          to_kids = msg_hash["recipients"].map { |r| r["header"]["kid"] }

          secrets = Keys::AnoncryptKeysSelector.find_unpack_recipient_private_keys(
            to_kids, resolvers_config
          )

          protected_header = Validation.parse_protected(msg_hash["protected"])
          enc = protected_header["enc"]
          alg_obj = AnonCryptAlg.by_enc(enc)

          last_error = nil
          unpack_result = nil
          secrets.each do |secret|
            begin
              key_info = KeyUtils.extract_key(secret)
              key_info[:kid] = secret.kid
              plaintext = JWEEnvelope.decrypt_es(msg_hash, key_info)

              unpack_result = {
                msg: plaintext.force_encoding("UTF-8"),
                to_kids: to_kids,
                alg: alg_obj
              }
              return unpack_result unless decrypt_by_all_keys
            rescue StandardError => e
              if decrypt_by_all_keys
                raise MalformedMessageError.new(:can_not_decrypt, "Cannot decrypt by all available keys")
              end
              last_error = e
              next
            end
          end

          return unpack_result if unpack_result

          raise last_error || MalformedMessageError.new(:can_not_decrypt, "Cannot decrypt with any available key")
        end
      end
    end
  end
end
