# frozen_string_literal: true

require "json"

module DIDComm
  module Crypto
    module Authcrypt
      def self.pack(msg_hash, to_did_or_kid, frm_did_or_kid, alg, resolvers_config)
        keys = Keys::AuthcryptKeysSelector.find_pack_sender_and_recipient_keys(
          frm_did_or_kid, to_did_or_kid, resolvers_config
        )

        sender_secret = keys[:sender_secret]
        recipient_vms = keys[:recipient_vms]

        sender_key = KeyUtils.extract_key(sender_secret)
        sender_key[:kid] = sender_secret.kid

        recipient_keys = recipient_vms.map do |vm|
          key_info = KeyUtils.extract_key(vm)
          key_info[:kid] = vm.id
          key_info
        end

        plaintext = JSON.generate(msg_hash)
        jwe = JWEEnvelope.encrypt_1pu(plaintext, recipient_keys, sender_key, alg)

        {
          msg: jwe,
          to_kids: recipient_keys.map { |k| k[:kid] },
          from_kid: sender_secret.kid,
          to_keys: recipient_keys
        }
      end

      def self.unpack(msg_hash, resolvers_config, decrypt_by_all_keys: false)
        protected_header = Validation.validate_authcrypt_jwe(msg_hash)

        # Extract sender KID
        frm_kid = protected_header["skid"]
        if frm_kid.nil?
          frm_kid = KeyUtils.base64url_decode(protected_header["apu"]).force_encoding("UTF-8")
        end

        to_kids = msg_hash["recipients"].map { |r| r["header"]["kid"] }

        enc = protected_header["enc"]
        alg_obj = AuthCryptAlg.by_enc(enc)

        pairs = Keys::AuthcryptKeysSelector.find_unpack_sender_and_recipient_keys(
          frm_kid, to_kids, resolvers_config
        )

        last_error = nil
        unpack_result = nil
        pairs.each do |pair|
          begin
            recipient_key = KeyUtils.extract_key(pair[:recipient_secret])
            recipient_key[:kid] = pair[:recipient_secret].kid

            sender_key = KeyUtils.extract_key(pair[:sender_vm])
            sender_key[:kid] = pair[:sender_vm].id

            plaintext = JWEEnvelope.decrypt_1pu(msg_hash, recipient_key, sender_key)

            unpack_result = {
              msg: plaintext.force_encoding("UTF-8"),
              to_kids: to_kids,
              frm_kid: frm_kid,
              alg: alg_obj
            }
            return unpack_result unless decrypt_by_all_keys
          rescue StandardError => e
            if decrypt_by_all_keys
              raise MalformedMessageError.new(:can_not_decrypt, "Cannot decrypt by all available key pairs")
            end
            last_error = e
            next
          end
        end

        return unpack_result if unpack_result

        raise last_error || MalformedMessageError.new(:can_not_decrypt, "Cannot decrypt with any available key pair")
      end
    end
  end
end
