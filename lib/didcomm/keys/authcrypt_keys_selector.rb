# frozen_string_literal: true

module DIDComm
  module Keys
    module AuthcryptKeysSelector
      def self.find_pack_sender_and_recipient_keys(frm_did_or_kid, to_did_or_kid, resolvers_config)
        frm_did, frm_kid = DIDUtils.did_or_url(frm_did_or_kid)
        to_did, to_kid = DIDUtils.did_or_url(to_did_or_kid)

        # Resolve sender DID doc
        frm_did_doc = resolvers_config.did_resolver.resolve(frm_did)
        raise DIDDocNotResolvedError.new(frm_did) unless frm_did_doc

        # Resolve recipient DID doc
        to_did_doc = resolvers_config.did_resolver.resolve(to_did)
        raise DIDDocNotResolvedError.new(to_did) unless to_did_doc

        # Get sender key agreement kids
        sender_kids = if frm_kid
                        [frm_kid]
                      else
                        frm_did_doc.key_agreement
                      end
        raise DIDUrlNotFoundError, "No keyAgreement keys for sender #{frm_did}" if sender_kids.empty?

        # Get recipient key agreement kids
        recipient_kids = if to_kid
                           [to_kid]
                         else
                           to_did_doc.key_agreement
                         end
        raise DIDUrlNotFoundError, "No keyAgreement keys for recipient #{to_did}" if recipient_kids.empty?

        # Find first sender key with a secret and compatible recipients
        sender_secret = nil
        compatible_recipients = []

        sender_kids.each do |skid|
          secret = resolvers_config.secrets_resolver.get_key(skid)
          next unless secret

          vms = recipient_kids.filter_map do |rkid|
            vm = to_did_doc.get_verification_method(rkid)
            vm if vm && Crypto::KeyUtils.are_keys_compatible?(secret, vm)
          end

          if vms.any?
            sender_secret = secret
            compatible_recipients = vms
            break
          end
        end

        raise SecretNotFoundError, "No sender keyAgreement secret found" unless sender_secret
        raise IncompatibleCryptoError.new if compatible_recipients.empty?

        { sender_secret: sender_secret, recipient_vms: compatible_recipients }
      end

      def self.find_unpack_sender_and_recipient_keys(frm_kid, to_kids, resolvers_config)
        frm_did = DIDUtils.did_from_did_url(frm_kid)
        frm_did_doc = resolvers_config.did_resolver.resolve(frm_did)
        raise DIDDocNotResolvedError.new(frm_did) unless frm_did_doc

        sender_vm = frm_did_doc.get_verification_method(frm_kid)
        raise DIDUrlNotFoundError, "Sender key #{frm_kid} not found" unless sender_vm

        unless frm_did_doc.key_agreement.include?(frm_kid)
          raise DIDUrlNotFoundError, "Sender key #{frm_kid} not in key_agreement"
        end

        secret_ids = resolvers_config.secrets_resolver.get_keys(to_kids)
        raise SecretNotFoundError, "No recipient secrets found" if secret_ids.empty?

        pairs = []
        secret_ids.each do |sid|
          secret = resolvers_config.secrets_resolver.get_key(sid)
          next unless secret
          next unless Crypto::KeyUtils.are_keys_compatible?(secret, sender_vm)

          pairs << { recipient_secret: secret, sender_vm: sender_vm }
        end

        raise IncompatibleCryptoError.new if pairs.empty?

        pairs
      end
    end
  end
end
