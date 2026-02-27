# frozen_string_literal: true

module DIDComm
  module Keys
    module AnoncryptKeysSelector
      def self.find_pack_recipient_public_keys(to_did_or_kid, resolvers_config)
        did, kid = DIDUtils.did_or_url(to_did_or_kid)

        did_doc = resolvers_config.did_resolver.resolve(did)
        raise DIDDocNotResolvedError.new(did) unless did_doc

        if kid
          unless did_doc.key_agreement.include?(kid)
            raise DIDUrlNotFoundError, "Key #{kid} not in keyAgreement"
          end
          vm = did_doc.get_verification_method(kid)
          raise DIDUrlNotFoundError, "Verification method #{kid} not found" unless vm
          [vm]
        else
          ka_kids = did_doc.key_agreement
          raise DIDUrlNotFoundError, "No keyAgreement keys in DID Doc for #{did}" if ka_kids.empty?

          first_vm = did_doc.get_verification_method(ka_kids.first)
          raise DIDUrlNotFoundError, "Verification method #{ka_kids.first} not found" unless first_vm
          ka_kids.filter_map do |ka_kid|
            vm = did_doc.get_verification_method(ka_kid)
            vm if vm && Crypto::KeyUtils.are_keys_compatible?(first_vm, vm)
          end
        end
      end

      def self.find_unpack_recipient_private_keys(to_kids, resolvers_config)
        secret_ids = resolvers_config.secrets_resolver.get_keys(to_kids)
        raise SecretNotFoundError, "No secrets found for recipient keys" if secret_ids.empty?

        secret_ids.filter_map { |sid| resolvers_config.secrets_resolver.get_key(sid) }
      end
    end
  end
end
