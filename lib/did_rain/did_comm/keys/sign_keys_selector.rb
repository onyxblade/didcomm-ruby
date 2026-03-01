# frozen_string_literal: true

module DIDRain
  module DIDComm
    module Keys
      module SignKeysSelector
        def self.find_signing_key(frm_did_or_kid, resolvers_config)
          did, kid = DID::Utils.did_or_url(frm_did_or_kid)

          if kid
            find_signing_key_by_kid(kid, resolvers_config)
          else
            find_signing_key_by_did(did, resolvers_config)
          end
        end

        def self.find_verification_key(kid, resolvers_config)
          did = DID::Utils.did_from_did_url(kid)
          did_doc = resolvers_config.did_resolver.resolve(did)
          raise DID::DocumentNotResolvedError.new(did) unless did_doc

          unless did_doc.authentication.include?(kid)
            raise DID::UrlNotFoundError, "Key ID #{kid} not found in authentication"
          end

          vm = did_doc.get_verification_method(kid)
          raise DID::UrlNotFoundError, "Verification method #{kid} not found" unless vm

          vm
        end

        private_class_method def self.find_signing_key_by_did(did, resolvers_config)
          did_doc = resolvers_config.did_resolver.resolve(did)
          raise DID::DocumentNotResolvedError.new(did) unless did_doc

          auth_kids = did_doc.authentication
          raise DID::UrlNotFoundError, "No authentication keys in DID Doc for #{did}" if auth_kids.empty?

          secret_ids = resolvers_config.secrets_resolver.get_keys(auth_kids)
          raise DID::SecretNotFoundError, "No secret found for authentication keys of #{did}" if secret_ids.empty?

          resolvers_config.secrets_resolver.get_key(secret_ids.first)
        end

        private_class_method def self.find_signing_key_by_kid(kid, resolvers_config)
          did = DID::Utils.did_from_did_url(kid)
          did_doc = resolvers_config.did_resolver.resolve(did)
          raise DID::DocumentNotResolvedError.new(did) unless did_doc

          unless did_doc.authentication.include?(kid)
            raise DID::UrlNotFoundError, "Key ID #{kid} not found in authentication"
          end

          secret = resolvers_config.secrets_resolver.get_key(kid)
          raise DID::SecretNotFoundError, "Secret not found for #{kid}" unless secret
          secret
        end
      end
    end
  end
end
