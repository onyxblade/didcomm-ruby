# frozen_string_literal: true

module DIDRain
  module DIDComm
    module Keys
      module ForwardNextKeysSelector
        def self.has_keys_for_forward_next?(next_did_or_kid, resolvers_config)
          did, kid = DID::Utils.did_or_url(next_did_or_kid)

          did_doc = resolvers_config.did_resolver.resolve(did)
          return false unless did_doc

          kids = kid ? [kid] : did_doc.key_agreement
          return false if kids.empty?

          secret_ids = resolvers_config.secrets_resolver.get_keys(kids)
          !secret_ids.empty?
        rescue StandardError
          false
        end
      end
    end
  end
end
