# frozen_string_literal: true

module DIDRain
  module DID
    class SecretsResolverInMemory
      include SecretsResolver

      def initialize(secrets)
        @secrets = {}
        secrets.each { |s| @secrets[s.kid] = s }
      end

      def get_key(kid)
        @secrets[kid]
      end

      def get_keys(kids)
        kids.select { |kid| @secrets.key?(kid) }
      end
    end
  end
end
