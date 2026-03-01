# frozen_string_literal: true

module DIDRain
  module DID
    module SecretsResolver
      def get_key(kid)
        raise NotImplementedError, "#{self.class}#get_key must be implemented"
      end

      def get_keys(kids)
        raise NotImplementedError, "#{self.class}#get_keys must be implemented"
      end
    end
  end
end
