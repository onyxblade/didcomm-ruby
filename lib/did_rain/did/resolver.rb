# frozen_string_literal: true

module DIDRain
  module DID
    module Resolver
      def resolve(did)
        raise NotImplementedError, "#{self.class}#resolve must be implemented"
      end
    end
  end
end
