# frozen_string_literal: true

module DIDRain
  module DID
    class DocumentNotResolvedError < Error
      def initialize(did)
        super("DID `#{did}` is not found in DID resolver")
      end
    end
  end
end
