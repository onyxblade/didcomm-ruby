# frozen_string_literal: true

module DIDRain
  module DID
    class IncompatibleCryptoError < Error
      def initialize(msg = nil)
        super(msg || "Sender and recipient keys corresponding to provided parameters are incompatible to each other")
      end
    end
  end
end
