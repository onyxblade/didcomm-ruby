# frozen_string_literal: true

module DIDRain
  module DID
    class Secret
      attr_accessor :kid, :type, :verification_material

      def initialize(kid:, type:, verification_material:)
        @kid = kid
        @type = type
        @verification_material = verification_material
      end
    end
  end
end
