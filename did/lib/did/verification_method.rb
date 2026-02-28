# frozen_string_literal: true

module DID
  class VerificationMethod
    attr_accessor :id, :type, :controller, :verification_material

    def initialize(id:, type:, controller:, verification_material:)
      @id = id
      @type = type
      @controller = controller
      @verification_material = verification_material
    end
  end
end
