# frozen_string_literal: true

module DIDComm
  class VerificationMethod
    attr_accessor :id, :type, :controller, :verification_material

    def initialize(id:, type:, controller:, verification_material:)
      @id = id
      @type = type
      @controller = controller
      @verification_material = verification_material
    end
  end

  class DIDCommService
    attr_accessor :id, :type, :service_endpoint, :routing_keys, :accept

    def initialize(id:, type: "DIDCommMessaging", service_endpoint:, routing_keys: [], accept: [])
      @id = id
      @type = type
      @service_endpoint = service_endpoint
      @routing_keys = routing_keys || []
      @accept = accept || []
    end
  end

  class DIDDoc
    attr_accessor :id, :authentication, :key_agreement, :verification_method, :service

    def initialize(id:, authentication: [], key_agreement: [], verification_method: [], service: [])
      @id = id
      @authentication = authentication || []
      @key_agreement = key_agreement || []
      @verification_method = verification_method || []
      @service = service || []
    end

    def get_verification_method(kid)
      @verification_method.find { |vm| vm.id == kid }
    end

    def get_didcomm_service(service_id = nil)
      if service_id
        @service.find { |s| s.id == service_id }
      else
        @service.find { |s| s.type == "DIDCommMessaging" && (s.accept.empty? || s.accept.include?("didcomm/v2")) }
      end
    end

    def authentication_methods
      @verification_method.select { |vm| @authentication.include?(vm.id) }
    end

    def key_agreement_methods
      @verification_method.select { |vm| @key_agreement.include?(vm.id) }
    end
  end
end
