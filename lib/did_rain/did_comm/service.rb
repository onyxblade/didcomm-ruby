# frozen_string_literal: true

module DIDRain
  module DIDComm
    class Service
      attr_accessor :id, :type, :service_endpoint, :routing_keys, :accept

      def initialize(id:, type: "DIDCommMessaging", service_endpoint:, routing_keys: [], accept: [])
        @id = id
        @type = type
        @service_endpoint = service_endpoint
        @routing_keys = routing_keys || []
        @accept = accept || []
      end

      def self.find_in(document, service_id = nil)
        if service_id
          document.service.find { |s| s.id == service_id }
        else
          document.service.find { |s| s.type == "DIDCommMessaging" && (s.accept.empty? || s.accept.include?("didcomm/v2")) }
        end
      end
    end
  end
end
