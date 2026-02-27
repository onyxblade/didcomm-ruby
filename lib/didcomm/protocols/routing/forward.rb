# frozen_string_literal: true

require "json"
require "securerandom"

module DIDComm
  module Protocols
    module Routing
      module Forward
        FORWARD_TYPE = "https://didcomm.org/routing/2.0/forward"

        def self.forward?(msg)
          msg.is_a?(Hash) && msg["type"] == FORWARD_TYPE
        end

        def self.parse(msg)
          body = msg["body"]
          raise MalformedMessageError.new(:not_supported_fwd_protocol, "Missing body") unless body
          raise MalformedMessageError.new(:not_supported_fwd_protocol, "Missing next in body") unless body["next"]

          attachments = msg["attachments"]
          raise MalformedMessageError.new(:not_supported_fwd_protocol, "Missing attachments") unless attachments&.any?

          forwarded_msg = attachments[0]
          data = forwarded_msg["data"]
          raise MalformedMessageError.new(:not_supported_fwd_protocol, "Missing data in attachment") unless data

          forwarded = data["json"]
          raise MalformedMessageError.new(:not_supported_fwd_protocol, "Missing json in attachment data") unless forwarded

          { next: body["next"], forwarded_msg: forwarded }
        end

        def self.wrap_in_forward(packed_msg, to, routing_keys, enc_alg_anon, resolvers_config)
          # Build pairs: (encrypt_to, forward_next) by reversing
          tos = routing_keys.reverse
          nexts = (routing_keys[1..] + [to]).reverse

          current_msg = packed_msg
          tos.zip(nexts).each do |encrypt_to, forward_next|
            forward_msg = build_forward(forward_next, current_msg)
            encrypt_result = Crypto::Anoncrypt.pack(
              forward_msg, encrypt_to, enc_alg_anon, resolvers_config
            )
            current_msg = encrypt_result[:msg]
          end

          # Resolve service metadata for the first routing key's DID
          did, _kid = DIDUtils.did_or_url(routing_keys.first)
          did_doc = resolvers_config.did_resolver.resolve(did)
          service = did_doc&.get_didcomm_service

          service_metadata = if service
                               ServiceMetadata.new(id: service.id, service_endpoint: service.service_endpoint)
                             end

          { msg: current_msg, service_metadata: service_metadata }
        end

        def self.build_forward(next_target, inner_msg)
          {
            "id" => SecureRandom.uuid,
            "type" => FORWARD_TYPE,
            "body" => { "next" => next_target },
            "attachments" => [
              {
                "id" => SecureRandom.uuid,
                "data" => { "json" => inner_msg }
              }
            ]
          }
        end
      end
    end
  end
end
