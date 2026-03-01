# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module PackEncrypted
      Result = Data.define(:packed_msg, :to_kids, :from_kid, :sign_from_kid,
                          :from_prior_issuer_kid, :service_metadata)

      Config = Data.define(:enc_alg_auth, :enc_alg_anon, :protect_sender_id, :forward) do
        def initialize(enc_alg_auth: Defaults::DEF_ENC_ALG_AUTH,
                       enc_alg_anon: Defaults::DEF_ENC_ALG_ANON,
                       protect_sender_id: false,
                       forward: true)
          super
        end
      end

      ServiceMetadata = Data.define(:id, :service_endpoint)

      def self.call(message, to:, from: nil, sign_from: nil,
                    resolvers_config:, pack_config: nil)
        pack_config ||= Config.new

        # Validate inputs
        raise ValueError, "'to' is not a valid DID or DID URL" unless DID::Utils.is_did(to)
        if from
          raise ValueError, "'from' is not a valid DID or DID URL" unless DID::Utils.is_did(from)
        end
        if sign_from
          raise ValueError, "'sign_from' is not a valid DID or DID URL" unless DID::Utils.is_did(sign_from)
        end

        msg_hash = message.is_a?(Message) ? message.to_hash : message
        validate_header_consistency!(msg_hash, to, from)

        # Pack from_prior
        from_prior_issuer_kid = FromPrior.pack(msg_hash, resolvers_config)

        # Sign if needed
        sign_from_kid = nil
        if sign_from
          sign_result = Crypto::Sign.pack(msg_hash, sign_from, resolvers_config)
          msg_hash = sign_result[:msg]
          sign_from_kid = sign_result[:sign_frm_kid]
        end

        # Encrypt
        if from
          # Authenticated encryption (ECDH-1PU)
          encrypt_result = Crypto::Authcrypt.pack(
            msg_hash, to, from, pack_config.enc_alg_auth, resolvers_config
          )
        else
          # Anonymous encryption (ECDH-ES)
          encrypt_result = Crypto::Anoncrypt.pack(
            msg_hash, to, pack_config.enc_alg_anon, resolvers_config
          )
        end

        packed_msg_hash = encrypt_result[:msg]
        from_kid = encrypt_result[:from_kid]

        # Protect sender ID if needed (re-encrypt with anoncrypt)
        if from_kid && pack_config.protect_sender_id
          anon_result = Crypto::Anoncrypt.pack(
            packed_msg_hash, to, pack_config.enc_alg_anon, resolvers_config
          )
          packed_msg_hash = anon_result[:msg]
        end

        # Forward wrapping
        service_metadata = nil
        if pack_config.forward
          fwd_result = try_forward_wrap(packed_msg_hash, to, pack_config, resolvers_config)
          if fwd_result
            packed_msg_hash = fwd_result[:msg]
            service_metadata = fwd_result[:service_metadata]
          end
        end

        packed_msg = JSON.generate(packed_msg_hash)

        Result.new(
          packed_msg: packed_msg,
          to_kids: encrypt_result[:to_kids],
          from_kid: from_kid,
          sign_from_kid: sign_from_kid,
          from_prior_issuer_kid: from_prior_issuer_kid,
          service_metadata: service_metadata
        )
      end

      def self.try_forward_wrap(packed_msg_hash, to, pack_config, resolvers_config)
        did, _kid = DID::Utils.did_or_url(to)
        did_doc = resolvers_config.did_resolver.resolve(did)
        return nil unless did_doc

        service = Service.find_in(did_doc)
        return nil unless service

        routing_keys = service.routing_keys
        return nil if routing_keys.nil? || routing_keys.empty?

        fwd_result = Protocols::Routing::Forward.wrap_in_forward(
          packed_msg_hash, to, routing_keys, pack_config.enc_alg_anon, resolvers_config
        )

        {
          msg: fwd_result[:msg],
          service_metadata: ServiceMetadata.new(id: service.id, service_endpoint: service.service_endpoint)
        }
      end
      private_class_method :try_forward_wrap

      def self.validate_header_consistency!(msg_hash, to, from)
        message_to = msg_hash["to"] || msg_hash[:to]
        if !message_to.nil? && !message_to.is_a?(Array)
          raise ValueError, "message 'to' value is not a list: #{message_to}"
        end

        to_did, _to_kid = DID::Utils.did_or_url(to)
        if message_to && !message_to.include?(to_did)
          raise ValueError, "message 'to' value #{message_to} does not contain 'to' DID #{to_did}"
        end

        message_from = msg_hash["from"] || msg_hash[:from]
        if from && message_from
          from_did, _from_kid = DID::Utils.did_or_url(from)
          if from_did != message_from
            raise ValueError, "message 'from' value #{message_from} does not match 'from' DID #{from_did}"
          end
        end
      end
      private_class_method :validate_header_consistency!
    end
  end
end
