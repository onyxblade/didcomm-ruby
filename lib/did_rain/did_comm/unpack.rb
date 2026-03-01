# frozen_string_literal: true

require "json"

module DIDRain
  module DIDComm
    module Unpack
      Result = Struct.new(:message, :metadata, keyword_init: true)

      Config = Struct.new(:expect_decrypt_by_all_keys, :unwrap_re_wrapping_forward, keyword_init: true) do
        def initialize(expect_decrypt_by_all_keys: false, unwrap_re_wrapping_forward: true)
          super
        end
      end

      class Metadata
        attr_accessor :encrypted, :authenticated, :non_repudiation, :anonymous_sender,
                      :re_wrapped_in_forward, :encrypted_from, :encrypted_to,
                      :sign_from, :from_prior_issuer_kid, :enc_alg_auth, :enc_alg_anon,
                      :sign_alg, :signed_message, :from_prior_jwt

        def initialize
          @encrypted = false
          @authenticated = false
          @non_repudiation = false
          @anonymous_sender = false
          @re_wrapped_in_forward = false
        end
      end

      def self.call(packed_msg, resolvers_config:, config: nil)
        config ||= Config.new

        msg_hash = if packed_msg.is_a?(String)
                     JSON.parse(packed_msg)
                   elsif packed_msg.is_a?(Hash)
                     packed_msg
                   else
                     raise ValueError, "unexpected type of packed_message: '#{packed_msg.class}'"
                   end

        metadata = Metadata.new

        do_unpack(resolvers_config, msg_hash, config, metadata)
      end

      def self.do_unpack(resolvers_config, msg_hash, config, metadata)
        if Crypto::JWEEnvelope.anoncrypted?(msg_hash)
          result = Crypto::Anoncrypt.unpack(msg_hash, resolvers_config,
                                            decrypt_by_all_keys: config.expect_decrypt_by_all_keys)
          msg_hash = JSON.parse(result[:msg])

          metadata.encrypted = true
          metadata.anonymous_sender = true
          metadata.encrypted_to = result[:to_kids]
          metadata.enc_alg_anon = result[:alg]

          if config.unwrap_re_wrapping_forward && Protocols::Routing::Forward.forward?(msg_hash)
            fwd = Protocols::Routing::Forward.parse(msg_hash)
            if Keys::ForwardNextKeysSelector.has_keys_for_forward_next?(fwd[:next], resolvers_config)
              metadata.re_wrapped_in_forward = true
              return do_unpack(resolvers_config, fwd[:forwarded_msg], config, metadata)
            end
          end
        end

        if Crypto::JWEEnvelope.authcrypted?(msg_hash)
          result = Crypto::Authcrypt.unpack(msg_hash, resolvers_config,
                                            decrypt_by_all_keys: config.expect_decrypt_by_all_keys)
          msg_hash = JSON.parse(result[:msg])

          metadata.encrypted = true
          metadata.authenticated = true
          metadata.encrypted_from = result[:frm_kid]
          metadata.encrypted_to = result[:to_kids]
          metadata.enc_alg_auth = result[:alg]
        end

        if Crypto::JWSEnvelope.signed?(msg_hash)
          result = Crypto::Sign.unpack(msg_hash, resolvers_config)
          metadata.signed_message = JSON.generate(msg_hash)
          msg_hash = JSON.parse(result[:msg])

          metadata.non_repudiation = true
          metadata.authenticated = true
          metadata.sign_from = result[:sign_frm_kid]
          metadata.sign_alg = result[:alg]
        end

        if msg_hash["from_prior"].is_a?(String)
          metadata.from_prior_jwt = msg_hash["from_prior"]
          from_prior_result = FromPrior.unpack(msg_hash, resolvers_config)
          metadata.from_prior_issuer_kid = from_prior_result
        end

        verify_message_consistency(msg_hash, metadata)

        message = Message.from_hash(msg_hash)

        Result.new(message: message, metadata: metadata)
      end
      private_class_method :do_unpack

      def self.verify_message_consistency(msg_hash, metadata)
        msg_from = msg_hash["from"]
        msg_to = msg_hash["to"]

        # authcrypt from consistency
        if metadata.encrypted_from && msg_from
          encrypted_from_did = metadata.encrypted_from.split("#").first
          msg_from_did = msg_from.split("#").first
          unless encrypted_from_did == msg_from_did
            raise MalformedMessageError.new(:invalid_message,
              "Mismatch between encrypted_from DID (#{encrypted_from_did}) and message from DID (#{msg_from_did})")
          end
        end

        # encrypted_to consistency
        if metadata.encrypted_to && msg_to.is_a?(Array)
          metadata.encrypted_to.each do |kid|
            kid_did = kid.split("#").first
            unless msg_to.include?(kid_did)
              raise MalformedMessageError.new(:invalid_message,
                "encrypted_to kid DID (#{kid_did}) not found in message to list")
            end
          end
        end

        # sign_from consistency
        if metadata.sign_from && msg_from
          sign_from_did = metadata.sign_from.split("#").first
          msg_from_did = msg_from.split("#").first
          unless sign_from_did == msg_from_did
            raise MalformedMessageError.new(:invalid_message,
              "Mismatch between sign_from DID (#{sign_from_did}) and message from DID (#{msg_from_did})")
          end
        end
      end
      private_class_method :verify_message_consistency
    end
  end
end
