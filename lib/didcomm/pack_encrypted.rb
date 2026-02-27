# frozen_string_literal: true

require "json"

module DIDComm
  PackEncryptedResult = Struct.new(:packed_msg, :to_kids, :from_kid, :sign_from_kid,
                                   :from_prior_issuer_kid, :service_metadata, keyword_init: true)

  PackEncryptedConfig = Struct.new(:enc_alg_auth, :enc_alg_anon, :protect_sender_id, :forward, keyword_init: true) do
    def initialize(enc_alg_auth: Defaults::DEF_ENC_ALG_AUTH,
                   enc_alg_anon: Defaults::DEF_ENC_ALG_ANON,
                   protect_sender_id: false,
                   forward: true)
      super
    end
  end

  ServiceMetadata = Struct.new(:id, :service_endpoint, keyword_init: true)

  def self.pack_encrypted(message, to:, from: nil, sign_from: nil,
                           resolvers_config:, pack_config: nil)
    pack_config ||= PackEncryptedConfig.new

    # Validate inputs
    raise ValueError, "'to' is not a valid DID or DID URL" unless DIDUtils.is_did(to)
    if from
      raise ValueError, "'from' is not a valid DID or DID URL" unless DIDUtils.is_did(from)
    end
    if sign_from
      raise ValueError, "'sign_from' is not a valid DID or DID URL" unless DIDUtils.is_did(sign_from)
    end

    msg_hash = message.is_a?(Message) ? message.to_hash : message

    # Pack from_prior
    from_prior_issuer_kid = FromPriorModule.pack_from_prior(msg_hash, resolvers_config)

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

    PackEncryptedResult.new(
      packed_msg: packed_msg,
      to_kids: encrypt_result[:to_kids],
      from_kid: from_kid,
      sign_from_kid: sign_from_kid,
      from_prior_issuer_kid: from_prior_issuer_kid,
      service_metadata: service_metadata
    )
  end

  private_class_method def self.try_forward_wrap(packed_msg_hash, to, pack_config, resolvers_config)
    did, _kid = DIDUtils.did_or_url(to)
    did_doc = resolvers_config.did_resolver.resolve(did)
    return nil unless did_doc

    service = did_doc.get_didcomm_service
    return nil unless service

    routing_keys = service.routing_keys
    return nil if routing_keys.nil? || routing_keys.empty?

    Protocols::Routing::Forward.wrap_in_forward(
      packed_msg_hash, to, routing_keys, pack_config.enc_alg_anon, resolvers_config
    )
  rescue StandardError
    nil
  end
end
