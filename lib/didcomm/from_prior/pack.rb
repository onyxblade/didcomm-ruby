# frozen_string_literal: true

require "json"
require "base64"

module DIDComm
  module FromPriorModule
    def self.pack_from_prior(message, resolvers_config, issuer_kid: nil)
      from_prior = message["from_prior"]
      return nil if from_prior.nil?
      unless from_prior.is_a?(Hash)
        raise MalformedMessageError.new(:invalid_plaintext, "from_prior plaintext is invalid")
      end

      # Validate
      raise ValueError, "from_prior iss is not a valid DID" unless DIDUtils.is_did(from_prior["iss"])
      raise ValueError, "from_prior sub is not a valid DID" unless DIDUtils.is_did(from_prior["sub"])
      if issuer_kid && DIDUtils.did_from_did_url(issuer_kid) != from_prior["iss"]
        raise ValueError, "issuer_kid does not belong to from_prior iss"
      end
      raise ValueError, "from_prior iss must differ from sub" if from_prior["iss"] == from_prior["sub"]

      if message["from"] && from_prior["sub"] != message["from"]
        raise ValueError, "from_prior sub must equal message from"
      end

      issuer_did_or_kid = issuer_kid || from_prior["iss"]

      secret = Keys::SignKeysSelector.find_signing_key(issuer_did_or_kid, resolvers_config)
      key_info = Crypto::KeyUtils.extract_key(secret)
      alg = Crypto::KeyUtils.extract_sign_alg(secret)

      # Build JWT header
      header = { "alg" => alg, "kid" => secret.kid, "typ" => "JWT" }
      header_b64 = Crypto::KeyUtils.base64url_encode(JSON.generate(header))

      # Build JWT payload
      payload_b64 = Crypto::KeyUtils.base64url_encode(JSON.generate(from_prior))

      # Sign
      signing_input = "#{header_b64}.#{payload_b64}"
      signature = Crypto::JWSEnvelope.compute_signature(signing_input, key_info, alg)
      signature_b64 = Crypto::KeyUtils.base64url_encode(signature)

      jwt = "#{header_b64}.#{payload_b64}.#{signature_b64}"
      message["from_prior"] = jwt

      secret.kid
    end

    def self.unpack_from_prior(message, resolvers_config)
      from_prior_jwt = message["from_prior"]
      return nil unless from_prior_jwt.is_a?(String)

      parts = from_prior_jwt.split(".")
      raise MalformedMessageError.new(:invalid_plaintext, "Invalid from_prior JWT") unless parts.length == 3

      # Extract kid from header
      header = JSON.parse(Crypto::KeyUtils.base64url_decode(parts[0]).force_encoding("UTF-8"))

      # Validate typ
      typ = header["typ"]
      raise MalformedMessageError.new(:invalid_plaintext, "from_prior typ is not JWT") if typ && typ != "JWT"

      issuer_kid = header["kid"]
      raise MalformedMessageError.new(:invalid_plaintext, "Missing kid in from_prior header") unless issuer_kid

      # Validate kid is DID URL with fragment
      raise MalformedMessageError.new(:invalid_plaintext, "from_prior kid is not a valid DID URL") unless DIDUtils.is_did_url(issuer_kid)

      # Verify signature
      vm = Keys::SignKeysSelector.find_verification_key(issuer_kid, resolvers_config)
      key_info = Crypto::KeyUtils.extract_key(vm)
      alg = Crypto::KeyUtils.extract_sign_alg(vm)

      signing_input = "#{parts[0]}.#{parts[1]}"
      signature = Crypto::KeyUtils.base64url_decode(parts[2])

      unless Crypto::JWSEnvelope.verify_signature(signing_input, signature, key_info, alg)
        raise MalformedMessageError.new(:invalid_signature, "from_prior signature verification failed")
      end

      # Decode payload
      payload = JSON.parse(Crypto::KeyUtils.base64url_decode(parts[1]).force_encoding("UTF-8"))
      message["from_prior"] = payload

      issuer_kid
    end
  end
end
