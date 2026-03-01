# frozen_string_literal: true

require "json"
require "base64"

module DIDRain
  module DIDComm
    class FromPrior
      attr_accessor :iss, :sub, :aud, :exp, :nbf, :iat, :jti

      def initialize(iss:, sub:, aud: nil, exp: nil, nbf: nil, iat: nil, jti: nil)
        @iss = iss
        @sub = sub
        @aud = aud
        @exp = exp
        @nbf = nbf
        @iat = iat
        @jti = jti
      end

      def to_hash
        d = { "iss" => @iss, "sub" => @sub }
        d["aud"] = @aud if @aud
        d["exp"] = @exp if @exp
        d["nbf"] = @nbf if @nbf
        d["iat"] = @iat if @iat
        d["jti"] = @jti if @jti
        d
      end

      def self.from_hash(d)
        raise MalformedMessageError.new(:invalid_plaintext, "from_prior plaintext is invalid") unless d.is_a?(Hash)
        raise MalformedMessageError.new(:invalid_plaintext, "from_prior missing iss") unless d["iss"]
        raise MalformedMessageError.new(:invalid_plaintext, "from_prior missing sub") unless d["sub"]

        new(
          iss: d["iss"],
          sub: d["sub"],
          aud: d["aud"],
          exp: d["exp"],
          nbf: d["nbf"],
          iat: d["iat"],
          jti: d["jti"]
        )
      end

      def self.pack(message, resolvers_config, issuer_kid: nil)
        from_prior = message["from_prior"]
        return nil if from_prior.nil?
        unless from_prior.is_a?(Hash)
          raise MalformedMessageError.new(:invalid_plaintext, "from_prior plaintext is invalid")
        end

        # Validate — iss and sub must be bare DIDs (no fragment)
        iss = from_prior["iss"]
        sub = from_prior["sub"]
        raise ValueError, "from_prior iss is not a valid DID" unless DID::Utils.is_did(iss)
        raise ValueError, "from_prior iss must be a DID, not a DID URL" if DID::Utils.is_did_url(iss)
        raise ValueError, "from_prior sub is not a valid DID" unless DID::Utils.is_did(sub)
        raise ValueError, "from_prior sub must be a DID, not a DID URL" if DID::Utils.is_did_url(sub)
        if issuer_kid && DID::Utils.did_from_did_url(issuer_kid) != from_prior["iss"]
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

      def self.unpack(message, resolvers_config)
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
        raise MalformedMessageError.new(:invalid_plaintext, "from_prior kid is not a valid DID URL") unless DID::Utils.is_did_url(issuer_kid)

        # Verify signature
        vm = Keys::SignKeysSelector.find_verification_key(issuer_kid, resolvers_config)
        key_info = Crypto::KeyUtils.extract_key(vm)
        alg = Crypto::KeyUtils.extract_sign_alg(vm)

        signing_input = "#{parts[0]}.#{parts[1]}"
        signature = Crypto::KeyUtils.base64url_decode(parts[2])

        unless Crypto::JWSEnvelope.verify_signature(signing_input, signature, key_info, alg)
          raise MalformedMessageError.new(:invalid_signature, "from_prior signature verification failed")
        end

        # Decode payload and validate iss matches kid's DID
        payload = JSON.parse(Crypto::KeyUtils.base64url_decode(parts[1]).force_encoding("UTF-8"))

        iss = payload["iss"]
        kid_did = issuer_kid.split("#").first
        if iss && kid_did != iss
          raise MalformedMessageError.new(:invalid_plaintext,
            "from_prior kid DID (#{kid_did}) does not match iss (#{iss})")
        end

        message["from_prior"] = payload

        issuer_kid
      end
    end
  end
end
