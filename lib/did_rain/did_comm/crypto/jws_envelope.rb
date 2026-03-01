# frozen_string_literal: true

require "json"
require "base64"

module DIDRain
  module DIDComm
    module Crypto
      module JWSEnvelope
        # Check if a message is in JWS format
        def self.signed?(msg)
          msg.is_a?(Hash) && msg.key?("payload") && msg.key?("signatures")
        end

        # Create a JWS in General JSON Serialization
        # Returns a Hash with payload, signatures
        def self.sign(payload_bytes, key_info, kid, alg)
          protected_header = {
            "typ" => MessageTypes::SIGNED,
            "alg" => alg
          }

          protected_b64 = KeyUtils.base64url_encode(JSON.generate(protected_header))
          payload_b64 = KeyUtils.base64url_encode(payload_bytes)

          signing_input = "#{protected_b64}.#{payload_b64}"
          signature = compute_signature(signing_input, key_info, alg)
          signature_b64 = KeyUtils.base64url_encode(signature)

          {
            "payload" => payload_b64,
            "signatures" => [
              {
                "protected" => protected_b64,
                "header" => { "kid" => kid },
                "signature" => signature_b64
              }
            ]
          }
        end

        # Verify a JWS and return the payload bytes
        def self.verify(jws, key_info, alg)
          sig_entry = jws["signatures"][0]
          protected_b64 = sig_entry["protected"]
          payload_b64 = jws["payload"]
          signature_b64 = sig_entry["signature"]

          signing_input = "#{protected_b64}.#{payload_b64}"
          signature = KeyUtils.base64url_decode(signature_b64)

          unless verify_signature(signing_input, signature, key_info, alg)
            raise MalformedMessageError.new(:invalid_signature)
          end

          KeyUtils.base64url_decode(payload_b64)
        end

        def self.compute_signature(signing_input, key_info, alg)
          case alg
          when SignAlg::ED25519
            require "rbnacl"
            signing_key = RbNaCl::Signatures::Ed25519::SigningKey.new(key_info[:private_bytes])
            signing_key.sign(signing_input.encode("UTF-8"))
          when SignAlg::ES256
            digest = OpenSSL::Digest::SHA256.new
            der_sig = key_info[:ec_key].sign(digest, signing_input.encode("UTF-8"))
            der_to_raw_ecdsa(der_sig, 32)
          when SignAlg::ES256K
            digest = OpenSSL::Digest::SHA256.new
            der_sig = key_info[:ec_key].sign(digest, signing_input.encode("UTF-8"))
            der_to_raw_ecdsa(der_sig, 32)
          else
            raise UnsupportedError, "Unsupported sign algorithm: #{alg}"
          end
        end

        def self.verify_signature(signing_input, signature, key_info, alg)
          case alg
          when SignAlg::ED25519
            require "rbnacl"
            verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(key_info[:public_bytes])
            begin
              verify_key.verify(signature, signing_input.encode("UTF-8"))
              true
            rescue RbNaCl::BadSignatureError
              false
            end
          when SignAlg::ES256
            digest = OpenSSL::Digest::SHA256.new
            der_sig = raw_to_der_ecdsa(signature, 32)
            key_info[:ec_key].verify(digest, der_sig, signing_input.encode("UTF-8"))
          when SignAlg::ES256K
            digest = OpenSSL::Digest::SHA256.new
            der_sig = raw_to_der_ecdsa(signature, 32)
            key_info[:ec_key].verify(digest, der_sig, signing_input.encode("UTF-8"))
          else
            raise UnsupportedError, "Unsupported sign algorithm: #{alg}"
          end
        rescue => e
          return false if e.is_a?(OpenSSL::PKey::PKeyError)
          raise
        end

        # Convert DER-encoded ECDSA signature to raw (r || s)
        def self.der_to_raw_ecdsa(der_sig, component_size)
          asn1 = OpenSSL::ASN1.decode(der_sig)
          r = asn1.value[0].value.to_s(2)
          s = asn1.value[1].value.to_s(2)
          r = r.rjust(component_size, "\x00")[-component_size, component_size]
          s = s.rjust(component_size, "\x00")[-component_size, component_size]
          r + s
        end

        # Convert raw (r || s) to DER-encoded ECDSA signature
        def self.raw_to_der_ecdsa(raw_sig, component_size)
          r_bytes = raw_sig[0, component_size]
          s_bytes = raw_sig[component_size, component_size]
          r = OpenSSL::BN.new(r_bytes, 2)
          s = OpenSSL::BN.new(s_bytes, 2)
          OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Integer.new(r),
            OpenSSL::ASN1::Integer.new(s)
          ]).to_der
        end
      end
    end
  end
end
