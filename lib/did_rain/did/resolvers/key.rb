# frozen_string_literal: true

require "base58"
require "base64"
require "rbnacl"

module DIDRain
  module DID
    module Resolvers
      class Key
        include DID::Resolver

        MULTICODEC_ED25519 = 0xED
        MULTICODEC_X25519 = 0xEC

        def resolve(did)
          return nil unless did.start_with?("did:key:")

          multibase_value = extract_multibase(did)
          raise InvalidDocumentError, "Only base58btc multibase (z prefix) is supported" unless multibase_value.start_with?("z")

          raw = begin
            Base58.base58_to_binary(multibase_value[1..], :bitcoin)
          rescue ArgumentError => e
            raise InvalidDocumentError, "Invalid base58btc encoding: #{e.message}"
          end
          raise InvalidDocumentError, "Multibase value too short" if raw.bytesize < 3

          codec, key_bytes = decode_varint(raw)

          case codec
          when MULTICODEC_ED25519
            raise InvalidDocumentError, "Ed25519 key must be 32 bytes, got #{key_bytes.bytesize}" unless key_bytes.bytesize == 32
            build_ed25519_document(did, multibase_value, key_bytes)
          when MULTICODEC_X25519
            raise InvalidDocumentError, "X25519 key must be 32 bytes, got #{key_bytes.bytesize}" unless key_bytes.bytesize == 32
            build_x25519_document(did, multibase_value, key_bytes)
          else
            raise InvalidDocumentError, "Unsupported multicodec: 0x#{codec.to_s(16)}"
          end
        end

        private

        # Parse did:key:<mb-value> or did:key:<version>:<mb-value>
        # Per spec, if only 3 components exist version defaults to "1".
        def extract_multibase(did)
          parts = did.split(":")
          case parts.length
          when 3 # did:key:<mb-value>
            parts[2]
          when 4 # did:key:<version>:<mb-value>
            raise InvalidDocumentError, "Unsupported did:key version: #{parts[2]}" unless parts[2] == "1"
            parts[3]
          else
            raise InvalidDocumentError, "Malformed did:key identifier"
          end
        end

        def decode_varint(bytes)
          if bytes[0].ord < 0x80
            code = bytes[0].ord
            data = bytes[1..]
          else
            code = (bytes[0].ord & 0x7F) | (bytes[1].ord << 7)
            data = bytes[2..]
          end
          [code, data]
        end

        def build_ed25519_document(did, multibase_value, ed_bytes)
          ed_kid = "#{did}##{multibase_value}"

          # Derive X25519 public key from Ed25519 public key
          verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(ed_bytes)
          x25519_bytes = verify_key.to_curve25519_public_key.to_bytes

          x_multibase = "z" + Base58.binary_to_base58("\xEC\x01".b + x25519_bytes, :bitcoin)
          x_kid = "#{did}##{x_multibase}"

          ed_jwk = {
            "kty" => "OKP",
            "crv" => "Ed25519",
            "x" => Base64.urlsafe_encode64(ed_bytes, padding: false)
          }

          x_jwk = {
            "kty" => "OKP",
            "crv" => "X25519",
            "x" => Base64.urlsafe_encode64(x25519_bytes, padding: false)
          }

          Document.new(
            id: did,
            authentication: [ed_kid],
            assertion_method: [ed_kid],
            capability_invocation: [ed_kid],
            capability_delegation: [ed_kid],
            key_agreement: [x_kid],
            verification_method: [
              VerificationMethod.new(
                id: ed_kid,
                type: VerificationMethodType::JSON_WEB_KEY_2020,
                controller: did,
                verification_material: VerificationMaterial.new(
                  format: VerificationMaterialFormat::JWK,
                  value: ed_jwk
                )
              ),
              VerificationMethod.new(
                id: x_kid,
                type: VerificationMethodType::JSON_WEB_KEY_2020,
                controller: did,
                verification_material: VerificationMaterial.new(
                  format: VerificationMaterialFormat::JWK,
                  value: x_jwk
                )
              )
            ]
          )
        end

        def build_x25519_document(did, multibase_value, x_bytes)
          x_kid = "#{did}##{multibase_value}"

          x_jwk = {
            "kty" => "OKP",
            "crv" => "X25519",
            "x" => Base64.urlsafe_encode64(x_bytes, padding: false)
          }

          Document.new(
            id: did,
            authentication: [],
            key_agreement: [x_kid],
            verification_method: [
              VerificationMethod.new(
                id: x_kid,
                type: VerificationMethodType::JSON_WEB_KEY_2020,
                controller: did,
                verification_material: VerificationMaterial.new(
                  format: VerificationMaterialFormat::JWK,
                  value: x_jwk
                )
              )
            ]
          )
        end
      end
    end
  end
end
