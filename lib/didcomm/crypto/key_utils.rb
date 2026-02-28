# frozen_string_literal: true

require "base64"
require "json"
require "openssl"

module DIDComm
  module Crypto
    module KeyUtils
      # Extract a crypto key object from a VerificationMethod or Secret
      # Returns a hash with :key (the crypto object), :type (:okp or :ec), :crv, :kid
      def self.extract_key(method_or_secret)
        vm = method_or_secret
        material = vm.verification_material
        kid = vm.respond_to?(:kid) ? vm.kid : vm.id

        case material.format
        when VerificationMaterialFormat::JWK
          jwk = material.value.is_a?(String) ? JSON.parse(material.value) : material.value
          import_jwk(jwk, kid)
        when VerificationMaterialFormat::BASE58
          import_base58(vm, kid)
        when VerificationMaterialFormat::MULTIBASE
          import_multibase(vm, kid)
        else
          raise UnsupportedError, "Unsupported verification material format: #{material.format}"
        end
      end

      def self.extract_sign_alg(method_or_secret)
        vm = method_or_secret
        material = vm.verification_material
        type = vm.type

        case type
        when VerificationMethodType::JSON_WEB_KEY_2020
          jwk = material.value.is_a?(String) ? JSON.parse(material.value) : material.value
          case jwk["kty"]
          when "OKP"
            case jwk["crv"]
            when "Ed25519" then SignAlg::ED25519
            else raise UnsupportedError, "Unsupported OKP curve: #{jwk["crv"]}"
            end
          when "EC"
            case jwk["crv"]
            when "P-256" then SignAlg::ES256
            when "secp256k1" then SignAlg::ES256K
            else raise UnsupportedError, "Unsupported EC curve: #{jwk["crv"]}"
            end
          else
            raise UnsupportedError, "Unsupported key type: #{jwk["kty"]}"
          end
        when VerificationMethodType::ED25519_VERIFICATION_KEY_2018,
             VerificationMethodType::ED25519_VERIFICATION_KEY_2020
          SignAlg::ED25519
        else
          raise UnsupportedError, "Cannot determine sign algorithm for type: #{type}"
        end
      end

      def self.are_keys_compatible?(key1, key2)
        crv1 = key_curve(key1)
        crv2 = key_curve(key2)
        crv1 && crv2 && crv1 == crv2
      end

      def self.key_curve(method_or_secret)
        vm = method_or_secret
        material = vm.verification_material
        type = vm.type

        case type
        when VerificationMethodType::JSON_WEB_KEY_2020
          jwk = material.value.is_a?(String) ? JSON.parse(material.value) : material.value
          jwk["crv"]
        when VerificationMethodType::X25519_KEY_AGREEMENT_KEY_2019,
             VerificationMethodType::X25519_KEY_AGREEMENT_KEY_2020
          "X25519"
        when VerificationMethodType::ED25519_VERIFICATION_KEY_2018,
             VerificationMethodType::ED25519_VERIFICATION_KEY_2020
          "Ed25519"
        else
          nil
        end
      end

      # Import JWK to internal key representation
      def self.import_jwk(jwk, kid = nil)
        kty = jwk["kty"]
        crv = jwk["crv"]

        case kty
        when "OKP"
          import_okp_jwk(jwk, kid)
        when "EC"
          import_ec_jwk(jwk, kid)
        else
          raise UnsupportedError, "Unsupported JWK kty: #{kty}"
        end
      end

      def self.import_okp_jwk(jwk, kid = nil)
        crv = jwk["crv"]
        x_bytes = base64url_decode(jwk["x"])
        d_bytes = jwk["d"] ? base64url_decode(jwk["d"]) : nil

        case crv
        when "X25519"
          {
            type: :okp, crv: "X25519", kid: kid,
            public_bytes: x_bytes, private_bytes: d_bytes,
            jwk: jwk
          }
        when "Ed25519"
          {
            type: :okp, crv: "Ed25519", kid: kid,
            public_bytes: x_bytes, private_bytes: d_bytes,
            jwk: jwk
          }
        else
          raise UnsupportedError, "Unsupported OKP curve: #{crv}"
        end
      end

      def self.import_ec_jwk(jwk, kid = nil)
        crv = jwk["crv"]
        has_private = jwk.key?("d")

        ec_key = build_ec_key(jwk)

        {
          type: :ec, crv: crv, kid: kid,
          ec_key: ec_key, has_private: has_private,
          jwk: jwk
        }
      end

      def self.build_ec_key(jwk)
        crv = jwk["crv"]
        curve_name = case crv
                     when "P-256" then "prime256v1"
                     when "P-384" then "secp384r1"
                     when "P-521" then "secp521r1"
                     when "secp256k1" then "secp256k1"
                     else raise UnsupportedError, "Unsupported EC curve: #{crv}"
                     end

        group = OpenSSL::PKey::EC::Group.new(curve_name)

        x_bytes = base64url_decode(jwk["x"])
        y_bytes = base64url_decode(jwk["y"])

        # Build the public key point (uncompressed: 0x04 || x || y)
        pub_point_hex = "04" + x_bytes.unpack1("H*") + y_bytes.unpack1("H*")
        point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(pub_point_hex, 16))

        if jwk["d"]
          d_bytes = base64url_decode(jwk["d"])
          d_bn = OpenSSL::BN.new(d_bytes.unpack1("H*"), 16)

          # Build private key using ASN1
          asn1 = OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Integer.new(1),
            OpenSSL::ASN1::OctetString.new(d_bytes),
            OpenSSL::ASN1::ObjectId.new(curve_name, 0, :EXPLICIT),
            OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed), 1, :EXPLICIT)
          ])
          OpenSSL::PKey::EC.new(asn1.to_der)
        else
          # Build public key only
          asn1 = OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
              OpenSSL::ASN1::ObjectId.new(curve_name)
            ]),
            OpenSSL::ASN1::BitString.new(point.to_octet_string(:uncompressed))
          ])
          OpenSSL::PKey::EC.new(asn1.to_der)
        end
      end

      def self.import_base58(method_or_secret, kid)
        require "base58"
        material = method_or_secret.verification_material
        type = method_or_secret.type

        raw_value = Base58.base58_to_binary(material.value, :bitcoin)

        crv = case type
              when VerificationMethodType::X25519_KEY_AGREEMENT_KEY_2019 then "X25519"
              when VerificationMethodType::ED25519_VERIFICATION_KEY_2018 then "Ed25519"
              else raise UnsupportedError, "Unsupported type for Base58: #{type}"
              end

        if method_or_secret.is_a?(Secret)
          if crv == "X25519" && raw_value.bytesize == 32
            # X25519: private key only, derive public
            require "rbnacl"
            d_bytes = raw_value
            priv = RbNaCl::PrivateKey.new(d_bytes)
            x_bytes = priv.public_key.to_bytes
          else
            # Ed25519 or 64-byte format: d || x
            d_bytes = raw_value[0, 32]
            x_bytes = raw_value[32, 32]
          end
          {
            type: :okp, crv: crv, kid: kid,
            public_bytes: x_bytes, private_bytes: d_bytes,
            jwk: {
              "kty" => "OKP", "crv" => crv,
              "x" => base64url_encode(x_bytes),
              "d" => base64url_encode(d_bytes)
            }
          }
        else
          {
            type: :okp, crv: crv, kid: kid,
            public_bytes: raw_value, private_bytes: nil,
            jwk: {
              "kty" => "OKP", "crv" => crv,
              "x" => base64url_encode(raw_value)
            }
          }
        end
      end

      def self.import_multibase(method_or_secret, kid)
        require "base58"
        material = method_or_secret.verification_material
        type = method_or_secret.type

        value = material.value
        raise UnsupportedError, "Only base58btc multibase (z prefix) is supported" unless value.start_with?("z")

        raw_prefixed = Base58.base58_to_binary(value[1..], :bitcoin)
        codec, raw_value = Multicodec.decode(raw_prefixed)

        crv = case type
              when VerificationMethodType::X25519_KEY_AGREEMENT_KEY_2020 then "X25519"
              when VerificationMethodType::ED25519_VERIFICATION_KEY_2020 then "Ed25519"
              else raise UnsupportedError, "Unsupported type for Multibase: #{type}"
              end

        if method_or_secret.is_a?(Secret)
          if crv == "X25519" && raw_value.bytesize == 32
            # X25519: private key only, derive public
            require "rbnacl"
            d_bytes = raw_value
            priv = RbNaCl::PrivateKey.new(d_bytes)
            x_bytes = priv.public_key.to_bytes
          else
            # Ed25519 or 64-byte format: d || x
            d_bytes = raw_value[0, 32]
            x_bytes = raw_value[32, 32]
          end
          {
            type: :okp, crv: crv, kid: kid,
            public_bytes: x_bytes, private_bytes: d_bytes,
            jwk: {
              "kty" => "OKP", "crv" => crv,
              "x" => base64url_encode(x_bytes),
              "d" => base64url_encode(d_bytes)
            }
          }
        else
          {
            type: :okp, crv: crv, kid: kid,
            public_bytes: raw_value, private_bytes: nil,
            jwk: {
              "kty" => "OKP", "crv" => crv,
              "x" => base64url_encode(raw_value)
            }
          }
        end
      end

      def self.base64url_encode(data)
        Base64.urlsafe_encode64(data, padding: false)
      end

      def self.base64url_decode(str)
        # Add padding if needed
        padded = str + "=" * ((4 - str.length % 4) % 4)
        Base64.urlsafe_decode64(padded)
      end

      def self.calculate_apv(kids)
        sorted = kids.sort.join(".")
        digest = OpenSSL::Digest::SHA256.digest(sorted)
        base64url_encode(digest)
      end
    end
  end
end
