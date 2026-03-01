# frozen_string_literal: true

require "securerandom"

module DIDComm
  module Crypto
    module ECDH
      # Generate an ephemeral key pair matching the recipient's key type
      def self.generate_ephemeral(recipient_key_info)
        case recipient_key_info[:crv]
        when "X25519"
          generate_x25519_ephemeral
        when "P-256"
          generate_ec_ephemeral("prime256v1")
        when "P-384"
          generate_ec_ephemeral("secp384r1")
        when "P-521"
          generate_ec_ephemeral("secp521r1")
        when "secp256k1"
          generate_ec_ephemeral("secp256k1")
        else
          raise UnsupportedError, "Unsupported curve for ECDH: #{recipient_key_info[:crv]}"
        end
      end

      # Perform ECDH key agreement
      def self.compute_shared_secret(private_key_info, public_key_info)
        case private_key_info[:crv]
        when "X25519"
          compute_x25519(private_key_info, public_key_info)
        when "P-256", "P-384", "P-521", "secp256k1"
          compute_ec(private_key_info, public_key_info)
        else
          raise UnsupportedError, "Unsupported curve for ECDH: #{private_key_info[:crv]}"
        end
      end

      # ECDH-ES key derivation: derive KEK from ephemeral + recipient
      def self.derive_key_es(ephemeral_private, recipient_public, algorithm, apu_bytes, apv_bytes, key_len)
        z = compute_shared_secret(ephemeral_private, recipient_public)
        ConcatKDF.derive(z, key_len, algorithm, apu_bytes, apv_bytes)
      end

      # ECDH-1PU key derivation: Z = Ze || Zs
      def self.derive_key_1pu(ephemeral_private, sender_static_private, recipient_public, algorithm, apu_bytes, apv_bytes, key_len, tag: "")
        ze = compute_shared_secret(ephemeral_private, recipient_public)
        zs = compute_shared_secret(sender_static_private, recipient_public)
        z = ze + zs
        ConcatKDF.derive(z, key_len, algorithm, apu_bytes, apv_bytes, tag: tag)
      end

      # Ephemeral key info to JWK (public part only, for epk header)
      def self.ephemeral_to_jwk(ephemeral)
        case ephemeral[:crv]
        when "X25519"
          {
            "kty" => "OKP",
            "crv" => "X25519",
            "x" => KeyUtils.base64url_encode(ephemeral[:public_bytes])
          }
        when "P-256", "P-384", "P-521", "secp256k1"
          ec_key = ephemeral[:ec_key]
          pub_point = ec_key.public_key
          pub_bn = pub_point.to_bn
          pub_bytes = pub_bn.to_s(2)

          # Uncompressed point: 0x04 || x || y
          coord_len = (pub_bytes.bytesize - 1) / 2
          x_bytes = pub_bytes[1, coord_len]
          y_bytes = pub_bytes[1 + coord_len, coord_len]

          {
            "kty" => "EC",
            "crv" => ephemeral[:crv],
            "x" => KeyUtils.base64url_encode(x_bytes),
            "y" => KeyUtils.base64url_encode(y_bytes)
          }
        end
      end

      # Import an ephemeral public key from JWK (for decryption)
      def self.import_epk(epk_jwk)
        KeyUtils.import_jwk(epk_jwk)
      end

      def self.generate_x25519_ephemeral
        require "rbnacl"
        private_key = RbNaCl::PrivateKey.generate
        {
          type: :okp, crv: "X25519",
          public_bytes: private_key.public_key.to_bytes,
          private_bytes: private_key.to_bytes
        }
      end

      def self.generate_ec_ephemeral(curve_name)
        ec_key = OpenSSL::PKey::EC.generate(curve_name)
        crv = case curve_name
              when "prime256v1" then "P-256"
              when "secp384r1" then "P-384"
              when "secp521r1" then "P-521"
              when "secp256k1" then "secp256k1"
              end

        {
          type: :ec, crv: crv,
          ec_key: ec_key, has_private: true
        }
      end

      def self.compute_x25519(private_key_info, public_key_info)
        require "rbnacl"
        RbNaCl::GroupElement.new(public_key_info[:public_bytes])
          .mult(private_key_info[:private_bytes]).to_bytes
      end

      def self.compute_ec(private_key_info, public_key_info)
        private_ec = private_key_info[:ec_key]
        public_ec = public_key_info[:ec_key]

        # Use OpenSSL ECDH
        private_ec.derive(public_ec)
      end

      private_class_method :generate_x25519_ephemeral, :generate_ec_ephemeral, :compute_x25519, :compute_ec
    end
  end
end
