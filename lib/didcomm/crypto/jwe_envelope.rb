# frozen_string_literal: true

require "json"
require "securerandom"

module DIDComm
  module Crypto
    module JWEEnvelope
      def self.anoncrypted?(msg)
        msg.is_a?(Hash) && msg.key?("ciphertext") && msg.key?("protected") &&
          begin
            protected_header = Validation.parse_protected(msg["protected"])
            protected_header["alg"]&.start_with?("ECDH-ES")
          rescue StandardError
            false
          end
      end

      def self.authcrypted?(msg)
        msg.is_a?(Hash) && msg.key?("ciphertext") && msg.key?("protected") &&
          begin
            protected_header = Validation.parse_protected(msg["protected"])
            protected_header["alg"]&.start_with?("ECDH-1PU")
          rescue StandardError
            false
          end
      end

      # Build and encrypt a JWE in General JSON Serialization (ECDH-ES, multi-recipient)
      def self.encrypt_es(plaintext, recipient_keys, alg_obj)
        alg = alg_obj.alg
        enc = alg_obj.enc

        kids = recipient_keys.map { |k| k[:kid] }
        apv = KeyUtils.calculate_apv(kids)
        apv_bytes = KeyUtils.base64url_decode(apv)

        # Generate ephemeral key pair
        ephemeral = ECDH.generate_ephemeral(recipient_keys.first)
        epk_jwk = ECDH.ephemeral_to_jwk(ephemeral)

        # Generate CEK
        ce = ContentEncryption.for_algorithm(enc)
        cek = SecureRandom.random_bytes(ce::KEY_LEN)

        # KEK length is always 32 for A256KW
        kek_len = 32

        # Wrap CEK for each recipient
        recipients = recipient_keys.map do |rk|
          kek = ECDH.derive_key_es(ephemeral, rk, alg, "".b, apv_bytes, kek_len)
          encrypted_key = KeyWrap.wrap(kek, cek)
          {
            "header" => { "kid" => rk[:kid] },
            "encrypted_key" => KeyUtils.base64url_encode(encrypted_key)
          }
        end

        # Build protected header
        protected_header = {
          "typ" => DIDCommMessageTypes::ENCRYPTED,
          "alg" => alg,
          "enc" => enc,
          "apv" => apv,
          "epk" => epk_jwk
        }
        protected_b64 = KeyUtils.base64url_encode(JSON.generate(protected_header))

        # Encrypt content
        aad = protected_b64.encode("ASCII")
        result = ce.encrypt(plaintext.encode("UTF-8"), aad, cek)

        {
          "protected" => protected_b64,
          "recipients" => recipients,
          "iv" => KeyUtils.base64url_encode(result[:iv]),
          "ciphertext" => KeyUtils.base64url_encode(result[:ciphertext]),
          "tag" => KeyUtils.base64url_encode(result[:tag])
        }
      end

      # Build and encrypt a JWE in General JSON Serialization (ECDH-1PU, multi-recipient)
      def self.encrypt_1pu(plaintext, recipient_keys, sender_key, alg_obj)
        alg = alg_obj.alg
        enc = alg_obj.enc

        kids = recipient_keys.map { |k| k[:kid] }
        apv = KeyUtils.calculate_apv(kids)
        apv_bytes = KeyUtils.base64url_decode(apv)

        apu = KeyUtils.base64url_encode(sender_key[:kid].encode("UTF-8"))
        apu_bytes = sender_key[:kid].encode("UTF-8")

        # Generate ephemeral key pair
        ephemeral = ECDH.generate_ephemeral(recipient_keys.first)
        epk_jwk = ECDH.ephemeral_to_jwk(ephemeral)

        # Generate CEK
        ce = ContentEncryption.for_algorithm(enc)
        cek = SecureRandom.random_bytes(ce::KEY_LEN)

        kek_len = 32

        # Encrypt content first (need tag for 1PU KDF in some cases)
        protected_header = {
          "typ" => DIDCommMessageTypes::ENCRYPTED,
          "alg" => alg,
          "enc" => enc,
          "apu" => apu,
          "apv" => apv,
          "skid" => sender_key[:kid],
          "epk" => epk_jwk
        }
        protected_b64 = KeyUtils.base64url_encode(JSON.generate(protected_header))
        aad = protected_b64.encode("ASCII")
        result = ce.encrypt(plaintext.encode("UTF-8"), aad, cek)

        # Wrap CEK for each recipient using ECDH-1PU
        recipients = recipient_keys.map do |rk|
          kek = ECDH.derive_key_1pu(ephemeral, sender_key, rk, alg, apu_bytes, apv_bytes, kek_len, tag: result[:tag])
          encrypted_key = KeyWrap.wrap(kek, cek)
          {
            "header" => { "kid" => rk[:kid] },
            "encrypted_key" => KeyUtils.base64url_encode(encrypted_key)
          }
        end

        {
          "protected" => protected_b64,
          "recipients" => recipients,
          "iv" => KeyUtils.base64url_encode(result[:iv]),
          "ciphertext" => KeyUtils.base64url_encode(result[:ciphertext]),
          "tag" => KeyUtils.base64url_encode(result[:tag])
        }
      end

      # Decrypt a JWE (ECDH-ES)
      def self.decrypt_es(jwe, recipient_private_key)
        protected_header = Validation.parse_protected(jwe["protected"])
        enc = protected_header["enc"]
        alg = protected_header["alg"]
        apv_bytes = KeyUtils.base64url_decode(protected_header["apv"])
        epk_jwk = protected_header["epk"]
        epk = ECDH.import_epk(epk_jwk)

        # Find recipient entry for this key
        recipient_entry = jwe["recipients"].find { |r| r["header"]["kid"] == recipient_private_key[:kid] }
        raise MalformedMessageError.new(:can_not_decrypt, "No recipient entry for key") unless recipient_entry

        encrypted_key = KeyUtils.base64url_decode(recipient_entry["encrypted_key"])

        kek_len = 32
        # For decrypt: recipient has private key, epk is public only
        # ECDH shared secret is commutative, so we compute with recipient_private + epk_public
        kek = ECDH.derive_key_es(recipient_private_key, epk, alg, "".b, apv_bytes, kek_len)
        cek = KeyWrap.unwrap(kek, encrypted_key)

        # Decrypt content
        ce = ContentEncryption.for_algorithm(enc)
        aad = jwe["protected"].encode("ASCII")
        iv = KeyUtils.base64url_decode(jwe["iv"])
        ciphertext = KeyUtils.base64url_decode(jwe["ciphertext"])
        tag = KeyUtils.base64url_decode(jwe["tag"])

        ce.decrypt(ciphertext, iv, tag, aad, cek)
      end

      # Decrypt a JWE (ECDH-1PU)
      def self.decrypt_1pu(jwe, recipient_private_key, sender_public_key)
        protected_header = Validation.parse_protected(jwe["protected"])
        enc = protected_header["enc"]
        alg = protected_header["alg"]
        apv_bytes = KeyUtils.base64url_decode(protected_header["apv"])
        apu_bytes = KeyUtils.base64url_decode(protected_header["apu"])
        epk_jwk = protected_header["epk"]
        epk = ECDH.import_epk(epk_jwk)

        # Find recipient entry
        recipient_entry = jwe["recipients"].find { |r| r["header"]["kid"] == recipient_private_key[:kid] }
        raise MalformedMessageError.new(:can_not_decrypt, "No recipient entry for key") unless recipient_entry

        encrypted_key = KeyUtils.base64url_decode(recipient_entry["encrypted_key"])

        # Need tag for 1PU KDF
        tag = KeyUtils.base64url_decode(jwe["tag"])

        kek_len = 32
        # For 1PU decrypt: ephemeral public + recipient private for Ze, sender public + recipient private for Zs
        # But we need to swap: compute Ze with (epk_private is unknown, so we use recipient_private + epk_public)
        # Actually: Ze = ECDH(epk_public, recipient_private), Zs = ECDH(sender_public, recipient_private)
        ze = ECDH.compute_shared_secret(recipient_private_key, epk)
        zs = ECDH.compute_shared_secret(recipient_private_key, sender_public_key)
        z = ze + zs
        kek = ConcatKDF.derive(z, kek_len, alg, apu_bytes, apv_bytes, tag: tag)
        cek = KeyWrap.unwrap(kek, encrypted_key)

        # Decrypt content
        ce = ContentEncryption.for_algorithm(enc)
        aad = jwe["protected"].encode("ASCII")
        iv = KeyUtils.base64url_decode(jwe["iv"])
        ciphertext = KeyUtils.base64url_decode(jwe["ciphertext"])

        ce.decrypt(ciphertext, iv, tag, aad, cek)
      end
    end
  end
end
