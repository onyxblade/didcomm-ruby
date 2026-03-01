# frozen_string_literal: true

require "openssl"
require "securerandom"

module DIDRain
  module DIDComm
    module Crypto
      module ContentEncryption
        # XChaCha20-Poly1305 (XC20P)
        module XC20P
          KEY_LEN = 32
          IV_LEN = 24
          TAG_LEN = 16

          def self.encrypt(plaintext, aad, key)
            require "rbnacl"
            iv = SecureRandom.random_bytes(IV_LEN)
            aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
            ciphertext_with_tag = aead.encrypt(iv, plaintext, aad)
            ciphertext = ciphertext_with_tag[0...-TAG_LEN]
            tag = ciphertext_with_tag[-TAG_LEN..]
            { ciphertext: ciphertext, iv: iv, tag: tag }
          end

          def self.decrypt(ciphertext, iv, tag, aad, key)
            require "rbnacl"
            aead = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
            aead.decrypt(iv, ciphertext + tag, aad)
          rescue RbNaCl::CryptoError
            raise MalformedMessageError.new(:can_not_decrypt, "Decryption failed")
          end
        end

        # AES-256-GCM (A256GCM)
        module A256GCM
          KEY_LEN = 32
          IV_LEN = 12
          TAG_LEN = 16

          def self.encrypt(plaintext, aad, key)
            cipher = OpenSSL::Cipher.new("aes-256-gcm")
            cipher.encrypt
            iv = cipher.random_iv
            cipher.key = key
            cipher.iv = iv
            cipher.auth_data = aad
            ciphertext = cipher.update(plaintext) + cipher.final
            tag = cipher.auth_tag
            { ciphertext: ciphertext, iv: iv, tag: tag }
          end

          def self.decrypt(ciphertext, iv, tag, aad, key)
            cipher = OpenSSL::Cipher.new("aes-256-gcm")
            cipher.decrypt
            cipher.key = key
            cipher.iv = iv
            cipher.auth_tag = tag
            cipher.auth_data = aad
            cipher.update(ciphertext) + cipher.final
          rescue OpenSSL::Cipher::CipherError
            raise MalformedMessageError.new(:can_not_decrypt, "Decryption failed")
          end
        end

        # AES-256-CBC + HMAC-SHA-512 (A256CBC-HS512)
        module A256CBC_HS512
          KEY_LEN = 64 # 32 bytes for MAC key + 32 bytes for encryption key
          IV_LEN = 16
          TAG_LEN = 32 # Truncated HMAC-SHA-512 (first 32 bytes)

          def self.encrypt(plaintext, aad, key)
            mac_key = key[0, 32]
            enc_key = key[32, 32]

            cipher = OpenSSL::Cipher.new("aes-256-cbc")
            cipher.encrypt
            iv = cipher.random_iv
            cipher.key = enc_key
            cipher.iv = iv
            ciphertext = cipher.update(plaintext) + cipher.final

            # Compute authentication tag: HMAC-SHA-512(mac_key, aad || iv || ciphertext || al)
            al = [aad.bytesize * 8].pack("Q>") # AAD length in bits, big-endian 64-bit
            mac_input = aad + iv + ciphertext + al
            full_tag = OpenSSL::HMAC.digest("SHA512", mac_key, mac_input)
            tag = full_tag[0, TAG_LEN]

            { ciphertext: ciphertext, iv: iv, tag: tag }
          end

          def self.decrypt(ciphertext, iv, tag, aad, key)
            mac_key = key[0, 32]
            enc_key = key[32, 32]

            # Verify tag
            al = [aad.bytesize * 8].pack("Q>")
            mac_input = aad + iv + ciphertext + al
            full_tag = OpenSSL::HMAC.digest("SHA512", mac_key, mac_input)
            expected_tag = full_tag[0, TAG_LEN]

            unless secure_compare(tag, expected_tag)
              raise MalformedMessageError.new(:can_not_decrypt, "Authentication tag mismatch")
            end

            cipher = OpenSSL::Cipher.new("aes-256-cbc")
            cipher.decrypt
            cipher.key = enc_key
            cipher.iv = iv
            cipher.update(ciphertext) + cipher.final
          end

          def self.secure_compare(a, b)
            return false unless a.bytesize == b.bytesize
            OpenSSL.fixed_length_secure_compare(a, b)
          end
        end

        def self.for_algorithm(enc)
          case enc
          when "XC20P" then XC20P
          when "A256GCM" then A256GCM
          when "A256CBC-HS512" then A256CBC_HS512
          else raise UnsupportedError, "Unsupported content encryption: #{enc}"
          end
        end

        def self.key_length(enc)
          for_algorithm(enc)::KEY_LEN
        end
      end
    end
  end
end
