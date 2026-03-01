# frozen_string_literal: true

require "openssl"

module DIDRain
  module DIDComm
    module Crypto
      module KeyWrap
        # AES Key Wrap (RFC 3394) using OpenSSL built-in cipher
        def self.wrap(kek, plaintext_key)
          cipher = OpenSSL::Cipher.new("aes-256-wrap")
          cipher.encrypt
          cipher.key = kek
          cipher.update(plaintext_key) + cipher.final
        end

        def self.unwrap(kek, wrapped_key)
          cipher = OpenSSL::Cipher.new("aes-256-wrap")
          cipher.decrypt
          cipher.key = kek
          cipher.update(wrapped_key) + cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise MalformedMessageError.new(:can_not_decrypt, "Key unwrap failed")
        end
      end
    end
  end
end
