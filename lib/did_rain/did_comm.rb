# frozen_string_literal: true

module DIDRain
  module DIDComm
    def self.pack_plaintext(message, resolvers_config:)
      PackPlaintext.call(message, resolvers_config:)
    end

    def self.pack_signed(message, sign_from:, resolvers_config:)
      PackSigned.call(message, sign_from:, resolvers_config:)
    end

    def self.pack_encrypted(message, to:, from: nil, sign_from: nil, resolvers_config:, pack_config: nil)
      PackEncrypted.call(message, to:, from:, sign_from:, resolvers_config:, pack_config:)
    end

    def self.unpack(packed_msg, resolvers_config:, unpack_config: nil)
      Unpack.call(packed_msg, resolvers_config:, config: unpack_config)
    end
  end
end
