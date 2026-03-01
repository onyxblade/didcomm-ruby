# frozen_string_literal: true

module DIDComm
  module Multicodec
    CODECS = {
      0xEC => :x25519_pub,
      0xED => :ed25519_pub,
      0x1302 => :x25519_priv,
      0x1300 => :ed25519_priv
    }.freeze

    def self.decode(bytes)
      if bytes[0].ord < 0x80
        code = bytes[0].ord
        data = bytes[1..]
      else
        code = (bytes[0].ord & 0x7F) | (bytes[1].ord << 7)
        data = bytes[2..]
      end

      codec = CODECS[code]
      raise UnsupportedError, "Unsupported multicodec: 0x#{code.to_s(16)}" unless codec

      [codec, data]
    end
  end
end
