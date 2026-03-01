# frozen_string_literal: true

module DIDRain
  module DIDComm
    module AuthCryptAlg
      A256CBC_HS512_ECDH_1PU_A256KW = Algs.new(alg: "ECDH-1PU+A256KW", enc: "A256CBC-HS512").freeze

      ALL = [A256CBC_HS512_ECDH_1PU_A256KW].freeze

      def self.by_enc(enc)
        ALL.find { |a| a.enc == enc }
      end
    end
  end
end
