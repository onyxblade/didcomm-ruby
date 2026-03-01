# frozen_string_literal: true

module DIDRain
  module DIDComm
    module AnonCryptAlg
      A256CBC_HS512_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "A256CBC-HS512").freeze
      XC20P_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "XC20P").freeze
      A256GCM_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "A256GCM").freeze

      ALL = [A256CBC_HS512_ECDH_ES_A256KW, XC20P_ECDH_ES_A256KW, A256GCM_ECDH_ES_A256KW].freeze

      def self.by_enc(enc)
        ALL.find { |a| a.enc == enc }
      end
    end
  end
end
