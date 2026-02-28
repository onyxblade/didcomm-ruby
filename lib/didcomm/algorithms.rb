# frozen_string_literal: true

module DIDComm
  Algs = Struct.new(:alg, :enc, keyword_init: true)

  module AnonCryptAlg
    A256CBC_HS512_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "A256CBC-HS512").freeze
    XC20P_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "XC20P").freeze
    A256GCM_ECDH_ES_A256KW = Algs.new(alg: "ECDH-ES+A256KW", enc: "A256GCM").freeze

    ALL = [A256CBC_HS512_ECDH_ES_A256KW, XC20P_ECDH_ES_A256KW, A256GCM_ECDH_ES_A256KW].freeze

    def self.by_enc(enc)
      ALL.find { |a| a.enc == enc }
    end
  end

  module AuthCryptAlg
    A256CBC_HS512_ECDH_1PU_A256KW = Algs.new(alg: "ECDH-1PU+A256KW", enc: "A256CBC-HS512").freeze

    ALL = [A256CBC_HS512_ECDH_1PU_A256KW].freeze

    def self.by_enc(enc)
      ALL.find { |a| a.enc == enc }
    end
  end

  module SignAlg
    ED25519 = "EdDSA"
    ES256 = "ES256"
    ES256K = "ES256K"
  end

  module Defaults
    DEF_ENC_ALG_AUTH = AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW
    DEF_ENC_ALG_ANON = AnonCryptAlg::XC20P_ECDH_ES_A256KW
  end
end
