# frozen_string_literal: true

module DIDRain
  module DIDComm
    module Defaults
      DEF_ENC_ALG_AUTH = AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW
      DEF_ENC_ALG_ANON = AnonCryptAlg::XC20P_ECDH_ES_A256KW
    end
  end
end
