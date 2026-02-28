# frozen_string_literal: true

module DIDComm
  class FromPrior
    attr_accessor :iss, :sub, :aud, :exp, :nbf, :iat, :jti

    def initialize(iss:, sub:, aud: nil, exp: nil, nbf: nil, iat: nil, jti: nil)
      @iss = iss
      @sub = sub
      @aud = aud
      @exp = exp
      @nbf = nbf
      @iat = iat
      @jti = jti
    end

    def to_hash
      d = { "iss" => @iss, "sub" => @sub }
      d["aud"] = @aud if @aud
      d["exp"] = @exp if @exp
      d["nbf"] = @nbf if @nbf
      d["iat"] = @iat if @iat
      d["jti"] = @jti if @jti
      d
    end

    def self.from_hash(d)
      raise MalformedMessageError.new(:invalid_plaintext, "from_prior plaintext is invalid") unless d.is_a?(Hash)
      raise MalformedMessageError.new(:invalid_plaintext, "from_prior missing iss") unless d["iss"]
      raise MalformedMessageError.new(:invalid_plaintext, "from_prior missing sub") unless d["sub"]

      new(
        iss: d["iss"],
        sub: d["sub"],
        aud: d["aud"],
        exp: d["exp"],
        nbf: d["nbf"],
        iat: d["iat"],
        jti: d["jti"]
      )
    end
  end
end
