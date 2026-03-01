# frozen_string_literal: true

require "zeitwerk"

loader = Zeitwerk::Loader.for_gem
loader.inflector.inflect(
  "did_rain"       => "DIDRain",
  "did"            => "DID",
  "did_comm"       => "DIDComm",
  "jws_envelope"   => "JWSEnvelope",
  "jwe_envelope"   => "JWEEnvelope",
  "ecdh"           => "ECDH",
  "concat_kdf"     => "ConcatKDF",
)
loader.setup

require_relative "did_rain/version"

module DIDRain
end
