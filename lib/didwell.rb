# frozen_string_literal: true

require "zeitwerk"

loader = Zeitwerk::Loader.new
loader.tag = "didwell"
loader.inflector.inflect(
  "did"            => "DID",
  "did_comm"       => "DIDComm",
  "did_well"       => "DIDWell",
  "jws_envelope"   => "JWSEnvelope",
  "jwe_envelope"   => "JWEEnvelope",
  "ecdh"           => "ECDH",
  "concat_kdf"     => "ConcatKDF",
)

loader.push_dir("#{__dir__}")

# Ignore the entry file itself (not an autoloadable constant)
loader.ignore("#{__dir__}/didwell.rb")

# utils/ is a grouping directory, not a namespace
loader.collapse("#{__dir__}/did_comm/utils")

# These files define multiple constants or add methods to existing modules,
# which doesn't fit Zeitwerk's one-file-one-constant convention
%w[
  did_well/version.rb
  did/error.rb
  did/types.rb
  did_comm/error.rb
  did_comm/types.rb
  did_comm/algorithms.rb
  did_comm/pack_plaintext.rb
  did_comm/pack_signed.rb
  did_comm/pack_encrypted.rb
  did_comm/unpack.rb
].each { |f| loader.ignore("#{__dir__}/#{f}") }

loader.setup

# Manually load ignored files
require_relative "did_well/version"
require_relative "did/error"
require_relative "did/types"
require_relative "did_comm/error"
require_relative "did_comm/types"
require_relative "did_comm/algorithms"
require_relative "did_comm/pack_plaintext"
require_relative "did_comm/pack_signed"
require_relative "did_comm/pack_encrypted"
require_relative "did_comm/unpack"
