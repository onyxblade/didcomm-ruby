# frozen_string_literal: true

require_relative "did"

require_relative "didcomm/version"
require_relative "didcomm/error"
require_relative "didcomm/types"
require_relative "didcomm/algorithms"

# Data models
require_relative "didcomm/attachment"
require_relative "didcomm/from_prior"
require_relative "didcomm/message"

# DIDComm Service
require_relative "didcomm/didcomm_service"

# Utilities
require_relative "didcomm/utils/multicodec"

# Crypto primitives
require_relative "didcomm/crypto/key_utils"
require_relative "didcomm/crypto/defaults"
require_relative "didcomm/crypto/validation"
require_relative "didcomm/crypto/content_encryption"
require_relative "didcomm/crypto/key_wrap"
require_relative "didcomm/crypto/concat_kdf"
require_relative "didcomm/crypto/ecdh"
require_relative "didcomm/crypto/jws_envelope"
require_relative "didcomm/crypto/jwe_envelope"
require_relative "didcomm/crypto/sign"
require_relative "didcomm/crypto/anoncrypt"
require_relative "didcomm/crypto/authcrypt"

# Key selectors
require_relative "didcomm/keys/sign_keys_selector"
require_relative "didcomm/keys/anoncrypt_keys_selector"
require_relative "didcomm/keys/authcrypt_keys_selector"
require_relative "didcomm/keys/forward_next_keys_selector"

# FromPrior
require_relative "didcomm/from_prior/pack"
require_relative "didcomm/from_prior/unpack"

# Protocols
require_relative "didcomm/protocols/routing/forward"

# Pack/Unpack
require_relative "didcomm/pack_plaintext"
require_relative "didcomm/pack_signed"
require_relative "didcomm/pack_encrypted"
require_relative "didcomm/unpack"

module DIDComm
  # Aliases for DID types — zero changes needed in internal code
  DIDDoc = DID::Document
  VerificationMethod = DID::VerificationMethod
  DIDResolver = DID::Resolver
  DIDResolverInMemory = DID::ResolverInMemory
  Secret = DID::Secret
  SecretsResolver = DID::SecretsResolver
  SecretsResolverInMemory = DID::SecretsResolverInMemory
  VerificationMethodType = DID::VerificationMethodType
  VerificationMaterialFormat = DID::VerificationMaterialFormat
  VerificationMaterial = DID::VerificationMaterial
  DIDUtils = DID::Utils
  DIDDocNotResolvedError = DID::DocumentNotResolvedError
  DIDUrlNotFoundError = DID::UrlNotFoundError
  SecretNotFoundError = DID::SecretNotFoundError
  IncompatibleCryptoError = DID::IncompatibleCryptoError
  InvalidDIDDocError = DID::InvalidDocumentError
end
