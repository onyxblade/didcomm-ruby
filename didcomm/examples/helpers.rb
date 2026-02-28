# frozen_string_literal: true

# Shared helpers for DIDComm examples.

require "didcomm"
require "rbnacl"
require "securerandom"
require "base64"
require "base58"

def b64u(bytes) = Base64.urlsafe_encode64(bytes, padding: false)

# Build a did:key from an X25519 public key (multicodec prefix 0xEC).
def did_key_from_x25519(public_bytes)
  multicodec = [0xEC, 0x01].pack("CC") + public_bytes
  "did:key:z#{Base58.binary_to_base58(multicodec, :bitcoin)}"
end

# Build a did:key from an Ed25519 public key (multicodec prefix 0xED).
def did_key_from_ed25519(public_bytes)
  multicodec = [0xED, 0x01].pack("CC") + public_bytes
  "did:key:z#{Base58.binary_to_base58(multicodec, :bitcoin)}"
end

# Build an identity with only an X25519 key (encryption only).
def build_x25519_identity(private_key)
  public_key = private_key.public_key
  did = did_key_from_x25519(public_key.to_bytes)
  kid = "#{did}##{did.split(':').last}"

  jwk_pub  = { "kty" => "OKP", "crv" => "X25519", "x" => b64u(public_key.to_bytes) }
  jwk_priv = jwk_pub.merge("d" => b64u(private_key.to_bytes))

  did_doc = DID::Document.new(
    id: did,
    authentication: [],
    key_agreement: [kid],
    verification_method: [
      DID::VerificationMethod.new(
        id: kid, controller: did,
        type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
        verification_material: DID::VerificationMaterial.new(
          format: DID::VerificationMaterialFormat::JWK, value: jwk_pub
        )
      )
    ],
    service: []
  )

  secret = DID::Secret.new(
    kid: kid,
    type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
    verification_material: DID::VerificationMaterial.new(
      format: DID::VerificationMaterialFormat::JWK, value: jwk_priv
    )
  )

  { did: did, did_doc: did_doc, secrets: [secret] }
end

# Build an identity with both Ed25519 (signing) and X25519 (encryption) keys.
# The did:key is derived from the Ed25519 key.
def build_full_identity(ed25519_seed: nil)
  ed_seed    = ed25519_seed || SecureRandom.random_bytes(32)
  signing_key = RbNaCl::Signatures::Ed25519::SigningKey.new(ed_seed)
  verify_key  = signing_key.verify_key

  did = did_key_from_ed25519(verify_key.to_bytes)
  ed_kid = "#{did}##{did.split(':').last}"

  # Derive X25519 keypair from Ed25519 seed via a separate random key
  x_private = RbNaCl::PrivateKey.generate
  x_public  = x_private.public_key
  x_kid     = "#{did}#x25519-1"

  # Ed25519 JWK
  ed_jwk_pub  = { "kty" => "OKP", "crv" => "Ed25519", "x" => b64u(verify_key.to_bytes) }
  ed_jwk_priv = ed_jwk_pub.merge("d" => b64u(ed_seed))

  # X25519 JWK
  x_jwk_pub  = { "kty" => "OKP", "crv" => "X25519", "x" => b64u(x_public.to_bytes) }
  x_jwk_priv = x_jwk_pub.merge("d" => b64u(x_private.to_bytes))

  did_doc = DID::Document.new(
    id: did,
    authentication: [ed_kid],
    key_agreement: [x_kid],
    verification_method: [
      DID::VerificationMethod.new(
        id: ed_kid, controller: did,
        type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
        verification_material: DID::VerificationMaterial.new(
          format: DID::VerificationMaterialFormat::JWK, value: ed_jwk_pub
        )
      ),
      DID::VerificationMethod.new(
        id: x_kid, controller: did,
        type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
        verification_material: DID::VerificationMaterial.new(
          format: DID::VerificationMaterialFormat::JWK, value: x_jwk_pub
        )
      )
    ],
    service: []
  )

  secrets = [
    DID::Secret.new(
      kid: ed_kid,
      type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
      verification_material: DID::VerificationMaterial.new(
        format: DID::VerificationMaterialFormat::JWK, value: ed_jwk_priv
      )
    ),
    DID::Secret.new(
      kid: x_kid,
      type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
      verification_material: DID::VerificationMaterial.new(
        format: DID::VerificationMaterialFormat::JWK, value: x_jwk_priv
      )
    )
  ]

  { did: did, did_doc: did_doc, secrets: secrets }
end
