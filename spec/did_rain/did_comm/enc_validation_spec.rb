# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "enc algorithm validation" do
  def build_protected(header_hash)
    json = JSON.generate(header_hash)
    DIDComm::Crypto::KeyUtils.base64url_encode(json)
  end

  describe "validate_anoncrypt_jwe" do
    it "accepts A256CBC-HS512" do
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      protected_b64 = build_protected({ "alg" => "ECDH-ES+A256KW", "enc" => "A256CBC-HS512", "apv" => apv })
      msg = {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
      expect { DIDComm::Crypto::Validation.validate_anoncrypt_jwe(msg) }.not_to raise_error
    end

    it "accepts A256GCM" do
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      protected_b64 = build_protected({ "alg" => "ECDH-ES+A256KW", "enc" => "A256GCM", "apv" => apv })
      msg = {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
      expect { DIDComm::Crypto::Validation.validate_anoncrypt_jwe(msg) }.not_to raise_error
    end

    it "accepts XC20P" do
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      protected_b64 = build_protected({ "alg" => "ECDH-ES+A256KW", "enc" => "XC20P", "apv" => apv })
      msg = {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
      expect { DIDComm::Crypto::Validation.validate_anoncrypt_jwe(msg) }.not_to raise_error
    end

    it "rejects unsupported enc algorithm" do
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      protected_b64 = build_protected({ "alg" => "ECDH-ES+A256KW", "enc" => "A128GCM", "apv" => apv })
      msg = {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
      expect {
        DIDComm::Crypto::Validation.validate_anoncrypt_jwe(msg)
      }.to raise_error(DIDComm::MalformedMessageError, /Unsupported enc algorithm for anoncrypt/)
    end

    it "rejects nil enc" do
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      protected_b64 = build_protected({ "alg" => "ECDH-ES+A256KW", "apv" => apv })
      msg = {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
      expect {
        DIDComm::Crypto::Validation.validate_anoncrypt_jwe(msg)
      }.to raise_error(DIDComm::MalformedMessageError, /Unsupported enc algorithm for anoncrypt/)
    end
  end

  describe "validate_authcrypt_jwe" do
    let(:sender_kid) { "did:example:alice#key-x25519-1" }

    def build_authcrypt_msg(enc:)
      kids = ["did:example:bob#key-x25519-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      apu = DIDComm::Crypto::KeyUtils.base64url_encode(sender_kid)
      protected_b64 = build_protected({
        "alg" => "ECDH-1PU+A256KW", "enc" => enc,
        "apu" => apu, "apv" => apv, "skid" => sender_kid
      })
      {
        "protected" => protected_b64,
        "recipients" => [{ "header" => { "kid" => "did:example:bob#key-x25519-1" } }],
        "ciphertext" => "x", "iv" => "x", "tag" => "x"
      }
    end

    it "accepts A256CBC-HS512" do
      msg = build_authcrypt_msg(enc: "A256CBC-HS512")
      expect { DIDComm::Crypto::Validation.validate_authcrypt_jwe(msg) }.not_to raise_error
    end

    it "rejects A256GCM" do
      msg = build_authcrypt_msg(enc: "A256GCM")
      expect {
        DIDComm::Crypto::Validation.validate_authcrypt_jwe(msg)
      }.to raise_error(DIDComm::MalformedMessageError, /Unsupported enc algorithm for authcrypt/)
    end

    it "rejects XC20P" do
      msg = build_authcrypt_msg(enc: "XC20P")
      expect {
        DIDComm::Crypto::Validation.validate_authcrypt_jwe(msg)
      }.to raise_error(DIDComm::MalformedMessageError, /Unsupported enc algorithm for authcrypt/)
    end

    it "rejects arbitrary enc" do
      msg = build_authcrypt_msg(enc: "A128CBC-HS256")
      expect {
        DIDComm::Crypto::Validation.validate_authcrypt_jwe(msg)
      }.to raise_error(DIDComm::MalformedMessageError, /Unsupported enc algorithm for authcrypt/)
    end
  end
end
