# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "Crypto primitives" do
  describe DIDComm::Crypto::KeyWrap do
    it "wraps and unwraps a 32-byte key" do
      kek = SecureRandom.random_bytes(32)
      plaintext = SecureRandom.random_bytes(32)

      wrapped = DIDComm::Crypto::KeyWrap.wrap(kek, plaintext)
      expect(wrapped.bytesize).to eq(plaintext.bytesize + 8)

      unwrapped = DIDComm::Crypto::KeyWrap.unwrap(kek, wrapped)
      expect(unwrapped).to eq(plaintext)
    end

    it "wraps and unwraps a 64-byte key" do
      kek = SecureRandom.random_bytes(32)
      plaintext = SecureRandom.random_bytes(64)

      wrapped = DIDComm::Crypto::KeyWrap.wrap(kek, plaintext)
      unwrapped = DIDComm::Crypto::KeyWrap.unwrap(kek, wrapped)
      expect(unwrapped).to eq(plaintext)
    end

    it "fails on tampered wrapped key" do
      kek = SecureRandom.random_bytes(32)
      plaintext = SecureRandom.random_bytes(32)
      wrapped = DIDComm::Crypto::KeyWrap.wrap(kek, plaintext)
      wrapped[0] = (wrapped[0].ord ^ 0xFF).chr
      expect { DIDComm::Crypto::KeyWrap.unwrap(kek, wrapped) }.to raise_error(DIDComm::MalformedMessageError)
    end
  end

  describe DIDComm::Crypto::ConcatKDF do
    it "derives a 32-byte key" do
      shared_secret = SecureRandom.random_bytes(32)
      result = DIDComm::Crypto::ConcatKDF.derive(shared_secret, 32, "ECDH-ES+A256KW", "".b, "".b)
      expect(result.bytesize).to eq(32)
    end

    it "produces deterministic output" do
      ss = "test_secret_value_for_kdf_test!".b
      r1 = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "A256KW", "apu".b, "apv".b)
      r2 = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "A256KW", "apu".b, "apv".b)
      expect(r1).to eq(r2)
    end

    it "includes tag in derivation when provided" do
      ss = "test_secret_value_for_kdf_test!".b
      without_tag = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "ECDH-1PU+A256KW", "apu".b, "apv".b)
      with_tag = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "ECDH-1PU+A256KW", "apu".b, "apv".b, tag: "sometag".b)
      expect(without_tag).not_to eq(with_tag)
    end

    it "ignores empty tag" do
      ss = "test_secret_value_for_kdf_test!".b
      without_tag = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "A256KW", "apu".b, "apv".b)
      with_empty_tag = DIDComm::Crypto::ConcatKDF.derive(ss, 32, "A256KW", "apu".b, "apv".b, tag: "")
      expect(without_tag).to eq(with_empty_tag)
    end
  end

  describe DIDComm::Crypto::ContentEncryption do
    describe "XC20P" do
      it "encrypts and decrypts" do
        key = SecureRandom.random_bytes(32)
        plaintext = "Hello, DIDComm!"
        aad = "test-aad"

        result = DIDComm::Crypto::ContentEncryption::XC20P.encrypt(plaintext, aad, key)
        decrypted = DIDComm::Crypto::ContentEncryption::XC20P.decrypt(
          result[:ciphertext], result[:iv], result[:tag], aad, key
        )
        expect(decrypted).to eq(plaintext)
      end
    end

    describe "A256GCM" do
      it "encrypts and decrypts" do
        key = SecureRandom.random_bytes(32)
        plaintext = "Hello, DIDComm!"
        aad = "test-aad"

        result = DIDComm::Crypto::ContentEncryption::A256GCM.encrypt(plaintext, aad, key)
        decrypted = DIDComm::Crypto::ContentEncryption::A256GCM.decrypt(
          result[:ciphertext], result[:iv], result[:tag], aad, key
        )
        expect(decrypted).to eq(plaintext)
      end

      it "raises MalformedMessageError on tampered ciphertext" do
        key = SecureRandom.random_bytes(32)
        result = DIDComm::Crypto::ContentEncryption::A256GCM.encrypt("test", "aad", key)
        result[:tag][0] = (result[:tag][0].ord ^ 0xFF).chr
        expect {
          DIDComm::Crypto::ContentEncryption::A256GCM.decrypt(
            result[:ciphertext], result[:iv], result[:tag], "aad", key
          )
        }.to raise_error(DIDComm::MalformedMessageError)
      end
    end

    describe "A256CBC_HS512" do
      it "encrypts and decrypts" do
        key = SecureRandom.random_bytes(64)
        plaintext = "Hello, DIDComm!"
        aad = "test-aad"

        result = DIDComm::Crypto::ContentEncryption::A256CBC_HS512.encrypt(plaintext, aad, key)
        decrypted = DIDComm::Crypto::ContentEncryption::A256CBC_HS512.decrypt(
          result[:ciphertext], result[:iv], result[:tag], aad, key
        )
        expect(decrypted).to eq(plaintext)
      end

      it "rejects tampered ciphertext" do
        key = SecureRandom.random_bytes(64)
        result = DIDComm::Crypto::ContentEncryption::A256CBC_HS512.encrypt("test", "aad", key)
        result[:tag][0] = (result[:tag][0].ord ^ 0xFF).chr
        expect {
          DIDComm::Crypto::ContentEncryption::A256CBC_HS512.decrypt(
            result[:ciphertext], result[:iv], result[:tag], "aad", key
          )
        }.to raise_error(DIDComm::MalformedMessageError)
      end
    end
  end

  describe DIDComm::Crypto::KeyUtils do
    it "calculates APV correctly" do
      kids = ["did:example:bob#key-2", "did:example:bob#key-1"]
      apv = DIDComm::Crypto::KeyUtils.calculate_apv(kids)
      # Should sort and hash
      sorted = "did:example:bob#key-1.did:example:bob#key-2"
      expected = DIDComm::Crypto::KeyUtils.base64url_encode(OpenSSL::Digest::SHA256.digest(sorted))
      expect(apv).to eq(expected)
    end

    it "extracts Ed25519 key from JWK" do
      secret = DIDComm::Secret.new(
        kid: "did:example:alice#key-1",
        type: DIDComm::VerificationMethodType::JSON_WEB_KEY_2020,
        verification_material: DIDComm::VerificationMaterial.new(
          format: DIDComm::VerificationMaterialFormat::JWK,
          value: JSON.generate({
            "kty" => "OKP", "crv" => "Ed25519",
            "x" => "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
            "d" => "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY"
          })
        )
      )
      key = DIDComm::Crypto::KeyUtils.extract_key(secret)
      expect(key[:crv]).to eq("Ed25519")
      expect(key[:type]).to eq(:okp)
      expect(key[:public_bytes]).to be_a(String)
      expect(key[:private_bytes]).to be_a(String)
    end

    it "determines sign algorithm" do
      secret_ed = DIDComm::Secret.new(
        kid: "k1", type: DIDComm::VerificationMethodType::JSON_WEB_KEY_2020,
        verification_material: DIDComm::VerificationMaterial.new(
          format: DIDComm::VerificationMaterialFormat::JWK,
          value: '{"kty":"OKP","crv":"Ed25519","x":"test"}'
        )
      )
      expect(DIDComm::Crypto::KeyUtils.extract_sign_alg(secret_ed)).to eq(DIDComm::SignAlg::ED25519)
    end
  end

  describe "Algorithm constants" do
    it "freezes AnonCryptAlg constants" do
      expect(DIDComm::AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW).to be_frozen
      expect(DIDComm::AnonCryptAlg::XC20P_ECDH_ES_A256KW).to be_frozen
      expect(DIDComm::AnonCryptAlg::A256GCM_ECDH_ES_A256KW).to be_frozen
    end

    it "freezes AuthCryptAlg constants" do
      expect(DIDComm::AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW).to be_frozen
    end
  end

  describe "ECDH private methods" do
    it "does not expose internal helper methods" do
      expect { DIDComm::Crypto::ECDH.generate_x25519_ephemeral }.to raise_error(NoMethodError)
      expect { DIDComm::Crypto::ECDH.generate_ec_ephemeral("prime256v1") }.to raise_error(NoMethodError)
      expect { DIDComm::Crypto::ECDH.compute_x25519({}, {}) }.to raise_error(NoMethodError)
      expect { DIDComm::Crypto::ECDH.compute_ec({}, {}) }.to raise_error(NoMethodError)
    end
  end

  describe "JWS typ header" do
    it "uses SIGNED typ in JWS protected header" do
      secret = TestVectors.alice_secrets.find { |s| s.kid == "did:example:alice#key-1" }
      key_info = DIDComm::Crypto::KeyUtils.extract_key(secret)
      alg = DIDComm::Crypto::KeyUtils.extract_sign_alg(secret)
      jws = DIDComm::Crypto::JWSEnvelope.sign("test payload", key_info, secret.kid, alg)

      protected_json = DIDComm::Crypto::KeyUtils.base64url_decode(jws["signatures"][0]["protected"])
      protected_header = JSON.parse(protected_json.force_encoding("UTF-8"))
      expect(protected_header["typ"]).to eq(DIDComm::DIDCommMessageTypes::SIGNED)
    end
  end
end
