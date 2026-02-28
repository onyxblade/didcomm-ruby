# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "Input validation" do
  let(:message) { TestVectors.test_message }
  let(:resolvers_alice) { TestVectors.resolvers_config_alice }
  let(:resolvers_bob) { TestVectors.resolvers_config_bob }

  describe "pack_encrypted validation" do
    it "raises on invalid 'to' DID" do
      expect {
        DIDComm.pack_encrypted(message, to: "not-a-did",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /'to'/)
    end

    it "raises on invalid 'from' DID" do
      expect {
        DIDComm.pack_encrypted(message, to: "did:example:bob", from: "not-a-did",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /'from'/)
    end

    it "raises on invalid 'sign_from' DID" do
      expect {
        DIDComm.pack_encrypted(message, to: "did:example:bob", sign_from: "not-a-did",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /'sign_from'/)
    end

    it "allows valid DID URLs" do
      expect {
        DIDComm.pack_encrypted(message,
                                to: "did:example:bob#key-x25519-1",
                                from: "did:example:alice#key-x25519-1",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.not_to raise_error
    end

    it "raises when message 'from' does not match 'from' argument DID" do
      msg = TestVectors.test_message
      msg.from = "did:example:bob"
      expect {
        DIDComm.pack_encrypted(msg, to: "did:example:bob", from: "did:example:alice",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /message 'from' value/)
    end

    it "raises when message 'to' does not contain 'to' argument DID" do
      msg = TestVectors.test_message
      msg.to = ["did:example:charlie"]
      expect {
        DIDComm.pack_encrypted(msg, to: "did:example:bob",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /message 'to' value/)
    end

    it "raises when message 'to' header is not a list" do
      msg_hash = message.to_hash
      msg_hash["to"] = "did:example:bob"
      expect {
        DIDComm.pack_encrypted(msg_hash, to: "did:example:bob",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DIDComm::ValueError, /not a list/)
    end
  end

  describe "pack_signed validation" do
    it "raises on invalid 'sign_from' DID" do
      expect {
        DIDComm.pack_signed(message, sign_from: "not-a-did", resolvers_config: resolvers_alice)
      }.to raise_error(DIDComm::ValueError, /'sign_from'/)
    end
  end

  describe "SignKeysSelector authentication check" do
    it "raises when kid is not in authentication" do
      # key-x25519-1 is a key_agreement key, not in authentication
      expect {
        DIDComm::Keys::SignKeysSelector.find_signing_key("did:example:alice#key-x25519-1", resolvers_alice)
      }.to raise_error(DID::UrlNotFoundError, /not found in authentication/)
    end

    it "succeeds when kid is in authentication" do
      secret = DIDComm::Keys::SignKeysSelector.find_signing_key("did:example:alice#key-1", resolvers_alice)
      expect(secret).not_to be_nil
      expect(secret.kid).to eq("did:example:alice#key-1")
    end
  end

  describe "AnoncryptKeysSelector nil check" do
    it "raises when first verification method is not found" do
      # Create a DID doc with key_agreement referencing a non-existent VM
      bad_doc = DIDComm::DIDDoc.new(
        id: "did:example:bad",
        key_agreement: ["did:example:bad#nonexistent-key"],
        verification_method: []
      )
      resolver = DIDComm::DIDResolverInMemory.new([bad_doc])
      config = DIDComm::ResolversConfig.new(
        did_resolver: resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new([])
      )

      expect {
        DIDComm::Keys::AnoncryptKeysSelector.find_pack_recipient_public_keys("did:example:bad", config)
      }.to raise_error(DID::UrlNotFoundError, /Verification method/)
    end
  end

  describe "AuthcryptKeysSelector validation" do
    it "raises when sender has no key_agreement keys" do
      empty_doc = DIDComm::DIDDoc.new(
        id: "did:example:empty",
        key_agreement: [],
        verification_method: []
      )
      resolver = DIDComm::DIDResolverInMemory.new([empty_doc, TestVectors.bob_did_doc])
      config = DIDComm::ResolversConfig.new(
        did_resolver: resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new([])
      )

      expect {
        DIDComm::Keys::AuthcryptKeysSelector.find_pack_sender_and_recipient_keys(
          "did:example:empty", "did:example:bob", config
        )
      }.to raise_error(DID::UrlNotFoundError, /No keyAgreement keys for sender/)
    end

    it "raises when recipient has no key_agreement keys" do
      empty_doc = DIDComm::DIDDoc.new(
        id: "did:example:empty",
        key_agreement: [],
        verification_method: []
      )
      resolver = DIDComm::DIDResolverInMemory.new([TestVectors.alice_did_doc, empty_doc])
      config = DIDComm::ResolversConfig.new(
        did_resolver: resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(TestVectors.alice_secrets)
      )

      expect {
        DIDComm::Keys::AuthcryptKeysSelector.find_pack_sender_and_recipient_keys(
          "did:example:alice", "did:example:empty", config
        )
      }.to raise_error(DID::UrlNotFoundError, /No keyAgreement keys for recipient/)
    end

    it "raises when sender kid is not in key_agreement on unpack" do
      # Create a DID doc where the kid exists as a VM but isn't in key_agreement
      doc_with_auth_only = DIDComm::DIDDoc.new(
        id: "did:example:authonly",
        authentication: ["did:example:authonly#key-1"],
        key_agreement: [],
        verification_method: [
          DIDComm::VerificationMethod.new(
            id: "did:example:authonly#key-1",
            controller: "did:example:authonly",
            type: DIDComm::VerificationMethodType::JSON_WEB_KEY_2020,
            verification_material: DIDComm::VerificationMaterial.new(
              format: DIDComm::VerificationMaterialFormat::JWK,
              value: { "kty" => "OKP", "crv" => "X25519", "x" => "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs" }
            )
          )
        ]
      )
      resolver = DIDComm::DIDResolverInMemory.new([doc_with_auth_only, TestVectors.bob_did_doc])
      config = DIDComm::ResolversConfig.new(
        did_resolver: resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(TestVectors.bob_secrets)
      )

      expect {
        DIDComm::Keys::AuthcryptKeysSelector.find_unpack_sender_and_recipient_keys(
          "did:example:authonly#key-1",
          ["did:example:bob#key-x25519-1"],
          config
        )
      }.to raise_error(DID::UrlNotFoundError, /not in key_agreement/)
    end
  end

  describe "FromPrior validation" do
    let(:resolvers_charlie) { TestVectors.resolvers_config_charlie }

    it "raises when from_prior iss is not a valid DID" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "not-a-did", "sub" => "did:example:alice" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::ValueError, /iss is not a valid DID/)
    end

    it "raises when from_prior iss is a DID URL with fragment" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "did:example:charlie#key-1", "sub" => "did:example:alice" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::ValueError, /iss must be a DID, not a DID URL/)
    end

    it "raises when from_prior sub is a DID URL with fragment" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "did:example:charlie", "sub" => "did:example:alice#key-1" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::ValueError, /sub must be a DID, not a DID URL/)
    end

    it "raises when from_prior sub is not a valid DID" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "did:example:charlie", "sub" => "not-a-did" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::ValueError, /sub is not a valid DID/)
    end

    it "raises when issuer_kid does not belong to iss" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "did:example:charlie", "sub" => "did:example:alice" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie,
                                                  issuer_kid: "did:example:alice#key-1")
      }.to raise_error(DIDComm::ValueError, /issuer_kid does not belong/)
    end

    it "raises when from_prior iss equals sub" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => { "iss" => "did:example:charlie", "sub" => "did:example:charlie" }
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::ValueError, /must differ/)
    end

    describe "unpack_from_prior validation" do
      it "raises when from_prior JWT has invalid typ" do
        # Build a JWT with wrong typ
        header = { "alg" => "EdDSA", "kid" => "did:example:charlie#key-1", "typ" => "WRONG" }
        payload = { "iss" => "did:example:charlie", "sub" => "did:example:alice" }
        header_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(header))
        payload_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(payload))
        fake_sig = DIDComm::Crypto::KeyUtils.base64url_encode("fakesig")

        msg_hash = {
          "id" => "test", "type" => "test", "body" => {},
          "from_prior" => "#{header_b64}.#{payload_b64}.#{fake_sig}"
        }

        expect {
          DIDComm::FromPriorModule.unpack_from_prior(msg_hash, resolvers_charlie)
        }.to raise_error(DIDComm::MalformedMessageError, /typ is not JWT/)
      end

      it "raises when from_prior kid is not a DID URL" do
        header = { "alg" => "EdDSA", "kid" => "not-a-did-url", "typ" => "JWT" }
        payload = { "iss" => "did:example:charlie", "sub" => "did:example:alice" }
        header_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(header))
        payload_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(payload))
        fake_sig = DIDComm::Crypto::KeyUtils.base64url_encode("fakesig")

        msg_hash = {
          "id" => "test", "type" => "test", "body" => {},
          "from_prior" => "#{header_b64}.#{payload_b64}.#{fake_sig}"
        }

        expect {
          DIDComm::FromPriorModule.unpack_from_prior(msg_hash, resolvers_charlie)
        }.to raise_error(DIDComm::MalformedMessageError, /kid is not a valid DID URL/)
      end
    end
  end

  describe "DIDCommMessageTypes short forms" do
    it "defines short form constants" do
      expect(DIDComm::DIDCommMessageTypes::ENCRYPTED_SHORT).to eq("didcomm-encrypted+json")
      expect(DIDComm::DIDCommMessageTypes::SIGNED_SHORT).to eq("didcomm-signed+json")
      expect(DIDComm::DIDCommMessageTypes::PLAINTEXT_SHORT).to eq("didcomm-plain+json")
    end
  end

  describe "pack_plaintext calls pack_from_prior" do
    it "packs from_prior JWT in plaintext message" do
      msg = DIDComm::Message.new(
        id: "test-fp",
        type: "http://example.com/test",
        from: "did:example:alice",
        to: ["did:example:bob"],
        body: { "test" => true },
        from_prior: DIDComm::FromPrior.new(
          iss: "did:example:charlie",
          sub: "did:example:alice"
        )
      )

      resolvers_charlie = TestVectors.resolvers_config_charlie
      result = DIDComm.pack_plaintext(msg, resolvers_config: resolvers_charlie)

      expect(result.from_prior_issuer_kid).to eq("did:example:charlie#key-1")
      parsed = JSON.parse(result.packed_msg)
      expect(parsed["from_prior"]).to be_a(String)
      expect(parsed["from_prior"].split(".").length).to eq(3)
    end

    it "returns nil from_prior_issuer_kid when no from_prior" do
      msg = DIDComm::Message.new(
        id: "test", type: "http://example.com/test", body: {}
      )
      result = DIDComm.pack_plaintext(msg, resolvers_config: resolvers_alice)
      expect(result.from_prior_issuer_kid).to be_nil
    end
  end

  describe "from_prior strictness" do
    it "raises when from_prior is present but not a Hash" do
      msg_hash = {
        "id" => "test", "type" => "test", "body" => {},
        "from_prior" => "already-a-jwt-string"
      }
      expect {
        DIDComm::FromPriorModule.pack_from_prior(msg_hash, resolvers_alice)
      }.to raise_error(DIDComm::MalformedMessageError, /from_prior plaintext is invalid/)
    end
  end

  describe "decrypt_by_all_keys" do
    it "succeeds in relaxed mode even if one key cannot decrypt" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      bad_bob_secrets = TestVectors.bob_secrets.map do |secret|
        next secret unless secret.kid == "did:example:bob#key-x25519-2"

        jwk = JSON.parse(secret.verification_material.value)
        jwk["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        DIDComm::Secret.new(
          kid: secret.kid, type: secret.type,
          verification_material: DIDComm::VerificationMaterial.new(
            format: secret.verification_material.format,
            value: JSON.generate(jwk)
          )
        )
      end

      bad_resolvers_bob = DIDComm::ResolversConfig.new(
        did_resolver: resolvers_bob.did_resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(bad_bob_secrets)
      )

      relaxed = DIDComm.unpack(pack_result.packed_msg, resolvers_config: bad_resolvers_bob)
      expect(relaxed.message.body).to eq(message.body)
    end

    it "raises in strict mode when one key cannot decrypt" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      bad_bob_secrets = TestVectors.bob_secrets.map do |secret|
        next secret unless secret.kid == "did:example:bob#key-x25519-2"

        jwk = JSON.parse(secret.verification_material.value)
        jwk["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        DIDComm::Secret.new(
          kid: secret.kid, type: secret.type,
          verification_material: DIDComm::VerificationMaterial.new(
            format: secret.verification_material.format,
            value: JSON.generate(jwk)
          )
        )
      end

      bad_resolvers_bob = DIDComm::ResolversConfig.new(
        did_resolver: resolvers_bob.did_resolver,
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(bad_bob_secrets)
      )

      expect {
        DIDComm.unpack(
          pack_result.packed_msg,
          resolvers_config: bad_resolvers_bob,
          unpack_config: DIDComm::UnpackConfig.new(expect_decrypt_by_all_keys: true)
        )
      }.to raise_error(DIDComm::MalformedMessageError, /Cannot decrypt by all/)
    end
  end

  describe "forward error propagation" do
    it "raises when forward wrapping fails instead of silently skipping" do
      bob_with_bad_service = TestVectors.bob_did_doc
      bob_with_bad_service.service = [
        DIDComm::DIDCommService.new(
          id: "did:example:bob#didcomm-1",
          service_endpoint: "https://mediator.example.com/inbox",
          routing_keys: ["did:example:unknown#key-1"],
          accept: ["didcomm/v2"]
        )
      ]

      bad_resolvers = DIDComm::ResolversConfig.new(
        did_resolver: DIDComm::DIDResolverInMemory.new([
          TestVectors.alice_did_doc, bob_with_bad_service, TestVectors.charlie_did_doc
        ]),
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(TestVectors.alice_secrets)
      )

      expect {
        DIDComm.pack_encrypted(message, to: "did:example:bob", resolvers_config: bad_resolvers)
      }.to raise_error(DID::DocumentNotResolvedError)
    end
  end

  describe "service_metadata from recipient service" do
    it "returns service_metadata from the recipient's DID doc, not routing key's" do
      bob_with_service = TestVectors.bob_did_doc
      bob_with_service.service = [
        DIDComm::DIDCommService.new(
          id: "did:example:bob#didcomm-1",
          service_endpoint: "https://bob-mediator.example.com/inbox",
          routing_keys: ["did:example:bob#key-x25519-1"],
          accept: ["didcomm/v2"]
        )
      ]

      routed_resolvers = DIDComm::ResolversConfig.new(
        did_resolver: DIDComm::DIDResolverInMemory.new([
          TestVectors.alice_did_doc, bob_with_service, TestVectors.charlie_did_doc
        ]),
        secrets_resolver: DIDComm::SecretsResolverInMemory.new(TestVectors.alice_secrets)
      )

      result = DIDComm.pack_encrypted(message, to: "did:example:bob", resolvers_config: routed_resolvers)
      expect(result.service_metadata).not_to be_nil
      expect(result.service_metadata.id).to eq("did:example:bob#didcomm-1")
      expect(result.service_metadata.service_endpoint).to eq("https://bob-mediator.example.com/inbox")
    end
  end
end
