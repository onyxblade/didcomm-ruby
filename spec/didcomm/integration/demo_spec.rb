# frozen_string_literal: true

require_relative "../didcomm_helper"

RSpec.describe "DIDComm Integration" do
  let(:message) { TestVectors.test_message }
  let(:resolvers_alice) { TestVectors.resolvers_config_alice }
  let(:resolvers_bob) { TestVectors.resolvers_config_bob }

  describe "Plaintext" do
    it "packs and unpacks plaintext message" do
      pack_result = DIDComm.pack_plaintext(message, resolvers_config: resolvers_alice)
      expect(pack_result.packed_msg).to be_a(String)

      parsed = JSON.parse(pack_result.packed_msg)
      expect(parsed["id"]).to eq("1234567890")
      expect(parsed["type"]).to eq("http://example.com/protocols/lets_do_lunch/1.0/proposal")
      expect(parsed["from"]).to eq("did:example:alice")
      expect(parsed["to"]).to eq(["did:example:bob"])
      expect(parsed["body"]).to eq({ "messagespecificattribute" => "and its value" })
      expect(parsed["typ"]).to eq("application/didcomm-plain+json")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message).to be_a(DIDComm::Message)
      expect(unpack_result.message.type).to eq("http://example.com/protocols/lets_do_lunch/1.0/proposal")
      expect(unpack_result.message.body).to eq({ "messagespecificattribute" => "and its value" })
      expect(unpack_result.metadata.encrypted).to eq(false)
      expect(unpack_result.metadata.authenticated).to eq(false)
      expect(unpack_result.metadata.non_repudiation).to eq(false)
    end

    it "round-trips message fields" do
      pack_result = DIDComm.pack_plaintext(message, resolvers_config: resolvers_alice)
      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      msg = unpack_result.message

      expect(msg.id).to eq("1234567890")
      expect(msg.from).to eq("did:example:alice")
      expect(msg.to).to eq(["did:example:bob"])
      expect(msg.created_time).to eq(1516269022)
      expect(msg.expires_time).to eq(1516385931)
    end
  end

  describe "Signed (non-repudiation)" do
    it "packs and unpacks signed message with Ed25519" do
      pack_result = DIDComm.pack_signed(message, sign_from: "did:example:alice",
                                         resolvers_config: resolvers_alice)
      expect(pack_result.packed_msg).to be_a(String)
      expect(pack_result.sign_from_kid).to eq("did:example:alice#key-1")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.type).to eq(message.type)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.non_repudiation).to eq(true)
      expect(unpack_result.metadata.authenticated).to eq(true)
      expect(unpack_result.metadata.sign_from).to eq("did:example:alice#key-1")
      expect(unpack_result.metadata.sign_alg).to eq(DIDComm::SignAlg::ED25519)
    end

    it "packs and unpacks signed message with P-256" do
      pack_result = DIDComm.pack_signed(message, sign_from: "did:example:alice#key-2",
                                         resolvers_config: resolvers_alice)
      expect(pack_result.sign_from_kid).to eq("did:example:alice#key-2")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.metadata.sign_alg).to eq(DIDComm::SignAlg::ES256)
    end

    it "packs and unpacks signed message with secp256k1" do
      pack_result = DIDComm.pack_signed(message, sign_from: "did:example:alice#key-3",
                                         resolvers_config: resolvers_alice)
      expect(pack_result.sign_from_kid).to eq("did:example:alice#key-3")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.metadata.sign_alg).to eq(DIDComm::SignAlg::ES256K)
    end
  end

  describe "Anonymous encryption (anoncrypt)" do
    it "packs and unpacks with X25519 XC20P" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::XC20P_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      expect(pack_result.packed_msg).to be_a(String)
      expect(pack_result.from_kid).to be_nil

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.anonymous_sender).to eq(true)
      expect(unpack_result.metadata.authenticated).to eq(false)
      expect(unpack_result.metadata.enc_alg_anon).to eq(DIDComm::AnonCryptAlg::XC20P_ECDH_ES_A256KW)
    end

    it "packs and unpacks with A256GCM" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::A256GCM_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.enc_alg_anon).to eq(DIDComm::AnonCryptAlg::A256GCM_ECDH_ES_A256KW)
    end

    it "packs and unpacks with A256CBC-HS512" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.enc_alg_anon).to eq(DIDComm::AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW)
    end

    it "packs and unpacks with P-256 keys" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob#key-p256-1",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::XC20P_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
    end
  end

  describe "Authenticated encryption (authcrypt)" do
    it "packs and unpacks authcrypt with X25519" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      expect(pack_result.from_kid).to eq("did:example:alice#key-x25519-1")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.authenticated).to eq(true)
      expect(unpack_result.metadata.anonymous_sender).to eq(false)
      expect(unpack_result.metadata.encrypted_from).to eq("did:example:alice#key-x25519-1")
      expect(unpack_result.metadata.enc_alg_auth).to eq(DIDComm::AuthCryptAlg::A256CBC_HS512_ECDH_1PU_A256KW)
    end

    it "packs and unpacks authcrypt with P-256" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob#key-p256-1",
                                            from: "did:example:alice#key-p256-1",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      expect(pack_result.from_kid).to eq("did:example:alice#key-p256-1")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.authenticated).to eq(true)
    end
  end

  describe "Signed + Encrypted (non-repudiation)" do
    it "sign then encrypt with Ed25519/X25519" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            from: "did:example:alice",
                                            sign_from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      expect(pack_result.sign_from_kid).to eq("did:example:alice#key-1")
      expect(pack_result.from_kid).to eq("did:example:alice#key-x25519-1")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.authenticated).to eq(true)
      expect(unpack_result.metadata.non_repudiation).to eq(true)
      expect(unpack_result.metadata.sign_from).to eq("did:example:alice#key-1")
      expect(unpack_result.metadata.sign_alg).to eq(DIDComm::SignAlg::ED25519)
    end
  end

  describe "Protected sender" do
    it "hides sender identity with anoncrypt wrapper" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              protect_sender_id: true,
                                              forward: false
                                            ))

      # First layer is anoncrypt
      parsed = JSON.parse(pack_result.packed_msg)
      protected_header = JSON.parse(
        DIDComm::Crypto::KeyUtils.base64url_decode(parsed["protected"]).force_encoding("UTF-8")
      )
      expect(protected_header["alg"]).to start_with("ECDH-ES")

      # Unpack should still work (two layers)
      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.authenticated).to eq(true)
    end
  end
end
