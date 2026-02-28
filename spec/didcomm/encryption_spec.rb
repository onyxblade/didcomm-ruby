# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "Encryption with various curves" do
  let(:message) { TestVectors.test_message }
  let(:resolvers_alice) { TestVectors.resolvers_config_alice }
  let(:resolvers_bob) { TestVectors.resolvers_config_bob }

  describe "Anoncrypt with P-384" do
    it "encrypts and decrypts with A256CBC-HS512" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob#key-p384-1",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::A256CBC_HS512_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.anonymous_sender).to eq(true)
    end
  end

  describe "Anoncrypt with P-521" do
    it "encrypts and decrypts with A256GCM" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob#key-p521-1",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::A256GCM_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
    end
  end

  describe "Anoncrypt multi-recipient" do
    it "encrypts for all X25519 recipients" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(
                                              enc_alg_anon: DIDComm::AnonCryptAlg::XC20P_ECDH_ES_A256KW,
                                              forward: false
                                            ))

      # Should have multiple to_kids (all X25519 keys)
      expect(pack_result.to_kids.length).to be >= 2

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
    end
  end

  describe "Authcrypt with P-521" do
    it "encrypts and decrypts" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob#key-p521-1",
                                            from: "did:example:alice#key-p521-1",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      expect(pack_result.from_kid).to eq("did:example:alice#key-p521-1")

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.message.body).to eq(message.body)
      expect(unpack_result.metadata.authenticated).to eq(true)
      expect(unpack_result.metadata.encrypted_from).to eq("did:example:alice#key-p521-1")
    end
  end

  describe "Signed + Anoncrypt" do
    it "signs then anon-encrypts" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            sign_from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      expect(pack_result.sign_from_kid).to eq("did:example:alice#key-1")
      expect(pack_result.from_kid).to be_nil

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.metadata.encrypted).to eq(true)
      expect(unpack_result.metadata.anonymous_sender).to eq(true)
      expect(unpack_result.metadata.non_repudiation).to eq(true)
      expect(unpack_result.metadata.sign_from).to eq("did:example:alice#key-1")
    end
  end

  describe "Error cases" do
    it "raises on unknown recipient DID" do
      msg = TestVectors.test_message
      msg.to = nil
      expect {
        DIDComm.pack_encrypted(msg, to: "did:example:unknown",
                                resolvers_config: resolvers_alice,
                                pack_config: DIDComm::PackEncryptedConfig.new(forward: false))
      }.to raise_error(DID::DocumentNotResolvedError)
    end

    it "raises on tampered ciphertext" do
      pack_result = DIDComm.pack_encrypted(message, to: "did:example:bob",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncryptedConfig.new(forward: false))

      tampered = JSON.parse(pack_result.packed_msg)
      tampered["ciphertext"] = "AAAA" + tampered["ciphertext"][4..]

      expect {
        DIDComm.unpack(JSON.generate(tampered), resolvers_config: resolvers_bob)
      }.to raise_error(DIDComm::MalformedMessageError)
    end
  end
end
