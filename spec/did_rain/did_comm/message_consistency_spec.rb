# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "Message consistency verification" do
  def verify(msg_hash, metadata)
    DIDComm::Unpack.send(:verify_message_consistency, msg_hash, metadata)
  end

  describe "encrypted_from consistency" do
    it "passes when encrypted_from DID matches message from" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_from = "did:example:alice#key-x25519-1"
      msg_hash = { "from" => "did:example:alice", "to" => ["did:example:bob"], "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "raises when encrypted_from DID does not match message from" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_from = "did:example:evil#key-1"
      msg_hash = { "from" => "did:example:alice", "to" => ["did:example:bob"], "body" => {} }
      expect {
        verify(msg_hash, metadata)
      }.to raise_error(DIDComm::MalformedMessageError, /Mismatch between encrypted_from DID/)
    end

    it "skips check when encrypted_from is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      msg_hash = { "from" => "did:example:alice", "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "skips check when message from is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_from = "did:example:alice#key-1"
      msg_hash = { "to" => ["did:example:bob"], "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end
  end

  describe "encrypted_to consistency" do
    it "passes when all encrypted_to DIDs are in message to" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_to = ["did:example:bob#key-x25519-1", "did:example:bob#key-x25519-2"]
      msg_hash = { "to" => ["did:example:bob"], "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "raises when encrypted_to DID is not in message to" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_to = ["did:example:charlie#key-1"]
      msg_hash = { "to" => ["did:example:bob"], "body" => {} }
      expect {
        verify(msg_hash, metadata)
      }.to raise_error(DIDComm::MalformedMessageError, /encrypted_to kid DID.*not found in message to/)
    end

    it "skips check when encrypted_to is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      msg_hash = { "to" => ["did:example:bob"], "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "skips check when message to is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_to = ["did:example:bob#key-1"]
      msg_hash = { "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "skips check when message to is not an array" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.encrypted_to = ["did:example:bob#key-1"]
      msg_hash = { "to" => "did:example:bob", "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end
  end

  describe "sign_from consistency" do
    it "passes when sign_from DID matches message from" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.sign_from = "did:example:alice#key-1"
      msg_hash = { "from" => "did:example:alice", "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "raises when sign_from DID does not match message from" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.sign_from = "did:example:evil#key-1"
      msg_hash = { "from" => "did:example:alice", "body" => {} }
      expect {
        verify(msg_hash, metadata)
      }.to raise_error(DIDComm::MalformedMessageError, /Mismatch between sign_from DID/)
    end

    it "skips check when sign_from is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      msg_hash = { "from" => "did:example:alice", "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end

    it "skips check when message from is nil" do
      metadata = DIDComm::Unpack::Metadata.new
      metadata.sign_from = "did:example:alice#key-1"
      msg_hash = { "body" => {} }
      expect { verify(msg_hash, metadata) }.not_to raise_error
    end
  end

  describe "integration: consistency through full pack/unpack" do
    let(:message) { TestVectors.test_message }
    let(:resolvers_alice) { TestVectors.resolvers_config_alice }
    let(:resolvers_bob) { TestVectors.resolvers_config_bob }

    it "passes for a valid authcrypt round-trip" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncrypted::Config.new(forward: false))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.metadata.encrypted_from).to start_with("did:example:alice#")
      expect(unpack_result.message.from).to eq("did:example:alice")
    end

    it "passes for a valid signed + anoncrypt round-trip" do
      pack_result = DIDComm.pack_encrypted(message,
                                            to: "did:example:bob",
                                            sign_from: "did:example:alice",
                                            resolvers_config: resolvers_alice,
                                            pack_config: DIDComm::PackEncrypted::Config.new(forward: false))

      unpack_result = DIDComm.unpack(pack_result.packed_msg, resolvers_config: resolvers_bob)
      expect(unpack_result.metadata.sign_from).to start_with("did:example:alice#")
      expect(unpack_result.message.from).to eq("did:example:alice")
    end
  end
end
