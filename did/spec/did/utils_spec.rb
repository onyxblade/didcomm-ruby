# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe DID::Utils do
  describe ".is_did" do
    it "accepts bare DIDs" do
      expect(described_class.is_did("did:example:alice")).to be true
      expect(described_class.is_did("did:key:z6Mkf5rG")).to be true
      expect(described_class.is_did("did:web:example.com")).to be true
    end

    it "accepts DID URLs with fragment" do
      expect(described_class.is_did("did:example:alice#key-1")).to be true
    end

    it "accepts method-specific-id with colons" do
      expect(described_class.is_did("did:web:example.com:path:sub")).to be true
    end

    it "rejects strings without did: prefix" do
      expect(described_class.is_did("not-a-did")).to be false
      expect(described_class.is_did("http://example.com")).to be false
    end

    it "rejects empty method-specific-id" do
      expect(described_class.is_did("did:example:")).to be false
    end
  end

  describe ".is_did_url" do
    it "accepts DID URLs with fragment" do
      expect(described_class.is_did_url("did:example:alice#key-1")).to be true
    end

    it "rejects bare DIDs without fragment" do
      expect(described_class.is_did_url("did:example:alice")).to be false
    end
  end

  describe ".did_from_did_url" do
    it "extracts DID from DID URL" do
      expect(described_class.did_from_did_url("did:example:alice#key-1")).to eq("did:example:alice")
    end
  end

  describe ".did_or_url" do
    it "splits DID URL into DID and full URL" do
      did, kid = described_class.did_or_url("did:example:alice#key-1")
      expect(did).to eq("did:example:alice")
      expect(kid).to eq("did:example:alice#key-1")
    end

    it "returns bare DID with nil kid" do
      did, kid = described_class.did_or_url("did:example:alice")
      expect(did).to eq("did:example:alice")
      expect(kid).to be_nil
    end
  end
end
