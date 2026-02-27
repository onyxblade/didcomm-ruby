# frozen_string_literal: true

require "spec_helper"

RSpec.describe DIDComm::DIDDoc do
  let(:doc) { TestVectors.alice_did_doc }

  it "resolves verification methods by ID" do
    vm = doc.get_verification_method("did:example:alice#key-1")
    expect(vm).not_to be_nil
    expect(vm.type).to eq(DIDComm::VerificationMethodType::JSON_WEB_KEY_2020)
  end

  it "returns nil for unknown verification method" do
    vm = doc.get_verification_method("did:example:alice#unknown")
    expect(vm).to be_nil
  end

  it "lists authentication methods" do
    methods = doc.authentication_methods
    expect(methods.length).to eq(3)
    expect(methods.map(&:id)).to include("did:example:alice#key-1")
  end

  it "lists key agreement methods" do
    methods = doc.key_agreement_methods
    expect(methods.length).to eq(3)
    expect(methods.map(&:id)).to include("did:example:alice#key-x25519-1")
  end
end

RSpec.describe DIDComm::DIDResolverInMemory do
  it "resolves known DIDs" do
    resolver = DIDComm::DIDResolverInMemory.new([TestVectors.alice_did_doc])
    doc = resolver.resolve("did:example:alice")
    expect(doc).not_to be_nil
    expect(doc.id).to eq("did:example:alice")
  end

  it "returns nil for unknown DIDs" do
    resolver = DIDComm::DIDResolverInMemory.new([])
    expect(resolver.resolve("did:example:unknown")).to be_nil
  end
end

RSpec.describe DIDComm::SecretsResolverInMemory do
  let(:resolver) { DIDComm::SecretsResolverInMemory.new(TestVectors.alice_secrets) }

  it "finds a key by kid" do
    secret = resolver.get_key("did:example:alice#key-1")
    expect(secret).not_to be_nil
    expect(secret.kid).to eq("did:example:alice#key-1")
  end

  it "returns nil for unknown kid" do
    expect(resolver.get_key("did:example:unknown#key")).to be_nil
  end

  it "finds multiple keys" do
    kids = resolver.get_keys(["did:example:alice#key-1", "did:example:alice#key-2", "did:example:unknown#key"])
    expect(kids).to contain_exactly("did:example:alice#key-1", "did:example:alice#key-2")
  end

  it "preserves caller's key order" do
    kids = resolver.get_keys(["did:example:alice#key-2", "did:example:alice#key-1"])
    expect(kids).to eq(["did:example:alice#key-2", "did:example:alice#key-1"])
  end
end

RSpec.describe "DIDDoc#get_didcomm_service accept filter" do
  it "returns service with empty accept list" do
    doc = DIDComm::DIDDoc.new(
      id: "did:example:test",
      service: [
        DIDComm::DIDCommService.new(id: "svc-1", service_endpoint: "http://example.com", accept: [])
      ]
    )
    expect(doc.get_didcomm_service).not_to be_nil
  end

  it "returns service that accepts didcomm/v2" do
    doc = DIDComm::DIDDoc.new(
      id: "did:example:test",
      service: [
        DIDComm::DIDCommService.new(id: "svc-1", service_endpoint: "http://example.com", accept: ["didcomm/v2"])
      ]
    )
    expect(doc.get_didcomm_service).not_to be_nil
  end

  it "rejects service that only accepts didcomm/v1" do
    doc = DIDComm::DIDDoc.new(
      id: "did:example:test",
      service: [
        DIDComm::DIDCommService.new(id: "svc-1", service_endpoint: "http://example.com", accept: ["didcomm/v1"])
      ]
    )
    expect(doc.get_didcomm_service).to be_nil
  end

  it "picks the first compatible service" do
    doc = DIDComm::DIDDoc.new(
      id: "did:example:test",
      service: [
        DIDComm::DIDCommService.new(id: "svc-v1", service_endpoint: "http://v1.example.com", accept: ["didcomm/v1"]),
        DIDComm::DIDCommService.new(id: "svc-v2", service_endpoint: "http://v2.example.com", accept: ["didcomm/v2"])
      ]
    )
    svc = doc.get_didcomm_service
    expect(svc.id).to eq("svc-v2")
  end
end
