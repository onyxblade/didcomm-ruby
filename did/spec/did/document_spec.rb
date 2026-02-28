# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe DID::Document do
  let(:vm1) do
    DID::VerificationMethod.new(
      id: "did:example:alice#key-1",
      type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
      controller: "did:example:alice",
      verification_material: DID::VerificationMaterial.new(format: DID::VerificationMaterialFormat::JWK, value: "{}")
    )
  end

  let(:vm2) do
    DID::VerificationMethod.new(
      id: "did:example:alice#key-x25519-1",
      type: DID::VerificationMethodType::X25519_KEY_AGREEMENT_KEY_2019,
      controller: "did:example:alice",
      verification_material: DID::VerificationMaterial.new(format: DID::VerificationMaterialFormat::JWK, value: "{}")
    )
  end

  let(:doc) do
    DID::Document.new(
      id: "did:example:alice",
      authentication: ["did:example:alice#key-1"],
      key_agreement: ["did:example:alice#key-x25519-1"],
      verification_method: [vm1, vm2]
    )
  end

  it "resolves verification methods by ID" do
    vm = doc.get_verification_method("did:example:alice#key-1")
    expect(vm).not_to be_nil
    expect(vm.type).to eq(DID::VerificationMethodType::JSON_WEB_KEY_2020)
  end

  it "returns nil for unknown verification method" do
    vm = doc.get_verification_method("did:example:alice#unknown")
    expect(vm).to be_nil
  end

  it "lists authentication methods" do
    methods = doc.authentication_methods
    expect(methods.length).to eq(1)
    expect(methods.map(&:id)).to include("did:example:alice#key-1")
  end

  it "lists key agreement methods" do
    methods = doc.key_agreement_methods
    expect(methods.length).to eq(1)
    expect(methods.map(&:id)).to include("did:example:alice#key-x25519-1")
  end

  it "defaults collections to empty arrays" do
    doc = DID::Document.new(id: "did:example:minimal")
    expect(doc.authentication).to eq([])
    expect(doc.key_agreement).to eq([])
    expect(doc.verification_method).to eq([])
    expect(doc.service).to eq([])
  end
end
