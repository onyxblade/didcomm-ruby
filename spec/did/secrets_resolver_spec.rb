# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe DID::SecretsResolverInMemory do
  let(:secret1) do
    DID::Secret.new(
      kid: "did:example:alice#key-1",
      type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
      verification_material: DID::VerificationMaterial.new(format: DID::VerificationMaterialFormat::JWK, value: "{}")
    )
  end

  let(:secret2) do
    DID::Secret.new(
      kid: "did:example:alice#key-2",
      type: DID::VerificationMethodType::JSON_WEB_KEY_2020,
      verification_material: DID::VerificationMaterial.new(format: DID::VerificationMaterialFormat::JWK, value: "{}")
    )
  end

  let(:resolver) { DID::SecretsResolverInMemory.new([secret1, secret2]) }

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

RSpec.describe DID::SecretsResolver do
  it "raises NotImplementedError for unimplemented methods" do
    klass = Class.new { include DID::SecretsResolver }
    instance = klass.new
    expect { instance.get_key("kid") }.to raise_error(NotImplementedError)
    expect { instance.get_keys(["kid"]) }.to raise_error(NotImplementedError)
  end
end
