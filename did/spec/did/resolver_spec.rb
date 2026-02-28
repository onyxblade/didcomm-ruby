# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe DID::ResolverInMemory do
  let(:doc) { DID::Document.new(id: "did:example:alice") }
  let(:resolver) { DID::ResolverInMemory.new([doc]) }

  it "resolves known DIDs" do
    result = resolver.resolve("did:example:alice")
    expect(result).not_to be_nil
    expect(result.id).to eq("did:example:alice")
  end

  it "returns nil for unknown DIDs" do
    expect(resolver.resolve("did:example:unknown")).to be_nil
  end
end

RSpec.describe DID::Resolver do
  it "raises NotImplementedError for unimplemented resolve" do
    klass = Class.new { include DID::Resolver }
    expect { klass.new.resolve("did:example:test") }.to raise_error(NotImplementedError)
  end
end
