# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe DIDComm::Protocols::Routing::Forward do
  it "detects forward messages" do
    fwd = {
      "type" => "https://didcomm.org/routing/2.0/forward",
      "body" => { "next" => "did:example:bob" },
      "attachments" => [{ "data" => { "json" => { "test" => true } } }]
    }
    expect(DIDComm::Protocols::Routing::Forward.forward?(fwd)).to be true
  end

  it "rejects non-forward messages" do
    msg = { "type" => "http://example.com/test", "body" => {} }
    expect(DIDComm::Protocols::Routing::Forward.forward?(msg)).to be false
  end

  it "parses forward messages" do
    inner = { "encrypted" => "data" }
    fwd = {
      "type" => "https://didcomm.org/routing/2.0/forward",
      "body" => { "next" => "did:example:bob" },
      "attachments" => [{ "data" => { "json" => inner } }]
    }
    parsed = DIDComm::Protocols::Routing::Forward.parse(fwd)
    expect(parsed[:next]).to eq("did:example:bob")
    expect(parsed[:forwarded_msg]).to eq(inner)
  end
end
