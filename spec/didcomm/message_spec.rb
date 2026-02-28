# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe DIDComm::Message do
  describe "#to_hash" do
    it "serializes all fields" do
      msg = DIDComm::Message.new(
        id: "test-123",
        type: "https://example.com/test",
        body: { "key" => "value" },
        from: "did:example:alice",
        to: ["did:example:bob"],
        created_time: 100,
        expires_time: 200,
        thid: "thread-1",
        pthid: "parent-1"
      )

      h = msg.to_hash
      expect(h["id"]).to eq("test-123")
      expect(h["type"]).to eq("https://example.com/test")
      expect(h["body"]).to eq({ "key" => "value" })
      expect(h["from"]).to eq("did:example:alice")
      expect(h["to"]).to eq(["did:example:bob"])
      expect(h["created_time"]).to eq(100)
      expect(h["expires_time"]).to eq(200)
      expect(h["thid"]).to eq("thread-1")
      expect(h["pthid"]).to eq("parent-1")
      expect(h["typ"]).to eq("application/didcomm-plain+json")
    end

    it "auto-generates id" do
      msg = DIDComm::Message.new(type: "test", body: {})
      expect(msg.id).to match(/\A[0-9a-f-]+\z/)
    end

    it "does not default thid to id" do
      msg = DIDComm::Message.new(id: "my-id", type: "test", body: {})
      expect(msg.thid).to be_nil
    end

    it "does not serialize thid when nil" do
      msg = DIDComm::Message.new(id: "my-id", type: "test", body: {})
      h = msg.to_hash
      expect(h).not_to have_key("thid")
    end

    it "preserves explicit thid" do
      msg = DIDComm::Message.new(id: "my-id", type: "test", body: {}, thid: "thread-1")
      expect(msg.thid).to eq("thread-1")
      h = msg.to_hash
      expect(h["thid"]).to eq("thread-1")
    end

    it "omits nil fields" do
      msg = DIDComm::Message.new(type: "test", body: {})
      h = msg.to_hash
      expect(h).not_to have_key("from")
      expect(h).not_to have_key("to")
      expect(h).not_to have_key("pthid")
    end

    it "includes custom headers" do
      msg = DIDComm::Message.new(
        type: "test", body: {},
        custom_headers: { "my_header" => "my_value" }
      )
      h = msg.to_hash
      expect(h["my_header"]).to eq("my_value")
      expect(h).not_to have_key("custom_headers")
    end
  end

  describe ".from_hash" do
    it "parses a valid message" do
      h = {
        "id" => "123", "type" => "test", "body" => { "key" => "val" },
        "from" => "did:example:alice", "to" => ["did:example:bob"],
        "typ" => "application/didcomm-plain+json"
      }
      msg = DIDComm::Message.from_hash(h)
      expect(msg.id).to eq("123")
      expect(msg.type).to eq("test")
      expect(msg.body).to eq({ "key" => "val" })
      expect(msg.from).to eq("did:example:alice")
    end

    it "raises on missing required fields" do
      expect { DIDComm::Message.from_hash({}) }.to raise_error(DIDComm::MalformedMessageError)
      expect { DIDComm::Message.from_hash({ "id" => "1" }) }.to raise_error(DIDComm::MalformedMessageError)
    end

    it "raises on invalid typ" do
      h = { "id" => "1", "type" => "t", "body" => {}, "typ" => "wrong" }
      expect { DIDComm::Message.from_hash(h) }.to raise_error(DIDComm::MalformedMessageError)
    end

    it "accepts short-form plaintext typ" do
      h = { "id" => "1", "type" => "t", "body" => {}, "typ" => "didcomm-plain+json" }
      msg = DIDComm::Message.from_hash(h)
      expect(msg.id).to eq("1")
    end

    it "preserves custom headers" do
      h = { "id" => "1", "type" => "t", "body" => {}, "custom_field" => 42 }
      msg = DIDComm::Message.from_hash(h)
      expect(msg.custom_headers).to eq({ "custom_field" => 42 })
    end

    it "round-trips through JSON" do
      msg = DIDComm::Message.new(
        id: "test", type: "https://example.com/test",
        body: { "nested" => { "deep" => true } },
        from: "did:example:alice"
      )
      json = msg.to_json
      parsed = DIDComm::Message.from_json(json)
      expect(parsed.id).to eq(msg.id)
      expect(parsed.type).to eq(msg.type)
      expect(parsed.body).to eq(msg.body)
    end
  end
end
