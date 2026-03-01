# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe DIDComm::Attachment do
  it "round-trips Base64 attachment" do
    a = DIDComm::Attachment.new(
      data: DIDComm::AttachmentDataBase64.new(base64: "dGVzdA=="),
      id: "att-1", description: "test attachment"
    )
    h = a.to_hash
    expect(h["data"]["base64"]).to eq("dGVzdA==")

    parsed = DIDComm::Attachment.from_hash(h)
    expect(parsed.data).to be_a(DIDComm::AttachmentDataBase64)
    expect(parsed.data.base64).to eq("dGVzdA==")
    expect(parsed.description).to eq("test attachment")
  end

  it "round-trips JSON attachment" do
    a = DIDComm::Attachment.new(
      data: DIDComm::AttachmentDataJson.new(json: { "key" => "value" })
    )
    h = a.to_hash
    parsed = DIDComm::Attachment.from_hash(h)
    expect(parsed.data).to be_a(DIDComm::AttachmentDataJson)
    expect(parsed.data.json).to eq({ "key" => "value" })
  end

  it "round-trips Links attachment" do
    a = DIDComm::Attachment.new(
      data: DIDComm::AttachmentDataLinks.new(
        links: ["https://example.com/file"],
        data_hash: "abc123"
      )
    )
    h = a.to_hash
    parsed = DIDComm::Attachment.from_hash(h)
    expect(parsed.data).to be_a(DIDComm::AttachmentDataLinks)
    expect(parsed.data.links).to eq(["https://example.com/file"])
  end

  describe "data_hash accessor" do
    it "uses data_hash for the hash JSON field" do
      data = DIDComm::AttachmentDataBase64.new(base64: "dGVzdA==", data_hash: "sha256-abc")
      expect(data.data_hash).to eq("sha256-abc")

      h = data.to_hash
      expect(h["hash"]).to eq("sha256-abc")
    end

    it "round-trips hash field through JSON" do
      h = { "base64" => "dGVzdA==", "hash" => "sha256-xyz" }
      data = DIDComm::AttachmentDataBase64.from_hash(h)
      expect(data.data_hash).to eq("sha256-xyz")
      expect(data.to_hash["hash"]).to eq("sha256-xyz")
    end

    it "preserves Object#hash for use as Hash keys" do
      data1 = DIDComm::AttachmentDataJson.new(json: { "a" => 1 }, data_hash: "h1")
      data2 = DIDComm::AttachmentDataJson.new(json: { "b" => 2 }, data_hash: "h2")
      # Object#hash should return an Integer, not our data_hash string
      expect(data1.hash).to be_a(Integer)
      # Should be usable as Hash keys without collision
      map = { data1 => "first", data2 => "second" }
      expect(map[data1]).to eq("first")
      expect(map[data2]).to eq("second")
    end

    it "supports data_hash on AttachmentDataLinks" do
      data = DIDComm::AttachmentDataLinks.new(links: ["http://example.com"], data_hash: "sha-links")
      expect(data.data_hash).to eq("sha-links")
      expect(data.to_hash["hash"]).to eq("sha-links")
    end
  end

  it "includes message with attachments" do
    msg = DIDComm::Message.new(
      type: "test", body: {},
      attachments: [
        DIDComm::Attachment.new(
          id: "123",
          data: DIDComm::AttachmentDataBase64.new(base64: "qwerty"),
          description: "abc",
          filename: "test.txt",
          media_type: "text/plain",
          format: "text",
          lastmod_time: 123,
          byte_count: 6
        )
      ]
    )
    h = msg.to_hash
    expect(h["attachments"].length).to eq(1)
    expect(h["attachments"][0]["data"]["base64"]).to eq("qwerty")
    expect(h["attachments"][0]["id"]).to eq("123")

    parsed = DIDComm::Message.from_hash(h)
    expect(parsed.attachments.length).to eq(1)
    expect(parsed.attachments[0].data.base64).to eq("qwerty")
  end
end
