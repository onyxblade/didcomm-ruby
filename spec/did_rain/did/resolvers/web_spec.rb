# frozen_string_literal: true

require_relative "../../../spec_helper"

RSpec.describe DIDRain::DID::Resolvers::Web do
  def did_document_json(id, extras = {})
    doc = {
      "id" => id,
      "verificationMethod" => [
        {
          "id" => "#{id}#key-0",
          "type" => "JsonWebKey2020",
          "controller" => id,
          "publicKeyJwk" => {
            "kty" => "OKP",
            "crv" => "Ed25519",
            "x" => "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU"
          }
        }
      ],
      "authentication" => ["#{id}#key-0"]
    }.merge(extras)
    JSON.generate(doc)
  end

  describe ".did_to_url" do
    it "converts a domain-only DID to a .well-known URL" do
      expect(described_class.did_to_url("did:web:example.com"))
        .to eq("https://example.com/.well-known/did.json")
    end

    it "converts a DID with path to a nested URL" do
      expect(described_class.did_to_url("did:web:example.com:user:alice"))
        .to eq("https://example.com/user/alice/did.json")
    end

    it "decodes percent-encoded port" do
      expect(described_class.did_to_url("did:web:example.com%3A3000"))
        .to eq("https://example.com:3000/.well-known/did.json")
    end

    it "decodes percent-encoded port with path" do
      expect(described_class.did_to_url("did:web:example.com%3A3000:user:alice"))
        .to eq("https://example.com:3000/user/alice/did.json")
    end

    it "raises InvalidDocumentError for a malformed DID" do
      expect { described_class.did_to_url("did:web") }
        .to raise_error(DIDRain::DID::InvalidDocumentError, /Malformed/)
    end

    it "raises InvalidDocumentError for an IP address" do
      expect { described_class.did_to_url("did:web:192.168.1.1") }
        .to raise_error(DIDRain::DID::InvalidDocumentError, /IP address/)
    end

    it "raises InvalidDocumentError for a non-did:web identifier" do
      expect { described_class.did_to_url("did:key:z6Mkf5rGMoatrSj1f") }
        .to raise_error(DIDRain::DID::InvalidDocumentError, /Not a did:web/)
    end
  end

  describe "#resolve" do
    context "with a valid did:web" do
      let(:did) { "did:web:example.com" }
      let(:fetcher) { ->(url) { did_document_json(did) } }
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "returns a Document with the correct id" do
        doc = resolver.resolve(did)
        expect(doc).to be_a(DIDRain::DID::Document)
        expect(doc.id).to eq(did)
      end

      it "passes the correct URL to the fetcher" do
        received_url = nil
        capturing_fetcher = ->(url) { received_url = url; did_document_json(did) }
        resolver = described_class.new(fetcher: capturing_fetcher)

        resolver.resolve(did)
        expect(received_url).to eq("https://example.com/.well-known/did.json")
      end

      it "parses verification methods" do
        doc = resolver.resolve(did)
        expect(doc.verification_method.size).to eq(1)

        vm = doc.verification_method.first
        expect(vm.id).to eq("#{did}#key-0")
        expect(vm.type).to eq(DIDRain::DID::VerificationMethodType::JSON_WEB_KEY_2020)
        expect(vm.controller).to eq(did)
      end

      it "parses authentication references" do
        doc = resolver.resolve(did)
        expect(doc.authentication).to eq(["#{did}#key-0"])
      end
    end

    context "with a path-based DID" do
      let(:did) { "did:web:example.com:user:alice" }

      it "fetches from the correct URL" do
        received_url = nil
        fetcher = ->(url) { received_url = url; did_document_json(did) }
        resolver = described_class.new(fetcher: fetcher)

        resolver.resolve(did)
        expect(received_url).to eq("https://example.com/user/alice/did.json")
      end
    end

    context "with a non-did:web DID" do
      let(:fetcher) { ->(_url) { raise "should not be called" } }
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "returns nil" do
        expect(resolver.resolve("did:key:z6Mkf5rGMoatrSj1f")).to be_nil
        expect(resolver.resolve("did:example:123")).to be_nil
      end
    end

    context "when the document id does not match the DID" do
      let(:did) { "did:web:example.com" }
      let(:fetcher) { ->(_url) { did_document_json("did:web:other.com") } }
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "raises InvalidDocumentError" do
        expect { resolver.resolve(did) }
          .to raise_error(DIDRain::DID::InvalidDocumentError, /does not match/)
      end
    end

    context "when the fetcher returns invalid JSON" do
      let(:did) { "did:web:example.com" }
      let(:fetcher) { ->(_url) { "not json" } }
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "raises a JSON parse error" do
        expect { resolver.resolve(did) }.to raise_error(JSON::ParserError)
      end
    end

    context "when the document is missing the id field" do
      let(:did) { "did:web:example.com" }
      let(:fetcher) { ->(_url) { '{"verificationMethod": []}' } }
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "raises InvalidDocumentError from the Parser" do
        expect { resolver.resolve(did) }
          .to raise_error(DIDRain::DID::InvalidDocumentError, /id/)
      end
    end

    context "with a document containing services" do
      let(:did) { "did:web:example.com" }
      let(:fetcher) do
        ->(_url) do
          did_document_json(did, "service" => [
            {
              "id" => "#{did}#messaging",
              "type" => "DIDCommMessaging",
              "serviceEndpoint" => "https://example.com/didcomm"
            }
          ])
        end
      end
      subject(:resolver) { described_class.new(fetcher: fetcher) }

      it "parses services correctly" do
        doc = resolver.resolve(did)
        expect(doc.service.size).to eq(1)

        svc = doc.service.first
        expect(svc.id).to eq("#{did}#messaging")
        expect(svc.type).to eq("DIDCommMessaging")
        expect(svc.service_endpoint).to eq("https://example.com/didcomm")
      end
    end
  end
end
