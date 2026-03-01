# frozen_string_literal: true

require_relative "../../../spec_helper"
require "rbnacl"
require "base58"

RSpec.describe DID::Resolvers::Key do
  subject(:resolver) { described_class.new }

  describe "#resolve" do
    context "with an Ed25519 did:key" do
      # Known seed → deterministic public key
      let(:seed) { "\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60".b }
      let(:verify_key) { RbNaCl::Signatures::Ed25519::SigningKey.new(seed).verify_key }
      let(:ed_bytes) { verify_key.to_bytes }
      let(:did) { "did:key:z" + Base58.binary_to_base58("\xED\x01".b + ed_bytes, :bitcoin) }

      it "returns a DID::Document" do
        doc = resolver.resolve(did)
        expect(doc).to be_a(DID::Document)
        expect(doc.id).to eq(did)
      end

      it "has an Ed25519 authentication method" do
        doc = resolver.resolve(did)
        expect(doc.authentication).not_to be_empty
        expect(doc.authentication_methods.size).to eq(1)

        vm = doc.authentication_methods.first
        expect(vm.type).to eq(DID::VerificationMethodType::JSON_WEB_KEY_2020)
        expect(vm.controller).to eq(did)

        jwk = vm.verification_material.value
        expect(jwk["kty"]).to eq("OKP")
        expect(jwk["crv"]).to eq("Ed25519")
      end

      it "has a derived X25519 key agreement method" do
        doc = resolver.resolve(did)
        expect(doc.key_agreement).not_to be_empty
        expect(doc.key_agreement_methods.size).to eq(1)

        vm = doc.key_agreement_methods.first
        expect(vm.type).to eq(DID::VerificationMethodType::JSON_WEB_KEY_2020)

        jwk = vm.verification_material.value
        expect(jwk["kty"]).to eq("OKP")
        expect(jwk["crv"]).to eq("X25519")

        # Verify the derived key matches direct conversion
        expected_x = verify_key.to_curve25519_public_key.to_bytes
        actual_x = Base64.urlsafe_decode64(jwk["x"])
        expect(actual_x).to eq(expected_x)
      end

      it "uses spec-compliant key IDs" do
        doc = resolver.resolve(did)
        multibase_value = did.delete_prefix("did:key:")

        ed_kid = "#{did}##{multibase_value}"
        expect(doc.authentication).to eq([ed_kid])

        x_kid = doc.key_agreement.first
        expect(x_kid).to start_with("#{did}#z6LS")
      end

      it "populates assertionMethod, capabilityInvocation, and capabilityDelegation" do
        doc = resolver.resolve(did)
        ed_kid = doc.authentication.first

        expect(doc.assertion_method).to eq([ed_kid])
        expect(doc.capability_invocation).to eq([ed_kid])
        expect(doc.capability_delegation).to eq([ed_kid])
      end
    end

    context "with an X25519 did:key" do
      let(:x_priv) { RbNaCl::PrivateKey.new("\x01".b * 32) }
      let(:x_bytes) { x_priv.public_key.to_bytes }
      let(:did) { "did:key:z" + Base58.binary_to_base58("\xEC\x01".b + x_bytes, :bitcoin) }

      it "returns a DID::Document" do
        doc = resolver.resolve(did)
        expect(doc).to be_a(DID::Document)
        expect(doc.id).to eq(did)
      end

      it "has a key agreement method but no authentication or signing relationships" do
        doc = resolver.resolve(did)
        expect(doc.authentication).to be_empty
        expect(doc.assertion_method).to be_empty
        expect(doc.capability_invocation).to be_empty
        expect(doc.capability_delegation).to be_empty
        expect(doc.key_agreement).not_to be_empty
        expect(doc.key_agreement_methods.size).to eq(1)

        vm = doc.key_agreement_methods.first
        expect(vm.type).to eq(DID::VerificationMethodType::JSON_WEB_KEY_2020)

        jwk = vm.verification_material.value
        expect(jwk["kty"]).to eq("OKP")
        expect(jwk["crv"]).to eq("X25519")
        actual_x = Base64.urlsafe_decode64(jwk["x"])
        expect(actual_x).to eq(x_bytes)
      end

      it "uses spec-compliant key ID" do
        doc = resolver.resolve(did)
        multibase_value = did.delete_prefix("did:key:")
        expect(doc.key_agreement).to eq(["#{did}##{multibase_value}"])
      end
    end

    context "with a non-did:key DID" do
      it "returns nil" do
        expect(resolver.resolve("did:example:123")).to be_nil
        expect(resolver.resolve("did:web:example.com")).to be_nil
      end
    end

    context "with versioned did:key syntax" do
      let(:seed) { "\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60".b }
      let(:verify_key) { RbNaCl::Signatures::Ed25519::SigningKey.new(seed).verify_key }
      let(:mb_value) { "z" + Base58.binary_to_base58("\xED\x01".b + verify_key.to_bytes, :bitcoin) }

      it "resolves did:key:1:<mb-value> (version 1)" do
        did = "did:key:1:#{mb_value}"
        doc = resolver.resolve(did)
        expect(doc).to be_a(DID::Document)
        expect(doc.id).to eq(did)
      end

      it "raises InvalidDocumentError for unsupported versions" do
        expect { resolver.resolve("did:key:2:#{mb_value}") }.to raise_error(DID::InvalidDocumentError, /version/)
      end
    end

    context "with invalid did:key values" do
      it "raises InvalidDocumentError for non-multibase encoding" do
        expect { resolver.resolve("did:key:abc123") }.to raise_error(DID::InvalidDocumentError, /base58btc/)
      end

      it "raises InvalidDocumentError for invalid base58 characters" do
        expect { resolver.resolve("did:key:z!!!") }.to raise_error(DID::InvalidDocumentError, /Invalid base58btc/)
      end

      it "raises InvalidDocumentError for truncated data" do
        expect { resolver.resolve("did:key:z1") }.to raise_error(DID::InvalidDocumentError)
      end

      it "raises InvalidDocumentError for unsupported multicodec" do
        bogus = "\x00\x01".b + ("\x00".b * 32)
        did = "did:key:z" + Base58.binary_to_base58(bogus, :bitcoin)
        expect { resolver.resolve(did) }.to raise_error(DID::InvalidDocumentError, /Unsupported multicodec/)
      end

      it "raises InvalidDocumentError for wrong key length" do
        bad = "\xED\x01".b + ("\x00".b * 16)
        did = "did:key:z" + Base58.binary_to_base58(bad, :bitcoin)
        expect { resolver.resolve(did) }.to raise_error(DID::InvalidDocumentError, /32 bytes/)
      end
    end
  end
end
