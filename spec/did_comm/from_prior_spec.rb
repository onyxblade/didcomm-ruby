# frozen_string_literal: true

require_relative "didcomm_helper"

RSpec.describe "FromPrior" do
  let(:resolvers_alice) { TestVectors.resolvers_config_alice }
  let(:resolvers_bob) { TestVectors.resolvers_config_bob }
  let(:resolvers_charlie) { TestVectors.resolvers_config_charlie }

  describe DIDComm::FromPrior do
    it "serializes and deserializes" do
      fp = DIDComm::FromPrior.new(
        iss: "did:example:charlie",
        sub: "did:example:alice",
        aud: "test", exp: 100, nbf: 50, iat: 1, jti: "jwt-id"
      )
      h = fp.to_hash
      expect(h["iss"]).to eq("did:example:charlie")
      expect(h["sub"]).to eq("did:example:alice")

      parsed = DIDComm::FromPrior.from_hash(h)
      expect(parsed.iss).to eq("did:example:charlie")
      expect(parsed.jti).to eq("jwt-id")
    end
  end

  describe "unpack_from_prior kid/iss consistency" do
    it "raises when kid DID does not match payload iss" do
      # Manually build a JWT: sign with charlie's key but set iss to alice
      msg_hash = { "id" => "test", "type" => "test", "body" => {} }

      secret = TestVectors.charlie_secrets.find { |s| s.kid == "did:example:charlie#key-1" }
      key_info = DIDComm::Crypto::KeyUtils.extract_key(secret)
      alg = DIDComm::Crypto::KeyUtils.extract_sign_alg(secret)

      header = { "alg" => alg, "kid" => secret.kid, "typ" => "JWT" }
      payload = { "iss" => "did:example:alice", "sub" => "did:example:bob" }
      header_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(header))
      payload_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(JSON.generate(payload))
      signing_input = "#{header_b64}.#{payload_b64}"
      signature = DIDComm::Crypto::JWSEnvelope.compute_signature(signing_input, key_info, alg)
      sig_b64 = DIDComm::Crypto::KeyUtils.base64url_encode(signature)

      msg_hash["from_prior"] = "#{header_b64}.#{payload_b64}.#{sig_b64}"

      expect {
        DIDComm::FromPrior.unpack(msg_hash, resolvers_charlie)
      }.to raise_error(DIDComm::MalformedMessageError, /kid DID.*does not match iss/)
    end

    it "passes when kid DID matches payload iss" do
      msg = DIDComm::Message.new(
        id: "test-fp",
        type: "http://example.com/test",
        from: "did:example:alice",
        to: ["did:example:bob"],
        body: { "test" => true },
        from_prior: DIDComm::FromPrior.new(
          iss: "did:example:charlie",
          sub: "did:example:alice"
        )
      )

      resolvers_charlie = TestVectors.resolvers_config_charlie
      msg_hash = msg.to_hash
      DIDComm::FromPrior.pack(msg_hash, resolvers_charlie)

      resolvers_bob = TestVectors.resolvers_config_bob
      issuer_kid = DIDComm::FromPrior.unpack(msg_hash, resolvers_bob)
      expect(issuer_kid).to eq("did:example:charlie#key-1")
      expect(msg_hash["from_prior"]["iss"]).to eq("did:example:charlie")
    end
  end

  describe "from_prior pack/unpack in message" do
    it "packs and unpacks from_prior JWT in plaintext" do
      msg = DIDComm::Message.new(
        id: "test-fp",
        type: "http://example.com/test",
        from: "did:example:alice",
        to: ["did:example:bob"],
        body: { "test" => true },
        from_prior: DIDComm::FromPrior.new(
          iss: "did:example:charlie",
          sub: "did:example:alice"
        )
      )

      # Pack plaintext - from_prior should be JWT string
      msg_hash = msg.to_hash
      kid = DIDComm::FromPrior.pack(msg_hash, resolvers_charlie)
      expect(kid).to eq("did:example:charlie#key-1")
      expect(msg_hash["from_prior"]).to be_a(String)
      expect(msg_hash["from_prior"].split(".").length).to eq(3)

      # Unpack
      issuer_kid = DIDComm::FromPrior.unpack(msg_hash, resolvers_bob)
      expect(issuer_kid).to eq("did:example:charlie#key-1")
      expect(msg_hash["from_prior"]).to be_a(Hash)
      expect(msg_hash["from_prior"]["iss"]).to eq("did:example:charlie")
      expect(msg_hash["from_prior"]["sub"]).to eq("did:example:alice")
    end
  end
end
