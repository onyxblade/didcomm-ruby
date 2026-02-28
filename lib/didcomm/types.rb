# frozen_string_literal: true

module DIDComm
  module DIDCommMessageTypes
    ENCRYPTED = "application/didcomm-encrypted+json"
    ENCRYPTED_SHORT = "didcomm-encrypted+json"
    SIGNED = "application/didcomm-signed+json"
    SIGNED_SHORT = "didcomm-signed+json"
    PLAINTEXT = "application/didcomm-plain+json"
    PLAINTEXT_SHORT = "didcomm-plain+json"
  end

  module DIDCommMessageProtocolTypes
    FORWARD = "https://didcomm.org/routing/2.0/forward"
  end

  ResolversConfig = Struct.new(:did_resolver, :secrets_resolver, keyword_init: true)
end
