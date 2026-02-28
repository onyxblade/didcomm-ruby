# frozen_string_literal: true

module DIDComm
  class Error < StandardError; end

  class ValueError < Error; end

  class MalformedMessageError < Error
    attr_reader :code

    CODES = {
      can_not_decrypt: 1,
      invalid_signature: 2,
      invalid_plaintext: 3,
      invalid_message: 4,
      not_supported_fwd_protocol: 5
    }.freeze

    DEFAULT_MESSAGES = {
      can_not_decrypt: "DIDComm message cannot be decrypted",
      invalid_signature: "Signature is invalid",
      invalid_plaintext: "Plaintext is invalid",
      invalid_message: "DIDComm message is invalid",
      not_supported_fwd_protocol: "Not supported Forward protocol"
    }.freeze

    def initialize(code, message = nil)
      @code = code
      super(message || DEFAULT_MESSAGES[code] || "Unknown error")
    end
  end

  class UnsupportedError < Error; end
end
