# frozen_string_literal: true

module DID
  class Error < StandardError; end

  class DocumentNotResolvedError < Error
    def initialize(did)
      super("DID `#{did}` is not found in DID resolver")
    end
  end

  class UrlNotFoundError < Error; end

  class SecretNotFoundError < Error; end

  class IncompatibleCryptoError < Error
    def initialize(msg = nil)
      super(msg || "Sender and recipient keys corresponding to provided parameters are incompatible to each other")
    end
  end

  class InvalidDocumentError < Error; end
end
