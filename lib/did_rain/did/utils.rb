# frozen_string_literal: true

module DIDRain
  module DID
    module Utils
      # W3C DID grammar (https://www.w3.org/TR/did-1.1/#did-syntax):
      #   did                = "did:" method-name ":" method-specific-id
      #   method-specific-id = *( *idchar ":" ) 1*idchar
      #   idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
      #   pct-encoded        = "%" HEXDIG HEXDIG
      PCT_ENCODED = '%[0-9A-Fa-f]{2}'
      IDCHAR = "(?:[a-zA-Z0-9._-]|#{PCT_ENCODED})"
      METHOD_SPECIFIC_ID = "(?:#{IDCHAR}+:)*#{IDCHAR}+"
      DID_BASE = "did:[a-z0-9]+:#{METHOD_SPECIFIC_ID}"

      DID_PATTERN = /\A#{DID_BASE}(?:##{IDCHAR}+)?\z/
      DID_URL_PATTERN = /\A#{DID_BASE}##{IDCHAR}+\z/

      def self.is_did(str)
        DID_PATTERN.match?(str)
      end

      def self.is_did_url(str)
        DID_URL_PATTERN.match?(str)
      end

      def self.did_from_did_url(did_url)
        did_url.split("#").first
      end

      def self.did_or_url(did_or_url)
        if did_or_url.include?("#")
          [did_or_url.split("#").first, did_or_url]
        else
          [did_or_url, nil]
        end
      end
    end
  end
end
