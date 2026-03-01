# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

module DIDRain
  module DID
    module Resolvers
      # Resolver for `did:web` method identifiers. Fetches DID documents over HTTPS.
      #
      # @example Resolve a did:web
      #   resolver = DIDRain::DID::Resolvers::Web.new
      #   doc = resolver.resolve("did:web:example.com")
      #
      # @example With a custom fetcher (useful for testing)
      #   fetcher = ->(url) { File.read("did.json") }
      #   resolver = DIDRain::DID::Resolvers::Web.new(fetcher: fetcher)
      class Web
        include DID::Resolver

        # @api private
        IP_ADDRESS_PATTERN = /\A\d{1,3}(\.\d{1,3}){3}\z/
        # @api private
        MAX_REDIRECTS = 3

        # @param fetcher [#call, nil] callable that takes a URL string and returns the response body.
        #   Defaults to an internal HTTPS fetcher.
        # @param open_timeout [Integer] connection open timeout in seconds (default 5)
        # @param read_timeout [Integer] read timeout in seconds (default 5)
        def initialize(fetcher: nil, open_timeout: 5, read_timeout: 5)
          @fetcher = fetcher || default_fetch(open_timeout, read_timeout)
        end

        # Convert a `did:web` identifier to the HTTPS URL of its DID document.
        #
        # @param did [String] a `did:web:` identifier
        # @return [String] the HTTPS URL
        # @raise [InvalidDocumentError] if the DID is malformed or uses an IP address
        def self.did_to_url(did)
          parts = did.split(":")
          raise InvalidDocumentError, "Malformed did:web identifier" if parts.length < 3
          raise InvalidDocumentError, "Not a did:web identifier" unless parts[0] == "did" && parts[1] == "web"

          domain = URI.decode_www_form_component(parts[2])
          host = domain.split(":").first
          raise InvalidDocumentError, "did:web MUST NOT use IP addresses" if host.match?(IP_ADDRESS_PATTERN)

          if parts.length == 3
            "https://#{domain}/.well-known/did.json"
          else
            path = parts[3..].map { |p| URI.decode_www_form_component(p) }.join("/")
            "https://#{domain}/#{path}/did.json"
          end
        end

        # Resolve a `did:web` identifier to a DID Document.
        #
        # @param did [String] a `did:web:` identifier
        # @return [Document, nil] the resolved document, or nil if not a did:web
        # @raise [InvalidDocumentError] if the document id does not match the DID
        # @raise [DocumentNotResolvedError] if the document cannot be fetched
        def resolve(did)
          return nil unless did.start_with?("did:web:")

          url = self.class.did_to_url(did)
          body = @fetcher.call(url)
          doc = Document::Parser.parse_json(body)

          raise InvalidDocumentError, "Document id '#{doc.id}' does not match DID '#{did}'" if doc.id != did

          doc
        end

        private

        def default_fetch(open_timeout, read_timeout)
          lambda do |url_string|
            uri = URI.parse(url_string)
            fetch_with_redirects(uri, open_timeout, read_timeout, MAX_REDIRECTS)
          end
        end

        def fetch_with_redirects(uri, open_timeout, read_timeout, remaining_redirects)
          raise DocumentNotResolvedError, uri.to_s if remaining_redirects < 0

          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = true
          http.open_timeout = open_timeout
          http.read_timeout = read_timeout

          response = http.request(Net::HTTP::Get.new(uri))

          case response
          when Net::HTTPSuccess
            response.body
          when Net::HTTPRedirection
            location = URI.parse(response["location"])
            raise DocumentNotResolvedError, uri.to_s unless location.scheme == "https"

            fetch_with_redirects(location, open_timeout, read_timeout, remaining_redirects - 1)
          else
            raise DocumentNotResolvedError, uri.to_s
          end
        end
      end
    end
  end
end
