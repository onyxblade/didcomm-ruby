# frozen_string_literal: true

require "base64"
require "json"

module DIDComm
  module Crypto
    module Validation
      def self.validate_jws(msg)
        sigs = msg["signatures"]
        raise MalformedMessageError.new(:invalid_message, "Missing signatures") unless sigs.is_a?(Array) && !sigs.empty?

        sig = sigs[0]
        raise MalformedMessageError.new(:invalid_message, "Missing header in signature") unless sig.is_a?(Hash) && sig["header"].is_a?(Hash)
        raise MalformedMessageError.new(:invalid_message, "Missing kid in signature header") unless sig["header"]["kid"]
      end

      ANONCRYPT_ENC_ALGORITHMS = %w[A256CBC-HS512 A256GCM XC20P].freeze

      def self.validate_anoncrypt_jwe(msg)
        recipients = msg["recipients"]
        raise MalformedMessageError.new(:invalid_message, "Missing recipients") unless recipients.is_a?(Array) && !recipients.empty?

        recipients.each do |r|
          raise MalformedMessageError.new(:invalid_message, "Missing kid in recipient") unless r.dig("header", "kid")
        end

        protected_header = parse_protected(msg["protected"])

        enc = protected_header["enc"]
        unless ANONCRYPT_ENC_ALGORITHMS.include?(enc)
          raise MalformedMessageError.new(:invalid_message, "Unsupported enc algorithm for anoncrypt: #{enc}")
        end

        kids = recipients.map { |r| r["header"]["kid"] }
        check_apv(protected_header, kids)

        protected_header
      end

      def self.validate_authcrypt_jwe(msg)
        recipients = msg["recipients"]
        raise MalformedMessageError.new(:invalid_message, "Missing recipients") unless recipients.is_a?(Array) && !recipients.empty?

        recipients.each do |r|
          kid = r.dig("header", "kid")
          raise MalformedMessageError.new(:invalid_message, "Missing kid in recipient") unless kid
          unless DIDUtils.is_did_url(kid)
            raise MalformedMessageError.new(:invalid_message, "Recipient kid is not a valid DID URL")
          end
        end

        protected_header = parse_protected(msg["protected"])

        # Validate apu
        apu = protected_header["apu"]
        raise MalformedMessageError.new(:invalid_message, "Missing apu") unless apu
        apu_value = KeyUtils.base64url_decode(apu)
        apu_str = apu_value.force_encoding("UTF-8")

        unless DIDUtils.is_did_url(apu_str)
          raise MalformedMessageError.new(:invalid_message, "APU is not a valid DID URL")
        end

        # Validate skid consistency
        skid = protected_header["skid"]
        if skid && skid != apu_str
          raise MalformedMessageError.new(:invalid_message, "skid does not match apu")
        end

        enc = protected_header["enc"]
        unless enc == "A256CBC-HS512"
          raise MalformedMessageError.new(:invalid_message, "Unsupported enc algorithm for authcrypt: #{enc}")
        end

        kids = recipients.map { |r| r["header"]["kid"] }
        check_apv(protected_header, kids)

        protected_header
      end

      def self.parse_protected(protected_b64)
        json_str = KeyUtils.base64url_decode(protected_b64).force_encoding("UTF-8")
        JSON.parse(json_str)
      rescue => e
        raise MalformedMessageError.new(:invalid_message, "Cannot parse protected header: #{e.message}")
      end

      def self.check_apv(protected_header, kids)
        expected_apv = KeyUtils.calculate_apv(kids)
        actual_apv = protected_header["apv"]
        unless actual_apv == expected_apv
          raise MalformedMessageError.new(:invalid_message, "APV mismatch")
        end
      end
    end
  end
end
