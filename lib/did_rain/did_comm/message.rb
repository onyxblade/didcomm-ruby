# frozen_string_literal: true

require "json"
require "securerandom"

module DIDRain
  module DIDComm
    class Message
      RESERVED_FIELDS = %w[
        ack attachments body created_time expires_time from from_prior
        id please_ack pthid thid to type
      ].freeze

      attr_accessor :id, :type, :body, :from, :to, :created_time, :expires_time,
                    :from_prior, :please_ack, :ack, :thid, :pthid, :attachments,
                    :custom_headers

      def initialize(type:, body:, id: nil, from: nil, to: nil, created_time: nil,
                     expires_time: nil, from_prior: nil, please_ack: nil, ack: nil,
                     thid: nil, pthid: nil, attachments: nil, custom_headers: nil)
        @id = id || SecureRandom.uuid
        @type = type
        @body = body
        @from = from
        @to = to
        @created_time = created_time
        @expires_time = expires_time
        @from_prior = from_prior
        @please_ack = please_ack
        @ack = ack
        @thid = thid
        @pthid = pthid
        @attachments = attachments
        @custom_headers = custom_headers
      end

      def to_hash
        d = {}
        d["id"] = @id
        d["type"] = @type
        d["body"] = @body
        d["typ"] = MessageTypes::PLAINTEXT
        d["from"] = @from if @from
        d["to"] = @to if @to
        d["created_time"] = @created_time if @created_time
        d["expires_time"] = @expires_time if @expires_time
        d["thid"] = @thid if @thid
        d["pthid"] = @pthid if @pthid
        d["please_ack"] = @please_ack if @please_ack
        d["ack"] = @ack if @ack

        if @from_prior
          d["from_prior"] = @from_prior.is_a?(FromPrior) ? @from_prior.to_hash : @from_prior
        end

        if @attachments
          d["attachments"] = @attachments.map { |a| a.is_a?(Attachment) ? a.to_hash : a }
        end

        if @custom_headers
          @custom_headers.each { |k, v| d[k] = v }
        end

        d
      end

      def to_json(*_args)
        JSON.generate(to_hash)
      end

      def self.from_hash(d)
        raise MalformedMessageError.new(:invalid_plaintext) unless d.is_a?(Hash)

        %w[id type body].each do |f|
          raise MalformedMessageError.new(:invalid_plaintext, "Missing required field: #{f}") unless d.key?(f)
        end

        d = d.dup

        typ = d.delete("typ")
        if typ && typ != MessageTypes::PLAINTEXT && typ != MessageTypes::PLAINTEXT_SHORT
          raise MalformedMessageError.new(:invalid_plaintext, "Invalid typ: #{typ}")
        end

        custom_headers = {}
        d.keys.each do |k|
          unless RESERVED_FIELDS.include?(k)
            custom_headers[k] = d.delete(k)
          end
        end

        from_prior = d["from_prior"]
        if from_prior.is_a?(Hash)
          from_prior = FromPrior.from_hash(from_prior)
        end

        attachments = d["attachments"]
        if attachments.is_a?(Array)
          attachments = attachments.map { |a| a.is_a?(Hash) ? Attachment.from_hash(a) : a }
        end

        new(
          id: d["id"],
          type: d["type"],
          body: d["body"],
          from: d["from"],
          to: d["to"],
          created_time: d["created_time"],
          expires_time: d["expires_time"],
          from_prior: from_prior,
          please_ack: d["please_ack"],
          ack: d["ack"],
          thid: d["thid"],
          pthid: d["pthid"],
          attachments: attachments,
          custom_headers: custom_headers.empty? ? nil : custom_headers
        )
      end

      def self.from_json(json_str)
        from_hash(JSON.parse(json_str))
      end
    end
  end
end
