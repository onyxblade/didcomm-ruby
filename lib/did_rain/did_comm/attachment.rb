# frozen_string_literal: true

require "securerandom"

module DIDRain
  module DIDComm
    class AttachmentDataLinks
      attr_accessor :links, :jws
      attr_writer :data_hash

      def initialize(links:, data_hash:, jws: nil)
        @links = links
        @data_hash = data_hash
        @jws = jws
      end

      def data_hash
        @data_hash
      end

      def to_hash
        d = { "links" => @links, "hash" => @data_hash }
        d["jws"] = @jws if @jws
        d
      end

      def self.from_hash(d)
        new(links: d["links"], data_hash: d["hash"], jws: d["jws"])
      end
    end

    class AttachmentDataBase64
      attr_accessor :base64, :jws
      attr_writer :data_hash

      def initialize(base64:, data_hash: nil, jws: nil)
        @base64 = base64
        @data_hash = data_hash
        @jws = jws
      end

      def data_hash
        @data_hash
      end

      def to_hash
        d = { "base64" => @base64 }
        d["hash"] = @data_hash if @data_hash
        d["jws"] = @jws if @jws
        d
      end

      def self.from_hash(d)
        new(base64: d["base64"], data_hash: d["hash"], jws: d["jws"])
      end
    end

    class AttachmentDataJson
      attr_accessor :json, :jws
      attr_writer :data_hash

      def initialize(json:, data_hash: nil, jws: nil)
        @json = json
        @data_hash = data_hash
        @jws = jws
      end

      def data_hash
        @data_hash
      end

      def to_hash
        d = { "json" => @json }
        d["hash"] = @data_hash if @data_hash
        d["jws"] = @jws if @jws
        d
      end

      def self.from_hash(d)
        new(json: d["json"], data_hash: d["hash"], jws: d["jws"])
      end
    end

    class Attachment
      attr_accessor :data, :id, :description, :filename, :media_type, :format,
                    :lastmod_time, :byte_count

      def initialize(data:, id: nil, description: nil, filename: nil, media_type: nil,
                     format: nil, lastmod_time: nil, byte_count: nil)
        @data = data
        @id = id || SecureRandom.uuid
        @description = description
        @filename = filename
        @media_type = media_type
        @format = format
        @lastmod_time = lastmod_time
        @byte_count = byte_count
      end

      def to_hash
        d = { "data" => @data.to_hash, "id" => @id }
        d["description"] = @description if @description
        d["filename"] = @filename if @filename
        d["media_type"] = @media_type if @media_type
        d["format"] = @format if @format
        d["lastmod_time"] = @lastmod_time if @lastmod_time
        d["byte_count"] = @byte_count if @byte_count
        d
      end

      def self.from_hash(d)
        raise MalformedMessageError.new(:invalid_plaintext) unless d.is_a?(Hash)

        data_hash = d["data"]
        raise MalformedMessageError.new(:invalid_plaintext) unless data_hash.is_a?(Hash)

        data = if data_hash.key?("links")
                 AttachmentDataLinks.from_hash(data_hash)
               elsif data_hash.key?("base64")
                 AttachmentDataBase64.from_hash(data_hash)
               elsif data_hash.key?("json")
                 AttachmentDataJson.from_hash(data_hash)
               else
                 raise MalformedMessageError.new(:invalid_plaintext)
               end

        new(
          data: data,
          id: d["id"],
          description: d["description"],
          filename: d["filename"],
          media_type: d["media_type"],
          format: d["format"],
          lastmod_time: d["lastmod_time"],
          byte_count: d["byte_count"]
        )
      end
    end
  end
end
