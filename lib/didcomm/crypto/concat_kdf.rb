# frozen_string_literal: true

require "openssl"

module DIDComm
  module Crypto
    module ConcatKDF
      # Concat KDF as specified in RFC 7518 Section 4.6
      # NIST SP 800-56A Concatenation Key Derivation Function
      def self.derive(shared_secret, key_data_len, algorithm, apu, apv, tag: "")
        # otherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
        # AlgorithmID = length(algorithm) || algorithm
        # PartyUInfo = length(apu) || apu
        # PartyVInfo = length(apv) || apv
        # SuppPubInfo = key_data_len_bits (32-bit big-endian)

        alg_id = length_prefixed(algorithm.encode("UTF-8"))
        apu_info = length_prefixed(apu)
        apv_info = length_prefixed(apv)
        supp_pub = [key_data_len * 8].pack("N") # key length in bits

        other_info = alg_id + apu_info + apv_info + supp_pub
        other_info += length_prefixed(tag) unless tag.nil? || tag.empty?

        hash_len = 32 # SHA-256 output
        reps = (key_data_len.to_f / hash_len).ceil
        result = "".b

        (1..reps).each do |counter|
          round_input = [counter].pack("N") + shared_secret + other_info
          result += OpenSSL::Digest::SHA256.digest(round_input)
        end

        result[0, key_data_len]
      end

      def self.length_prefixed(data)
        [data.bytesize].pack("N") + data
      end
    end
  end
end
