# frozen_string_literal: true

module DIDRain
  module DIDComm
    ResolversConfig = Struct.new(:did_resolver, :secrets_resolver, keyword_init: true)
  end
end
