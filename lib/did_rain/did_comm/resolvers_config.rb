# frozen_string_literal: true

module DIDRain
  module DIDComm
    ResolversConfig = Data.define(:did_resolver, :secrets_resolver)
  end
end
