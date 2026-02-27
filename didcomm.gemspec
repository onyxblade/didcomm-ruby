# frozen_string_literal: true

require_relative "lib/didcomm/version"

Gem::Specification.new do |spec|
  spec.name = "didcomm"
  spec.version = DIDComm::VERSION
  spec.authors = ["DIDComm Ruby"]
  spec.summary = "DIDComm v2 messaging protocol implementation"
  spec.description = "Ruby implementation of DIDComm v2 secure messaging using Decentralized Identifiers (DIDs)"
  spec.homepage = "https://github.com/onyxblade/didcomm-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.files = Dir["lib/**/*.rb"]
  spec.require_paths = ["lib"]

  spec.add_dependency "rbnacl", "~> 7.1"
  spec.add_dependency "base58", "~> 0.2"
  spec.add_dependency "base64", ">= 0.2"

  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rake", "~> 13.0"
end
