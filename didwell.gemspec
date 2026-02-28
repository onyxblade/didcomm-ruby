# frozen_string_literal: true

require_relative "lib/didwell/version"

Gem::Specification.new do |spec|
  spec.name = "didwell"
  spec.version = DIDWell::VERSION
  spec.authors = ["DIDWell"]
  spec.summary = "DID toolkit for Ruby"
  spec.description = "Ruby toolkit for Decentralized Identifiers (DIDs) — DIDComm messaging, and more"
  spec.homepage = "https://github.com/didwell-rb/didwell"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 4.0"

  spec.files = Dir["lib/**/*.rb", "did/lib/**/*.rb", "didcomm/lib/**/*.rb"]
  spec.require_paths = ["lib", "did/lib", "didcomm/lib"]

  spec.add_dependency "rbnacl", "~> 7.1"
  spec.add_dependency "base58", "~> 0.2"
  spec.add_dependency "base64", ">= 0.2"

  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rake", "~> 13.0"
end
