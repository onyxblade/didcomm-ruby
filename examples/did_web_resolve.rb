#!/usr/bin/env ruby
# frozen_string_literal: true

# Resolve a did:web identifier over HTTPS and inspect the DID Document.
#
# Run:
#   ruby -I lib examples/did_web_resolve.rb
#   ruby -I lib examples/did_web_resolve.rb did:web:example.com

require "did_rain"

did = ARGV.fetch(0, "did:web:mattr.global")

resolver = DIDRain::DID::Resolvers::Web.new
doc = resolver.resolve(did)

puts "DID:    #{doc.id}"
puts "URL:    #{DIDRain::DID::Resolvers::Web.did_to_url(did)}"
puts

puts "── Verification Methods (#{doc.verification_method.size}) ──"
doc.verification_method.each do |vm|
  puts "  #{vm.id}"
  puts "    type:       #{vm.type}"
  puts "    controller: #{vm.controller}"
end
puts

{
  "authentication" => doc.authentication,
  "assertionMethod" => doc.assertion_method,
  "keyAgreement" => doc.key_agreement,
  "capabilityDelegation" => doc.capability_delegation,
  "capabilityInvocation" => doc.capability_invocation
}.each do |name, refs|
  next if refs.empty?

  puts "── #{name} ──"
  refs.each { |ref| puts "  #{ref}" }
  puts
end

unless doc.service.empty?
  puts "── Services (#{doc.service.size}) ──"
  doc.service.each do |svc|
    puts "  #{svc.id} (#{svc.type}) -> #{svc.service_endpoint}"
  end
end
