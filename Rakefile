# frozen_string_literal: true

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec) do |t|
  t.pattern = "{did,didcomm}/spec/**/*_spec.rb"
end

task default: :spec
