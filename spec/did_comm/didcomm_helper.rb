# frozen_string_literal: true

require_relative "../spec_helper"

Dir[File.join(__dir__, "test_vectors/**/*.rb")].each { |f| require f }
