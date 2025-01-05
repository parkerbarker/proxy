require 'rspec'
require 'webmock/rspec'
require 'simplecov'
require_relative '../proxy/mitm_proxy'

# Enable SimpleCov for test coverage
SimpleCov.start do
  add_filter '/spec/' # Exclude test files from coverage
end

RSpec.configure do |config|
  # Start a thread for the proxy server
  config.before(:suite) do
    @proxy_thread = Thread.new do
      begin
        proxy = MITMProxy.new(port: 8081, logging_enabled: false)
        proxy.start
      rescue StandardError => e
        puts "[ERROR] Proxy thread encountered an error: #{e.message}"
      end
    end
    sleep 1 # Give the server time to start
  end

  # Terminate the proxy thread after the suite finishes
  config.after(:suite) do
    if @proxy_thread
      @proxy_thread.kill
      @proxy_thread.join
    end
  end

  # Disable external network connections except localhost
  WebMock.disable_net_connect!(allow_localhost: true)

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups

  # Allow focusing on specific tests
  config.filter_run_when_matching :focus

  # Enable example status persistence
  # config.example_status_persistence_file_path = "spec/examples.txt"

  # Run tests in random order
  config.order = :random
  Kernel.srand config.seed
end
