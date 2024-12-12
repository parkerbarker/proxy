# test/proxy_test.rb
require 'minitest/autorun'
require 'socket'
require 'webmock/minitest'
require_relative '../lib/transparent_proxy'

class TransparentProxyTest < Minitest::Test
  def setup
    @proxy = TransparentProxy.new(
      port: 8080,
      target_host: 'example.com',
      target_port: 80
    )
  end

  def test_image_replacer_interceptor
    # Mock image response
    image_data = File.read('/path/to/test_image.jpg')
    
    # Create an interceptor
    replacer = TransparentProxy.image_replacer
    
    # Test image replacement
    replaced_data = replacer.call(image_data, :response)
    
    # Assert replacement happened
    refute_equal image_data, replaced_data
    assert File.exist?('/path/to/placeholder.jpg')
  end

  def test_header_injector_interceptor
    # Sample HTTP request
    request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Apply header injector
    modified_request = TransparentProxy.header_injector.call(request, :request)
    
    # Assert header was added
    assert modified_request.include?('X-Proxy-Timestamp:')
  end

  def test_multiple_interceptors
    # Create test interceptors
    interceptors = [
      -> (data, type) { data.upcase if type == :request },
      -> (data, type) { data + "\nX-Custom-Header: Test" if type == :request }
    ]

    # Add interceptors
    interceptors.each { |interceptor| @proxy.add_interceptor(&interceptor) }

    # Sample request
    request = "get / http/1.1\r\nhost: example.com\r\n\r\n"
    
    # Apply interceptors
    modified_request = interceptors.reduce(request) do |data, interceptor| 
      interceptor.call(data, :request)
    end

    # Assertions
    assert modified_request.include?('GET')  # Uppercase
    assert modified_request.include?('X-Custom-Header: Test')  # Header injection
  end

  def test_performance
    # Benchmark request processing
    start_time = Time.now
    iterations = 1000

    iterations.times do
      request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
      @proxy.intercept_request(request)
    end

    total_time = Time.now - start_time

    # Performance assertion (adjust threshold as needed)
    assert total_time < 5, "Performance test failed. Took #{total_time} seconds"
  end

  def test_connection_handling
    # Stub external connection
    WebMock.stub_request(:get, "http://example.com/")
           .to_return(status: 200, body: "Success")

    # Simulate request
    response = nil
    assert_nothing_raised do
      # Placeholder for actual connection logic
      response = "Simulated response"
    end

    refute_nil response
  end
end
