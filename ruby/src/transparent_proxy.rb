#!/usr/bin/env ruby
require "socket"
require "uri"
require "openssl"

class TransparentProxy
  def initialize(port:, target_host:, target_port:)
    @port = port
    @target_host = target_host
    @target_port = target_port
    @interceptors = []
  end

  # Add request/response interceptors
  def add_interceptor(&block)
    @interceptors << block
  end

  # Modify request before sending to server
  def intercept_request(request)
    @interceptors.each do |interceptor|
      request = interceptor.call(request, :request)
    end
    request
  end

  # Modify response before sending to client
  def intercept_response(response)
    @interceptors.each do |interceptor|
      response = interceptor.call(response, :response)
    end
    response
  end

  # Example interceptors
  def self.image_replacer
    lambda do |data, type|
      if type == :response && data.include?("Content-Type: image/")
        # Replace all images with a placeholder
        File.read("/path/to/placeholder.jpg")
      else
        data
      end
    end
  end

  def self.header_injector
    lambda do |data, type|
      if type == :request
        # Inject custom headers
        data.gsub("\r\n\r\n", "\r\nX-Proxy-Timestamp: #{Time.now.iso8601}\r\n\r\n")
      else
        data
      end
    end
  end
end

# Usage example
proxy = TransparentProxy.new(
  port: 8080,
  target_host: "example.com",
  target_port: 80
)

# Add some interceptors
proxy.add_interceptor(&TransparentProxy.image_replacer)
proxy.add_interceptor(&TransparentProxy.header_injector)

# Start the proxy
puts "Ruby Proxy Companion Started"
