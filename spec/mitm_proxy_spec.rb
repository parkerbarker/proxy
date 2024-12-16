require "net/http"
require "openssl"
require_relative "../proxy/mitm_proxy"

RSpec.describe MITMProxy do
  PROXY_PORT = 8888
  TEST_HTTP_URL = "http://httpbin.org/get"
  TEST_HTTPS_URL = "https://httpbin.org/get"

  before(:context) do
    # Start the proxy server in a thread
    @proxy_thread = Thread.new do
      MITMProxy.new(port: PROXY_PORT).start
    end
    sleep 1 # Allow time for the proxy to start
  end

  after(:context) do
    @proxy_thread.kill if @proxy_thread # Stop the proxy server
  end

  context "when handling HTTP traffic" do
    it "proxies HTTP requests and returns a valid response" do
      uri = URI(TEST_HTTP_URL)
      response = Net::HTTP.start(uri.host, uri.port, "localhost", PROXY_PORT) do |http|
        http.get(uri.request_uri)
      end

      expect(response.code).to eq("200")
      expect(response.body).to include('"url": "http://httpbin.org/get"')
    end
  end

  context "when handling HTTPS traffic" do
    it "proxies HTTPS requests and intercepts the traffic" do
      uri = URI(TEST_HTTPS_URL)

      http = Net::HTTP.new(uri.host, uri.port, "localhost", PROXY_PORT)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      response = http.get(uri.request_uri)

      expect(response.code).to eq("200")
      expect(response.body).to include('"url": "https://httpbin.org/get"')
    end
  end
end
