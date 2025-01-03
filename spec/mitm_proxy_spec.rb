require 'rspec'
require 'fileutils'
require 'webmock/rspec'
require 'socket'
require 'stringio'
require 'openssl'
require 'uri'
require 'net/http'
require_relative '../proxy/certificate'
require_relative '../proxy/mitm_proxy'

RSpec.describe MITMProxy do
  let(:port) { 8080}
  let(:logging_enabled) {true}
  let(:proxy) { MITMProxy.new(port: port, logging_enabled: logging_enabled) }
  let(:mock_logger) {instance_double("Logger", info: nil)}
  let(:mock_client) {instance_double("TCPSocket")}
  let(:mock_ssl_socket) {instance_double("OpenSSL::SSL::SSLSocket")}
  let(:mock_cert) {instance_double("OpenSSL::X509::Certificate")}
  let(:mock_key) {instance_double("OpenSSL::Pkey::RSA")}

  before do
    allow(Logger).to receive(:new).and_return(mock_logger)
  end

  describe "initialization" do
    before do
      cert_dir = File.expand_path('../certificates/dynamic', __dir__)
      FileUtils.rm_rf(cert_dir)
    end

    after do
      cert_dir = File.expand_path('../certificates/dynamic', __dir__)
      FileUtils.rm_rf(cert_dir)
    end

    it "sets the port and logging_enabled variables" do
      expect(proxy.instance_variable_get(:@port)).to eq(port)
      expect(proxy.instance_variable_get(:@logging_enabled)).to eq(logging_enabled)
    end
    
    it "sets the base certificate directory correctly" do
      base_cert_dir = File.expand_path('../certificates', __dir__)
      expect(proxy.instance_variable_get(:@ca_cert_path)).to eq(File.join(base_cert_dir, 'root/certs/rootCA.crt'))
    end

    it "sets the CA key path correctly" do
      base_cert_dir = File.expand_path('../certificates', __dir__)
      expect(proxy.instance_variable_get(:@ca_key_path)).to eq(File.join(base_cert_dir, 'root/private/rootCA.key'))
    end
    
    it "sets the dynamic certificate path correctly" do
      base_cert_dir = File.expand_path('../certificates', __dir__)
      expect(proxy.instance_variable_get(:@cert_dir)).to eq(File.join(base_cert_dir, 'dynamic'))  
    end

    it "loads the CA certificate correctly" do
      ca_cert = proxy.instance_variable_get(:@ca_cert)
      expect(ca_cert).to be_a(OpenSSL::X509::Certificate)
      # expect(ca_cert.subject.to_s).to  include("Root CA")
    end

    it "loads the CA private key correctly" do
      ca_key = proxy.instance_variable_get(:@ca_key)
      expect(ca_key).to be_a(OpenSSL::PKey::RSA)  
    end
    
    it "Ensure the dynamic certificates directory exists" do
      cert_dir = proxy.instance_variable_get(:@cert_dir)
      expect(Dir.exist?(cert_dir)).to be true 
    end

    it "sets up logging when logging is enabled" do
      if logging_enabled
        logger = proxy.instance_variable_get(:@logger)
        expect(logger).to eq(mock_logger)
      else
        expect(proxy.instance_variable_get(:@logger)).to be_nil
      end
    end

    it "creates a real logger with the correct log file" do
      allow(Logger).to receive(:new).and_call_original
    
      real_proxy = MITMProxy.new(port: port, logging_enabled: true)
      logger = real_proxy.instance_variable_get(:@logger)
    
      expect(logger).to be_a(Logger)
      expect(logger.instance_variable_get(:@logdev).dev.path).to eq('proxy_logs.log')
    end    
  end

  describe "#start" do
    before do
      @mock_server = instance_double("TCPServer")
      allow(TCPServer).to receive(:new).with(port).and_return(@mock_server)

      @mock_client = instance_double("TCPSocket", gets: nil, close: nil, closed?: false)
      allow(@mock_server).to receive(:accept).and_return(@mock_client, nil)

      allow(proxy).to receive(:handle_client)
    end

    it "accepts client connections and processes them" do
      thread = Thread.new { proxy.start }
      sleep 0.1

      expect(@mock_server).to have_received(:accept).at_least(:once)
      expect(proxy).to have_received(:handle_client).with(@mock_client)

      thread.kill
      thread.join
    end

    it "skips nil clients and continues accepting" do
      allow(@mock_server).to receive(:accept).and_return(nil, @mock_client, nil)

      thread = Thread.new { proxy.start }
      sleep 0.1

      expect(proxy).to have_received(:handle_client).with(@mock_client).once
      thread.kill
      thread.join
    end
  end

  describe "#log" do
    before do
      allow(Logger).to receive(:new).and_return(mock_logger)
    end

    it "logs a message when logging is enabled" do
      proxy.send(:log, "Test log message")
      expect(mock_logger).to have_received(:info).with("Test log message")
    end

    it "does not log a message when logging is disabled" do
      proxy = MITMProxy.new(port: port, logging_enabled: false)
      proxy.send(:log, "Test log message")
      expect(mock_logger).not_to have_received(:info) 
    end
  end

  describe "#handle_client" do
    before do
      allow(mock_client).to receive(:close)
      allow(mock_client).to receive(:closed?).and_return(false)
    end

    context "when processing valid HTTP requests" do
      before do
        allow(mock_client).to receive(:gets).and_return("GET / HTTP/1.1\r\n", nil)
        allow(proxy).to receive(:handle_http_request)
      end
      
      it "calls handle_http_request for valid HTTP methods" do
        proxy.send(:handle_client, mock_client)
        expect(proxy).to have_received(:handle_http_request).with(mock_client, "GET", "/")
        expect(mock_client).to have_received(:close)
      end
    end
  end

  describe "#send_error_response" do
    {
      400 => "Bad Request",
      405 => "Method Not Allowed",
      500 => "Internal Server Error",
      501 => "Not Implemented"
    }.each do |code, message|
      it "sends the error response for HTTP #{code}" do
        expected_response = <<~RESPONSE
          HTTP/1.1 #{code} #{message}\r
          Content-Type: text/plain\r
          Content-Length: #{message.bytesize}\r
          Connection: close\r
          \r
          #{message}
        RESPONSE

        allow(mock_client).to receive(:write).with(expected_response.strip)
        proxy.send(:send_error_response, mock_client, code, message)
        expect(mock_client).to have_received(:write).with(expected_response.strip)
        expect(mock_logger).to have_received(:info).with("[ERROR] Sent #{code}: #{message}")
      end
    end
  end

  describe "#valid_domain?" do
    context "when the domain is valid" do
      it "returns true for a simple domain" do
        expect(proxy.send(:valid_domain?, "example.com")).to be_truthy
      end

      it "returns true for a sub domain" do
        expect(proxy.send(:valid_domain?, "sub.example.com")).to be_truthy
      end

      it "returns true for a domain with hypen" do
        expect(proxy.send(:valid_domain?, "my-example.com")).to be_truthy
      end
    end

    context "when the domain is invalid" do
      it "returns false for a domain without a TLD" do
        expect(proxy.send(:valid_domain?, "example")).to be_falsey
      end

      it "returns false for a domain with special characters" do
        expect(proxy.send(:valid_domain?, "exam$ple.com")).to be_falsey
      end

      it "returns false for an empty string" do
        expect(proxy.send(:valid_domain?, "")).to be_falsey
      end

      it "returns false for nil input" do
        expect(proxy.send(:valid_domain?, nil)).to be_falsey
      end

      it "returns false for a domain starting with a period" do
        expect(proxy.send(:valid_domain?, ".example.com")).to be_falsey
      end

      it "returns false for a domain ending with a period" do
        expect(proxy.send(:valid_domain?, "example.com.")).to be_falsey
      end
    end
  end

  describe "#handle_https_connect" do
    let(:valid_target) {"example.com:443"}
    let(:invalid_target) {"invalid_domain.com:443"}
    let(:host) {"example.com"}
    let(:port) {"443"}

    before do
      allow(mock_client).to receive(:write)
      allow(mock_client).to receive(:close)
      allow(mock_client).to receive(:closed?).and_return(false)
      allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_return(mock_ssl_socket)
      allow(mock_ssl_socket).to receive(:sync_close=)
      allow(mock_ssl_socket).to receive(:accept)
      allow(mock_ssl_socket).to receive(:close)
      allow(mock_ssl_socket).to receive(:closed?).and_return(false)
      allow(Certificate).to receive(:generate_or_retrieve_cert).and_return([mock_cert, mock_key])
    end

    context "when domain is valid" do
      before do
        allow(proxy).to receive(:valid_domain?).with(host).and_return(true)
      end

      it "logs the interception, establishes a connection, and forwards traffic" do
        expect(proxy).to receive(:log).with("[HTTPS] Intercepting: #{host}:#{port}")
        expect(proxy).to receive(:forward_https_traffic).with(mock_ssl_socket, host, port)

        proxy.send(:handle_https_connect, mock_client, valid_target)

        expect(mock_client).to have_received(:write).with("HTTP/1.1 200 Connection Established\r\n\r\n")
      end
    end

    context "when certificate generation fails" do
      before do
        allow(proxy).to receive(:valid_domain?).with(host).and_return(true)
        allow(Certificate).to receive(:generate_or_retrieve_cert).and_raise(StandardError.new("Certificate error"))
      end

      it "logs an error and sends a 500 response" do
        allow(proxy).to receive(:log)
        allow(mock_client).to receive(:write)

        proxy.send(:handle_https_connect, mock_client, valid_target)

        expect(proxy).to have_received(:log).with("[ERROR] Failed to generate or retrieve certificate for #{host}: Certificate error")
        expect(mock_client).to have_received(:write).with(/500 Internal Server Error/)
      end
    end

    context "when SSL connection with the client fails" do
      before do
        allow(proxy).to receive(:valid_domain?).with(host).and_return(true)
        allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_raise(StandardError.new("SSL connection error"))
        allow(proxy).to receive(:log)
        allow(mock_client).to receive(:write)
        allow(proxy).to receive(:forward_https_traffic)
      end

      it "logs an error and does not forward traffic" do
        proxy.send(:handle_https_connect, mock_client, valid_target)

        expect(proxy).to have_received(:log).with("[ERROR] Failed to establish SSL connection with client: SSL connection error")
        expect(proxy).not_to have_received(:forward_https_traffic)
      end
    end
  end

  describe "#forward_https_traffic" do
    let(:host) { "example.com" }
    let(:port) { 443 }
    let(:mock_http) { instance_double(Net::HTTP) }
    let(:mock_ssl_socket) { instance_double(OpenSSL::SSL::SSLSocket) }
    let(:mock_response) { instance_double(Net::HTTPResponse, code: "200", message: "OK", body: "response_body", http_version: "1.1") }

    before do
      # Mock the SSL socket behavior
      allow(mock_ssl_socket).to receive(:readpartial).and_return(request_data, EOFError)
      allow(mock_ssl_socket).to receive(:write)
      allow(mock_ssl_socket).to receive(:close)

      # Mock the HTTP client and response behavior
      allow(Net::HTTP).to receive(:new).with(host, port).and_return(mock_http)
      allow(mock_http).to receive(:use_ssl=).with(true)
      allow(mock_http).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      allow(mock_http).to receive(:request).and_return(mock_response)

      # Properly mock each_header to yield headers as expected
      allow(mock_response).to receive(:each_header).and_return(nil)
      allow(mock_response).to receive(:each_header) do |&block|
        block.call("Content-Type", "application/json") if block
      end

      # Mock other response attributes
      allow(mock_response).to receive(:body).and_return("response_body")
      allow(mock_response).to receive(:code).and_return("200")
      allow(mock_response).to receive(:message).and_return("OK")
      allow(mock_response).to receive(:http_version).and_return("1.1")
    end

    context "when handling GET requests" do
      let(:request_data) { "GET /test HTTP/1.1\r\nHost: #{host}\r\n\r\n" }

      it "forwards them correctly" do
        # Mock the GET request behavior
        mock_request = instance_double(Net::HTTP::Get)
        allow(Net::HTTP::Get).to receive(:new).and_return(mock_request)
        allow(mock_request).to receive(:[]=) # Allow setting headers on the HTTP request

        # Call the method being tested
        proxy.send(:forward_https_traffic, mock_ssl_socket, host, port)

        # Validate that the correct response is written to the SSL socket
        expect(mock_ssl_socket).to have_received(:write).with("HTTP/1.1 200 OK\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("Content-Type: application/json\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("response_body")
      end
    end

    context "when handling POST requests" do
      let(:request_data) {"POST /test HTTP/1.1\r\nHost: #{host}\r\nContent-length: 11\r\n\r\nparam=value"}

      it "modifies the body and forwards them correctly" do
        #Mock the POST request behavior
        mock_request = instance_double(Net::HTTP::Post)
        allow(Net::HTTP::Post).to receive(:new).and_return(mock_request)
        allow(mock_request).to receive(:body=)
        allow(mock_request).to receive(:[]=)

        # Call the method being tested
        proxy.send(:forward_https_traffic, mock_ssl_socket, host, port)

        # validate that the body is modified and the correct response is written to the SSL socket
        expect(mock_request).to have_received(:body=).with("param=value&modified=true")
        expect(mock_ssl_socket).to have_received(:write).with("HTTP/1.1 200 OK\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("Content-Type: application/json\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("\r\n")
        expect(mock_ssl_socket).to have_received(:write).with("response_body")
      end
    end

    context "when an EOFError occurs" do
      let(:request_data) { "GET /test HTTP/1.1\r\nHost: #{host}\r\n\r\n" }

      before do
        allow(mock_ssl_socket).to receive(:readpartial).and_raise(EOFError)
      end

      it "closes the SSL socket gracefully" do
        # Call the method being tested
        proxy.send(:forward_https_traffic, mock_ssl_socket, host, port)

        # Validate that the SSL socket is closed
        expect(mock_ssl_socket).to have_received(:close)
      end

    end

    context "when an Unsupported HTTP method is used" do
      let(:request_data) { "UNSUPPORTED /test HTTP/1.1\r\nHost: #{host}\r\n\r\n" }

      it "logs an error and does not proceed" do
        allow(proxy).to receive(:log)

        # Call the method being tested
        proxy.send(:forward_https_traffic, mock_ssl_socket, host, port)

        # Validate that an error is logged
        expect(proxy).to have_received(:log).with("[ERROR] Unsupported HTTP method: UNSUPPORTED")
      end
    end
  end
end