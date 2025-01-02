require 'rspec'
require 'fileutils'
require 'webmock/rspec'
require 'socket'
require_relative '../proxy/mitm_proxy'

RSpec.describe MITMProxy do
  let(:port) { 8080}
  let(:logging_enabled) {true}
  let(:proxy) { MITMProxy.new(port: port, logging_enabled: logging_enabled) }
  let(:mock_logger) {instance_double("Logger", info: nil)}
  let(:mock_client) {instance_double("TCPSocket")}

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
  
end