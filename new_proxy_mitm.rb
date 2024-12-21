require 'webrick'
require 'webrick/https'
require 'openssl'
require 'uri'
require 'net/http'
require 'fileutils'

# Directory to store generated certificates
CERT_DIR = './certificates'
FileUtils.mkdir_p(CERT_DIR)

# Generate a self-signed root certificate authority
def generate_root_ca
  key = OpenSSL::PKey::RSA.new(4096)
  cert = OpenSSL::X509::Certificate.new
  cert.subject = cert.issuer = OpenSSL::X509::Name.new([['CN', 'Ruby Proxy Root CA']])
  cert.public_key = key.public_key
  cert.serial = 1
  cert.version = 2
  cert.not_before = Time.now
  cert.not_after = Time.now + (10 * 365 * 24 * 60 * 60)
  cert.sign(key, OpenSSL::Digest::SHA256.new)

  File.write("#{CERT_DIR}/root_ca.key", key.to_pem)
  File.write("#{CERT_DIR}/root_ca.crt", cert.to_pem)
  [cert, key]
end

# Load or generate the root CA
if File.exist?("#{CERT_DIR}/root_ca.key") && File.exist?("#{CERT_DIR}/root_ca.crt")
  ROOT_CA_KEY = OpenSSL::PKey::RSA.new(File.read("#{CERT_DIR}/root_ca.key"))
  ROOT_CA_CERT = OpenSSL::X509::Certificate.new(File.read("#{CERT_DIR}/root_ca.crt"))
else
  ROOT_CA_CERT, ROOT_CA_KEY = generate_root_ca
end

# Generate certificates dynamically for each domain
def generate_certificate(domain)
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.subject = OpenSSL::X509::Name.new([['CN', domain]])
  cert.issuer = ROOT_CA_CERT.subject
  cert.public_key = key.public_key
  cert.serial = rand(1000..9999)
  cert.version = 2
  cert.not_before = Time.now
  cert.not_after = Time.now + (365 * 24 * 60 * 60)
  cert.sign(ROOT_CA_KEY, OpenSSL::Digest::SHA256.new)

  [cert, key]
end

# HTTPS Proxy Server
class MITMProxy < WEBrick::HTTPServer
  def initialize(options = {})
    super(options)
    @certificates = {}
    @logger = options[:Logger] || WEBrick::Log.new($stdout, WEBrick::Log::INFO)
  end

  def service(req, res)
    if req.request_method == 'CONNECT'
      handle_connect(req, res)
    else
      forward_request(req, res)
    end
  end

  private

  def handle_connect(req, res)
    host, port = req.unparsed_uri.split(':')
    port ||= 443

    @logger.info("Intercepting CONNECT request for #{host}:#{port}")

    cert, key = @certificates[host] ||= generate_certificate(host)

    client_socket = req.instance_variable_get(:@socket)
    client_socket.write("HTTP/1.1 200 Connection established\r\n\r\n")

    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key
    ssl_context.ca_file = "./certificates/root_ca.crt"
    ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
    ssl_context.verify_depth = 5
    ssl_context.cert_store = OpenSSL::X509::Store.new
    ssl_context.cert_store.add_file(File.expand_path("./certificates/root_ca.crt"))

    ssl_client_socket = OpenSSL::SSL::SSLSocket.new(client_socket, ssl_context)
    ssl_client_socket.sync_close = true
    ssl_client_socket.accept

    Thread.new { proxy_https(ssl_client_socket, host, port) }
  end

  def proxy_https(client_socket, host, port)
    begin
      target_socket = TCPSocket.new(host, port.to_i)
      target_ssl_socket = OpenSSL::SSL::SSLSocket.new(target_socket)
      target_ssl_socket.sync_close = true
      target_ssl_socket.connect

      [client_socket, target_ssl_socket].each do |sock|
        Thread.new { IO.copy_stream(sock, sock == client_socket ? target_ssl_socket : client_socket) }
      end
    rescue => e
      @logger.error("Error proxying HTTPS traffic: #{e.message}")
    ensure
      client_socket.close
      target_socket.close if target_socket
    end
  end

  def forward_request(req, res)
    uri = URI(req.request_uri)

    @logger.info("Forwarding HTTP request to #{uri}")

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')

    forward_req = Net::HTTP.const_get(req.request_method.capitalize).new(uri)
    forward_req.initialize_http_header(req.header)
    forward_req.body = req.body if req.body

    forward_res = http.request(forward_req)

    res.status = forward_res.code.to_i
    res.body = forward_res.body
    forward_res.each_header { |k, v| res[k] = v }

    @logger.info("Response forwarded with status #{res.status}")
  end
end

# Start the MITM Proxy
proxy = MITMProxy.new(Port: 8888, Logger: WEBrick::Log.new($stdout, WEBrick::Log::DEBUG))
trap('INT') { proxy.shutdown }
proxy.start
