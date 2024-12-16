require "webrick/httpproxy"
require "openssl"
require_relative "../certificates/certificate"

class MITMProxy
  def initialize(port: 8888)
    @port = port
    @server = WEBrick::HTTPProxyServer.new(
      Port: @port,
      SSLEnable: true,
      SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE,
      ProxyVia: true,
      ProxyContentHandler: method(:handle_content)
    )
  end

  def start
    puts "MITM Proxy running on port #{@port}"
    trap("INT") { @server.shutdown }
    @server.start
  end

  private

  # Handle intercepted content (modify request/response here)
  def handle_content(req, res)
    puts "Intercepted request to #{req.host}"

    # Log or modify the request
    if req.request_line.start_with?("CONNECT")
      handle_https(req, res)
    else
      handle_http(req, res)
    end
  end

  def handle_http(req, res)
    puts "[HTTP] #{req.request_line}"
    # Optionally modify the response
  end

  def handle_https(req, res)
    puts "[HTTPS] #{req.request_line}"

    # Extract the host from the request
    host = req.host || req.unparsed_uri.split(":").first

    if host.nil? || host.empty?
      puts "[ERROR] Unable to extract host from request: #{req.request_line}"
      res.status = 500
      res.body = "Internal Server Error: Unable to determine host"
      return
    end

    # Dynamically generate certificate for the domain
    begin
      cert_data = Certificate.generate(host)
      cert = OpenSSL::X509::Certificate.new(File.read(cert_data[:crt]))
      key = OpenSSL::PKey::RSA.new(File.read(cert_data[:key]))
    rescue ArgumentError => e
      puts "[ERROR] Failed to generate certificate: #{e.message}"
      res.status = 500
      res.body = "Internal Server Error: Invalid certificate request"
      return
    end

    # Set up SSL context
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key

    # Handle decrypted traffic (Placeholder for now)
    puts "[MITM] Intercepting HTTPS for #{host}"
  end
end
