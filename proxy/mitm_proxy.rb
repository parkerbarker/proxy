require "webrick"
require "webrick/httpproxy"
require "openssl"
require "socket"
require 'net/http'
require 'logger'
require_relative "../certificates/certificate"

class MITMProxy
  def initialize(port: 8080)
    @port = port
    @logger = Logger.new('proxy_logs.log', 'daily') # Logs rotate daily
    @server = WEBrick::HTTPProxyServer.new(
      Port: @port,
      SSLEnable: true,
      ProxyVia: true,
      # SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE,
      ProxyContentHandler: method(:handle_content)
    )
  end

  def start
    puts "MITM Proxy running on port #{@port}"
    trap("INT") { @server.shutdown }
    @server.start
  end

  private

  def handle_content(req, res)
    puts "Intercepted request to #{req.host}"

    # Handle CONNECT requests for HTTPS traffic
    if req.request_line.start_with?("CONNECT")
      handle_https(req, res)
    else
      handle_http(req, res)
    end
  end

  def handle_http(req, res)
    puts "[HTTP] Intercepted request: #{req.request_line}"

    log_request(req)

    case req.request_method
    when "GET"
      handle_get_request(req, res)
    when "POST"
      handle_post_request(req, res)
    else
      # Handle other HTTP methods (PUT, DELETE, etc.)
      res.status = 405  # Method Not Allowed
      res.body = "Method Not Allowed"
    end
  end

  def handle_get_request(req, res)
    # Check if the request path is the root `/`
    if req.path == "/"
      res.status = 200
      res.body = "Welcome to the MITM Proxy!"  # Custom response for the root path
    else
      forward_request(req, res)
    end
  end

  def handle_post_request(req, res)
    # Example for handling POST requests at `/`
    if req.path == "/"
      # Read the body of the POST request (assuming JSON or form data)
      request_body = req.body
      puts "Received POST data: #{request_body}"

      # Respond to the POST request
      res.status = 200
      res.body = "POST request received. Data: #{request_body}"
    else
      forward_request(req, res)
    end
  end

  def forward_request(req, res)
    uri = URI.parse("http://#{req.host}:#{req.port}#{req.path}")
    
    # Set up the HTTP client to forward the request
    http = Net::HTTP.new(uri.host, uri.port)
    request = case req.request_method
              when "POST"
                Net::HTTP::Post.new(uri.request_uri)
              else
                Net::HTTP::Get.new(uri.request_uri)
              end

    # Forward the original request headers
    req.each_header { |key, value| request[key] = value }

    # Forward the request body for POST
    request.body = req.body if req.request_method == "POST"

    # Send the request and get the response
    response = http.request(request)

    log_response(response)

    # Set the response code and body
    res.status = response.code.to_i
    res.body = response.body
  end

  def handle_https(req, res)
    puts "[HTTPS] #{req.request_line}"

    host = req.request_line.split(" ")[1].split(":")[0]
    port = 443  # Default to port 443 for HTTPS

    if host.nil? || host.empty?
      puts "[ERROR] Unable to extract host from request: #{req.request_line}"
      res.status = 500
      res.body = "Internal Server Error: Unable to determine host"
      return
    end

    # Generate certificate for the intercepted host
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

    puts "Generated certificate for #{host}"

    base_dir = File.expand_path('../certificates', __dir__)

    # Load Root and Intermediate Certificates
    root_ca_cert_path = File.join(base_dir, 'root/certs/rootCA.crt')
    root_ca_cert = OpenSSL::X509::Certificate.new(File.read(root_ca_cert_path))

    intermediate_cert_path = File.join(base_dir, 'intermediate/certs/intermediateCA.crt')
    intermediate_cert = OpenSSL::X509::Certificate.new(File.read(intermediate_cert_path))

    # Create Chain File (chain.pem)
    chain_file_path = File.join(base_dir, 'chain.pem')
    File.open(chain_file_path, 'w') do |f|
      f.puts intermediate_cert.to_pem
      f.puts root_ca_cert.to_pem
    end

    # SSL Context Configuration
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key
    ssl_context.ca_file = chain_file_path
    ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER

    # Use TLS v1.2 and v1.3 (if supported by OpenSSL)
    ssl_context.ssl_version = :TLSv1_2
    ssl_context.ciphers = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'

    # Access the raw socket from the HTTP request
    client = req.instance_variable_get(:@socket)
    client_ssl = OpenSSL::SSL::SSLSocket.new(client, ssl_context)
    client_ssl.sync_close = true

    # Handle SSL handshake with the client
    Thread.new do
      begin
        client_ssl.accept
        puts "[INFO] SSL handshake successful"
      rescue OpenSSL::SSL::SSLError => e
        puts "[ERROR] SSL handshake failed: #{e.message}"
        res.status = 500
        res.body = "SSL Handshake Error: #{e.message}"
        client_ssl.close
      end

      # Establish connection to the upstream server
      begin
        upstream_socket = TCPSocket.new(host, port)
        upstream_ssl = OpenSSL::SSL::SSLSocket.new(upstream_socket)
        upstream_ssl.sync_close = true
        upstream_ssl.connect
      rescue => e
        puts "[ERROR] Failed to connect to upstream server #{host}: #{e.message}"
        client_ssl.close
        return
      end
    end

    # intercept_https(client_ssl, upstream_ssl)
  end

  def intercept_https(client_ssl, upstream_ssl)
    Thread.new do
      begin
        loop do
          data = client_ssl.readpartial(1024)
          log_https_data(data, "Client to Server")
          upstream_ssl.write(data)
        end
      rescue EOFError
        puts "[INFO] EOF reached on client side"
      end
    end

    Thread.new do
      begin
        loop do
          data = upstream_ssl.readpartial(1024)
          log_https_data(data, "Server to Client")
          client_ssl.write(data)
        end
      rescue EOFError
        puts "[INFO] EOF reached on server side"
      end
    end
  end

  def log_request(req)
    @logger.info("[LOG] Request Headers:")
    req.each_header { |k, v| @logger.info("  #{k}: #{v}") }
    @logger.info("[LOG] Request Body: #{req.body}") if req.body
  end

  def log_response(res)
    @logger.info("[LOG] Response Status: #{res.code}")
    res.each_header { |k, v| @logger.info("  #{k}: #{v}") }
    @logger.info("[LOG] Response Body: #{res.body}") if res.body
  end

  def log_https_data(data, direction)
    puts "ahmadaddsads"
    @logger.info("[LOG] HTTPS #{direction} Data:")
    @logger.debug(data.inspect) # Use debug level for detailed data
  end
end