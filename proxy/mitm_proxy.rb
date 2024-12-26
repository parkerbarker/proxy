require "webrick"
require "webrick/httpproxy"
require "openssl"
require "socket"
require 'net/http'
require 'logger'
require 'timeout'
require 'mutex_m'
require_relative "../certificates/certificate"

class MITMProxy
  def initialize(port: 8080)
    @port = port
    @logger = Logger.new("proxy_logs.log", "daily") # Logs rotate daily
    @server = WEBrick::HTTPProxyServer.new(
      Port: @port,
      SSLEnable: true,
      ProxyVia: true,
      AccessLog: [
        [@logger, "%h %l %u %t \"%r\" %>s %b"],
        [@logger, "%v"]
      ],
      Logger: @logger,
      # SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE,
      ProxyContentHandler: method(:handle_content)
    )
  end

  def start
    puts "MITM Proxy running on port #{@port}"
    trap("INT") do
      puts "Shutting down server..."
      @server.shutdown
      cleanup_resources
    end
    @server.start
  end
  
  private
  
  def cleanup_resources
    # Close all sockets if any
    @server.listeners.each(&:close) if @server.respond_to?(:listeners)
  
    # Terminate threads
    Thread.list.each do |thread|
      thread.kill unless thread == Thread.current
    end
  
    puts "All resources cleaned up."
  end

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
    port = req.request_line.split(" ")[1].split(":")[1] || 443  # Default to port 443 for HTTPS

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
    # ssl_context.extra_chain_cert = [
    #   OpenSSL::X509::Certificate.new(File.read("./certificates/intermediate/certs/intermediateCA.crt")),
    #   OpenSSL::X509::Certificate.new(File.read("./certificates/root/certs/rootCA.crt"))
    # ]

    # Allow multiple SSL/TLS versions
    ssl_context.min_version = OpenSSL::SSL::TLS1_VERSION
    ssl_context.max_version = OpenSSL::SSL::TLS1_2_VERSION
    ssl_context.ciphers = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
  
    # Access the raw socket from the HTTP request
    client = req.instance_variable_get(:@socket)
    client_ssl = OpenSSL::SSL::SSLSocket.new(client, ssl_context)
    # client_ssl.io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
    client_ssl.sync_close = true
  
    upstream_ssl = nil
    upstream_socket = nil

    Thread.new do
      begin
        # Perform SSL handshake with the client
        client_ssl.accept
        puts "[INFO] SSL handshake successful with client"

        upstream_ssl_context = OpenSSL::SSL::SSLContext.new
        # # upstream_ssl_context.ca_file = chain_file_path
        # upstream_ssl_context.ca_file = '/etc/ssl/certs/ca-certificates.crt'
        # upstream_ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        # upstream_ssl_context.min_version = OpenSSL::SSL::TLS1_2_VERSION
        # upstream_ssl_context.max_version = OpenSSL::SSL::TLS1_3_VERSION
        # upstream_ssl_context.ciphers = OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
        
        upstream_ssl_context.set_params(
          ca_file: '/etc/ssl/certs/ca-certificates.crt',
          verify_mode: OpenSSL::SSL::VERIFY_PEER,
          min_version: OpenSSL::SSL::TLS1_VERSION,
          max_version: OpenSSL::SSL::TLS1_2_VERSION,
          ciphers: OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers]
        )
        # Connect to the upstream server
        upstream_socket = TCPSocket.new(host, port)
        puts "[DEBUG] Connected to upstream server #{host} on port #{port}"
      
        upstream_ssl = OpenSSL::SSL::SSLSocket.new(upstream_socket, upstream_ssl_context)
        upstream_ssl.io.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
        upstream_ssl.sync_close = true
      
        # Establish SSL connection to the upstream server
        upstream_ssl.connect
        puts "[INFO] SSL handshake successful with upstream server"

        # Start intercepting HTTPS traffic
        intercept_https(client_ssl, upstream_ssl)

      rescue OpenSSL::SSL::SSLError => e
        puts "[ERROR] SSL error: #{e.message}"
        client_ssl.close unless client_ssl.closed?
        upstream_ssl.close if upstream_ssl && !upstream_ssl.closed?
      rescue SocketError => e
        puts "[ERROR] Socket error: #{e.message}"
        client_ssl.close unless client_ssl.closed?
        upstream_ssl.close if upstream_ssl && !upstream_ssl.closed?
      rescue IOError => e
        puts "[ERROR] IOError: #{e.message}"
        client_ssl.close unless client_ssl.closed?
        upstream_ssl.close if upstream_ssl && !upstream_ssl.closed?
      rescue => e
        puts "[ERROR] Unexpected error: #{e.message}"
        client_ssl.close unless client_ssl.closed?
        upstream_ssl.close if upstream_ssl && !upstream_ssl.closed?
      ensure
        # Ensure all sockets are closed after the operation
        client_ssl.close unless client_ssl.closed?
        upstream_ssl.close if upstream_ssl && !upstream_ssl.closed?
        upstream_socket.close if upstream_socket && !upstream_socket.closed?
      end
    end
  end  

  def intercept_https(client_ssl, upstream_ssl)
    loop do
      if client_ssl.closed?
        puts "A"
      elsif upstream_ssl.closed?
        puts "B"
      end

      readable_sockets = IO.select([client_ssl, upstream_ssl])&.first
  
      readable_sockets&.each do |socket|
        begin
          data = socket.read_nonblock(4096)
          if socket == client_ssl
            puts "sadad"
            upstream_ssl.write(data)
            upstream_ssl.flush
          else
            client_ssl.write(data)
            client_ssl.flush
          end
        rescue IO::WaitReadable, IO::WaitWritable
          next
        rescue EOFError
          puts "[INFO] Connection closed by #{socket == client_ssl ? 'client' : 'upstream'}"
          return
        rescue IOError => e
          puts "[INFO] Stream closed: #{e.message}"
          return
        rescue => e
          puts "[ERROR] Unexpected error during data transfer: #{e.message}"
          return
        end
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
    @logger.info("[LOG] HTTPS #{direction} Data:")
    @logger.debug(data.inspect) # Use debug level for detailed data
  end
end