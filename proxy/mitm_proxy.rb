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
    # Run the setup_certs.sh script when the proxy starts
    run_cert_setup_script
    puts "MITM Proxy running on port #{@port}"
    trap("INT") { @server.shutdown }
    @server.start
  end

  private

  def run_cert_setup_script
    puts "Running setup_certs.sh to generate certificates..."
    # Use system to execute the shell script
    system('./certificates/setup_certs.sh')

    if $?.success?
      puts "Certificate setup completed successfully!"
    else
      puts "Error occurred during certificate setup."
    end
  end

  # Handle intercepted content (modify request/response here)
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
    puts "[HTTP] #{req.request_line}"
    # Optionally modify HTTP requests or responses here
  end

  def handle_https(req, res)
    puts "[HTTPS] #{req.request_line}"

    # Extract the host and port from the CONNECT request
    host = req.request_line.split(" ")[1].split(":")[0]

    if host.nil? || host.empty?
      puts "[ERROR] Unable to extract host from request: #{req.request_line}"
      res.status = 500
      res.body = "Internal Server Error: Unable to determine host"
      return
    end

    puts "Host: #{host}"

    # Generate a certificate for the requested domain
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

    # Set up an SSL server for the client
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key

    # Upgrade the connection to SSL
    client = req.io
    client_ssl = OpenSSL::SSL::SSLSocket.new(client, ssl_context)
    client_ssl.sync_close = true

    begin
      client_ssl.accept
    rescue OpenSSL::SSL::SSLError => e
      puts "[ERROR] SSL handshake failed with client: #{e.message}"
      return
    end

    # Establish a connection to the upstream server
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

    # Intercept and modify the traffic
    intercept_https(client_ssl, upstream_ssl)

    # Close the connections
    client_ssl.close
    upstream_ssl.close
  end

  def intercept_https(client_ssl, upstream_ssl)
    Thread.new do
      begin
        loop do
          # Read data from the client, log or modify, and send to the server
          data = client_ssl.readpartial(1024)
          puts "[FROM CLIENT] #{data}"
          # Optionally modify the request here
          upstream_ssl.write(data)
        end
      rescue EOFError
        # End of data
      end
    end

    Thread.new do
      begin
        loop do
          # Read data from the server, log or modify, and send to the client
          data = upstream_ssl.readpartial(1024)
          puts "[FROM SERVER] #{data}"
          # Optionally modify the response here
          client_ssl.write(data)
        end
      rescue EOFError
        # End of data
      end
    end
  end
end