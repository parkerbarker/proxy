require 'net/http'
require 'openssl'
require 'uri'
require 'fileutils'
require 'logger'
require_relative 'certificate'

class MITMProxy
  def initialize(port:, logging_enabled: true)
    @port = port
    @logging_enabled = logging_enabled

    # Hardcoded paths for certificates and keys
    base_cert_dir = File.expand_path('../certificates', __dir__)
    @ca_cert_path = File.join(base_cert_dir, 'root/certs/rootCA.crt')
    @ca_key_path = File.join(base_cert_dir, 'root/private/rootCA.key')
    @cert_dir = File.join(base_cert_dir, 'dynamic')

    # Load CA certificate and key
    @ca_cert = OpenSSL::X509::Certificate.new(File.read(@ca_cert_path))
    @ca_key = OpenSSL::PKey::RSA.new(File.read(@ca_key_path))

    # Ensure the dynamic certificates directory exists
    FileUtils.mkdir_p(@cert_dir)

    # Set up logging
    @logger = Logger.new('proxy_logs.log', 'daily') if @logging_enabled
  end

  def start
    puts "MITM Proxy running on port #{@port}..."
    server = TCPServer.new(@port)
    loop do
      client = server.accept
      next if client.nil?
      Thread.new { handle_client(client) }
    end
  end

  private

  def log(message)
    return unless @logging_enabled
    @logger.info(message)
  end

  def handle_client(client)
    begin
      return if client.nil?
  
      request_line = client.gets
      return if request_line.nil?
  
      method, target, _ = request_line.split(' ')
  
      unless valid_http_method?(method)
        send_error_response(client, 405, "Method not Allowed: #{method}")
        return
      end
  
      if method == 'CONNECT'
        handle_https_connect(client, target)
      else
        handle_http_request(client, method, target)
      end
    rescue StandardError => e
      log("[ERROR] Unexpected error: #{e.message}")
      send_error_response(client, 500, "Internal Server Error: #{e.message}") if client
    ensure
      client&.close unless client&.closed?
    end
  end  

  def send_error_response(client, code, message)
    response = "HTTP/1.1 #{code} #{http_status_message(code)}\r\n"
    response += "Content-Type: text/plain\r\n"
    response += "Content-Length: #{message.bytesize}\r\n"
    response += "Connection: close\r\n\r\n"
    response += message
    client.write(response)
    log("[ERROR] Sent #{code}: #{message}")
  end

  def valid_http_method?(method)
    %w[CONNECT GET POST PUT DELETE PATCH].include?(method)
  end

  def valid_domain?(domain)
    return false unless domain
    domain =~ /\A[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\z/
  end

  def http_status_message(code)
    {
      400 => "Bad Request",
      405 => "Method Not Allowed",
      500 => "Internal Server Error",
      501 => "Not Implemented"
    }[code] || "Unknown Status"
  end

  def handle_https_connect(client, target)
    host, port = target.split(':')
    port ||= 443

    # Validate the domain
    unless valid_domain?(host)
      log("[ERROR] Invalid domain in HTTPS target: #{host}")
      send_error_response(client, 400, "Invalid domain in HTTPS target: #{host}")
      return
    end

    log("[HTTPS] Intercepting: #{host}:#{port}")

    # Generate or retrieve certificate and key for the host
    begin
      cert, key = Certificate.generate_or_retrieve_cert(host, @cert_dir, @ca_key, @ca_cert)
    rescue => e
      log("[ERROR] Failed to generate or retrieve certificate for #{host}: #{e.message}")
      send_error_response(client, 500, "Internal Server Error: Unable to generate certificate for #{host}")
      return # Exit the thread
    end

    # Set up SSL context for the client connection
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key
    ssl_context.min_version = OpenSSL::SSL::TLS1_2_VERSION
    ssl_context.max_version = OpenSSL::SSL::TLS1_3_VERSION

    # Respond to the client to establish the connection
    client.write("HTTP/1.1 200 Connection Established\r\n\r\n")

    # Create an SSL connection with the client
    begin
      client_ssl = OpenSSL::SSL::SSLSocket.new(client, ssl_context)
      client_ssl.sync_close = true
      client_ssl.accept

      # Forward traffic between the client and the upstream server
      forward_https_traffic(client_ssl, host, port)
    rescue => e
      log("[ERROR] Failed to establish SSL connection with client: #{e.message}")
    ensure
      client_ssl.close if client_ssl && !client_ssl.closed?
    end
  end

  def forward_https_traffic(client_ssl, host, port)
    uri = URI("https://#{host}")
    http = Net::HTTP.new(uri.host, port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    loop do
      begin
        request_data = client_ssl.readpartial(4096)
        request_line, headers, body = parse_request(request_data)

        method, path, _version = request_line.split(' ')
        uri = URI("https://#{host}#{path}")

        log("[HTTPS] Request to #{host}")
        log("Method: #{method}")
        log("Headers: #{headers}")
        log("Body (original): #{body}") if body

        # Optionally modify the request body
        if method == 'POST' && body
          modified_body = "#{body}&modified=true"
          log("Body (modified): #{modified_body}")
          body = modified_body
        end

        upstream_request = case method
                           when 'GET' then Net::HTTP::Get.new(uri)
                           when 'POST' then Net::HTTP::Post.new(uri).tap { |req| req.body = body }
                           when 'PUT' then Net::HTTP::Put.new(uri).tap { |req| req.body = body }
                           when 'DELETE' then Net::HTTP::Delete.new(uri)
                           else
                             log("[ERROR] Unsupported HTTP method: #{method}")
                             break
                           end

        headers.each { |key, value| upstream_request[key] = value }

        upstream_response = http.request(upstream_request)

        log("[HTTPS] Response from #{host}")
        log("Status: #{upstream_response.code}")
        log("Headers: #{upstream_response.each_header.to_h}")
        log("Body: #{upstream_response.body}") if upstream_response.body

        client_ssl.write "HTTP/#{upstream_response.http_version} #{upstream_response.code} #{upstream_response.message}\r\n"
        upstream_response.each_header { |key, value| client_ssl.write("#{key}: #{value}\r\n") }
        client_ssl.write("\r\n")
        client_ssl.write(upstream_response.body) if upstream_response.body
      rescue EOFError
        log("[HTTPS] Connection closed by client or server")
        break
      rescue => e
        log("[ERROR] #{e.message}")
        break
      end
    end
  ensure
    client_ssl.close
  end

  def parse_request(data)
    headers, body = data.split("\r\n\r\n", 2)
    request_line, *header_lines = headers.split("\r\n")
    parsed_headers = header_lines.each_with_object({}) do |line, hash|
      key, value = line.split(': ', 2)
      hash[key] = value
    end
    [request_line, parsed_headers, body]
  end

  def handle_http_request(client, method, target)
    uri = URI(target)

    unless valid_domain?(uri.host)
      send_error_response(client, 400, "Invalid domain in HTTP target: #{uri.host}")
      return
    end

    log("[HTTP] Intercepting: #{uri}")

    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP.const_get(method.capitalize).new(uri)

    response = http.request(request)

    log("[HTTP] Request to #{uri.host}")
    log("Method: #{method}")
    log("Response Code: #{response.code}")
    log("Response Headers: #{response.each_header.to_h}")
    log("Response Body: #{response.body}") if response.body

    client.write("HTTP/1.1 #{response.code} #{response.message}\r\n")
    response.each_header { |key, value| client.write("#{key}: #{value}\r\n") }
    client.write("\r\n")
    client.write(response.body)
  ensure
    client.close
  end
end

if __FILE__ == $PROGRAM_NAME
  proxy = MITMProxy.new(port: 8080, logging_enabled: true)
  proxy.start
end