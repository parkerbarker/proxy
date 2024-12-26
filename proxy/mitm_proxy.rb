require 'net/http'
require 'openssl'
require 'uri'
require 'fileutils'
require 'logger'

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
      Thread.new { handle_client(client) }
    end
  end

  private

  def log(message)
    return unless @logging_enabled
    @logger.info(message)
  end

  def handle_client(client)
    request_line = client.gets
    method, target, _ = request_line.split(' ')

    if method == 'CONNECT'
      handle_https_connect(client, target)
    else
      handle_http_request(client, method, target)
    end
  end

  def handle_https_connect(client, target)
    host, port = target.split(':')
    port ||= 443

    log("[HTTPS] Intercepting: #{host}:#{port}")

    cert, key = generate_or_retrieve_cert(host)

    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_context.cert = cert
    ssl_context.key = key
    ssl_context.min_version = OpenSSL::SSL::TLS1_2_VERSION
    ssl_context.max_version = OpenSSL::SSL::TLS1_3_VERSION

    client.write("HTTP/1.1 200 Connection Established\r\n\r\n")

    client_ssl = OpenSSL::SSL::SSLSocket.new(client, ssl_context)
    client_ssl.sync_close = true
    client_ssl.accept

    forward_https_traffic(client_ssl, host, port)
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

  def generate_or_retrieve_cert(host)
    cert_path = File.join(@cert_dir, "#{host}.crt")
    key_path = File.join(@cert_dir, "#{host}.key")

    if File.exist?(cert_path) && File.exist?(key_path)
      return [
        OpenSSL::X509::Certificate.new(File.read(cert_path)),
        OpenSSL::PKey::RSA.new(File.read(key_path))
      ]
    end

    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{host}")
    cert.issuer = @ca_cert.subject
    cert.public_key = key.public_key
    cert.serial = rand(1..100_000)
    cert.version = 2
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = cert
    extension_factory.issuer_certificate = @ca_cert
    cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE'))
    cert.add_extension(extension_factory.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature'))
    cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))

    cert.sign(@ca_key, OpenSSL::Digest::SHA256.new)

    File.write(cert_path, cert.to_pem)
    File.write(key_path, key.to_pem)

    [cert, key]
  end
end

# Start the proxy
proxy = MITMProxy.new(port: 8080, logging_enabled: true)
proxy.start