require_relative "agent"
require_relative "certificate"
require_relative "proxy"

# Acts as a data pipe
#
# Validating, Transforming, Storing of data
# Tap into these events for large data access
#

class Middleware < Proxy
  attr_reader :ca
  HOST = "127.0.0.1"
  DEFAULT_PORT = 443

  def initialize(config = {})
    super
    @mitm_pattern = config[:MITMPattern]
    @mitm_servers = {}
    @mitm_port = 4433
    @ca = Certificate.new(config[:certificate_config])
  end

  def start(host, port)
    return @mitm_servers[host].config[:Port] if @mitm_servers[host]

    cert, key = @ca.create_self_signed_cert(host)
    agent_config = config.merge(
      MITMProxyServer: self,
      SSLEnable: true,
      SSLVerifyClient: OpenSSL::SSL::VERIFY_NONE,
      SSLCertificate: cert,
      SSLPrivateKey: key,
      Port: @mitm_port
    )
    mitm_server = Agent.new(agent_config)

    @mitm_servers[host] = mitm_server

    Thread.new { mitm_server.start }
    mitm_server.config[:Port]
  end

  def do_MITM req, res
    fire(:before_mitm, req)

    host, port = req.unparsed_uri.split(":")
    port ||= DEFAULT_PORT

    mitm_port = start(host, port)
    req.unparsed_uri = "#{HOST}:#{mitm_port}"

    fire(:after_mitm, req, res)
  end

  def do_CONNECT req, res
    if !@mitm_pattern || req.unparsed_uri =~ @mitm_pattern
      do_MITM req, res
    end
    super
  end
end
