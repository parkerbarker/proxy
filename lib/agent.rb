require "openssl"
require_relative "proxy"

# Acts on behalf of the requestor
#
# Denote this system as a class responsible with filtering
# the client requests going to the internet.
#
# I could see agents for different kind of privacy
# Like if I'm sending the wrong password it'd be great to send the right one from my bitwarden
# Or like any place where I use the name ender I would prefer for it to be gavin
# Or if theres a picture going out with my kids face on it, it should be blurred
# Or if there are any nude pictures going out, they should be stopped =)
#

class Agent < Proxy
  def initialize_callbacks(config)
    @mitm_server = config[:MITMProxyServer]
  end

  # It's a direct copy from webrick
  # Continues the request on the clients behalf
  def perform_proxy_request(req, res, req_class, body_stream = nil)
    uri = req.request_uri
    path = uri.path.dup
    path << "?" << uri.query if uri.query
    header = setup_proxy_header(req, res)
    upstream = setup_upstream_proxy_authentication(req, res, header)

    body_tmp = []
    http = create_net_http(uri, upstream)
    req_fib = Fiber.new do
      http.start do
        if @config[:ProxyTimeout]
          ##################################   these issues are
          http.open_timeout = 30   # secs  #   necessary (maybe because
          http.read_timeout = 60   # secs  #   Ruby's bug, but why?)
          ##################################
        end
        if body_stream && req["transfer-encoding"] =~ /\bchunked\b/i
          header["Transfer-Encoding"] = "chunked"
        end
        http_req = req_class.new(path, header)
        http_req.body_stream = body_stream if body_stream
        http.request(http_req) do |response|
          # Persistent connection requirements are mysterious for me.
          # So I will close the connection in every response.
          res["proxy-connection"] = "close"
          res["connection"] = "close"

          # stream Net::HTTP::HTTPResponse to WEBrick::HTTPResponse
          res.status = response.code.to_i
          res.chunked = response.chunked?
          choose_header(response, res)
          set_cookie(response, res)
          set_via(res)
          response.read_body do |buf|
            body_tmp << buf
            Fiber.yield # wait for res.body Proc#call
          end
        end # http.request
      end
    end
    req_fib.resume # read HTTP response headers and first chunk of the body
    res.body = ->(socket) do
      while buf = body_tmp.shift
        socket.write(buf)
        buf.clear
        req_fib.resume # continue response.read_body
      end
    end
  end

  def service req, res
    fire :before_agent_request, req
    proxy_service req, res
    fire :before_agent_response, req, res
  end
end
