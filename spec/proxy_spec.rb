require "proxy"
RSpec.describe Proxy do
  before :all do
    @server_thread = Thread.new do
      @server = Proxy.new Port: 3128, Quiet: true
      @server.start
    end

    # Wait a moment to ensure the server is fully started
    sleep 1
  end

  after :all do
    @server.shutdown
    @server_thread.join
  end

  let(:proxy_host) { "127.0.0.1" }
  let(:proxy_port) { 3128 }

  describe "http" do
    it "proxies GET requests" do
      response = HTTP.via(proxy_host, proxy_port).get("http://httpbin.org/get")
      expect(response).not_to be_nil
      expect(response.status).to eq(200)
    end

    it "proxies POST requests" do
      response = HTTP.via(proxy_host, proxy_port).post("http://httpbin.org/post", form: {param: "value"})
      expect(response).not_to be_nil

      json = JSON.parse(response.body.to_s)
      expect(json["form"]["param"]).to eq("value")
    end

    it "proxies PUT requests", focuse: true do
      response = HTTP.headers(accept: "application/json").via(proxy_host, proxy_port).put("http://httpbin.org/put", form: {param: "value"})
      expect(response).not_to be_nil

      json = JSON.parse(response.body.to_s)
      expect(json["form"]["param"]).to eq("value")
    end

    it "proxies PATCH requests" do
      response = HTTP.via(proxy_host, proxy_port).patch("http://httpbin.org/patch", form: {param: "value"})
      expect(response).not_to be_nil

      json = JSON.parse(response.body.to_s)
      expect(json["form"]["param"]).to eq("value")
    end

    it "proxies DELETE requests" do
      response = HTTP.via(proxy_host, proxy_port).delete("http://httpbin.org/delete")
      expect(response).not_to be_nil
    end

    it "proxies HEAD requests" do
      response = HTTP.via(proxy_host, proxy_port).head("http://httpbin.org/get")
      expect(response).not_to be_nil
    end
  end
end
