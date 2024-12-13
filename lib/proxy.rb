require "webrick"
require "webrick/httpproxy"
require "webrick/httprequest"

WEBrick::HTTPRequest.class_eval do
  attr_writer :body, :unparsed_uri
end

class Proxy < WEBrick::HTTPProxyServer
  SUPPORTED_METHODS = %w[GET HEAD POST PUT PATCH DELETE OPTIONS CONNECT].freeze
  DEFAULT_CALLBACKS = {}

  attr_reader :callbacks

  def initialize config = {}, default = WEBrick::Config::HTTP
    initialize_callbacks config

    if config[:Quiet]
      config[:Logger] = WEBrick::Log.new(nil, 0)
      config[:AccessLog] = []
    end

    super
  end

  def start
    fire :when_start
    super
  ensure
    fire :when_shutdown
  end

  def stop
    logger.info "#{self.class}#stop: pid=#{$$}"
    super
  end

  def exit
    logger.info "#{self.class}#exit: pid=#{$$}"
    Kernel.exit
  end

  def restart &block
    logger.info "#{self.class}#restart: pid=#{$$}" if @status == :Running
    instance_exec(&block) if block
  end

  def fire event, *args
    logger.info "#{self.class}#service: event=#{event}"
  end

  def service req, res
    logger.info "#{self.class}#service: pid=#{$$}"
    fire :before_request, req
    super(req, res)
    fire :before_response, req, res
  end

  def do_PUT(req, res)
    perform_proxy_request(req, res, Net::HTTP::Put, req.body_reader)
  end

  def do_PATCH(req, res)
    perform_proxy_request(req, res, Net::HTTP::Patch, req.body_reader)
  end

  def do_DELETE(req, res)
    perform_proxy_request(req, res, Net::HTTP::Delete, req.body_reader)
  end

  # SUPPORTED_METHODS.each do |method|
  #   do_method = :"do_#{method}"
  #   do_method_without_callbacks = :"#{do_method}_without_callbacks"
  #   before_method = :"before_#{method.downcase}"
  #   after_method = :"after_#{method.downcase}"

  #   alias_method do_method_without_callbacks, do_method
  #   define_method do_method do |req, res|
  #     fire before_method, req
  #     send do_method_without_callbacks, req, res
  #     fire after_method, req, res
  #   end
  # end

  private

  def initialize_callbacks config
    @callbacks = {}
    DEFAULT_CALLBACKS.each do |key, callbacks|
      @callbacks[key] = callbacks.clone
    end
  end
end
