require "openssl"
require "logger"
require_relative "certificate/sign_cert"
require_relative "certificate/authority"
require_relative "certificate/signing_request"

class Certificate
  include Certificate::SignCert
  include Certificate::Authority
  include Certificate::SigningRequest

  DEFAULT_FOLDER_PATH = "certs/CA"
  DEFUALT_CONFIG = {
    hostname: "ca",
    domainname: "pb.proxy",
    password: ENV.fetch("CA_PASSWORD") { SecureRandom.hex(16) },
    ca_cert_days: 2 * 365,
    ca_rsa_key_length: 2048,
    cert_days: 398,
    cert_key_length_min: 2048,
    cert_key_length_max: 3072,
    crl_days: 14,
    name: [
      ["C", "US", OpenSSL::ASN1::PRINTABLESTRING],
      ["O", "pb.proxy", OpenSSL::ASN1::UTF8STRING],
      ["OU", "ca", OpenSSL::ASN1::UTF8STRING],
      ["CN", "pb.proxy", OpenSSL::ASN1::UTF8STRING]
    ]
  }

  ##
  # Creates a new Certificate instance using the Certificate
  # Authority described in +config+.  If there is no CA at
  # config[:CA_dir], then Certificate will initialize a new one.

  attr_reader :config
  def initialize(config = {}, cert_directory: "certs")
    @cert_directory = File.join(Dir.pwd, cert_directory)
    Dir.mkdir(@cert_directory, 0o700) unless File.exist?(@cert_directory)

    ca_files = config_CA_files
    @config = DEFUALT_CONFIG
      .merge(ca_files)
      .merge(config)

    @logger = Logger.new($stdout)
    @logger.level = Logger::INFO
  end

  def create_self_signed_cert(host)
    cn = [["C", "US"], ["O", host], ["CN", host]]
    name = OpenSSL::X509::Name.new(cn)
    hostname = name.to_s.scan(/CN=([\w.]+)/)[0][0]

    @logger.info "Create cert for #{hostname}"
    cert_config = {type: "server", hostname: hostname}
    _, cert, key = ca.create_cert(cert_config)

    [cert, key]
  end

  ##
  # Creates a new certificate from +cert_config+ that is signed
  # by the CA.

  def create_cert(cert_config)
    dest = cert_config[:hostname] || cert_config[:user]
    key_file = "#{@cert_directory}/#{dest}/#{dest}_keypair.pem"
    cert_file = "#{@cert_directory}/#{dest}/cert_#{dest}.pem"
    if File.exist?(cert_file) && File.exist?(key_file)
      key = OpenSSL::PKey::RSA.new(File.read(key_file))
      cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    else
      cert_keypair, key = create_key(cert_config)
      cert_csr = create_csr(cert_config, cert_keypair)
      cert_file, cert = sign_cert(cert_config, cert_keypair, cert_csr)
    end
    [cert_file, cert, key]
  end

  ##
  # Creates a new RSA key from +cert_config+.

  def create_key(cert_config)
    dest = cert_config[:hostname] || cert_config[:user]
    keypair_file = File.join(@cert_directory, dest, "#{dest}_keypair.pem")

    # Check if the keypair already exists
    if File.exist?(keypair_file)
      @logger.info("Loading existing keypair for #{dest}")
      keypair = OpenSSL::PKey::RSA.new(File.read(keypair_file), cert_config[:password])
      return keypair_file, keypair
    end

    # Ensures the directory exists and is secure
    path = File.join(@cert_directory, dest)
    Dir.mkdir(path, 0o700) unless File.exist?(path)
    @logger.info("Created directory: #{path}")

    # Generate a new keypair
    key_length = cert_config[:key_length] || 2048
    @logger.info("Generating RSA keypair (#{key_length} bits) for #{dest}")
    keypair = OpenSSL::PKey::RSA.new(key_length)

    # Writes the keypair to a file, encrypted if a password is provided
    keypair_data = if password.nil?
      keypair.to_pem
    else
      keypair.export(OpenSSL::Cipher.new("AES-256-CBC"), password)
    end
    File.open(file_path, "w", 0o400) do |f|
      f << keypair_data
    end
    @logger.info("Keypair written to: #{file_path}")

    [keypair_file, keypair]
  end

  def config_CA_files
    {
      CA_dir: File.join(@cert_directory),
      private_dir: File.join(@cert_directory, "private"),
      keypair_file: File.join(@cert_directory, "private/cakeypair.pem"),
      cert_file: File.join(@cert_directory, "cacert.pem"),
      serial_file: File.join(@cert_directory, "serial"),
      new_certs_dir: File.join(@cert_directory, "newcerts"),
      new_keypair_dir: File.join(@cert_directory, "private/keypair_backup"),
      crl_dir: File.join(@cert_directory, "crl"),
      crl_file: File.join(@cert_directory, "crl", "ca.crl"),
      crl_pem_file: File.join(@cert_directory, "crl", "ca.pem")
    }.each do |key, path|
      if key.to_s.include?("dir")
        Dir.mkdir(path, 0o700) unless File.exist?(path)
      else
        # File.open(path, "w") {} unless File.exist?(path)
      end
    end
  end
end # class Certificate
