require "openssl"
require "logger"

class Certificate
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

    @logger = Logger.new(STDOUT)
    @logger.level = Logger::INFO

    create_ca
  end

  private

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
  # Creates a new Certificate Authority from @config if it
  # does not already exist at config[:CA_dir].

  def create_ca
    validate_config!

    initialize_serial_file

    @logger.info("Generating CA keypair")
    keypair = OpenSSL::PKey::RSA.new(@config[:ca_rsa_key_length])

    cert = generate_certificate(keypair)

    export_keypair(keypair)
    write_certificate(cert)

    @logger.info("Done generating certificate for #{cert.subject}")
  end

  def validate_config!
    required_keys = [:serial_file, :keypair_file, :cert_file, :ca_cert_days, :password]
    missing_keys = required_keys.select { |key| @config[key].nil? }
    raise "Missing required config keys: #{missing_keys.join(", ")}" unless missing_keys.empty?
  end

  def initialize_serial_file
    File.open(@config[:serial_file], "w", 0o600) do |f|
      f << SecureRandom.random_number(2**128)
    end
  end

  def generate_certificate(keypair)
    cert = OpenSSL::X509::Certificate.new
    name = @config[:name].dup << ["CN", "CA"]
    cert.subject = cert.issuer = OpenSSL::X509::Name.new(name)
    cert.not_before = Time.now
    cert.not_after = Time.now + @config[:ca_cert_days] * 24 * 60 * 60
    cert.public_key = keypair.public_key
    cert.serial = SecureRandom.random_number(2**128)
    cert.version = 2 # X509v3

    # Initialize the extension factory with proper references
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert

    # Add necessary extensions
    cert.add_extension(ef.create_extension("basicConstraints", "CA:TRUE", true))
    cert.add_extension(ef.create_extension("keyUsage", "cRLSign,keyCertSign", true))
    # TODO: WHAT does this do?
    # cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))

    # Sign the certificate with the private key
    cert.sign(keypair, OpenSSL::Digest.new("SHA512"))
    cert
  end

  def export_keypair(keypair)
    keypair_export = keypair.export(OpenSSL::Cipher.new("AES-256-CBC"), @config[:password])
    @logger.info("Writing keypair to #{@config[:keypair_file]}")
    File.open(@config[:keypair_file], "w", 0o600) do |fp|
      fp << keypair_export
    end
  end

  def write_certificate(cert)
    @logger.info("Writing cert to #{@config[:cert_file]}")
    File.open(@config[:cert_file], "w", 0o644) do |f|
      f << cert.to_pem
    end
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

  ##
  # Creates a new Certificate Signing Request for the keypair in
  # +keypair_file+, generating and saving new keypair if nil.

  def create_csr(cert_config, keypair_file = nil)
    dest = cert_config[:hostname] || cert_config[:user]
    cert_dir = cert_config[:cert_dir] || @cert_directory
    csr_file = File.join(cert_dir, dest, "csr_#{dest}.pem")

    ensure_directory(File.dirname(csr_file))

    # Build the subject name based on cert_config
    name = build_subject_name(cert_config)

    # Retrieve or create the keypair
    keypair = retrieve_or_create_keypair(cert_config, keypair_file)

    # Generate the CSR
    req = generate_csr(name, keypair)

    # Write the CSR to file
    write_csr(csr_file, req)

    csr_file
  end

  # Builds the subject name for the CSR
  def build_subject_name(cert_config)
    name = @config[:name].dup
    case cert_config[:type]
    when "server"
      name << ["OU", "CA"]
      name << ["CN", cert_config[:hostname]]
    when "client"
      name << ["CN", cert_config[:user]]
      name << ["emailAddress", cert_config[:email]]
    else
      raise "Unknown certificate type: #{cert_config[:type]}"
    end
    OpenSSL::X509::Name.new(name)
  end

  # Retrieves or creates the keypair
  def retrieve_or_create_keypair(cert_config, keypair_file)
    if keypair_file && File.exist?(keypair_file)
      OpenSSL::PKey::RSA.new(File.read(keypair_file), cert_config[:password])
    else
      _, keypair = create_key(cert_config)
      keypair
    end
  end

  # Generates the CSR
  def generate_csr(name, keypair)
    req = OpenSSL::X509::Request.new
    req.version = 0
    req.subject = name
    req.public_key = keypair.public_key
    req.sign(keypair, OpenSSL::Digest.new("SHA256"))
    req
  end

  # Writes the CSR to a file
  def write_csr(file_path, req)
    @logger.info("Writing CSR to #{file_path}")
    File.open(file_path, "w", 0o644) do |f|
      f << req.to_pem
    end
  end

  ##
  # Signs the certificate described in +cert_config+ and
  # +csr_file+, saving it to +cert_file+.

  def sign_cert(cert_config, cert_file, csr_file)
    csr = validate_csr(csr_file, cert_config)

    ca, ca_keypair = load_ca

    serial = next_serial

    cert = generate_certificate_sign_cert(csr, ca, ca_keypair, cert_config, serial)

    backup_cert(cert)

    dest = cert_config[:hostname] || cert_config[:user]
    cert_file = write_cert(cert, dest)

    [cert_file, cert]
  end

  # Validates the CSR and returns the parsed object
  def validate_csr(csr_file, cert_config)
    csr = OpenSSL::X509::Request.new(File.read(csr_file))
    raise "CSR sign verification failed." unless csr.verify(csr.public_key)

    key_bits = csr.public_key.n.num_bits
    if key_bits < @config[:cert_key_length_min] || key_bits > @config[:cert_key_length_max]
      raise "Invalid key length: #{key_bits} bits"
    end

    if csr.subject.to_a[0, @config[:name].size] != @config[:name]
      raise "DN does not match"
    end

    csr
  end

  # Loads the CA certificate and keypair
  def load_ca
    ca = OpenSSL::X509::Certificate.new(File.read(@config[:cert_file]))
    ca_keypair = OpenSSL::PKey::RSA.new(File.read(@config[:keypair_file]), @config[:password])
    [ca, ca_keypair]
  end

  # Generates the next serial number
  def next_serial
    serial = File.read(@config[:serial_file]).chomp.hex
    File.open(@config[:serial_file], "w", 0o600) { |f| f << "%04X" % (serial + 1) }
    serial
  end

  # Generates the certificate
  def generate_certificate_sign_cert(csr, ca, ca_keypair, cert_config, serial)
    cert = OpenSSL::X509::Certificate.new
    cert.subject = csr.subject
    cert.issuer = ca.subject
    cert.not_before = Time.now
    cert.not_after = Time.now + @config[:cert_days] * 24 * 60 * 60
    cert.public_key = csr.public_key
    cert.serial = serial
    cert.version = 2 # X509v3

    extensions = build_extensions(cert, ca, cert_config)
    cert.extensions = extensions
    cert.sign(ca_keypair, OpenSSL::Digest.new("SHA256"))
    cert
  end

  # Builds the required extensions for the certificate
  def build_extensions(cert, ca, cert_config)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca

    extensions = []
    extensions << ef.create_extension("basicConstraints", (cert_config[:type] == "ca") ? "CA:TRUE" : "CA:FALSE", true)
    extensions << ef.create_extension("keyUsage", key_usage_for_type(cert_config[:type]).join(","), true)
    extensions << ef.create_extension("extendedKeyUsage", extended_key_usage_for_type(cert_config[:type]).join(","), false) unless cert_config[:type] == "ca"
    extensions << ef.create_extension("subjectAltName", "DNS:#{cert_config[:hostname]}", false) if cert_config[:type] == "server"
    extensions
  end

  # Determines key usage based on certificate type
  def key_usage_for_type(type)
    case type
    when "ca" then ["cRLSign", "keyCertSign"]
    when "server" then ["digitalSignature", "keyEncipherment"]
    when "client" then ["nonRepudiation", "digitalSignature", "keyEncipherment"]
    else raise "Unknown cert type: #{type}"
    end
  end

  # Determines extended key usage based on certificate type
  def extended_key_usage_for_type(type)
    case type
    when "server" then ["serverAuth"]
    when "client" then ["clientAuth", "emailProtection"]
    when "ocsp" then ["OCSPSigning"]
    else []
    end
  end

  # Writes the certificate to a backup file
  def backup_cert(cert)
    backup_cert_file = File.join(@config[:new_certs_dir], "cert_#{cert.serial}.pem")
    @logger.info("Writing backup cert to #{backup_cert_file}")
    File.open(backup_cert_file, "w", 0o644) { |f| f << cert.to_pem }
  end

  # Writes the certificate to its final destination
  def write_cert(cert, dest)
    cert_file = File.join(@cert_directory, dest, "cert_#{dest}.pem")
    ensure_directory(File.dirname(cert_file))
    @logger.info("Writing cert to #{cert_file}")
    File.open(cert_file, "w", 0o644) { |f| f << cert.to_pem }
    cert_file
  end

  # Ensures the directory exists
  def ensure_directory(path)
    Dir.mkdir(path, 0o700) unless File.directory?(path)
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
