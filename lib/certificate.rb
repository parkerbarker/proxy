require "openssl"

class Certificate
  ##
  # Certificate Version

  VERSION = "1.0.2"
  CERT_DIR = File.join(Dir.pwd, "certs")
  Dir.mkdir(CERT_DIR) unless File.exist?(CERT_DIR)

  DEFAULT_CA_CONFIG = {
    hostname: "ca",
    domainname: "mitm.proxy",
    password: "password",
    CA_dir: File.join(Dir.pwd, "certs/CA"),
    keypair_file: File.join(Dir.pwd, "certs/CA", "private/cakeypair.pem"),
    cert_file: File.join(Dir.pwd, "certs/CA", "cacert.pem"),
    serial_file: File.join(Dir.pwd, "certs/CA", "serial"),
    new_certs_dir: File.join(Dir.pwd, "certs/CA", "newcerts"),
    new_keypair_dir: File.join(Dir.pwd, "certs/CA", "private/keypair_backup"),
    crl_dir: File.join(Dir.pwd, "certs/CA", "crl"),
    ca_cert_days: 5 * 365,
    ca_rsa_key_length: 2048,
    cert_days: 365,
    cert_key_length_min: 1024,
    cert_key_length_max: 2048,
    crl_file: File.join(Dir.pwd, "certs/CA", "crl", "ca.crl"),
    crl_pem_file: File.join(Dir.pwd, "certs/CA", "crl", "ca.pem"),
    crl_days: 14,
    name: [
      ["C", "US", OpenSSL::ASN1::PRINTABLESTRING],
      ["O", "mitm.proxy", OpenSSL::ASN1::UTF8STRING],
      ["OU", "ca", OpenSSL::ASN1::UTF8STRING]
    ]
  }

  ##
  # Creates a new Certificate instance using the Certificate
  # Authority described in +ca_config+.  If there is no CA at
  # ca_config[:CA_dir], then Certificate will initialize a new one.

  def initialize(ca_config = {})
    @ca_config = DEFAULT_CA_CONFIG.merge(ca_config)

    create_ca
  end

  def create_self_signed_cert host
    cn = [["C", "US"], ["O", host], ["CN", host]]
    name = OpenSSL::X509::Name.new(cn)
    hostname = name.to_s.scan(/CN=([\w.]+)/)[0][0]

    logger.info "Create cert for #{hostname}"
    cert_config = {type: "server", hostname: hostname}
    _, cert, key = ca.create_cert(cert_config)

    [cert, key]
  end

  ##
  # Creates a new certificate from +cert_config+ that is signed
  # by the CA.

  def create_cert(cert_config)
    dest = cert_config[:hostname] || cert_config[:user]
    key_file = "#{CERT_DIR}/#{dest}/#{dest}_keypair.pem"
    cert_file = "#{CERT_DIR}/#{dest}/cert_#{dest}.pem"
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
  # Creates a new Certificate Authority from @ca_config if it
  # does not already exist at ca_config[:CA_dir].

  def create_ca
    return if File.exist? @ca_config[:CA_dir]

    Dir.mkdir @ca_config[:CA_dir]

    Dir.mkdir File.join(@ca_config[:CA_dir], "private"), 0o700
    Dir.mkdir File.join(@ca_config[:CA_dir], "newcerts")
    Dir.mkdir File.join(@ca_config[:CA_dir], "crl")

    File.open @ca_config[:serial_file], "w" do |f| f << "#{Time.now.to_i}" end

    puts "Generating CA keypair" if $DEBUG
    keypair = OpenSSL::PKey::RSA.new @ca_config[:ca_rsa_key_length]

    cert = OpenSSL::X509::Certificate.new
    name = @ca_config[:name].dup << ["CN", "CA"]
    cert.subject = cert.issuer = OpenSSL::X509::Name.new(name)
    cert.not_before = Time.now
    cert.not_after = Time.now + @ca_config[:ca_cert_days] * 24 * 60 * 60
    cert.public_key = keypair.public_key
    cert.serial = 0x0
    cert.version = 2 # X509v3

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension("basicConstraints", "CA:TRUE", true),
      ef.create_extension("nsComment", "Ruby/OpenSSL Generated Certificate"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
      ef.create_extension("keyUsage", "cRLSign,keyCertSign", true)
    ]
    cert.add_extension ef.create_extension("authorityKeyIdentifier",
      "keyid:always,issuer:always")
    cert.sign(keypair, OpenSSL::Digest.new("SHA256"))

    keypair_export = keypair.export(OpenSSL::Cipher.new("des-ede3-cbc"), @ca_config[:password])

    puts "Writing keypair to #{@ca_config[:keypair_file]}" if $DEBUG
    File.open @ca_config[:keypair_file], "w", 0o400 do |fp|
      fp << keypair_export
    end

    puts "Writing cert to #{@ca_config[:cert_file]}" if $DEBUG
    File.open @ca_config[:cert_file], "w", 0o644 do |f|
      f << cert.to_pem
    end

    puts "Done generating certificate for #{cert.subject}" if $DEBUG
  end

  ##
  # Creates a new RSA key from +cert_config+.

  def create_key(cert_config)
    dest = cert_config[:hostname] || cert_config[:user]
    keypair_file = "#{CERT_DIR}/#{dest}/#{dest}_keypair.pem"
    if File.exist?(keypair_file)
      keypair = OpenSSL::PKey::RSA.new(File.read(keypair_file),
        cert_config[:password])
      return keypair_file, keypair
    end
    Dir.mkdir("#{CERT_DIR}/#{dest}", 0o700) unless File.exist?("#{CERT_DIR}/#{dest}")

    puts "Generating RSA keypair" if $DEBUG
    keypair = OpenSSL::PKey::RSA.new 1024

    if cert_config[:password].nil?
      File.open keypair_file, "w", 0o400 do |f|
        f << keypair.to_pem
      end
    else
      keypair_export = keypair.export(OpenSSL::Cipher.new("des-ede3-cbc"),
        cert_config[:password])

      puts "Writing keypair to #{keypair_file}" if $DEBUG
      File.open keypair_file, "w", 0o400 do |f|
        f << keypair_export
      end
    end

    [keypair_file, keypair]
  end

  ##
  # Creates a new Certificate Signing Request for the keypair in
  # +keypair_file+, generating and saving new keypair if nil.

  def create_csr(cert_config, keypair_file = nil)
    dest = cert_config[:hostname] || cert_config[:user]
    csr_file = "#{CERT_DIR}/#{dest}/csr_#{dest}.pem"

    name = @ca_config[:name].dup
    case cert_config[:type]
    when "server"
      name << ["OU", "CA"]
      name << ["CN", cert_config[:hostname]]
    when "client"
      name << ["CN", cert_config[:user]]
      name << ["emailAddress", cert_config[:email]]
    end
    name = OpenSSL::X509::Name.new name

    keypair = if File.exist? keypair_file
      OpenSSL::PKey::RSA.new(File.read(keypair_file),
        cert_config[:password])
    else
      create_key cert_config
    end

    puts "Generating CSR for #{name}" if $DEBUG

    req = OpenSSL::X509::Request.new
    req.version = 0
    req.subject = name
    req.public_key = keypair.public_key
    req.sign keypair, OpenSSL::Digest.new("MD5")

    puts "Writing CSR to #{csr_file}" if $DEBUG
    File.open csr_file, "w" do |f|
      f << req.to_pem
    end

    csr_file
  end

  ##
  # Signs the certificate described in +cert_config+ and
  # +csr_file+, saving it to +cert_file+.

  def sign_cert(cert_config, cert_file, csr_file)
    csr = OpenSSL::X509::Request.new File.read(csr_file)

    raise "CSR sign verification failed." unless csr.verify csr.public_key

    if csr.public_key.n.num_bits < @ca_config[:cert_key_length_min]
      raise "Key length too short"
    end

    if csr.public_key.n.num_bits > @ca_config[:cert_key_length_max]
      raise "Key length too long"
    end

    if csr.subject.to_a[0, @ca_config[:name].size] != @ca_config[:name]
      raise "DN does not match"
    end

    # Only checks signature here.  You must verify CSR according to your
    # CP/CPS.

    # CA setup

    puts "Reading CA cert from #{@ca_config[:cert_file]}" if $DEBUG
    ca = OpenSSL::X509::Certificate.new File.read(@ca_config[:cert_file])

    puts "Reading CA keypair from #{@ca_config[:keypair_file]}" if $DEBUG
    ca_keypair = OpenSSL::PKey::RSA.new File.read(@ca_config[:keypair_file]),
      @ca_config[:password]

    serial = File.read(@ca_config[:serial_file]).chomp.hex
    File.open @ca_config[:serial_file], "w" do |f|
      f << "%04X" % (serial + 1)
    end

    puts "Generating cert" if $DEBUG

    cert = OpenSSL::X509::Certificate.new
    from = Time.now
    cert.subject = csr.subject
    cert.issuer = ca.subject
    cert.not_before = from
    cert.not_after = from + @ca_config[:cert_days] * 24 * 60 * 60
    cert.public_key = csr.public_key
    cert.serial = serial
    cert.version = 2 # X509v3

    basic_constraint = nil
    key_usage = []
    ext_key_usage = []
    alt_names = []

    case cert_config[:type]
    when "ca"
      basic_constraint = "CA:TRUE"
      key_usage << "cRLSign" << "keyCertSign"
    when "terminalsubca"
      basic_constraint = "CA:TRUE,pathlen:0"
      key_usage << "cRLSign" << "keyCertSign"
    when "server"
      basic_constraint = "CA:FALSE"
      key_usage << "digitalSignature" << "keyEncipherment"
      ext_key_usage << "serverAuth"
      alt_names << "DNS: #{cert_config[:hostname]}"
    when "ocsp"
      basic_constraint = "CA:FALSE"
      key_usage << "nonRepudiation" << "digitalSignature"
      ext_key_usage << "serverAuth" << "OCSPSigning"
    when "client"
      basic_constraint = "CA:FALSE"
      key_usage << "nonRepudiation" << "digitalSignature" << "keyEncipherment"
      ext_key_usage << "clientAuth" << "emailProtection"
    else
      raise "unknown cert type \"#{cert_config[:type]}\""
    end

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = ca
    ex = []
    ex << ef.create_extension("basicConstraints", basic_constraint, true)
    ex << ef.create_extension("nsComment",
      "Ruby/OpenSSL Generated Certificate")
    ex << ef.create_extension("subjectKeyIdentifier", "hash")
    # ex << ef.create_extension("nsCertType", "client,email")
    unless key_usage.empty?
      ex << ef.create_extension("keyUsage", key_usage.join(","))
    end
    # ex << ef.create_extension("authorityKeyIdentifier",
    #                          "keyid:always,issuer:always")
    # ex << ef.create_extension("authorityKeyIdentifier", "keyid:always")
    unless ext_key_usage.empty?
      ex << ef.create_extension("extendedKeyUsage", ext_key_usage.join(","))
    end

    if @ca_config[:cdp_location]
      ex << ef.create_extension("crlDistributionPoints",
        @ca_config[:cdp_location])
    end

    if @ca_config[:ocsp_location]
      ex << ef.create_extension("authorityInfoAccess",
        "OCSP;" << @ca_config[:ocsp_location])
    end

    unless alt_names.empty?
      ex << ef.create_extension("subjectAltName", alt_names.join(","))
    end

    cert.extensions = ex
    cert.sign(ca_keypair, OpenSSL::Digest.new("SHA256"))

    backup_cert_file = @ca_config[:new_certs_dir] + "/cert_#{cert.serial}.pem"
    puts "Writing backup cert to #{backup_cert_file}" if $DEBUG
    File.open backup_cert_file, "w", 0o644 do |f|
      f << cert.to_pem
    end

    # Write cert
    dest = cert_config[:hostname] || cert_config[:user]
    cert_file = "#{CERT_DIR}/#{dest}/cert_#{dest}.pem"
    puts "Writing cert to #{cert_file}" if $DEBUG
    File.open cert_file, "w", 0o644 do |f|
      f << cert.to_pem
    end

    [cert_file, cert]
  end
end # class Certificate
