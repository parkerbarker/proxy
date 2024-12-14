class Certificate
  module Authority
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
  end
end
