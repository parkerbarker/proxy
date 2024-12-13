class Certificate
  module SignCert
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
      final_cert_file = write_cert(cert, dest)

      [final_cert_file, cert]
    end

    private

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
      raise "CA key file not found: #{@config[:keypair_file]}" unless File.exist?(@config[:keypair_file])
      ca = OpenSSL::X509::Certificate.new(File.read(@config[:cert_file]))
      begin
        ca_keypair = OpenSSL::PKey::RSA.new(File.read(@config[:keypair_file]), @config[:password])
      rescue OpenSSL::PKey::RSAError => e
        raise "Failed to load CA keypair: #{e.message}"
      end

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
  end
end
