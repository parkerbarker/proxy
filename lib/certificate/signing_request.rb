class Certificate
  module SigningRequest
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

    # Ensures the directory exists
    def ensure_directory(path)
      Dir.mkdir(path, 0o700) unless File.directory?(path)
    end
  end
end
