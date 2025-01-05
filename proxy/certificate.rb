class Certificate
  class << self
    def generate_or_retrieve_cert(host, cert_dir, ca_key, ca_cert)
      raise ArgumentError, 'CA key is invalid' if ca_key.nil?
      raise ArgumentError, 'CA certificate is invalid' if ca_cert.nil?

      cert_path = File.join(cert_dir, "#{host}.crt")
      key_path = File.join(cert_dir, "#{host}.key")

      if File.exist?(cert_path) && File.exist?(key_path)
        return [
          OpenSSL::X509::Certificate.new(File.read(cert_path)),
          OpenSSL::PKey::RSA.new(File.read(key_path))
        ]
      end

      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{host}")
      cert.issuer = ca_cert.subject
      cert.public_key = key.public_key
      cert.serial = rand(1..100_000)
      cert.version = 2
      cert.not_before = Time.now
      cert.not_after = Time.now + 365 * 24 * 60 * 60

      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = cert
      extension_factory.issuer_certificate = ca_cert
      cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE'))
      cert.add_extension(extension_factory.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature'))
      cert.add_extension(extension_factory.create_extension('subjectKeyIdentifier', 'hash'))

      cert.sign(ca_key, OpenSSL::Digest::SHA256.new)

      File.write(cert_path, cert.to_pem)
      File.write(key_path, key.to_pem)

      [cert, key]
    end
  end
end