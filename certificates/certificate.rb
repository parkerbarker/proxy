require "openssl"
class Certificate
  class << self
    def generate(domain)
      validate_domain!(domain)

      current_dir = File.dirname(__FILE__)

      intermediate_cert_path = File.join(current_dir, "intermediate/certs/intermediateCA.crt")
      intermediate_key_path = File.join(current_dir, "intermediate/private/intermediateCA.key")
      private_key_path = File.join(current_dir, "intermediate/private/#{domain}.key")
      csr_path = File.join(current_dir, "intermediate/csr/#{domain}.csr")
      cert_path = File.join(current_dir, "intermediate/certs/#{domain}.crt")

      # Generate private key
      private_key = OpenSSL::PKey::RSA.new(2048)
      File.write(private_key_path, private_key.to_pem)

      # Generate CSR
      csr = OpenSSL::X509::Request.new
      csr.version = 0
      csr.subject = OpenSSL::X509::Name.new([["CN", domain]])
      csr.public_key = private_key.public_key
      csr.sign(private_key, OpenSSL::Digest.new("SHA256"))
      File.write(csr_path, csr.to_pem)

      # Load Intermediate CA
      intermediate_cert = OpenSSL::X509::Certificate.new(File.read(intermediate_cert_path))
      intermediate_key = OpenSSL::PKey::RSA.new(File.read(intermediate_key_path))

      # Generate Certificate
      certificate = OpenSSL::X509::Certificate.new
      certificate.serial = Random.rand(1000..9999)
      certificate.version = 2
      certificate.not_before = Time.now
      certificate.not_after = Time.now + 365 * 24 * 60 * 60
      certificate.subject = csr.subject
      certificate.public_key = csr.public_key
      certificate.issuer = intermediate_cert.subject

      # Add Extensions
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = certificate
      ef.issuer_certificate = intermediate_cert

      certificate.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
      certificate.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
      certificate.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth", true))
      certificate.add_extension(ef.create_extension("subjectKeyIdentifier", "hash"))
      certificate.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always"))

      # Sign the Certificate
      certificate.issuer = intermediate_cert.subject
      certificate.sign(intermediate_key, OpenSSL::Digest.new("SHA256"))
      File.write(cert_path, certificate.to_pem)

      {
        key: private_key_path,
        csr: csr_path,
        crt: cert_path,
        domain: domain
      }
    end

    private

    # Validates the domain name
    def validate_domain!(domain)
      # Check if the domain is nil or empty
      if domain.nil? || domain.empty?
        raise ArgumentError, "Domain name cannot be nil or empty"
      end

      # Define the regex pattern for a valid domain name
      domain_regex = /\A[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\z/

      # Check if the domain matches the regex
      unless domain.match?(domain_regex)
        raise ArgumentError, "Invalid domain name: #{domain}"
      end
    end
  end
end
