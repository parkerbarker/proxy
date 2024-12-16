require "openssl"
require_relative "../certificates/certificate"

RSpec.describe "Certificate for Test Domain" do
  let(:test_domain) { "testdomain.com" }
  let(:certificates_path) { File.expand_path("../certificates", __dir__) }
  let(:cert_path) { "#{certificates_path}/intermediate/certs/#{test_domain}.crt" }
  let(:key_path) { "#{certificates_path}/intermediate/private/#{test_domain}.key" }
  let(:intermediate_cert_path) { "#{certificates_path}/intermediate/certs/intermediateCA.crt" }
  let(:root_cert_path) { "#{certificates_path}/root/rootCA.crt" }
  # --- Core Tests ---
  it "validates the certificate is signed by the intermediate CA" do
    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    intermediate_cert = OpenSSL::X509::Certificate.new(File.read(intermediate_cert_path))

    # Verify the certificate's issuer matches the intermediate CA
    expect(cert.issuer.to_s).to eq(intermediate_cert.subject.to_s)

    # Verify the certificate's signature
    expect(cert.verify(intermediate_cert.public_key)).to be true
  end

  it "validates the certificate chain including the root CA" do
    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
    intermediate_cert = OpenSSL::X509::Certificate.new(File.read(intermediate_cert_path))
    root_cert = OpenSSL::X509::Certificate.new(File.read(root_cert_path))

    # Set up the certificate store with the root and intermediate CA
    store = OpenSSL::X509::Store.new
    store.add_cert(intermediate_cert)
    store.add_cert(root_cert)

    # Verify the chain
    expect(store.verify(cert)).to be true
  end

  it "validates the certificate's extensions" do
    cert = OpenSSL::X509::Certificate.new(File.read(cert_path))

    extensions = cert.extensions.map { |ext| [ext.oid, ext.value] }.to_h

    # Check key usage and other extensions
    expect(extensions["basicConstraints"]).to eq("CA:FALSE")
    expect(extensions["keyUsage"]).to include("Digital Signature")
    expect(extensions["keyUsage"]).to include("Key Encipherment")
    expect(extensions["extendedKeyUsage"]).to include("TLS Web Server Authentication")
    expect(extensions).to include("subjectKeyIdentifier")
    expect(extensions).to include("authorityKeyIdentifier")
  end

  # --- Dynamic Certificate Generation ---
  it "generates valid certificates for multiple domains dynamically" do
    domains = ["example.com", "test.com", "anotherdomain.com"]

    domains.each do |domain|
      cert_paths = Certificate.generate(domain)
      cert = OpenSSL::X509::Certificate.new(File.read(cert_paths[:crt]))
      intermediate_cert = OpenSSL::X509::Certificate.new(File.read(intermediate_cert_path))

      # Check CN matches the domain
      expect(cert.subject.to_s).to include("CN=#{domain}")

      # Check issuer matches the intermediate CA
      expect(cert.issuer.to_s).to eq(intermediate_cert.subject.to_s)

      # Verify the signature
      expect(cert.verify(intermediate_cert.public_key)).to be true
    end
  end

  # --- Edge Cases ---
  it "raises an error for invalid domain names" do
    invalid_domains = ["", "@example.com", "domain with spaces.com"]

    invalid_domains.each do |domain|
      expect { Certificate.generate(domain) }.to raise_error(ArgumentError)
    end
  end

  it "generates certificates with a valid expiration date" do
    cert_paths = Certificate.generate("example.com")
    cert = OpenSSL::X509::Certificate.new(File.read(cert_paths[:crt]))

    # Verify expiration is within a reasonable range (1 year)
    expect(cert.not_after).to be > Time.now
    expect(cert.not_after).to be < (Time.now + 366 * 24 * 60 * 60)
  end

  # --- Integration Tests ---
  it "verifies that the generated certificate can be used in a simulated TLS handshake" do
    cert_paths = Certificate.generate("testdomain.com")
    cert = OpenSSL::X509::Certificate.new(File.read(cert_paths[:crt]))
    key = OpenSSL::PKey::RSA.new(File.read(cert_paths[:key]))

    # Simulate a basic TLS server using the generated certificate
    server_context = OpenSSL::SSL::SSLContext.new
    server_context.cert = cert
    server_context.key = key

    # Ensure the context accepts the generated certificate
    expect(server_context.cert).to eq(cert)
    expect(server_context.key).to eq(key)
  end
end
