require_relative "../../lib/certificate"

RSpec.describe "Certificate Signing" do
  let(:cert_config) do
    {
      hostname: "test.server",
      domainname: "test.server",
      password: SecureRandom.hex(16),
      cert_file: "tmp/CA/ca_cert.pem",
      keypair_file: "tmp/CA/ca_keypair.pem",
      serial_file: "tmp/CA/serial",
      csr_file: "tmp/CA/test_csr.pem",
      cert_days: 365,
      cert_directory: "tmp/CA/certs",
      new_certs_dir: "tmp/CA/certs_backup",
      cert_key_length_min: 2048,
      cert_key_length_max: 4096,
      type: "server",
      name: [
        ["C", "US", OpenSSL::ASN1::PRINTABLESTRING],
        ["O", "TestOrg", OpenSSL::ASN1::UTF8STRING],
        ["OU", "TestUnit", OpenSSL::ASN1::UTF8STRING],
        ["CN", "test.server", OpenSSL::ASN1::UTF8STRING]
      ]
    }
  end

  before do
    @certificate = Certificate.new(cert_config, cert_directory: "tmp/CA")

    # Setup CA certificate and keypair
    ca_keypair = OpenSSL::PKey::RSA.new(2048)
    ca_cert = OpenSSL::X509::Certificate.new
    ca_cert.subject = ca_cert.issuer = OpenSSL::X509::Name.parse("/C=US/O=TestCA/OU=TestUnit/CN=TestRoot")
    ca_cert.not_before = Time.now
    ca_cert.not_after = Time.now + 365 * 24 * 60 * 60
    ca_cert.public_key = ca_keypair.public_key
    ca_cert.serial = 0x01
    ca_cert.version = 2
    ca_cert.sign(ca_keypair, OpenSSL::Digest.new("SHA256"))

    File.write(cert_config[:cert_file], ca_cert.to_pem)
    File.write(cert_config[:keypair_file], ca_keypair.export(OpenSSL::Cipher.new("AES-256-CBC"), cert_config[:password]))
    File.write(cert_config[:serial_file], "0001")

    # Create CSR for the test
    keypair = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/C=US/O=TestOrg/OU=TestUnit/CN=test.server")
    csr.public_key = keypair.public_key
    csr.sign(keypair, OpenSSL::Digest.new("SHA256"))

    # Write CSR to file
    File.write(cert_config[:csr_file], csr.to_pem)

    # Create necessary directories
    FileUtils.mkdir_p(cert_config[:cert_directory])
    FileUtils.mkdir_p(cert_config[:new_certs_dir])
  end

  after do
    dir = File.join(Dir.pwd, "tmp/CA")
    FileUtils.rm_rf(dir) if File.directory?(dir)
  end

  it "validates the CA keypair and certificate" do
    # Ensure the keypair and certificate are valid
    expect do
      @certificate.sign_cert(cert_config, nil, cert_config[:csr_file])
    end.not_to raise_error
  end

  it "validates the CSR before signing" do
    # Generate a CSR
    keypair = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/C=US/O=TestOrg/OU=TestUnit/CN=test.server")
    csr.public_key = keypair.public_key
    csr.sign(keypair, OpenSSL::Digest.new("SHA256"))

    csr_file = "tmp/CA/csr_test.server.pem"
    File.write(csr_file, csr.to_pem)

    expect do
      @certificate.sign_cert(cert_config, nil, csr_file)
    end.not_to raise_error

    File.delete(csr_file)
  end

  it "creates a valid certificate signed by the CA" do
    # Generate a CSR
    keypair = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/C=US/O=TestOrg/OU=TestUnit/CN=test.server")
    csr.public_key = keypair.public_key
    csr.sign(keypair, OpenSSL::Digest.new("SHA256"))

    csr_file = "tmp/CA/csr_test.server.pem"
    File.write(csr_file, csr.to_pem)

    cert_file, cert = @certificate.sign_cert(cert_config, nil, csr_file)

    expect(File.exist?(cert_file)).to be true
    expect(cert).to be_a(OpenSSL::X509::Certificate)
    expect(cert.issuer.to_s).to include("TestRoot")
    expect(cert.subject.to_s).to include("test.server")
    expect(cert.not_after).to be > Time.now

    File.delete(csr_file)
  end

  it "writes the certificate to the correct location" do
    # Generate a CSR
    keypair = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/C=US/O=TestOrg/OU=TestUnit/CN=test.server")
    csr.public_key = keypair.public_key
    csr.sign(keypair, OpenSSL::Digest.new("SHA256"))

    csr_file = "tmp/CA/csr_test.server.pem"
    File.write(csr_file, csr.to_pem)

    cert_file, = @certificate.sign_cert(cert_config, nil, csr_file)

    # Verify the certificate file exists
    expect(File.exist?(cert_file)).to be true
    cert = OpenSSL::X509::Certificate.new(File.read(cert_file))
    expect(cert.subject.to_s).to include("test.server")

    File.delete(csr_file)
  end

  it "increments the serial number after signing" do
    # Generate a CSR
    keypair = OpenSSL::PKey::RSA.new(2048)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/C=US/O=TestOrg/OU=TestUnit/CN=test.server")
    csr.public_key = keypair.public_key
    csr.sign(keypair, OpenSSL::Digest.new("SHA256"))

    csr_file = "tmp/CA/csr_test.server.pem"
    File.write(csr_file, csr.to_pem)

    initial_serial = File.read(cert_config[:serial_file]).to_i(16)
    @certificate.sign_cert(cert_config, nil, csr_file)
    new_serial = File.read(cert_config[:serial_file]).to_i(16)

    expect(new_serial).to eq(initial_serial + 1)

    File.delete(csr_file)
  end
end
