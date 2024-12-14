require_relative "../../lib/certificate"

RSpec.describe Certificate::Authority do
  let(:ca_config) do
    {
      cert_file: "tmp/CA/ca_cert.pem",
      keypair_file: "tmp/CA/ca_keypair.pem",
      serial_file: "tmp/CA/serial",
      ca_cert_days: 365 * 2,
      password: SecureRandom.hex(16),
      name: [
        ["C", "US", OpenSSL::ASN1::PRINTABLESTRING],
        ["O", "TestCA", OpenSSL::ASN1::UTF8STRING],
        ["OU", "TestUnit", OpenSSL::ASN1::UTF8STRING]
      ],
      ca_rsa_key_length: 2048
    }
  end

  before do
    class CertificateTest
      include Certificate::Authority
      attr_accessor :config, :logger

      def initialize(config)
        @config = config
        @logger = Logger.new(nil) # Prevent actual logging during tests
      end
    end

    @certificate_authority = CertificateTest.new(ca_config)

    # Ensure the directory structure exists
    FileUtils.mkdir_p(File.dirname(ca_config[:cert_file]))
  end

  after do
    dir = File.join(Dir.pwd, "tmp/CA")
    FileUtils.rm_rf(dir) if File.directory?(dir)
  end

  describe "#create_ca" do
    it "creates a new Certificate Authority if it does not exist" do
      @certificate_authority.create_ca

      # Validate the existence of the keypair and certificate files
      expect(File.exist?(ca_config[:keypair_file])).to be true
      expect(File.exist?(ca_config[:cert_file])).to be true
      expect(File.exist?(ca_config[:serial_file])).to be true

      # Validate the contents of the certificate file
      cert = OpenSSL::X509::Certificate.new(File.read(ca_config[:cert_file]))
      expect(cert.subject.to_s).to include("CN=CA")
      expect(cert.issuer.to_s).to include("CN=CA")
      expect(cert.not_after).to be > Time.now
      expect(cert.public_key).to be_a(OpenSSL::PKey::RSA)
    end

    it "raises an error if required configuration keys are missing" do
      @certificate_authority.config.delete(:password)
      expect { @certificate_authority.create_ca }.to raise_error(RuntimeError, /Missing required config keys: password/)
    end
  end

  describe "#initialize_serial_file" do
    it "creates the serial file with a valid random serial number" do
      @certificate_authority.initialize_serial_file

      expect(File.exist?(ca_config[:serial_file])).to be true
      serial = File.read(ca_config[:serial_file]).to_i
      expect(serial).to be_a(Integer)
      expect(serial).to be > 0
    end
  end

  describe "#generate_certificate" do
    it "generates a valid self-signed certificate for the CA" do
      keypair = OpenSSL::PKey::RSA.new(ca_config[:ca_rsa_key_length])
      cert = @certificate_authority.generate_certificate(keypair)

      expect(cert).to be_a(OpenSSL::X509::Certificate)
      expect(cert.subject.to_s).to include("CN=CA")
      expect(cert.issuer.to_s).to include("CN=CA")
      expect(cert.not_after).to be > Time.now
      expect(cert.public_key).to eq(keypair.public_key)
    end
  end

  describe "#export_keypair" do
    it "exports the keypair to the configured keypair file" do
      keypair = OpenSSL::PKey::RSA.new(ca_config[:ca_rsa_key_length])
      @certificate_authority.export_keypair(keypair)

      expect(File.exist?(ca_config[:keypair_file])).to be true

      # Validate the exported keypair
      exported_keypair = OpenSSL::PKey::RSA.new(File.read(ca_config[:keypair_file]), ca_config[:password])
      expect(exported_keypair).to be_a(OpenSSL::PKey::RSA)
      expect(exported_keypair.public_key).to eq(keypair.public_key)
    end
  end

  describe "#write_certificate" do
    it "writes the certificate to the configured certificate file" do
      keypair = OpenSSL::PKey::RSA.new(ca_config[:ca_rsa_key_length])
      cert = @certificate_authority.generate_certificate(keypair)

      @certificate_authority.write_certificate(cert)

      expect(File.exist?(ca_config[:cert_file])).to be true

      # Validate the written certificate
      written_cert = OpenSSL::X509::Certificate.new(File.read(ca_config[:cert_file]))
      expect(written_cert.subject.to_s).to eq(cert.subject.to_s)
      expect(written_cert.public_key).to eq(cert.public_key)
    end
  end
end
