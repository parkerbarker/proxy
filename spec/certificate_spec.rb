require "certificate"

RSpec.describe Certificate do
  before(:all) do
    config = {path: "tmp/CA"}
    @certificate = Certificate.new(config)
    @config = @certificate.config
  end

  after(:all) do
    dir = File.join(Dir.pwd, "tmp/CA")
    FileUtils.rm_rf(dir) if File.directory?(dir)
  end

  describe "CA certificate creation" do
    it "creates a CA certificate with the specified configuration" do
      expect(@certificate).not_to be_nil
    end
  end
end

#   after(:all) do
#     # Cleanup generated certificates and directories
#     if File.directory?(@config[:CA_dir])
#       FileUtils.rm_rf(@config[:CA_dir])
#     end
#   end

#   let(:config) { @config }

#   describe "CA certificate creation" do

#     it "generates a valid CA certificate" do
#       cert = OpenSSL::X509::Certificate.new(File.read(config[:cert_file]))
#       expect(cert).to be_a(OpenSSL::X509::Certificate)
#       expect(cert.subject.to_s).to include("CN=ca.test.proxy")
#       expect(cert.issuer.to_s).to include("CN=ca.test.proxy")
#       expect(cert.not_after).to be > Time.now
#     end
#   end

#   describe "Certificate generation" do
#     let(:leaf_config) do
#       {
#         type: "server",
#         hostname: "test.server",
#         cert_days: 365,
#         rsa_key_length: 2048,
#         password: "server_password"
#       }
#     end

#     it "generates a server certificate signed by the CA" do
#       leaf_cert_path = @certificate.generate_leaf_certificate(leaf_config)
#       expect(File.exist?(leaf_cert_path[:keypair_file])).to be true
#       expect(File.exist?(leaf_cert_path[:cert_file])).to be true

#       cert = OpenSSL::X509::Certificate.new(File.read(leaf_cert_path[:cert_file]))
#       expect(cert.issuer.to_s).to include("CN=ca.test.proxy")
#       expect(cert.subject.to_s).to include("CN=test.server")
#     end
#   end

#   describe "CRL management" do
#     it "generates a valid CRL" do
#       crl_path = @certificate.generate_crl
#       expect(File.exist?(crl_path)).to be true

#       crl = OpenSSL::X509::CRL.new(File.read(crl_path))
#       expect(crl).to be_a(OpenSSL::X509::CRL)
#       expect(crl.issuer.to_s).to include("CN=ca.test.proxy")
#     end
#   end
# end
