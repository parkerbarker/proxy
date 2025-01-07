require 'rspec'
require 'openssl'
require 'fileutils'
require_relative '../proxy/certificate'

RSpec.describe Certificate do
  let(:host) { "example.com" }
  let(:cert_dir) { File.expand_path("./tmp_certs", __dir__) }
  let(:ca_key) { OpenSSL::PKey::RSA.new(2048) } # Corrected typo here
  let(:ca_cert) do
    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse("/CN=Root CA")
    cert.issuer = cert.subject
    cert.public_key = ca_key.public_key
    cert.serial = 1
    cert.version = 2
    cert.not_before = Time.now
    cert.not_after = Time.now + 365 * 24 * 60 * 60
    cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
    cert
  end

  let(:cert_path) { File.join(cert_dir, "#{host}.crt") }
  let(:key_path) { File.join(cert_dir, "#{host}.key") }

  before do
    FileUtils.mkdir_p(cert_dir)
  end

  after do
    FileUtils.rm_rf(cert_dir)
  end

  describe ".generate_or_retrieve_cert" do
    context "when the certificate and key do not exist" do
      it "generates a new certificate and key" do
        cert, key = Certificate.generate_or_retrieve_cert(host, cert_dir, ca_key, ca_cert)

        expect(File.exist?(cert_path)).to be true
        expect(File.exist?(key_path)).to be true

        expect(cert).to be_a(OpenSSL::X509::Certificate)
        expect(cert.subject.to_s).to include("CN=#{host}")
        expect(cert.issuer.to_s).to eq(ca_cert.subject.to_s)
        expect(cert.not_before).to be <= Time.now
        expect(cert.not_after).to be > Time.now

        expect(key).to be_a(OpenSSL::PKey::RSA)
        expect(key.public_key.to_pem).to eq(cert.public_key.to_pem)
      end
    end

    context "when the certificate and key already exist" do
      before do

        existing_key = OpenSSL::PKey::RSA.new(2048)
        existing_cert = OpenSSL::X509::Certificate.new
        existing_cert.subject = OpenSSL::X509::Name.parse("/CN=#{host}")
        existing_cert.issuer = ca_cert.subject
        existing_cert.public_key = existing_key.public_key
        existing_cert.serial = rand(1..100_000)
        existing_cert.version = 2
        existing_cert.not_before = Time.now
        existing_cert.not_after = Time.now + 365 * 24 * 60 * 60
        existing_cert.sign(ca_key, OpenSSL::Digest::SHA256.new)

        File.write(cert_path, existing_cert.to_pem)
        File.write(key_path, existing_key.to_pem)
      end

      it "retrieves the existing certificate and key" do
        cert, key = Certificate.generate_or_retrieve_cert(host, cert_dir, ca_key, ca_cert)

        expect(cert.to_pem).to eq(File.read(cert_path))
        expect(key.to_pem).to eq(File.read(key_path))
      end
    end

    context 'when there is an error writing the certificate or key' do
      before do
        allow(File).to receive(:write).and_raise(StandardError, 'File write error')
      end

      it 'raises an error' do
        expect {
          Certificate.generate_or_retrieve_cert(host, cert_dir, ca_key, ca_cert)
        }.to raise_error(StandardError, 'File write error')
      end
    end

    context 'when the CA certificate or key is invalid' do
      let(:invalid_ca_cert) { nil }
      let(:invalid_ca_key) { nil }

      it 'raises an ArgumentError for nil CA certificate' do
        expect {
          Certificate.generate_or_retrieve_cert(host, cert_dir, ca_key, invalid_ca_cert)
        }.to raise_error(ArgumentError, 'CA certificate is invalid')
      end

      it 'raises an ArgumentError for nil CA key' do
        expect {
          Certificate.generate_or_retrieve_cert(host, cert_dir, invalid_ca_key, ca_cert)
        }.to raise_error(ArgumentError, 'CA key is invalid')
      end
    end
  end
end