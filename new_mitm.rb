require 'openssl'
require 'sinatra'
require 'fileutils'

# Directory to store generated files
OUTPUT_DIR = "./certificates"
FileUtils.mkdir_p(OUTPUT_DIR)

# Generate and save a file
def save_file(filename, content)
  File.write(File.join(OUTPUT_DIR, filename), content)
end

# Generate Root CA
def generate_root_ca
  root_key = OpenSSL::PKey::RSA.new(4096)
  root_ca = OpenSSL::X509::Certificate.new
  root_ca.subject = OpenSSL::X509::Name.new([["CN", "My Root CA"]])
  root_ca.issuer = root_ca.subject
  root_ca.public_key = root_key.public_key
  root_ca.serial = 1
  root_ca.version = 2
  root_ca.not_before = Time.now
  root_ca.not_after = Time.now + (365 * 10 * 24 * 60 * 60)
  root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

  save_file("root_ca.key", root_key.to_pem)
  save_file("root_ca.crt", root_ca.to_pem)
  [root_ca, root_key]
end

# Generate Intermediate CA
def generate_intermediate_ca(root_ca, root_key)
  intermediate_key = OpenSSL::PKey::RSA.new(4096)
  intermediate_csr = OpenSSL::X509::Request.new
  intermediate_csr.subject = OpenSSL::X509::Name.new([["CN", "My Intermediate CA"]])
  intermediate_csr.public_key = intermediate_key.public_key
  intermediate_csr.sign(intermediate_key, OpenSSL::Digest::SHA256.new)

  intermediate_ca = OpenSSL::X509::Certificate.new
  intermediate_ca.subject = intermediate_csr.subject
  intermediate_ca.issuer = root_ca.subject
  intermediate_ca.public_key = intermediate_csr.public_key
  intermediate_ca.serial = 2
  intermediate_ca.version = 2
  intermediate_ca.not_before = Time.now
  intermediate_ca.not_after = Time.now + (365 * 5 * 24 * 60 * 60)
  intermediate_ca.sign(root_key, OpenSSL::Digest::SHA256.new)

  save_file("intermediate_ca.key", intermediate_key.to_pem)
  save_file("intermediate_ca.crt", intermediate_ca.to_pem)
  [intermediate_ca, intermediate_key]
end

# Generate Domain Certificate
def generate_domain_certificate(domain, intermediate_ca, intermediate_key)
  domain_key = OpenSSL::PKey::RSA.new(2048)
  domain_csr = OpenSSL::X509::Request.new
  domain_csr.subject = OpenSSL::X509::Name.new([["CN", domain]])
  domain_csr.public_key = domain_key.public_key
  domain_csr.sign(domain_key, OpenSSL::Digest::SHA256.new)

  domain_cert = OpenSSL::X509::Certificate.new
  domain_cert.subject = domain_csr.subject
  domain_cert.issuer = intermediate_ca.subject
  domain_cert.public_key = domain_csr.public_key
  domain_cert.serial = rand(1000..9999)
  domain_cert.version = 2
  domain_cert.not_before = Time.now
  domain_cert.not_after = Time.now + (365 * 1 * 24 * 60 * 60)
  domain_cert.sign(intermediate_key, OpenSSL::Digest::SHA256.new)

  save_file("#{domain}.key", domain_key.to_pem)
  save_file("#{domain}.crt", domain_cert.to_pem)

  { key: domain_key.to_pem, cert: domain_cert.to_pem }
end

# Generate CA and Intermediate CA on initialization
ROOT_CA, ROOT_KEY = generate_root_ca
INTERMEDIATE_CA, INTERMEDIATE_KEY = generate_intermediate_ca(ROOT_CA, ROOT_KEY)

# Sinatra application to dynamically generate certificates
set :port, 4567

post '/generate_cert' do
  content_type :json
  domain = params['domain']
  halt 400, { error: "Domain is required" }.to_json unless domain

  cert_info = generate_domain_certificate(domain, INTERMEDIATE_CA, INTERMEDIATE_KEY)
  {
    message: "Certificate generated for #{domain}",
    cert: cert_info[:cert],
    key: cert_info[:key]
  }.to_json
end


# ruby script_name.rb
# curl -X POST http://localhost:4567/generate_cert -d "domain=example.com"
