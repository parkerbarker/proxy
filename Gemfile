source "https://rubygems.org"

# Specify the Ruby version
ruby "3.2.2"

# Gems required for your script
gem "webrick", "~> 1.8"     # For debugging or HTTP server fallback
gem "async", "~> 2.0"       # For asynchronous event handling
gem "async-http", "~> 0.54" # For handling HTTP requests in async environments

# Task automation
gem "rake", "~> 13.0"       # To define and manage tasks

# Dependency management
gem "bundler", "~> 2.0"

# Development/testing tools
group :development, :test do
  gem "rspec", "~> 3.12"    # Testing framework
  gem "standard", "~> 1.0"  # Code formatting and linting
  gem 'webmock'     # Mocking HTTP/HTTPS requests
  gem 'simplecov'   # Test coverage analysis (optional)
end