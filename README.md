# PB Proxy

[V1 Project Board](https://github.com/orgs/parkerbarker/projects/4)

#### Install dependencies

```bash
# Install ruby -v 3.2.2 or greater
bundle install
```

#### Start server

This can be run in a ruby session by using `irb`.
```ruby
require_relative "proxy/mitm_proxy"

proxy = MITMProxy.new(port: 8080)
proxy.start
```

#### Run Tests

Tests can be run by running `rspec` command in your console.

#### Test server connection

```bash
curl -x http://localhost:8080 --cacert rootCA.crt -d "param=value" -X POST https://www.example.com
```


