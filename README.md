# tlsja3proxy

A HTTP/HTTPS proxy that modifies TLS fingerprints using uTLS, allowing emulation of various modern browsers.

## Features

- Supports a wide range of modern browser TLS fingerprints:
  - Chrome (133, 124, 120, 117, 110, 107, 104)
  - Firefox (117, 110, 108)
  - Safari (18.0, 16.0)
  - Safari iOS (18.0, 17.0, 16.0)
- Automatically handles HTTPS connections with modified TLS fingerprints
- Supports upstream SOCKS5 proxy
- Debug mode for troubleshooting
- Transparent certificate generation for MITM capabilities

## Installation

1. Build from source:
```bash
git clone [repository-url]
cd tlsja3proxy
go build
```

2. Generate CA certificate (automatic on first run):
```bash
# The proxy will automatically generate cert.pem and key.pem on first run
# You need to install cert.pem in your browser or system trust store
```

## Usage

```bash
# Run with default settings (Chrome 133 profile)
./tlsja3proxy

# Specify browser profile
./tlsja3proxy -browser firefox117

# Set proxy listening port
./tlsja3proxy -port 8888

# Use an upstream SOCKS5 proxy
./tlsja3proxy -upstream 127.0.0.1:1080

# Enable debug logging
./tlsja3proxy -debug
```

## Available Browser Profiles

| Profile Name | Browser Version |
|--------------|----------------|
| chrome133    | Chrome 133     |
| chrome124    | Chrome 124     |
| chrome120    | Chrome 120     |
| chrome110    | Chrome 110     |
| chrome107    | Chrome 107     |
| chrome104    | Chrome 104     |
| firefox117   | Firefox 117    |
| firefox110   | Firefox 110    |
| firefox108   | Firefox 108    |
| safari18_0   | Safari 18.0    |
| safari16_0   | Safari 16.0    |
| safari_ios_18_0 | Safari iOS 18.0 |
| safari_ios_17_0 | Safari iOS 17.0 |
| safari_ios_16_0 | Safari iOS 16.0 |

## Command Line Options

- `-cert`: Path to CA certificate (default: cert.pem)
- `-key`: Path to CA private key (default: key.pem)
- `-addr`: Proxy listen address (default: all interfaces)
- `-port`: Proxy listen port (default: 8080)
- `-browser`: Browser profile to emulate (default: chrome133)
- `-upstream`: Upstream SOCKS5 proxy (optional)
- `-debug`: Enable verbose debug logging

## Verifying TLS Fingerprints

To verify that the TLS fingerprints are changing correctly:

1. Start the proxy with a specific browser profile:
```bash
./tlsja3proxy -browser firefox117 -debug
```

2. Configure your browser or system to use the proxy (typically http://localhost:8080)

3. Visit a JA3 fingerprint checking website such as:
   - https://ja3er.com/
   - https://tls.browserleaks.com/
   - https://tools.scrapfly.io/api/fp/ja3

4. You should see a JA3 fingerprint that matches the selected browser profile rather than your actual browser

5. Switch to a different browser profile (e.g., `-browser safari16_0`) and verify that the fingerprint changes

Note that when using curl or other command-line tools with the proxy, you need to ensure they are configured to use the proxy for HTTPS connections, for example:

```bash
curl -x http://localhost:8080 https://ja3er.com/json
```

## Troubleshooting

- **Same fingerprint with different browser profiles**: Ensure you're using the latest version which directly uses uTLS for fingerprinting.
- **Connection errors with curl**: Make sure you're properly configuring curl to use the proxy for HTTPS connections.
- **Certificate issues**: Install the generated cert.pem as a trusted CA in your browser or system.

## How It Works

tlsja3proxy combines [ja3proxy](https://github.com/lylemi/ja3proxy) with the uTLS library to provide enhanced TLS fingerprinting capabilities. When you make a HTTPS request through the proxy:

1. The proxy intercepts the CONNECT request
2. It establishes a connection to the target server using uTLS with the selected browser fingerprint
3. It generates a dynamic certificate for the MITM connection
4. It proxies the data between your client and the target server

## Credits

This tool combines:
- [ja3proxy](https://github.com/lylemi/ja3proxy) - The original proxy framework
- [utls](https://github.com/bogdanfinn/utls) - TLS fingerprinting library
- [tls-client](https://github.com/bogdanfinn/tls-client) - Modern browser TLS fingerprinting implementation
