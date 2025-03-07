# tlsja3proxy

A HTTP/HTTPS proxy that modifies TLS fingerprints using tls-client library, allowing emulation of various modern browsers.

## Features

- Supports a wide range of modern browser TLS fingerprints:
  - Chrome (133, 124, 120, 117, 110, 107, 104)
  - Firefox (117, 110, 108)
  - Safari (18.0, 16.0)
  - Safari iOS (18.0, 17.0, 16.0)
  - Opera (91, 90)
- Automatically handles HTTPS connections with modified TLS fingerprints
- Supports upstream SOCKS5 proxy
- Debug mode for troubleshooting
- Transparent certificate generation for MITM capabilities

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
| chrome117    | Chrome 117     |
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
| opera91      | Opera 91       |
| opera90      | Opera 90       |

## Command Line Options

- `-cert`: Path to CA certificate (default: cert.pem)
- `-key`: Path to CA private key (default: key.pem)
- `-addr`: Proxy listen address (default: all interfaces)
- `-port`: Proxy listen port (default: 8080)
- `-browser`: Browser profile to emulate (default: chrome133)
- `-upstream`: Upstream SOCKS5 proxy (optional)
- `-debug`: Enable verbose debug logging

## How It Works

tlsja3proxy integrates [ja3proxy](https://github.com/lylemi/ja3proxy) with [tls-client](https://github.com/bogdanfinn/tls-client) to provide enhanced TLS fingerprinting capabilities. When you make a HTTPS request through the proxy:

1. The proxy intercepts the CONNECT request
2. It establishes a connection to the target server using the selected browser TLS fingerprint
3. It generates a dynamic certificate for the MITM connection
4. It proxies the data between your client and the target server

This allows you to emulate different browsers' TLS fingerprints while maintaining full compatibility with standard HTTP clients.

## Use Cases

- Testing website compatibility with different browsers
- Bypassing some forms of fingerprinting-based blocking
- Web scraping with realistic browser fingerprints
- Security testing and research

## Building from Source

```bash
go build
```

## Credits

This tool combines:
- [ja3proxy](https://github.com/lylemi/ja3proxy) - The original proxy framework
- [tls-client](https://github.com/bogdanfinn/tls-client) - Modern browser TLS fingerprinting library
