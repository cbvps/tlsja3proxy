package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	utls "github.com/bogdanfinn/utls"
)

// Global instance of the tls-client
var (
	tlsClientInstance tlsclient.HttpClient
	clientMutex       sync.Mutex
)

// ALPSExtension implements Application Layer Protocol Settings (ALPS) Extension
// RFC draft: https://datatracker.ietf.org/doc/html/draft-ietf-tls-alps
type ALPSExtension struct {
	SupportedVersions []uint16
	CipherSuites      []uint16
}

// TypeID returns the extension type ID
func (e *ALPSExtension) TypeID() uint16 { return 0x4469 } // ALPS extension ID

// Marshal implements the TLSExtension interface
func (e *ALPSExtension) Marshal() ([]byte, error) {
	if len(e.CipherSuites) == 0 || len(e.SupportedVersions) == 0 {
		return nil, errors.New("ALPSExtension: CipherSuites and SupportedVersions must not be empty")
	}

	totalLength := 2 + 2*len(e.SupportedVersions) + 2 + 2*len(e.CipherSuites)
	result := make([]byte, 4+totalLength)

	// Extension Type
	binary.BigEndian.PutUint16(result[0:], e.TypeID())
	// Extension Length
	binary.BigEndian.PutUint16(result[2:], uint16(totalLength))

	// Supported Versions Length
	binary.BigEndian.PutUint16(result[4:], uint16(2*len(e.SupportedVersions)))
	// Supported Versions List
	for i, v := range e.SupportedVersions {
		binary.BigEndian.PutUint16(result[6+2*i:], v)
	}

	// Cipher Suites Length
	offset := 6 + 2*len(e.SupportedVersions)
	binary.BigEndian.PutUint16(result[offset:], uint16(2*len(e.CipherSuites)))
	// Cipher Suites List
	for i, cs := range e.CipherSuites {
		binary.BigEndian.PutUint16(result[offset+2+2*i:], cs)
	}

	return result, nil
}

// Unmarshal implements the TLSExtension interface
func (e *ALPSExtension) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return errors.New("ALPSExtension: data too short")
	}

	extID := binary.BigEndian.Uint16(data[0:])
	if extID != e.TypeID() {
		return fmt.Errorf("ALPSExtension: unexpected type ID %d, expected %d", extID, e.TypeID())
	}

	extLen := int(binary.BigEndian.Uint16(data[2:]))
	if 4+extLen != len(data) {
		return errors.New("ALPSExtension: data length mismatch")
	}

	verLen := int(binary.BigEndian.Uint16(data[4:]))
	if verLen%2 != 0 || verLen+6 > len(data) {
		return errors.New("ALPSExtension: invalid versions length")
	}

	e.SupportedVersions = make([]uint16, verLen/2)
	for i := range e.SupportedVersions {
		e.SupportedVersions[i] = binary.BigEndian.Uint16(data[6+2*i:])
	}

	offset := 6 + verLen
	csLen := int(binary.BigEndian.Uint16(data[offset:]))
	if csLen%2 != 0 || offset+2+csLen > len(data) {
		return errors.New("ALPSExtension: invalid cipher suites length")
	}

	e.CipherSuites = make([]uint16, csLen/2)
	for i := range e.CipherSuites {
		e.CipherSuites[i] = binary.BigEndian.Uint16(data[offset+2+2*i:])
	}

	return nil
}

// Read implements the TLSExtension interface
func (e *ALPSExtension) Read(b []byte) (n int, err error) {
	data, err := e.Marshal()
	if err != nil {
		return 0, err
	}
	if len(b) < len(data) {
		return 0, io.ErrShortBuffer
	}
	copy(b, data)
	return len(data), nil
}

// Len implements the TLSExtension interface
func (e *ALPSExtension) Len() int {
	if len(e.CipherSuites) == 0 || len(e.SupportedVersions) == 0 {
		return 4
	}
	return 4 + 2 + 2*len(e.SupportedVersions) + 2 + 2*len(e.CipherSuites)
}

// String implements the TLSExtension interface
func (e *ALPSExtension) String() string {
	return "ALPS Extension"
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// Initialize the TLS client with the specified browser profile
func initTLSClient() error {
	clientMutex.Lock()
	defer clientMutex.Unlock()

	if tlsClientInstance != nil {
		return nil
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(GetClientProfile(Config.BrowserProfile)),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithTimeoutSeconds(30),
	}

	var err error
	tlsClientInstance, err = tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	return err
}

// Create a TLS connection with the browser fingerprint using direct utls for proper fingerprinting
func customTLSWrap(conn net.Conn, sni string) (net.Conn, error) {
	// Get the client hello ID based on the configured browser profile
	clientHelloID := getClientHelloID(Config.BrowserProfile)

	// Create a utls connection with the specific client hello
	utlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, clientHelloID, false, false) // Set randomize to false to match profile exactly

	// Perform the handshake
	if err := utlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	log.Printf("Connected to %s using browser profile: %s", sni, Config.BrowserProfile)

	return utlsConn, nil
}

// Map browser profile names to utls ClientHelloID using tls-client profile specs
func getClientHelloID(profileName string) utls.ClientHelloID {
	// Extract browser and version information from the profile name
	browser, version := parseBrowserInfo(profileName)

	// Create a ClientHelloID that will generate a spec matching tls-client's profiles
	return utls.ClientHelloID{
		Client:               browser,
		Version:              version,
		RandomExtensionOrder: false,
		Seed:                 nil,
		SpecFactory: func() (utls.ClientHelloSpec, error) {
			return createClientHelloSpec(profileName), nil
		},
	}
}

// Extract browser and version information from profile name
func parseBrowserInfo(profileName string) (browser, version string) {
	profileName = strings.ToLower(profileName)

	if strings.HasPrefix(profileName, "chrome") {
		browser = "Chrome"
		version = strings.TrimPrefix(profileName, "chrome")
	} else if strings.HasPrefix(profileName, "firefox") {
		browser = "Firefox"
		version = strings.TrimPrefix(profileName, "firefox")
	} else if strings.HasPrefix(profileName, "opera") {
		browser = "Opera"
		version = strings.TrimPrefix(profileName, "opera")
	} else if strings.HasPrefix(profileName, "safari_ios") {
		browser = "Safari iOS"
		version = strings.TrimPrefix(profileName, "safari_ios_")
	} else if strings.HasPrefix(profileName, "safari") {
		browser = "Safari"
		version = strings.TrimPrefix(profileName, "safari")
		if strings.HasPrefix(version, "_") {
			version = strings.TrimPrefix(version, "_")
		}
	} else {
		// Default to Chrome 133
		browser = "Chrome"
		version = "133"
	}

	return browser, version
}

// Create a ClientHelloSpec based on tls-client's profiles
func createClientHelloSpec(profileName string) utls.ClientHelloSpec {
	// This is where we'll implement the specs for each profile
	// We need to handle each profile we want to support

	switch strings.ToLower(profileName) {
	case "chrome133":
		return createChrome133Spec()
	case "chrome124":
		return createChrome124Spec()
	case "chrome120":
		return createChrome120Spec()
	case "chrome110":
		return createChrome110Spec()
	case "firefox117":
		return createFirefox117Spec()
	case "firefox110":
		return createFirefox110Spec()
	case "safari_ios_16_0", "safari_ios_17_0", "safari_ios_18_0":
		return createSafariIOSSpec()
	case "safari16_0", "safari18_0":
		return createSafariSpec()
	case "opera91", "opera90":
		return createOperaSpec()
	// Add more cases for other browsers as needed
	default:
		// Default to Chrome 133
		return createChrome133Spec()
	}
}

// Create a ClientHelloSpec based on the Chrome 133 profile from tls-client
func createChrome133Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				51969, // X25519MLKEM768 (Kyber) curve ID
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtension{
				SupportedProtocols: []string{"h2"},
			},
			// ALPS Extension (Application Layer Protocol Settings)
			&utls.GenericExtension{Id: 0x4469, Data: []byte{
				// Supported Versions length: 2 bytes
				0x00, 0x02,
				// TLS 1.3: 0x0304
				0x03, 0x04,
				// Cipher Suites length: 6 bytes
				0x00, 0x06,
				// TLS_AES_128_GCM_SHA256: 0x1301
				0x13, 0x01,
				// TLS_AES_256_GCM_SHA384: 0x1302
				0x13, 0x02,
				// TLS_CHACHA20_POLY1305_SHA256: 0x1303
				0x13, 0x03,
			}},
			&utls.UtlsGREASEExtension{},
			utls.BoringGREASEECH(),
		},
	}
}

// Chrome 124 specification from tls-client
func createChrome124Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtension{
				SupportedProtocols: []string{"h2"},
			},
			&utls.UtlsGREASEExtension{},
			utls.BoringGREASEECH(),
		},
	}
}

// Chrome 120 specification from tls-client
func createChrome120Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.ApplicationSettingsExtension{
				SupportedProtocols: []string{"h2"},
			},
			&utls.UtlsGREASEExtension{},
			utls.BoringGREASEECH(),
		},
	}
}

// Chrome 110 specification from tls-client
func createChrome110Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionBrotli,
			}},
			&utls.UtlsGREASEExtension{},
			utls.BoringGREASEECH(),
		},
	}
}

// Firefox 117 specification from tls-client
func createFirefox117Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.X25519,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// Firefox 110 specification from tls-client
func createFirefox110Spec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.X25519,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}

// Safari specification from tls-client
func createSafariSpec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
			&utls.UtlsGREASEExtension{},
		},
	}
}

// Safari iOS specification from tls-client
func createSafariIOSSpec() utls.ClientHelloSpec {
	return utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []byte{
			utls.CompressionNone,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{
				utls.PointFormatUncompressed,
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{
				"h2",
				"http/1.1",
			}},
			&utls.StatusRequestExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{
				utls.PskModeDHE,
			}},
		},
	}
}

// Opera specification from tls-client
func createOperaSpec() utls.ClientHelloSpec {
	// Opera uses the same spec as Chrome for the most part
	return createChrome120Spec()
}

// Use tls-client to fetch a URL via the proxy, for testing
func fetchViaProxy(proxyURL, targetURL string) (*http.Response, error) {
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(GetClientProfile(Config.BrowserProfile)),
		tlsclient.WithInsecureSkipVerify(),
		tlsclient.WithTimeoutSeconds(30),
	}

	// Parse the proxy URL
	if proxyURL != "" {
		// Set proxy through the available option
		options = append(options, tlsclient.WithProxyUrl(proxyURL))
	}

	// If we have an upstream SOCKS5 proxy configured, use it
	if Config.Upstream != "" {
		parts := strings.Split(Config.Upstream, ":")
		if len(parts) >= 2 {
			host := parts[0]
			port := parts[1]

			socksProxy := fmt.Sprintf("socks5://%s:%s", host, port)

			// If we have credentials
			if len(parts) >= 4 {
				user := parts[2]
				pass := parts[3]
				socksProxy = fmt.Sprintf("socks5://%s:%s@%s:%s", user, pass, host, port)
			}

			log.Printf("Configuring tls-client to use upstream SOCKS5 proxy: %s", socksProxy)
			options = append(options, tlsclient.WithProxyUrl(socksProxy))
		}
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	// Create request using fhttp which is used by tls-client
	req, err := fhttp.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// Create a compatible http.Response
	httpResp := &http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Header:     http.Header{},
		Body:       resp.Body,
	}

	// Copy headers
	for k, v := range resp.Header {
		for _, val := range v {
			httpResp.Header.Add(k, val)
		}
	}

	return httpResp, nil
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	log.Printf("proxy to %s", r.Host)

	destConn, err := CustomDialer.Dial("tcp", r.Host)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Tunneling err: ", err)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		log.Println("Hijacking not supported")
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println("Hijack error: ", err)
	}
	go connect(strings.Split(r.Host, ":")[0], destConn, clientConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()

	destTLSConn, err := customTLSWrap(destConn, sni)
	if err != nil {
		fmt.Println("TLS handshake failed: ", err)
		return
	}

	tlsCert, err := generateCertificate(sni)
	if err != nil {
		fmt.Println("Error generating certificate: ", err)
		return
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{tlsCert},
	}

	// Get the negotiated protocol
	var protocols string
	if tlsConn, ok := destTLSConn.(*utls.UConn); ok {
		state := tlsConn.ConnectionState()
		protocols = state.NegotiatedProtocol
	}

	if protocols == "h2" {
		config.NextProtos = []string{"h2", "http/1.1"}
	} else {
		config.NextProtos = []string{"http/1.1"}
	}

	clientTLSConn := tls.Server(
		clientConn,
		config,
	)
	err = clientTLSConn.Handshake()
	if err != nil {
		log.Println("Failed to perform TLS handshake: ", err)
		return
	}

	if Config.Debug {
		debugJunction(destTLSConn, clientTLSConn)
	} else {
		junction(destTLSConn, clientTLSConn)
	}
}

func junction(destConn net.Conn, clientConn net.Conn) {
	chDone := make(chan bool, 2)

	go func() {
		_, err := io.Copy(destConn, clientConn)
		if err != nil {
			log.Println("copy dest to client error: ", err)
		}
		chDone <- true
	}()

	go func() {
		_, err := io.Copy(clientConn, destConn)
		if err != nil {
			log.Println("copy client to dest error: ", err)
		}
		chDone <- true
	}()

	// wait for both copy ops to complete
	<-chDone
	<-chDone
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
