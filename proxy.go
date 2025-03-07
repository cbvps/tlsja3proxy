package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	tlsclient "github.com/bogdanfinn/tls-client"
	utls "github.com/bogdanfinn/utls"
)

// Global instance of the tls-client
var (
	tlsClientInstance tlsclient.HttpClient
	clientMutex       sync.Mutex
)

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
	}, clientHelloID)

	// Perform the handshake
	if err := utlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	
	log.Printf("Connected to %s using browser profile: %s", sni, Config.BrowserProfile)
	
	return utlsConn, nil
}

// Map browser profile names to utls ClientHelloID
func getClientHelloID(profileName string) utls.ClientHelloID {
	// Map common profile names to ClientHelloID values
	switch strings.ToLower(profileName) {
	case "chrome133", "chrome133a":
		return utls.HelloChrome_Auto
	case "chrome124":
		return utls.HelloChrome_Auto
	case "chrome120":
		return utls.HelloChrome_Auto
	case "chrome110":
		return utls.HelloChrome_110
	case "chrome107":
		return utls.HelloChrome_107
	case "chrome104":
		return utls.HelloChrome_104
	case "firefox117", "firefox110":
		return utls.HelloFirefox_Auto
	case "firefox108":
		return utls.HelloFirefox_108
	case "safari18_0", "safari16_0":
		return utls.HelloSafari_16_0
	case "safari_ios_18_0", "safari_ios_17_0":
		return utls.HelloIOS_Auto
	case "safari_ios_16_0":
		return utls.HelloIOS_16_0
	default:
		// Use Chrome as the default
		return utls.HelloChrome_Auto
	}
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
		proxySetting := map[string]string{
			"http":  proxyURL,
			"https": proxyURL,
		}
		options = append(options, tlsclient.WithProxyURL(proxyURL))
		options = append(options, tlsclient.WithProxies(proxySetting))
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}

	// Create request
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Make the request
	return client.Do(req)
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
