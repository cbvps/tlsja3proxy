package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	// Show usage if no arguments
	if len(os.Args) > 1 && os.Args[1] == "help" {
		fmt.Println("Usage: testchrome133")
		fmt.Println("This tool tests the Chrome 133 fingerprint via the tlsja3proxy")
		return
	}

	// Set browser profile to Chrome 133 in proxy config first
	fmt.Println("Testing Chrome 133 with tlsja3proxy")
	fmt.Println("Make sure the proxy is running with chrome133 profile!")
	fmt.Println("=====================================")

	// Test using our proxy
	proxyURL := "http://localhost:8082"
	targetURL := "https://tls.browserleaks.com/json"

	// Configure the standard HTTP client to use our proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyURL)),
		},
		Timeout: 30 * time.Second,
	}

	// Make the request
	resp, err := client.Get(targetURL)
	if err != nil {
		log.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
	}

	fmt.Printf("Response from %s:\n%s\n", targetURL, string(body))
}

// mustParseURL parses a URL and panics on failure
func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Failed to parse URL %s: %v", urlStr, err)
	}
	return u
}
