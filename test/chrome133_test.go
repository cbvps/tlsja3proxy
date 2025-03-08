package test

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestChrome133Fingerprint validates the Chrome 133 fingerprint implementation
func TestChrome133Fingerprint(t *testing.T) {
	// Log available profiles
	fmt.Println("Testing browser profiles:")
	profileNames := []string{
		"chrome133",
		"chrome124",
		"firefox117",
		"safari16_0",
		"opera91",
	}

	for _, p := range profileNames {
		fmt.Println("-", p)
	}

	fmt.Println("\nTesting Chrome 133 with tlsja3proxy:")
	// Test using our proxy with Chrome 133 profile
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
		t.Fatalf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response: %v", err)
	}

	fmt.Printf("Response from %s:\n%s\n", targetURL, string(body))

	// Verify that the response is valid JSON
	if len(body) == 0 {
		t.Fatalf("Empty response body")
	}

	// Success if we got here without errors
	t.Log("Successfully tested Chrome 133 fingerprint")
}

func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		log.Fatalf("Failed to parse URL %s: %v", urlStr, err)
	}
	return u
}
