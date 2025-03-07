package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type UpstreamDialer struct {
	dialer proxy.Dialer
}

func NewUpstreamDialer(socksAddr string, timeout time.Duration) (*UpstreamDialer, error) {
	var dialer proxy.Dialer

	if socksAddr != "" {
		var (
			host, port, user, password string
			auth                       *proxy.Auth
		)

		// Parse the proxy address in format host:port:user:pass
		parts := strings.Split(socksAddr, ":")
		if len(parts) >= 2 {
			host = parts[0]
			port = parts[1]

			if len(parts) >= 4 {
				// Format is host:port:user:pass
				user = parts[2]
				password = parts[3]
				auth = &proxy.Auth{
					User:     user,
					Password: password,
				}

				fmt.Printf("Using SOCKS5 proxy %s:%s with authentication\n", host, port)
			} else {
				// Format is host:port with no auth
				fmt.Printf("Using SOCKS5 proxy %s:%s without authentication\n", host, port)
			}
		} else {
			// Try parsing as URL
			parsedURL, err := url.Parse(socksAddr)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy address format: %s", socksAddr)
			}

			host = parsedURL.Hostname()
			port = parsedURL.Port()

			if parsedURL.User != nil {
				user = parsedURL.User.Username()
				password, _ = parsedURL.User.Password()
				if user != "" {
					auth = &proxy.Auth{
						User:     user,
						Password: password,
					}
				}
			}
		}

		// Now connect to the SOCKS proxy
		proxyAddr := net.JoinHostPort(host, port)
		socksDialer, err := proxy.SOCKS5(
			"tcp", proxyAddr,
			auth,
			proxy.Direct,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
		}
		dialer = socksDialer

		// Set upstream proxy for HTTP connections
		// Create a proxy URL for the DefaultTransport
		var proxyURL *url.URL
		if user != "" && password != "" {
			proxyURL = &url.URL{
				Scheme: "socks5",
				User:   url.UserPassword(user, password),
				Host:   proxyAddr,
			}
		} else {
			proxyURL = &url.URL{
				Scheme: "socks5",
				Host:   proxyAddr,
			}
		}

		// Configure the default transport to use our proxy
		defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		defaultTransport.Proxy = func(req *http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
		http.DefaultTransport = defaultTransport

		fmt.Printf("SOCKS5 proxy configured: %s\n", proxyURL.Redacted())
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}

	return &UpstreamDialer{dialer: dialer}, nil
}

func (u *UpstreamDialer) Dial(network, addr string) (net.Conn, error) {
	return u.dialer.Dial(network, addr)
}
