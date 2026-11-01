package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/x509roots/fallback/bundle"
)

var userAgent = "ubuntu-sys-audit"

// newHTTPClient builds the client for advisory downloads. The system trust
// store is extended with an embedded root bundle, because the hosts this tool
// cares about most are unpatched ones whose ca-certificates may be stale or
// missing. HTTP/2 is disabled: the OVAL mirror answered with an HTTP/2 framing
// error during development, and these are single sequential downloads anyway.
func newHTTPClient(proxy string) *http.Client {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for root := range bundle.Roots() {
		if cert, err := x509.ParseCertificate(root.Certificate); err == nil {
			pool.AddCert(cert)
		}
	}
	proxyFn := http.ProxyFromEnvironment
	if proxy != "" {
		if u, err := url.Parse(proxy); err == nil {
			proxyFn = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 proxyFn,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     false,
			TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
	}
}

// fetch performs a GET and hands the response body to fn, retrying transient
// failures. Downloads stay in memory; nothing is written to the host.
func fetch(ctx context.Context, client *http.Client, target string, limit int64, fn func(io.Reader) error) error {
	return fetchWithHeaders(ctx, client, target, nil, limit, fn)
}

// fetchWithHeaders is fetch for APIs that need request headers.
func fetchWithHeaders(ctx context.Context, client *http.Client, target string, headers map[string]string, limit int64, fn func(io.Reader) error) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode < 500 {
				return last
			}
			continue
		}
		err = fn(io.LimitReader(resp.Body, limit))
		resp.Body.Close()
		if err == nil {
			return nil
		}
		last = err
	}
	return last
}
