// Package originhttp provides a fail-closed HTTP client whose destination
// policy is enforced immediately before a request reaches the network.
package originhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client sends requests only to the exact origins approved at construction.
// It deliberately exposes no unguarded http.Client or RoundTripper.
type Client struct {
	transport        http.RoundTripper
	timeout          time.Duration
	allowedOrigins   map[string]struct{}
	credentialOrigin string
}

// New constructs a destination-bound client. The credential origin must also
// be one of the allowed origins. Ambient proxies and cookie jars are disabled.
func New(base *http.Client, credentialOrigin *url.URL, allowed ...*url.URL) (*Client, error) {
	if len(allowed) == 0 {
		return nil, errors.New("at least one HTTP origin must be allowed")
	}

	allowedOrigins := make(map[string]struct{}, len(allowed))
	for _, candidate := range allowed {
		origin, err := canonicalOrigin(candidate)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed HTTP origin: %w", err)
		}
		allowedOrigins[origin] = struct{}{}
	}

	credential := ""
	if credentialOrigin != nil {
		var err error
		credential, err = canonicalOrigin(credentialOrigin)
		if err != nil {
			return nil, fmt.Errorf("invalid credential HTTP origin: %w", err)
		}
		if _, ok := allowedOrigins[credential]; !ok {
			return nil, errors.New("credential HTTP origin is not in the allowed origin set")
		}
	}

	timeout := time.Duration(0)
	var transport http.RoundTripper = http.DefaultTransport
	if base != nil {
		timeout = base.Timeout
		if base.Transport != nil {
			transport = base.Transport
		}
	}
	if standard, ok := transport.(*http.Transport); ok {
		standard = standard.Clone()
		standard.Proxy = nil
		transport = standard
	}

	return &Client{
		transport:        transport,
		timeout:          timeout,
		allowedOrigins:   allowedOrigins,
		credentialOrigin: credential,
	}, nil
}

// Do validates the final request origin, Host header, and credential boundary
// immediately before the underlying transport is called. It performs one
// exchange only, so redirects are never followed.
func (c *Client) Do(request *http.Request) (*http.Response, error) {
	if c == nil || c.transport == nil {
		return nil, errors.New("origin-bound HTTP client is not initialized")
	}
	if request == nil || request.URL == nil {
		return nil, errors.New("HTTP request URL is required")
	}
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		return nil, fmt.Errorf("HTTP method %q is not allowed", request.Method)
	}
	if request.URL.User != nil || request.URL.Opaque != "" || request.URL.Fragment != "" {
		return nil, errors.New("HTTP request contains credentials, an opaque URL, or a fragment")
	}

	origin, err := canonicalOrigin(request.URL)
	if err != nil {
		return nil, err
	}
	if _, ok := c.allowedOrigins[origin]; !ok {
		return nil, fmt.Errorf("HTTP request origin %q is not allowed", origin)
	}
	if request.Host != "" && !strings.EqualFold(request.Host, request.URL.Host) {
		return nil, errors.New("HTTP Host override does not match the approved destination")
	}
	if hasCredentials(request) && origin != c.credentialOrigin {
		return nil, errors.New("HTTP credentials cannot be sent to this origin")
	}

	prepared := request
	var cancel context.CancelFunc
	if c.timeout > 0 {
		ctx := request.Context()
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > c.timeout {
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
			prepared = request.Clone(ctx)
		}
	}
	response, err := c.transport.RoundTrip(prepared)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	if cancel != nil {
		response.Body = &cancelOnClose{ReadCloser: response.Body, cancel: cancel}
	}
	return response, nil
}

func hasCredentials(request *http.Request) bool {
	return request.Header.Get("Authorization") != "" ||
		request.Header.Get("Proxy-Authorization") != "" ||
		request.Header.Get("Cookie") != ""
}

func canonicalOrigin(value *url.URL) (string, error) {
	if value == nil {
		return "", errors.New("HTTP origin is required")
	}
	scheme := strings.ToLower(value.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("HTTP origin must use HTTP or HTTPS")
	}
	if value.User != nil || value.Opaque != "" {
		return "", errors.New("HTTP origin must not contain credentials or an opaque URL")
	}
	hostname := strings.TrimSuffix(strings.ToLower(value.Hostname()), ".")
	if hostname == "" {
		return "", errors.New("HTTP origin must contain a host")
	}
	port := value.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(hostname, port), nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cancelOnClose) Close() error {
	err := body.ReadCloser.Close()
	body.cancel()
	return err
}
