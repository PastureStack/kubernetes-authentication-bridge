package originhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type recordingTransport struct {
	requests atomic.Int32
	response *http.Response
	err      error
}

func (r *recordingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.requests.Add(1)
	return r.response, r.err
}

func parsedURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestClientAllowsOnlyApprovedOrigin(t *testing.T) {
	transport := &recordingTransport{response: &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}}
	client, err := New(&http.Client{Transport: transport, Timeout: time.Second}, parsedURL(t, "https://platform.example/v2-beta"), parsedURL(t, "https://platform.example/v2-beta"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://platform.example/v2-beta/projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if transport.requests.Load() != 1 {
		t.Fatalf("approved transport received %d requests", transport.requests.Load())
	}

	foreign, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://foreign.example/projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(foreign); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected foreign origin to be rejected, got %v", err)
	}
	if transport.requests.Load() != 1 {
		t.Fatal("rejected request reached the network transport")
	}
}

func TestClientKeepsCredentialsOnCredentialOrigin(t *testing.T) {
	transport := &recordingTransport{}
	platform := parsedURL(t, "http://127.0.0.1:8080/v2-beta")
	metadata := parsedURL(t, "http://169.254.169.250")
	client, err := New(&http.Client{Transport: transport}, platform, platform, metadata)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://169.254.169.250/metadata", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("access", "secret")
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("expected credential boundary rejection, got %v", err)
	}
	if transport.requests.Load() != 0 {
		t.Fatal("credential-bearing metadata request reached the transport")
	}
}

func TestClientRejectsHostOverrideAndUnsupportedMethod(t *testing.T) {
	transport := &recordingTransport{}
	origin := parsedURL(t, "https://platform.example")
	client, err := New(&http.Client{Transport: transport}, origin, origin)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://platform.example/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "foreign.example"
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "Host override") {
		t.Fatalf("expected Host override rejection, got %v", err)
	}
	request.Host = ""
	request.Method = http.MethodDelete
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected method rejection, got %v", err)
	}
}

func TestClientAppliesTimeoutAtTransportBoundary(t *testing.T) {
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	origin := parsedURL(t, "http://127.0.0.1:8080")
	client, err := New(&http.Client{Transport: transport, Timeout: 5 * time.Millisecond}, origin, origin)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/status", nil)
	if _, err := client.Do(request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected transport timeout, got %v", err)
	}
}

func TestNewRejectsInvalidPolicy(t *testing.T) {
	if _, err := New(nil, nil); err == nil {
		t.Fatal("expected empty allowlist to fail")
	}
	foreign := parsedURL(t, "https://foreign.example")
	allowed := parsedURL(t, "https://allowed.example")
	if _, err := New(nil, foreign, allowed); err == nil {
		t.Fatal("expected foreign credential origin to fail")
	}
	if _, err := New(nil, nil, parsedURL(t, "file:///tmp/socket")); err == nil {
		t.Fatal("expected non-HTTP origin to fail")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
