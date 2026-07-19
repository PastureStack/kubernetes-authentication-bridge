package bootstrap

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testPrivateKey(t *testing.T) []byte {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
}

func testArchive(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range entries {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestAcquireUsesSameOriginBoundedCertificateAction(t *testing.T) {
	key := testPrivateKey(t)
	archive := testArchive(t, map[string][]byte{
		"nested/ca.pem":   []byte("ca"),
		"nested/cert.pem": []byte("cert"),
		"nested/key.pem":  key,
	})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid":
			if r.Header.Get("Authorization") != "" {
				t.Fatal("platform credentials were sent to metadata")
			}
			fmt.Fprint(w, "1s1")
		case "/v2-beta/services":
			username, password, ok := r.BasicAuth()
			if !ok || username != "access" || password != "secret" || r.URL.Query().Get("uuid") != "1s1" {
				t.Fatal("service action request did not preserve credentials and UUID")
			}
			fmt.Fprintf(w, `{"data":[{"actions":{"certificate":%q}}]}`, server.URL+"/v2-beta/services/1s1?action=certificate")
		case "/v2-beta/services/1s1":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected certificate method %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	token, err := Acquire(context.Background(), Config{
		MetadataAddress: server.URL,
		PlatformURL:     server.URL + "/v2-beta",
		AccessKey:       "access",
		SecretKey:       "secret",
		RetryInterval:   time.Millisecond,
		HTTPClient:      server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(key)
	if token != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected bootstrap token %q", token)
	}
}

func TestPrivateKeyArchiveRejectsUnsafeContent(t *testing.T) {
	key := testPrivateKey(t)
	for name, archive := range map[string][]byte{
		"traversal":   testArchive(t, map[string][]byte{"../key.pem": key}),
		"unexpected":  testArchive(t, map[string][]byte{"password.txt": key}),
		"missing-key": testArchive(t, map[string][]byte{"cert.pem": []byte("cert")}),
		"invalid-key": testArchive(t, map[string][]byte{"key.pem": []byte("not a PEM key")}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := privateKeyFromArchive(archive); err == nil {
				t.Fatal("expected unsafe archive to fail")
			}
		})
	}
}

func TestAcquireRejectsCrossOriginCertificateAction(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
	}))
	defer target.Close()
	var platformRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		platformRequests.Add(1)
		switch r.URL.Path {
		case "/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid":
			fmt.Fprint(w, "1s1")
		case "/v2-beta/services":
			fmt.Fprintf(w, `{"data":[{"actions":{"certificate":%q}}]}`, target.URL+"/certificate")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	_, err := Acquire(context.Background(), Config{
		MetadataAddress: server.URL,
		PlatformURL:     server.URL + "/v2-beta",
		AccessKey:       "access",
		SecretKey:       "secret",
		RetryInterval:   time.Millisecond,
		HTTPClient:      server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "changed origin") {
		t.Fatalf("expected cross-origin action failure, got %v", err)
	}
	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("cross-origin target received %d requests", got)
	}
	if got := platformRequests.Load(); got != 2 {
		t.Fatalf("expected one metadata and one service request without retries, got %d", got)
	}
}

func TestAcquireDoesNotUseAmbientProxy(t *testing.T) {
	var proxyRequests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		http.Error(w, "request must not use ambient proxy", http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	key := testPrivateKey(t)
	archive := testArchive(t, map[string][]byte{"key.pem": key})
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid":
			fmt.Fprint(w, "1s1")
		case "/services":
			fmt.Fprintf(w, `{"data":[{"actions":{"certificate":%q}}]}`, server.URL+"/certificate")
		case "/certificate":
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(context.Background(), Config{
		MetadataAddress: server.URL,
		PlatformURL:     server.URL,
		AccessKey:       "access",
		SecretKey:       "secret",
		RetryInterval:   time.Millisecond,
		HTTPClient:      client,
	}); err != nil {
		t.Fatal(err)
	}
	if got := proxyRequests.Load(); got != 0 {
		t.Fatalf("ambient proxy received %d requests", got)
	}
}

func TestPlatformCARootRejectsArbitraryPath(t *testing.T) {
	t.Setenv("PLATFORM_CA_ROOT", "../../tmp/untrusted-ca.pem")
	if _, err := platformCARoot(); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("expected arbitrary CA path to be rejected, got %v", err)
	}
}

func TestValidatePlatformCARootKeepsSupportedMounts(t *testing.T) {
	for _, candidate := range []string{canonicalPlatformCA, legacyPlatformCA} {
		resolved, err := validatePlatformCARoot(candidate)
		if err != nil {
			t.Fatalf("supported CA path %q was rejected: %v", candidate, err)
		}
		if resolved != candidate {
			t.Fatalf("supported CA path changed from %q to %q", candidate, resolved)
		}
	}
}
