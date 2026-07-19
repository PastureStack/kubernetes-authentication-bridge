package platformauthentication

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PastureStack/kubernetes-authentication-bridge/internal/originhttp"
)

func testProvider(t *testing.T, server *httptest.Server, bootstrapToken string) *Provider {
	t.Helper()
	baseURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseClient, err := newPlatformHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	baseClient.Timeout = 2 * time.Second
	client, err := originhttp.New(baseClient, baseURL, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return &Provider{
		baseURL:        baseURL,
		accessKey:      "service-access",
		secretKey:      "service-secret",
		bootstrapToken: bootstrapToken,
		httpClient:     client,
	}
}

func encodedToken(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func TestLookupBootstrapTokenUsesConstantBoundary(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	provider := testProvider(t, server, "bootstrap-value")
	user, err := provider.Lookup(context.Background(), "bootstrap-value")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "bootstrap" || len(user.Groups) != 1 || user.Groups[0] != kubernetesMasterGroup {
		t.Fatalf("unexpected bootstrap identity: %#v", user)
	}
}

func TestLookupAuthDisabledReturnsLocalAdministrator(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/settings/api.security.enabled" {
			fmt.Fprint(w, `{"value":"false"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	user, err := testProvider(t, server, "bootstrap").Lookup(context.Background(), "another-token")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "admin" || user.Groups[0] != kubernetesMasterGroup {
		t.Fatalf("unexpected disabled-auth identity: %#v", user)
	}
}

func TestLookupOwnerUsesMinimalPlatformAPI(t *testing.T) {
	authorization := "Bearer upstream-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/settings/api.security.enabled":
			fmt.Fprint(w, `{"value":"true"}`)
		case "/identity":
			if r.Header.Get("Authorization") != authorization {
				t.Fatalf("identity token mismatch: %q", r.Header.Get("Authorization"))
			}
			fmt.Fprint(w, `{"data":[{"id":"i-user","externalIdType":"oidc","login":"person","user":true},{"id":"i-team","externalIdType":"team","login":"ops","user":false}]}`)
		case "/accounts":
			fmt.Fprint(w, `{"data":[]}`)
		case "/projects":
			username, password, ok := r.BasicAuth()
			if !ok || username != "service-access" || password != "service-secret" {
				t.Fatal("project request did not use service credentials")
			}
			fmt.Fprint(w, `{"data":[{"id":"p-1"}]}`)
		case "/projectMembers":
			if r.URL.Query().Get("projectId") != "p-1" {
				t.Fatalf("unexpected project query: %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"data":[{"id":"i-user","role":"owner"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	user, err := testProvider(t, server, "bootstrap").Lookup(context.Background(), encodedToken(authorization))
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "person" || user.UID != "i-user" {
		t.Fatalf("unexpected identity: %#v", user)
	}
	joined := strings.Join(user.Groups, ",")
	if !strings.Contains(joined, "team:ops") || !strings.Contains(joined, kubernetesMasterGroup) {
		t.Fatalf("unexpected groups: %v", user.Groups)
	}
}

func TestLookupAdminSkipsProjectMembership(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/settings/api.security.enabled":
			fmt.Fprint(w, `{"value":"true"}`)
		case "/identity":
			fmt.Fprint(w, `{"data":[{"id":"i-admin","externalIdType":"local","login":"admin-user","user":true}]}`)
		case "/accounts":
			fmt.Fprint(w, `{"data":[{"kind":"admin"}]}`)
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	user, err := testProvider(t, server, "bootstrap").Lookup(context.Background(), encodedToken("Bearer admin"))
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "admin-user" || user.Groups[0] != kubernetesMasterGroup {
		t.Fatalf("unexpected administrator identity: %#v", user)
	}
}

func TestLookupRejectsRedirectWithoutSendingAuthorization(t *testing.T) {
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedRequests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Fatal("authorization leaked across redirect")
		}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/settings/api.security.enabled" {
			fmt.Fprint(w, `{"value":"true"}`)
			return
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	_, err := testProvider(t, source, "bootstrap").Lookup(context.Background(), encodedToken("Bearer secret"))
	if err == nil {
		t.Fatal("expected redirect to fail")
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("redirect target received %d requests", redirectedRequests.Load())
	}
}

func TestLookupNoProjectFailsClosedInsteadOfPanicking(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/settings/api.security.enabled":
			fmt.Fprint(w, `{"value":"true"}`)
		case "/identity":
			fmt.Fprint(w, `{"data":[{"id":"i-user","externalIdType":"oidc","login":"person","user":true}]}`)
		case "/accounts", "/projects":
			fmt.Fprint(w, `{"data":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	if _, err := testProvider(t, server, "bootstrap").Lookup(context.Background(), encodedToken("Bearer member")); err == nil {
		t.Fatal("expected missing project to fail closed")
	}
}

func TestNormalizeBaseURLRejectsCredentialBearingURL(t *testing.T) {
	if _, err := normalizeBaseURL("https://user:pass@example.invalid/v2-beta"); err == nil {
		t.Fatal("expected URL credentials to be rejected")
	}
}

func TestEndpointKeepsConfiguredOrigin(t *testing.T) {
	baseURL, err := url.Parse("http://127.0.0.1:8080/v2-beta")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Provider{baseURL: baseURL}
	endpoint, err := provider.endpoint("/projects?limit=-1")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Scheme != "http" || endpoint.Host != "127.0.0.1:8080" || endpoint.Path != "/v2-beta/projects" || endpoint.Query().Get("limit") != "-1" {
		t.Fatalf("unexpected endpoint %s", endpoint)
	}
	for _, unsafe := range []string{"https://example.invalid/projects", "//example.invalid/projects", "/projects#fragment"} {
		if _, err := provider.endpoint(unsafe); err == nil {
			t.Fatalf("unsafe path %q was accepted", unsafe)
		}
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

func TestNewProviderFailsClosedForArbitraryCARoot(t *testing.T) {
	t.Setenv(platformURLEnv, "http://127.0.0.1:8080/v2-beta")
	t.Setenv("PLATFORM_CA_ROOT", "C:/untrusted/ca.pem")
	if _, err := NewProvider("bootstrap"); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("expected provider construction to reject arbitrary CA root, got %v", err)
	}
}
