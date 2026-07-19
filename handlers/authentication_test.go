package handlers

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
)

type stubProvider struct {
	user *authentication.UserInfo
	err  error
}

func (p *stubProvider) Lookup(_ context.Context, _ string) (*authentication.UserInfo, error) {
	return p.user, p.err
}

var _ authentication.Provider = (*stubProvider)(nil)

func request(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
}

func TestAuthenticationLimitsRequestBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	Authentication(&stubProvider{}, false)(recorder, request(strings.Repeat("x", MaxBody+1)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func TestAuthenticationRejectsUnsupportedMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Authentication(&stubProvider{}, false)(recorder, req)
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("unexpected method response: status=%d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestAuthenticationRejectsMalformedContract(t *testing.T) {
	for _, body := range []string{
		`{`,
		`{"apiVersion":"v1","kind":"TokenReview","spec":{"token":"test"}}`,
		`{"apiVersion":"authentication.k8s.io/v1beta1","kind":"Other","spec":{"token":"test"}}`,
		`{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","spec":{"token":"test"}} {}`,
	} {
		recorder := httptest.NewRecorder()
		Authentication(&stubProvider{}, false)(recorder, request(body))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %q: expected %d, got %d", body, http.StatusBadRequest, recorder.Code)
		}
	}
}

func TestAuthenticationReturnsUnauthenticated(t *testing.T) {
	body := `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","spec":{"token":"bad"}}`
	recorder := httptest.NewRecorder()
	Authentication(&stubProvider{}, false)(recorder, request(body))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"authenticated":false`) {
		t.Fatalf("unexpected unauthenticated response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store response header")
	}
}

func TestAuthenticationReturnsUser(t *testing.T) {
	body := `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","spec":{"token":"good"}}`
	provider := &stubProvider{user: &authentication.UserInfo{Username: "person", UID: "i-1", Groups: []string{"team:ops"}}}
	recorder := httptest.NewRecorder()
	Authentication(provider, false)(recorder, request(body))
	for _, expected := range []string{`"authenticated":true`, `"username":"person"`, `"uid":"i-1"`, `"team:ops"`} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("missing %s in response %s", expected, recorder.Body.String())
		}
	}
}

func TestAuthenticationProviderFailureIsGeneric(t *testing.T) {
	body := `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","spec":{"token":"secret-token"}}`
	recorder := httptest.NewRecorder()
	Authentication(&stubProvider{err: errors.New("upstream included sensitive details")}, false)(recorder, request(body))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "sensitive") || strings.Contains(recorder.Body.String(), "secret-token") {
		t.Fatalf("provider details leaked in response: %s", recorder.Body.String())
	}
}

func TestAuthenticationDebugLogRedactsToken(t *testing.T) {
	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousOutput)

	rawToken := "super-secret-token"
	body := `{"apiVersion":"authentication.k8s.io/v1beta1","kind":"TokenReview","spec":{"token":"` + rawToken + `"}}`
	recorder := httptest.NewRecorder()
	Authentication(&stubProvider{}, true)(recorder, request(body))
	if strings.Contains(logs.String(), rawToken) {
		t.Fatalf("debug log leaked raw token: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "sha256=") {
		t.Fatalf("expected token fingerprint in debug log, got %s", logs.String())
	}
}
