package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandlerMethods(t *testing.T) {
	server, err := NewServer(10240)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		recorder := httptest.NewRecorder()
		server.Handler.ServeHTTP(recorder, httptest.NewRequest(method, "/healthcheck", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s returned %d", method, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/healthcheck", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST returned %d", recorder.Code)
	}
}
