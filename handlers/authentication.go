package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
)

const (
	APIVersion = "authentication.k8s.io/v1beta1"
	Kind       = "TokenReview"
	MaxBody    = 1 << 20
)

type tokenReviewRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token string `json:"token"`
	} `json:"spec"`
}

type tokenReviewResponse struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Status     tokenReviewStatus `json:"status"`
}

type tokenReviewStatus struct {
	Authenticated bool             `json:"authenticated"`
	User          *tokenReviewUser `json:"user,omitempty"`
	Error         string           `json:"error,omitempty"`
}

type tokenReviewUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

func Authentication(provider authentication.Provider, debug bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, unauthenticated("method not allowed"))
			return
		}

		response, err := reviewAuthentication(r.Context(), provider, w, r, debug)
		if err != nil {
			status := http.StatusBadRequest
			message := "invalid token review request"
			if errors.Is(err, errProviderUnavailable) {
				status = http.StatusBadGateway
				message = "authentication provider unavailable"
			}
			writeJSON(w, status, unauthenticated(message))
			return
		}
		writeJSON(w, http.StatusOK, response)
	}
}

var errProviderUnavailable = errors.New("authentication provider unavailable")

func reviewAuthentication(ctx context.Context, provider authentication.Provider, w http.ResponseWriter, r *http.Request, debug bool) (tokenReviewResponse, error) {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBody))
	var request tokenReviewRequest
	if err := decoder.Decode(&request); err != nil {
		return tokenReviewResponse{}, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return tokenReviewResponse{}, err
	}

	if request.APIVersion != APIVersion || request.Kind != Kind {
		return tokenReviewResponse{}, fmt.Errorf("unsupported token review contract")
	}

	token := strings.TrimSpace(request.Spec.Token)
	if token == "" {
		return unauthenticated(""), nil
	}
	if debug {
		log.Printf("authentication request apiVersion=%s kind=%s token=%s", request.APIVersion, request.Kind, tokenFingerprint(token))
	}

	userInfo, err := provider.Lookup(ctx, token)
	if err != nil {
		log.Printf("authentication provider request failed for token %s", tokenFingerprint(token))
		return tokenReviewResponse{}, fmt.Errorf("%w: %v", errProviderUnavailable, err)
	}
	if userInfo == nil || strings.TrimSpace(userInfo.Username) == "" {
		return unauthenticated(""), nil
	}

	return tokenReviewResponse{
		APIVersion: APIVersion,
		Kind:       Kind,
		Status: tokenReviewStatus{
			Authenticated: true,
			User: &tokenReviewUser{
				Username: userInfo.Username,
				UID:      userInfo.UID,
				Groups:   userInfo.Groups,
			},
		},
	}, nil
}

func unauthenticated(message string) tokenReviewResponse {
	return tokenReviewResponse{
		APIVersion: APIVersion,
		Kind:       Kind,
		Status: tokenReviewStatus{
			Authenticated: false,
			Error:         message,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, value tokenReviewResponse) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("token review response write failed: %v", err)
	}
}

func tokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("len=%d sha256=%s", len(token), hex.EncodeToString(sum[:])[:16])
}
