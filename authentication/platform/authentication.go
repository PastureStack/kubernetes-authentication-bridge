package platformauthentication

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
	"github.com/PastureStack/kubernetes-authentication-bridge/internal/originhttp"
)

const (
	platformURLEnv        = "PLATFORM_URL"
	platformAccessKeyEnv  = "PLATFORM_ACCESS_KEY"
	platformSecretKeyEnv  = "PLATFORM_SECRET_KEY"
	legacyURLEnv          = "CATTLE_URL"
	legacyURLAccessKeyEnv = "CATTLE_ACCESS_KEY"
	legacyURLSecretKeyEnv = "CATTLE_SECRET_KEY"

	kubernetesMasterGroup = "system:masters"
	adminUser             = "admin"
	bootstrapUser         = "bootstrap"
	maxPlatformBody       = 1 << 20
	requestTimeout        = 30 * time.Second
	canonicalPlatformCA   = "/var/lib/pasturestack/etc/ssl/ca.crt"
	legacyPlatformCA      = "/var/lib/rancher/etc/ssl/ca.crt"
)

type Provider struct {
	baseURL        *url.URL
	accessKey      string
	secretKey      string
	bootstrapToken string
	httpClient     *originhttp.Client
}

func NewProvider(bootstrapToken string) (*Provider, error) {
	baseURL, err := normalizeBaseURL(preferredEnv(platformURLEnv, legacyURLEnv))
	if err != nil {
		return nil, err
	}
	caRoot, err := platformCARoot()
	if err != nil {
		return nil, err
	}
	baseClient, err := newPlatformHTTPClient(caRoot)
	if err != nil {
		return nil, err
	}
	httpClient, err := originhttp.New(baseClient, baseURL, baseURL)
	if err != nil {
		return nil, fmt.Errorf("construct destination-bound platform client: %w", err)
	}
	return &Provider{
		baseURL:        baseURL,
		accessKey:      preferredEnv(platformAccessKeyEnv, legacyURLAccessKeyEnv),
		secretKey:      preferredEnv(platformSecretKeyEnv, legacyURLSecretKeyEnv),
		bootstrapToken: strings.TrimSpace(bootstrapToken),
		httpClient:     httpClient,
	}, nil
}

func (p *Provider) Lookup(ctx context.Context, token string) (*authentication.UserInfo, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	if constantTimeEqual(token, p.bootstrapToken) {
		return &authentication.UserInfo{
			Username: bootstrapUser,
			Groups:   []string{kubernetesMasterGroup},
		}, nil
	}

	if p.authDisabled(ctx) {
		return &authentication.UserInfo{
			Username: adminUser,
			Groups:   []string{kubernetesMasterGroup},
		}, nil
	}

	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(decodedToken) == 0 {
		return nil, nil
	}
	authorization := string(decodedToken)
	defer clear(decodedToken)

	var identities identityCollection
	status, err := p.requestJSON(ctx, http.MethodGet, "/identity", authorization, false, &identities)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, nil
	}
	userInfo, ok := getUserInfoFromIdentityCollection(&identities)
	if !ok {
		return nil, nil
	}

	isAdmin, err := p.isAdmin(ctx, authorization)
	if err != nil {
		return nil, err
	}
	if isAdmin {
		userInfo.Groups = appendUnique(userInfo.Groups, kubernetesMasterGroup)
		return &userInfo, nil
	}

	environmentIdentities, err := p.getEnvironmentIdentities(ctx)
	if err != nil {
		return nil, err
	}
	authenticated, master := shouldBeAuthenticated(identities, environmentIdentities)
	if !authenticated {
		return nil, nil
	}
	if master {
		userInfo.Groups = appendUnique(userInfo.Groups, kubernetesMasterGroup)
	}
	return &userInfo, nil
}

func (p *Provider) authDisabled(ctx context.Context) bool {
	var setting settingResponse
	status, err := p.requestJSON(ctx, http.MethodGet, "/settings/api.security.enabled", "", false, &setting)
	return err == nil && status == http.StatusOK && setting.Value == "false"
}

func (p *Provider) isAdmin(ctx context.Context, authorization string) (bool, error) {
	var accounts accountCollection
	status, err := p.requestJSON(ctx, http.MethodGet, "/accounts", authorization, false, &accounts)
	if err != nil {
		return false, err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return false, nil
	}
	for _, account := range accounts.Data {
		if account.Kind == "admin" {
			return true, nil
		}
	}
	return false, nil
}

func (p *Provider) getEnvironmentIdentities(ctx context.Context) (map[string]projectMember, error) {
	if p.accessKey == "" || p.secretKey == "" {
		return nil, errors.New("platform service credentials are required for project membership lookup")
	}
	var projects projectCollection
	if _, err := p.requestJSON(ctx, http.MethodGet, "/projects?limit=-1", "", true, &projects); err != nil {
		return nil, err
	}
	if len(projects.Data) == 0 || projects.Data[0].ID == "" {
		return nil, errors.New("platform API returned no current project")
	}
	query := url.Values{"projectId": {projects.Data[0].ID}, "limit": {"-1"}}
	var members projectMemberCollection
	if _, err := p.requestJSON(ctx, http.MethodGet, "/projectMembers?"+query.Encode(), "", true, &members); err != nil {
		return nil, err
	}
	result := make(map[string]projectMember, len(members.Data))
	for _, member := range members.Data {
		if member.ID != "" {
			result[member.ID] = member
		}
	}
	return result, nil
}

func (p *Provider) requestJSON(ctx context.Context, method, relativePath, authorization string, serviceCredentials bool, output interface{}) (int, error) {
	endpoint, err := p.endpoint(relativePath)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if serviceCredentials {
		request.SetBasicAuth(p.accessKey, p.secretKey)
	}

	response, err := p.httpClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return response.StatusCode, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, fmt.Errorf("platform API request failed with status %d", response.StatusCode)
	}
	data, err := readBounded(response.Body, maxPlatformBody)
	if err != nil {
		return response.StatusCode, err
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return response.StatusCode, fmt.Errorf("decode platform API response: %w", err)
		}
	}
	return response.StatusCode, nil
}

func (p *Provider) endpoint(relativePath string) (*url.URL, error) {
	if !strings.HasPrefix(relativePath, "/") {
		return nil, errors.New("platform API path must be absolute")
	}
	reference, err := url.Parse(relativePath)
	if err != nil {
		return nil, err
	}
	if reference.IsAbs() || reference.Host != "" || reference.User != nil || reference.Fragment != "" {
		return nil, errors.New("platform API path must not specify an origin, credentials, or fragment")
	}
	// The destination origin always comes from the operator configuration. Only
	// a locally constructed API path and query are copied into the request URL.
	endpoint := *p.baseURL
	endpoint.Path = strings.TrimRight(p.baseURL.Path, "/") + reference.Path
	endpoint.RawPath = ""
	endpoint.RawQuery = reference.RawQuery
	endpoint.ForceQuery = reference.ForceQuery
	return &endpoint, nil
}

func normalizeBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("PLATFORM_URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse PLATFORM_URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("PLATFORM_URL must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("PLATFORM_URL must not contain user information, a query, or a fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func newPlatformHTTPClient(caPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		certificate, err := readPlatformCARoot(caPath)
		if err != nil {
			return nil, fmt.Errorf("read platform CA root: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certificate) {
			return nil, errors.New("platform CA root contains no valid PEM certificate")
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("platform API redirects are disabled")
		},
	}, nil
}

func platformCARoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("PLATFORM_CA_ROOT")); configured != "" {
		return validatePlatformCARoot(configured)
	}
	for _, candidate := range []string{
		canonicalPlatformCA,
		legacyPlatformCA,
	} {
		if information, err := os.Stat(candidate); err == nil && !information.IsDir() {
			return candidate, nil
		}
	}
	return "", nil
}

func validatePlatformCARoot(configured string) (string, error) {
	switch filepath.ToSlash(filepath.Clean(strings.TrimSpace(configured))) {
	case canonicalPlatformCA:
		return canonicalPlatformCA, nil
	case legacyPlatformCA:
		return legacyPlatformCA, nil
	default:
		return "", fmt.Errorf("PLATFORM_CA_ROOT must be %s or %s", canonicalPlatformCA, legacyPlatformCA)
	}
}

func readPlatformCARoot(caPath string) ([]byte, error) {
	validated, err := validatePlatformCARoot(caPath)
	if err != nil {
		return nil, err
	}
	switch validated {
	case canonicalPlatformCA:
		return os.ReadFile(canonicalPlatformCA)
	case legacyPlatformCA:
		return os.ReadFile(legacyPlatformCA)
	default:
		return nil, errors.New("platform CA root is not an approved mount path")
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("platform API response exceeds %d bytes", maximum)
	}
	return data, nil
}

func constantTimeEqual(left, right string) bool {
	if left == "" || len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func preferredEnv(primary, legacy string) string {
	if value := strings.TrimSpace(os.Getenv(primary)); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(legacy))
}
