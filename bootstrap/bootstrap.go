package bootstrap

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PastureStack/kubernetes-authentication-bridge/internal/originhttp"
)

const (
	defaultMetadataAddress = "169.254.169.250"
	maximumMetadataBody    = 4096
	maximumPlatformBody    = 1 << 20
	maximumArchiveBody     = 4 << 20
	maximumCertificateFile = 1 << 20
	defaultRetryInterval   = time.Second
	defaultRequestTimeout  = 15 * time.Second
	canonicalPlatformCA    = "/var/lib/pasturestack/etc/ssl/ca.crt"
	legacyPlatformCA       = "/var/lib/rancher/etc/ssl/ca.crt"
)

var (
	serviceIDPattern                  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,255}$`)
	errCertificateActionChangedOrigin = errors.New("Kubernetes certificate action changed origin")
)

type Config struct {
	MetadataAddress string
	PlatformURL     string
	AccessKey       string
	SecretKey       string
	CARoot          string
	RetryInterval   time.Duration
	HTTPClient      *http.Client
}

type serviceCollection struct {
	Data []struct {
		Actions map[string]string `json:"actions"`
	} `json:"data"`
}

func FromEnvironment(ctx context.Context) (string, error) {
	caRoot, err := platformCARoot()
	if err != nil {
		return "", err
	}
	config := Config{
		MetadataAddress: preferredEnv("PLATFORM_METADATA_ADDRESS", "RANCHER_METADATA_ADDRESS"),
		PlatformURL:     preferredEnv("PLATFORM_URL", "CATTLE_URL"),
		AccessKey:       preferredEnv("PLATFORM_ACCESS_KEY", "CATTLE_ACCESS_KEY"),
		SecretKey:       preferredEnv("PLATFORM_SECRET_KEY", "CATTLE_SECRET_KEY"),
		CARoot:          caRoot,
	}
	return Acquire(ctx, config)
}

func Acquire(ctx context.Context, config Config) (string, error) {
	metadataBase, err := normalizeMetadataURL(config.MetadataAddress)
	if err != nil {
		return "", err
	}
	platformBase, err := normalizePlatformURL(config.PlatformURL)
	if err != nil {
		return "", err
	}
	if config.AccessKey == "" || config.SecretKey == "" {
		return "", errors.New("platform service credentials are required for certificate bootstrap")
	}
	baseClient := config.HTTPClient
	if baseClient == nil {
		baseClient, err = newHTTPClient(config.CARoot)
		if err != nil {
			return "", err
		}
	} else {
		clientCopy := *baseClient
		baseClient = &clientCopy
		if baseClient.Timeout <= 0 {
			baseClient.Timeout = defaultRequestTimeout
		}
	}
	client, err := originhttp.New(baseClient, platformBase, metadataBase, platformBase)
	if err != nil {
		return "", fmt.Errorf("construct destination-bound bootstrap client: %w", err)
	}
	retryInterval := config.RetryInterval
	if retryInterval <= 0 {
		retryInterval = defaultRetryInterval
	}

	var lastError error
	for {
		token, attemptErr := acquireOnce(ctx, client, metadataBase, platformBase, config.AccessKey, config.SecretKey)
		if attemptErr == nil {
			return token, nil
		}
		if errors.Is(attemptErr, errCertificateActionChangedOrigin) {
			return "", attemptErr
		}
		lastError = attemptErr
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("certificate bootstrap did not complete: %w (last error: %v)", ctx.Err(), lastError)
		case <-timer.C:
		}
	}
}

func acquireOnce(ctx context.Context, client *originhttp.Client, metadataBase, platformBase *url.URL, accessKey, secretKey string) (string, error) {
	metadataEndpoint := *metadataBase
	metadataEndpoint.Path = "/2015-12-19/stacks/Kubernetes/services/kubernetes/uuid"
	metadataEndpoint.RawPath = ""
	metadataEndpoint.RawQuery = ""
	serviceIDBytes, status, err := request(ctx, client, http.MethodGet, metadataEndpoint, "", "", maximumMetadataBody)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes service metadata: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("Kubernetes service metadata returned status %d", status)
	}
	serviceID := strings.TrimSpace(string(serviceIDBytes))
	if !serviceIDPattern.MatchString(serviceID) {
		return "", errors.New("Kubernetes service metadata returned an invalid identifier")
	}

	query := url.Values{"uuid": {serviceID}}
	serviceEndpoint := *platformBase
	serviceEndpoint.Path = strings.TrimRight(platformBase.Path, "/") + "/services"
	serviceEndpoint.RawPath = ""
	serviceEndpoint.RawQuery = query.Encode()
	serviceBody, status, err := request(ctx, client, http.MethodGet, serviceEndpoint, accessKey, secretKey, maximumPlatformBody)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes service action: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("Kubernetes service action returned status %d", status)
	}
	var services serviceCollection
	if err := json.Unmarshal(serviceBody, &services); err != nil {
		return "", fmt.Errorf("decode Kubernetes service action: %w", err)
	}
	if len(services.Data) == 0 {
		return "", errors.New("Kubernetes service action is not available")
	}
	action := strings.TrimSpace(services.Data[0].Actions["certificate"])
	if action == "" {
		return "", errors.New("Kubernetes certificate action is not available")
	}
	actionURL, err := platformBase.Parse(action)
	if err != nil {
		return "", fmt.Errorf("parse Kubernetes certificate action: %w", err)
	}
	if actionURL.Scheme != platformBase.Scheme || !strings.EqualFold(actionURL.Host, platformBase.Host) || actionURL.User != nil {
		return "", errCertificateActionChangedOrigin
	}
	// Rebuild the destination from the trusted, operator-configured origin. The
	// platform controls only the path and query; it cannot redirect this client
	// to another scheme, host, or port even if the action value is compromised.
	certificateEndpoint := *platformBase
	certificateEndpoint.Path = actionURL.Path
	certificateEndpoint.RawPath = actionURL.RawPath
	certificateEndpoint.RawQuery = actionURL.RawQuery
	certificateEndpoint.ForceQuery = actionURL.ForceQuery
	certificateEndpoint.Fragment = ""

	archive, status, err := request(ctx, client, http.MethodPost, certificateEndpoint, accessKey, secretKey, maximumArchiveBody)
	if err != nil {
		return "", fmt.Errorf("download Kubernetes certificate archive: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("Kubernetes certificate action returned status %d", status)
	}
	key, err := privateKeyFromArchive(archive)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(key)
	clear(key)
	return hex.EncodeToString(digest[:]), nil
}

func request(ctx context.Context, client *originhttp.Client, method string, endpoint url.URL, username, password string, maximum int64) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json, application/zip")
	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if int64(len(body)) > maximum {
		return nil, response.StatusCode, fmt.Errorf("response exceeds %d bytes", maximum)
	}
	return body, response.StatusCode, nil
}

func privateKeyFromArchive(archive []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("open Kubernetes certificate archive: %w", err)
	}
	seen := make(map[string]bool)
	var key []byte
	for _, file := range reader.File {
		cleanName := path.Clean(strings.ReplaceAll(file.Name, "\\", "/"))
		if cleanName == "." || path.IsAbs(cleanName) || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
			return nil, errors.New("Kubernetes certificate archive contains an unsafe path")
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if file.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Kubernetes certificate archive contains a symbolic link")
		}
		baseName := path.Base(cleanName)
		switch baseName {
		case "ca.pem", "cert.pem", "key.pem":
		default:
			return nil, fmt.Errorf("Kubernetes certificate archive contains unexpected file %q", baseName)
		}
		if seen[baseName] {
			return nil, fmt.Errorf("Kubernetes certificate archive contains duplicate file %q", baseName)
		}
		seen[baseName] = true
		if file.UncompressedSize64 > maximumCertificateFile {
			return nil, fmt.Errorf("Kubernetes certificate file %q is too large", baseName)
		}
		opened, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, readErr := io.ReadAll(io.LimitReader(opened, maximumCertificateFile+1))
		closeErr := opened.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(content) > maximumCertificateFile {
			return nil, fmt.Errorf("Kubernetes certificate file %q is too large", baseName)
		}
		if baseName == "key.pem" {
			key = content
		}
	}
	if len(key) == 0 {
		return nil, errors.New("Kubernetes certificate archive does not contain key.pem")
	}
	block, _ := pem.Decode(key)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		clear(key)
		return nil, errors.New("Kubernetes certificate key.pem is not a PEM private key")
	}
	return key, nil
}

func normalizeMetadataURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultMetadataAddress
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("metadata address must be an absolute HTTP or HTTPS origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("metadata address must not contain a path")
	}
	parsed.Path = ""
	return parsed, nil
}

func normalizePlatformURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("PLATFORM_URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("PLATFORM_URL must be an absolute HTTP or HTTPS URL without credentials, query, or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func newHTTPClient(caPath string) (*http.Client, error) {
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
		Timeout:   defaultRequestTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("bootstrap redirects are disabled")
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

func preferredEnv(primary, legacy string) string {
	if value := strings.TrimSpace(os.Getenv(primary)); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv(legacy))
}
