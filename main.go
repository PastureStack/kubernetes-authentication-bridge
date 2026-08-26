package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/PastureStack/kubernetes-authentication-bridge/authentication"
	"github.com/PastureStack/kubernetes-authentication-bridge/authentication/platform"
	"github.com/PastureStack/kubernetes-authentication-bridge/authentication/test"
	"github.com/PastureStack/kubernetes-authentication-bridge/bootstrap"
	"github.com/PastureStack/kubernetes-authentication-bridge/handlers"
	"github.com/PastureStack/kubernetes-authentication-bridge/healthcheck"
)

var VERSION = "0.0.0"

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
	defaultBootstrapTimeout  = 5 * time.Minute
	maximumStdinTokenBytes   = 4096
)

type options struct {
	debug              bool
	testAuthentication bool
	evaluateToken      string
	authenticationPort int
	healthPort         int
	locale             string
	bootstrapFromStdin bool
	showVersion        bool
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		log.Printf("kubernetes authentication bridge stopped: %s", safeLogValue(err))
		os.Exit(1)
	}
}

func safeLogValue(value interface{}) string {
	text := fmt.Sprint(value)
	text = strings.ReplaceAll(text, "\r", "")
	return strings.ReplaceAll(text, "\n", " ")
}

func run(arguments []string, stdin io.Reader, stdout io.Writer) error {
	settings, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	if settings.showVersion {
		_, err := fmt.Fprintln(stdout, VERSION)
		return err
	}
	if settings.locale != "en-US" && settings.locale != "zh-TW" {
		return fmt.Errorf("unsupported locale %q; use en-US or zh-TW", settings.locale)
	}
	if settings.debug {
		log.Print(operatorMessage(settings.locale, "debug-warning"))
	}

	provider, err := buildProvider(settings, stdin)
	if err != nil {
		return err
	}
	if settings.evaluateToken != "" {
		userInfo, err := provider.Lookup(context.Background(), settings.evaluateToken)
		if err != nil {
			return err
		}
		if userInfo == nil {
			return fmt.Errorf("failed to evaluate token fingerprint %s", tokenFingerprint(settings.evaluateToken))
		}
		fmt.Fprintln(stdout, operatorMessage(settings.locale, "username"), userInfo.Username)
		fmt.Fprintln(stdout, operatorMessage(settings.locale, "groups"), userInfo.Groups)
		return nil
	}

	authenticationServer, err := newAuthenticationServer(settings.authenticationPort, provider, settings.debug)
	if err != nil {
		return err
	}
	healthServer, err := healthcheck.NewServer(settings.healthPort)
	if err != nil {
		return err
	}
	return serve(authenticationServer, healthServer, settings.locale)
}

func buildProvider(settings options, stdin io.Reader) (authentication.Provider, error) {
	if settings.testAuthentication {
		return &testauthentication.Provider{}, nil
	}
	var bootstrapToken string
	if settings.bootstrapFromStdin {
		data, err := io.ReadAll(io.LimitReader(stdin, maximumStdinTokenBytes+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maximumStdinTokenBytes {
			return nil, errors.New("bootstrap token from standard input is too large")
		}
		bootstrapToken = strings.TrimSpace(string(data))
		clear(data)
		if bootstrapToken == "" {
			return nil, errors.New("bootstrap token from standard input is empty")
		}
	} else {
		timeout, err := environmentDuration("PASTURESTACK_BOOTSTRAP_TIMEOUT", defaultBootstrapTimeout)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		bootstrapToken, err = bootstrap.FromEnvironment(ctx)
		if err != nil {
			return nil, err
		}
	}
	return platformauthentication.NewProvider(bootstrapToken)
}

func parseOptions(arguments []string) (options, error) {
	settings := options{}
	flags := flag.NewFlagSet("kubernetes-authentication-bridge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&settings.debug, "debug", false, "enable token-fingerprint diagnostics")
	flags.BoolVar(&settings.debug, "d", false, "enable token-fingerprint diagnostics")
	flags.BoolVar(&settings.testAuthentication, "test-authentication", false, "use the deterministic test provider")
	flags.StringVar(&settings.evaluateToken, "evaluate-token", "", "evaluate one token and exit")
	flags.IntVar(&settings.authenticationPort, "authentication-webhook-port", environmentInt("AUTHENTICATION_WEBHOOK_PORT", 8080), "TokenReview webhook port")
	flags.IntVar(&settings.healthPort, "health-check-port", environmentInt("HEALTH_CHECK_PORT", 10240), "health check port")
	flags.StringVar(&settings.locale, "locale", environmentString("PASTURESTACK_LOCALE", "en-US"), "operator message locale")
	flags.BoolVar(&settings.bootstrapFromStdin, "bootstrap-token-stdin", false, "read the bootstrap token from standard input")
	flags.BoolVar(&settings.showVersion, "version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if settings.authenticationPort <= 0 || settings.authenticationPort > 65535 {
		return options{}, fmt.Errorf("invalid authentication webhook port: %d", settings.authenticationPort)
	}
	return settings, nil
}

func newAuthenticationServer(port int, provider authentication.Provider, debug bool) (*http.Server, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid authentication webhook port: %d", port)
	}
	mux := http.NewServeMux()
	mux.Handle("/", handlers.Authentication(provider, debug))
	return newHTTPServer(fmt.Sprintf(":%d", port), mux), nil
}

func serve(authenticationServer, healthServer *http.Server, locale string) error {
	errorsChannel := make(chan error, 2)
	go func() {
		log.Printf(operatorMessage(locale, "authentication-listen"), authenticationServer.Addr)
		errorsChannel <- authenticationServer.ListenAndServe()
	}()
	go func() {
		log.Printf(operatorMessage(locale, "health-listen"), healthServer.Addr)
		errorsChannel <- healthServer.ListenAndServe()
	}()

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-signalContext.Done():
	case serverError := <-errorsChannel:
		if serverError != nil && !errors.Is(serverError, http.ErrServerClosed) {
			return serverError
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()
	firstError := authenticationServer.Shutdown(shutdownContext)
	if err := healthServer.Shutdown(shutdownContext); firstError == nil {
		firstError = err
	}
	return firstError
}

func operatorMessage(locale, key string) string {
	messages := map[string]map[string]string{
		"en-US": {
			"debug-warning":         "Token fingerprints will be logged when debug mode is enabled",
			"username":              "Username",
			"groups":                "Groups",
			"authentication-listen": "TokenReview webhook listening on %s",
			"health-listen":         "Health check listening on %s/healthcheck",
		},
		"zh-TW": {
			"debug-warning":         "啟用除錯模式時將記錄權杖指紋",
			"username":              "使用者名稱",
			"groups":                "群組",
			"authentication-listen": "TokenReview Webhook 正在監聽 %s",
			"health-listen":         "健康狀態檢查正在監聽 %s/healthcheck",
		},
	}
	return messages[locale][key]
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}
}

func tokenFingerprint(token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("len=%d sha256=%s", len(token), hex.EncodeToString(digest[:])[:16])
}

func environmentString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func environmentInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func environmentDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return parsed, nil
}
