package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/milter"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

// version is replaced at build time with -ldflags "-X main.version=<version>".
var version = "development"

func main() {
	configPath := flag.String("config", "/etc/milterguard/milterguard.yaml", "configuration file")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	checkEndpoint := flag.Bool("check-endpoint", false, "test the configured AI endpoint and exit")
	checkPort := flag.Bool("check-port", false, "check that the configured Milter listener is available and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	whitelistAdd := flag.String("whitelist-add", "", "manually whitelist sender for one recipient (service must be stopped)")
	whitelistDelete := flag.String("whitelist-del", "", "delete sender whitelist entry; recipient may be * (service must be stopped)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("MilterGuard %s\n", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	for _, warning := range cfg.Warnings {
		logger.Warn("configuration warning", "warning", warning)
	}
	if *check || *checkEndpoint || *checkPort {
		if *whitelistAdd != "" || *whitelistDelete != "" || len(flag.Args()) != 0 {
			fmt.Fprintln(os.Stderr, "configuration, endpoint, and port checks cannot be combined with whitelist operations or positional arguments")
			os.Exit(2)
		}
		if *check {
			fmt.Println("configuration is valid")
		}
		if *checkPort {
			available, err := checkMilterListenerAvailable(cfg.Milter.Socket, net.Listen)
			if err != nil {
				fmt.Fprintln(os.Stderr, portCheckErrorMessage(cfg.Milter.Socket, *configPath, err))
				os.Exit(1)
			}
			fmt.Println(available)
		}
		if *checkEndpoint {
			quietLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
			decision, err := checkAIEndpoint(cfg, quietLogger)
			if err != nil {
				fmt.Fprintln(os.Stderr, endpointCheckErrorMessage(err))
				os.Exit(1)
			}
			if err := validateEndpointTestDecision(decision); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("Endpoint OK")
		}
		return
	}
	if *whitelistAdd != "" || *whitelistDelete != "" {
		if *whitelistAdd != "" && *whitelistDelete != "" {
			fmt.Fprintln(os.Stderr, "specify only one of --whitelist-add or --whitelist-del")
			os.Exit(2)
		}
		if len(flag.Args()) != 1 {
			fmt.Fprintln(os.Stderr, "whitelist operation requires sender and recipient arguments")
			os.Exit(2)
		}
		if milterListenerActive(cfg.Milter.Socket) {
			fmt.Fprintln(os.Stderr, "MilterGuard appears to be running; stop it before modifying the whitelist")
			os.Exit(1)
		}
		recipient := flag.Args()[0]
		if *whitelistAdd != "" {
			created, err := milter.AddManualCorrespondent(cfg, *whitelistAdd, recipient)
			if err != nil {
				fmt.Fprintln(os.Stderr, "cannot add whitelist entry:", err)
				os.Exit(1)
			}
			result := "updated"
			if created {
				result = "added"
			}
			fmt.Printf("whitelist entry %s: sender=%s recipient=%s\n", result, *whitelistAdd, recipient)
			return
		}
		removed, err := milter.DeleteCorrespondents(cfg, *whitelistDelete, recipient)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot delete whitelist entry:", err)
			os.Exit(1)
		}
		fmt.Printf("whitelist entries deleted: %d\n", removed)
		return
	}
	if len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}

	prompt, err := os.ReadFile(cfg.AI.PromptFile)
	if err != nil {
		logger.Error("cannot read detection prompt", "error", err)
		os.Exit(2)
	}
	client := ai.NewClient(cfg.AI, string(prompt), logger)
	server := milter.NewServer(cfg, client, logger)
	defer server.Close()
	if err := server.StartupError(); err != nil {
		message := persistentStateStartupErrorMessage(err)
		if errors.Is(err, milter.ErrInternalTokenGeneration) {
			message = "cannot initialize internal email-command replies"
		}
		logger.Error(message, "error", err)
		os.Exit(2)
	}

	ln, cleanup, err := listen(cfg.Milter.Socket)
	if err != nil {
		logger.Error("cannot create milter listener", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("MilterGuard started", "socket", cfg.Milter.Socket, "mode", cfg.Mode)
	if err := server.Serve(ctx, ln); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("milter server stopped", "error", err)
		os.Exit(1)
	}
}

type listenFunc func(network, address string) (net.Listener, error)

func checkMilterListenerAvailable(address string, listen listenFunc) (string, error) {
	switch {
	case strings.HasPrefix(address, "tcp:"):
		target := strings.TrimPrefix(address, "tcp:")
		listener, err := listen("tcp", target)
		if err != nil {
			return "", err
		}
		if err := listener.Close(); err != nil {
			return "", fmt.Errorf("close test listener: %w", err)
		}
		_, port, err := net.SplitHostPort(target)
		if err != nil {
			return "Milter port is available", nil
		}
		return "Milter port " + port + " is available", nil
	case strings.HasPrefix(address, "unix:"):
		path := strings.TrimPrefix(address, "unix:")
		if _, err := os.Lstat(path); err == nil {
			return "", syscall.EADDRINUSE
		} else if !os.IsNotExist(err) {
			return "", err
		}
		return "Milter Unix socket path is available", nil
	default:
		return "", fmt.Errorf("unsupported Milter listener %q", address)
	}
}

func portCheckErrorMessage(address, configPath string, err error) string {
	if errors.Is(err, syscall.EADDRINUSE) {
		if strings.HasPrefix(address, "tcp:") {
			target := strings.TrimPrefix(address, "tcp:")
			_, port, splitErr := net.SplitHostPort(target)
			if splitErr == nil {
				return fmt.Sprintf("Milter port %s is already in use - check MilterGuard is not already running. If necessary, change milter.socket in %s to an unused port on your machine", port, configPath)
			}
		}
		return fmt.Sprintf("Milter listener %s is already in use; change milter.socket in %s", address, configPath)
	}
	return "Cannot check Milter listener: " + err.Error()
}

// endpointTestEmail is a synthetic phishing message used only by
// --check-endpoint to test that the configured AI endpoint is working correctly
// and able to successfully identify unwanted email.
const endpointTestEmail = `CONNECTION INFORMATION:
Remote IP: 192.0.2.20
MTA-reported client hostname: urgent-account-security.invalid
Forward-confirmed reverse DNS: no
SMTP HELO/EHLO identity: urgent-account-security.invalid

CORRESPONDENT INFORMATION:
Sender found in known correspondent database: no

AUTHENTICATION INFORMATION:
Visible From domain: urgent-account-security.invalid
DKIM: fail for signing domain urgent-account-security.invalid
SPF: fail for envelope-sender domain urgent-account-security.invalid
DMARC: fail for visible From domain urgent-account-security.invalid

SELECTED HEADERS:
From: Bank Security <alert@urgent-account-security.invalid>
Subject: Urgent: verify your bank password immediately
To: customer@example.com

BODY:
Your bank account will be permanently closed today unless you confirm your password immediately. Enter your online banking username, password, and security code at http://steal-bank-passwords.invalid/verify.`

func checkAIEndpoint(cfg config.Config, logger *slog.Logger) (ai.Decision, error) {
	prompt, err := os.ReadFile(cfg.AI.PromptFile)
	if err != nil {
		return ai.Decision{}, &endpointPromptError{err: err}
	}
	client := ai.NewClient(cfg.AI, string(prompt), logger)
	return analyzeEndpointTest(client)
}

type endpointAnalyzer interface {
	Analyze(context.Context, ai.Input) (ai.Decision, error)
}

func analyzeEndpointTest(client endpointAnalyzer) (ai.Decision, error) {
	return client.Analyze(context.Background(), ai.Input{Text: endpointTestEmail})
}

type endpointPromptError struct{ err error }

func (e *endpointPromptError) Error() string { return "cannot read detection prompt: " + e.err.Error() }
func (e *endpointPromptError) Unwrap() error { return e.err }

func validateEndpointTestDecision(decision ai.Decision) error {
	if decision.Classification != "unwanted" {
		return fmt.Errorf("Test email incorrectly classified as %s", decision.Classification)
	}
	return nil
}

func endpointCheckErrorMessage(err error) string {
	var promptErr *endpointPromptError
	if errors.As(err, &promptErr) {
		return "Cannot read detection prompt: " + promptErr.err.Error()
	}
	var endpointErr *ai.EndpointError
	if errors.As(err, &endpointErr) {
		switch endpointErr.Kind {
		case ai.ErrorCredentials:
			return "API key not valid"
		case ai.ErrorPaymentRequired:
			return "Insufficient API credit"
		case ai.ErrorResponse:
			return "Invalid endpoint response: " + err.Error()
		case ai.ErrorDecision:
			return "Invalid JSON decision returned: " + err.Error()
		case ai.ErrorHTTP:
			if endpointErr.StatusCode == http.StatusBadRequest {
				return "Endpoint returned HTTP 400 (check the configured model name and endpoint type)"
			}
			return fmt.Sprintf("Endpoint returned HTTP %d", endpointErr.StatusCode)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return "Endpoint request timed out"
	}
	return "Endpoint connection failed: " + err.Error()
}

func persistentStateStartupErrorMessage(err error) string {
	if errors.Is(err, sqlstore.ErrIncompatibleDatabase) {
		return "incompatible SQLite database format"
	}
	return "persistent state cannot be read"
}

func milterListenerActive(address string) bool {
	return milterListenerActiveUsing(address, net.DialTimeout)
}

func milterListenerActiveUsing(address string, dial func(string, string, time.Duration) (net.Conn, error)) bool {
	network := ""
	target := ""
	switch {
	case strings.HasPrefix(address, "unix:"):
		network, target = "unix", strings.TrimPrefix(address, "unix:")
	case strings.HasPrefix(address, "tcp:"):
		network, target = "tcp", strings.TrimPrefix(address, "tcp:")
	default:
		return false
	}
	conn, err := dial(network, target, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func listen(address string) (net.Listener, func(), error) {
	if strings.HasPrefix(address, "unix:") {
		path := strings.TrimPrefix(address, "unix:")
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, func() {}, err
		}
		if st, err := os.Lstat(path); err == nil {
			if st.Mode()&os.ModeSocket == 0 {
				return nil, func() {}, fmt.Errorf("refusing to replace non-socket path %s", path)
			}
			if err := os.Remove(path); err != nil {
				return nil, func() {}, err
			}
		} else if !os.IsNotExist(err) {
			return nil, func() {}, err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, func() {}, err
		}
		if err := setUnixSocketPermissions(ln, path, os.Chmod); err != nil {
			return nil, func() {}, err
		}
		return ln, func() { _ = ln.Close(); _ = os.Remove(path) }, nil
	}
	if strings.HasPrefix(address, "tcp:") {
		ln, err := net.Listen("tcp", strings.TrimPrefix(address, "tcp:"))
		return ln, func() {
			if ln != nil {
				_ = ln.Close()
			}
		}, err
	}
	return nil, func() {}, fmt.Errorf("socket must begin with unix: or tcp:")
}

func setUnixSocketPermissions(ln net.Listener, path string, chmod func(string, os.FileMode) error) error {
	if err := chmod(path, 0660); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return fmt.Errorf("set Unix Milter socket permissions: %w", err)
	}
	return nil
}
