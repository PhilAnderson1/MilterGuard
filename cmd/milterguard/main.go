package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	if *check {
		if *whitelistAdd != "" || *whitelistDelete != "" || len(flag.Args()) != 0 {
			fmt.Fprintln(os.Stderr, "--check-config cannot be combined with whitelist operations")
			os.Exit(2)
		}
		fmt.Println("configuration is valid")
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
