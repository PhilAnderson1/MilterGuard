package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoadAcceptsNewSectionsAndRejectsLegacySections(t *testing.T) {
	writeConfig := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "milterguard.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	valid := `
authentication:
  mode: internal
  shadow_internal: false
  timeout: 7s
  max_concurrent: 3
  message_storage: file
ai:
  api_key: test-key
  model: test-model
  prompt_file: /tmp/test-prompt
  max_concurrent: 3
filtering:
  reject_score: 0.8
  legitimate_low_confidence_score: 0.7
  add_email_headers: true
  authenticated_only_sender_domains:
    - example.com
attachments:
  block_executables: false
correspondents:
  scope: global
ip_reputation:
  max_entries: 42
persistence:
  database_file: /tmp/milterguard.db
  cleanup_interval: 2m
domain_registration:
  enabled: true
  timeout: 4s
  max_entries: 123
rejection_history:
  expiry: 48h
  max_entries: 321
  save_messages: true
  message_directory: /tmp/rejected-mail
  message_max_total_bytes: 52428800
logging:
  level: warn
`
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authentication.Mode != AuthenticationModeInternal || cfg.Authentication.Timeout.Value() != 7*time.Second || cfg.Authentication.MaxConcurrent != 3 || cfg.Authentication.MessageStorage != "file" || cfg.AI.MaxConcurrent != 3 || cfg.Filtering.RejectScore != 0.8 || cfg.Filtering.LegitimateLowConfidenceScore != 0.7 || !cfg.Filtering.AddEmailHeaders || !reflect.DeepEqual(cfg.Filtering.AuthenticatedOnlySenderDomains, []string{"example.com"}) || cfg.Correspondents.Scope != "global" || cfg.IPReputation.MaxEntries != 42 || cfg.Persistence.DatabaseFile != "/tmp/milterguard.db" || cfg.Persistence.CleanupInterval.Value() != 2*time.Minute || !cfg.DomainRegistration.Enabled || cfg.DomainRegistration.MaxEntries != 123 || cfg.RejectionHistory.Expiry.Value() != 48*time.Hour || cfg.RejectionHistory.MaxEntries != 321 || !cfg.RejectionHistory.SaveMessages || cfg.RejectionHistory.MessageDirectory != "/tmp/rejected-mail" || cfg.RejectionHistory.MessageMaxTotalBytes != 52428800 {
		t.Fatalf("new configuration sections not loaded: %#v", cfg)
	}

	legacy := valid + "\npolicy:\n  reject_score: 0.9\n"
	if _, err := Load(writeConfig(t, legacy)); err == nil || !strings.Contains(err.Error(), "field policy not found") {
		t.Fatalf("legacy policy section error = %v", err)
	}
	legacy = valid + "\nrejected_mail:\n  enabled: true\n"
	if _, err := Load(writeConfig(t, legacy)); err == nil || !strings.Contains(err.Error(), "field rejected_mail not found") {
		t.Fatalf("legacy rejected_mail section error = %v", err)
	}
	legacy = valid + "\nmilter:\n  exact_message_storage: memory\n"
	if _, err := Load(writeConfig(t, legacy)); err == nil || !strings.Contains(err.Error(), "field exact_message_storage not found") {
		t.Fatalf("legacy exact-message storage error = %v", err)
	}
}

func TestValidateDomainRegistration(t *testing.T) {
	cfg := validConfig()
	cfg.DomainRegistration.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid domain registration settings rejected: %v", err)
	}
	for _, configure := range []func(*Config){
		func(cfg *Config) { cfg.DomainRegistration.Timeout = 0 },
		func(cfg *Config) { cfg.DomainRegistration.MaxEntries = 0 },
	} {
		invalid := cfg
		configure(&invalid)
		if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "domain_registration") {
			t.Fatalf("invalid domain registration settings error = %v", err)
		}
	}
}

func TestValidatePersistenceCleanupInterval(t *testing.T) {
	if defaults().Persistence.DatabaseFile != "/var/lib/milterguard/milterguard.db" {
		t.Fatal("persistence database must default under /var/lib/milterguard")
	}
	if defaults().Persistence.CleanupInterval.Value() != 10*time.Minute {
		t.Fatal("persistence cleanup interval must default to ten minutes")
	}
	cfg := validConfig()
	cfg.Persistence.CleanupInterval = Duration(time.Minute - time.Nanosecond)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "persistence.cleanup_interval") {
		t.Fatalf("short persistence interval error = %v", err)
	}
	cfg.Persistence.CleanupInterval = Duration(time.Minute)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("minimum cleanup interval rejected: %v", err)
	}
}

func TestValidatePersistenceDatabaseFile(t *testing.T) {
	cfg := validConfig()
	cfg.Persistence.DatabaseFile = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "persistence.database_file") {
		t.Fatalf("empty persistence database path error = %v", err)
	}
}

func TestValidateMilterTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		cfg := validConfig()
		cfg.Milter.Timeout = Duration(timeout)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "milter.timeout") {
			t.Fatalf("timeout %s error = %v", timeout, err)
		}
	}
}

func TestValidateMilterSocket(t *testing.T) {
	for _, socket := range []string{
		"tcp:127.0.0.1:8895",
		"tcp:localhost:8895",
		"tcp:[::1]:8895",
		"tcp::8895",
		"unix:/run/milterguard/milterguard.sock",
	} {
		cfg := validConfig()
		cfg.Milter.Socket = socket
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid socket %q rejected: %v", socket, err)
		}
	}

	for _, socket := range []string{
		"",
		"127.0.0.1:8895",
		"tcp:",
		"tcp:127.0.0.1",
		"tcp:127.0.0.1:not-a-port",
		"tcp:127.0.0.1:0",
		"tcp:127.0.0.1:65536",
		"tcp:::1:8895",
		"tcp:bad host:8895",
		"unix:",
		"unix:/run/milterguard/invalid\x00socket",
	} {
		cfg := validConfig()
		cfg.Milter.Socket = socket
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "milter.socket") {
			t.Errorf("invalid socket %q error = %v", socket, err)
		}
	}
}

func TestValidateMilterMaxMessageSize(t *testing.T) {
	for _, test := range []struct {
		value   int64
		wantErr bool
	}{
		{value: 1},
		{value: maxMilterMessageSize},
		{value: 0, wantErr: true},
		{value: -1, wantErr: true},
		{value: maxMilterMessageSize + 1, wantErr: true},
	} {
		cfg := validConfig()
		cfg.Milter.MaxMessageSize = test.value
		err := cfg.Validate()
		if test.wantErr && (err == nil || !strings.Contains(err.Error(), "milter.max_message_size")) {
			t.Errorf("maximum message size %d error = %v", test.value, err)
		}
		if !test.wantErr && err != nil {
			t.Errorf("maximum message size %d rejected: %v", test.value, err)
		}
	}
}

func TestValidateAuthentication(t *testing.T) {
	for _, mode := range []string{"trusted_headers", "internal"} {
		cfg := validConfig()
		cfg.Authentication.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
	for _, configure := range []func(*Config){
		func(cfg *Config) { cfg.Authentication.Mode = "automatic" },
		func(cfg *Config) { cfg.Authentication.Timeout = 0 },
		func(cfg *Config) { cfg.Authentication.MaxConcurrent = 0 },
	} {
		cfg := validConfig()
		configure(&cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "authentication.") {
			t.Fatalf("invalid authentication settings error = %v", err)
		}
	}
	for _, storage := range []string{"memory", "file"} {
		cfg := validConfig()
		cfg.Authentication.MessageStorage = storage
		if err := cfg.Validate(); err != nil {
			t.Fatalf("storage %q rejected: %v", storage, err)
		}
	}
	cfg := validConfig()
	cfg.Authentication.MessageStorage = "automatic"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "authentication.message_storage") {
		t.Fatalf("invalid storage error = %v", err)
	}

	cfg = validConfig()
	cfg.Authentication.Mode = AuthenticationModeTrustedHeaders
	cfg.Authentication.ShadowInternal = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("trusted-header shadow observation rejected: %v", err)
	}
	cfg.Authentication.Mode = AuthenticationModeInternal
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "shadow_internal") {
		t.Fatalf("internal mode with redundant shadow error = %v", err)
	}
}

func TestLoadWarnsForTemporaryAuthenticationShadow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.yaml")
	content := "authentication:\n  mode: trusted_headers\n  shadow_internal: true\nai:\n  api_key: test-key\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) == 0 || !strings.Contains(strings.Join(cfg.Warnings, "\n"), "temporary diagnostic") {
		t.Fatalf("shadow warnings = %q", cfg.Warnings)
	}
}

func TestInternalAuthenticationDoesNotRequireTrustedHeaderProducers(t *testing.T) {
	cfg := validConfig()
	cfg.Authentication.Mode = "internal"
	cfg.Correspondents.TrustedAuthservIDs = nil
	cfg.Filtering.SenderDomainAllowlist = []string{"example.com"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("internal authentication incorrectly requires trusted headers: %v", err)
	}
}

func TestLoadRejectsEmptyAndMultipleYAMLDocuments(t *testing.T) {
	write := func(content string) string {
		path := filepath.Join(t.TempDir(), "milterguard.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for _, content := range []string{"", "  \n  \n", "# comment only\n"} {
		if _, err := Load(write(content)); err == nil || !strings.Contains(err.Error(), "configuration file is empty") {
			t.Errorf("empty configuration error = %v", err)
		}
	}

	multiple := "ai:\n  api_key: test-key\n---\nmode: enforce\n"
	if _, err := Load(write(multiple)); err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("multiple-document configuration error = %v", err)
	}
}

func TestValidateMilterMaxConnections(t *testing.T) {
	if got := defaults().Milter.MaxConnections; got != 64 {
		t.Fatalf("default maximum Milter connections = %d", got)
	}
	for _, maximum := range []int{0, -1} {
		cfg := validConfig()
		cfg.Milter.MaxConnections = maximum
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "milter.max_connections") {
			t.Fatalf("maximum %d error = %v", maximum, err)
		}
	}
}

func TestValidateMilterAllowedPeerIPs(t *testing.T) {
	defaults := defaults()
	if !reflect.DeepEqual(defaults.Milter.AllowedPeerIPs, []string{"127.0.0.0/8", "::1/128"}) {
		t.Fatalf("default allowed Milter peers = %#v", defaults.Milter.AllowedPeerIPs)
	}
	for _, entry := range []string{"192.0.2.10", "10.0.0.0/8", "2001:db8::/32"} {
		cfg := validConfig()
		cfg.Milter.AllowedPeerIPs = []string{entry}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid peer %q rejected: %v", entry, err)
		}
	}
	for _, entries := range [][]string{nil, {}, {"not-an-ip"}} {
		cfg := validConfig()
		cfg.Milter.AllowedPeerIPs = entries
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "milter.allowed_peer_ips") {
			t.Fatalf("invalid peers %#v error = %v", entries, err)
		}
	}
	cfg := validConfig()
	cfg.Milter.Socket = "unix:/run/milterguard/milterguard.sock"
	cfg.Milter.AllowedPeerIPs = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty TCP peer list rejected for Unix listener: %v", err)
	}
}

func TestValidateLegitimateLowConfidenceScore(t *testing.T) {
	if got := defaults().Filtering.LegitimateLowConfidenceScore; got != 0.8 {
		t.Fatalf("default legitimate low-confidence score = %v", got)
	}
	for _, field := range []struct {
		name string
		set  func(*Config, float64)
	}{
		{"filtering.reject_score", func(cfg *Config, score float64) { cfg.Filtering.RejectScore = score }},
		{"filtering.legitimate_low_confidence_score", func(cfg *Config, score float64) { cfg.Filtering.LegitimateLowConfidenceScore = score }},
	} {
		for _, score := range []float64{0, 0.49, 1.01} {
			cfg := validConfig()
			field.set(&cfg, score)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), field.name) {
				t.Errorf("invalid %s %v error = %v", field.name, score, err)
			}
		}
		for _, score := range []float64{0.5, 1} {
			cfg := validConfig()
			field.set(&cfg, score)
			if err := cfg.Validate(); err != nil {
				t.Errorf("valid %s %v rejected: %v", field.name, score, err)
			}
		}
	}
	cfg := validConfig()
	cfg.Filtering.RejectScore = 0.5
	cfg.Filtering.LegitimateLowConfidenceScore = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("independent threshold ordering rejected: %v", err)
	}
}

func validConfig() Config {
	cfg := defaults()
	cfg.AI.APIKey = "test-key"
	cfg.AI.Model = "test-model"
	cfg.AI.PromptFile = "/tmp/test-prompt"
	return cfg
}

func TestAuthenticatedMailScanningDefaultsDisabled(t *testing.T) {
	if defaults().Filtering.ScanAuthenticated {
		t.Fatal("authenticated mail scanning must match the disabled sample configuration")
	}
}

func TestAuthenticationDefaultsInternal(t *testing.T) {
	if defaults().Authentication.Mode != AuthenticationModeInternal {
		t.Fatal("authentication must default to internal verification")
	}
}

func TestConnectionLifecycleLoggingDefaultsDisabled(t *testing.T) {
	if defaults().Logging.IncludeConnections {
		t.Fatal("connection lifecycle logging must default to disabled")
	}
}

func TestValidateOperationModes(t *testing.T) {
	for _, mode := range []string{"monitor", "tag", "enforce"} {
		cfg := validConfig()
		cfg.Mode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("mode %q rejected: %v", mode, err)
		}
	}
	cfg := validConfig()
	cfg.Mode = "invalid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mode must") {
		t.Fatalf("invalid mode error = %v", err)
	}
}

func TestValidateAIEndpointType(t *testing.T) {
	for _, endpointType := range []string{"openrouter", "llamacpp", "openai"} {
		cfg := validConfig()
		cfg.AI.EndpointType = endpointType
		if err := cfg.Validate(); err != nil {
			t.Fatalf("endpoint type %q rejected: %v", endpointType, err)
		}
	}
	cfg := validConfig()
	cfg.AI.EndpointType = "unknown"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ai.endpoint_type") {
		t.Fatalf("invalid endpoint type error = %v", err)
	}
}

func TestValidateEmailCommands(t *testing.T) {
	cfg := validConfig()
	cfg.EmailCommands.Enabled = true
	cfg.EmailCommands.Recipient = "milterguard@example.com"
	cfg.EmailCommands.AllowAuthenticatedUsers = true
	cfg.Correspondents.UseAllowlist = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.EmailCommands.Recipient = "not-an-address"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "email_commands.recipient") {
		t.Fatalf("invalid command recipient error = %v", err)
	}
	cfg = validConfig()
	cfg.EmailCommands.Enabled = true
	cfg.EmailCommands.AllowAuthenticatedUsers = true
	cfg.EmailCommands.SMTPHost = "missing-port"
	cfg.Correspondents.UseAllowlist = true
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "email_commands.smtp_host") {
		t.Fatalf("invalid SMTP host error = %v", err)
	}
}

func TestValidateEmailCommandTLSMode(t *testing.T) {
	if got := defaults().EmailCommands.SMTPTLS; got != "opportunistic" {
		t.Fatalf("default SMTP TLS mode = %q, want opportunistic", got)
	}
	for _, mode := range []string{"off", "opportunistic", "required"} {
		cfg := validConfig()
		cfg.EmailCommands.SMTPTLS = mode
		if err := cfg.Validate(); err != nil {
			t.Errorf("SMTP TLS mode %q rejected: %v", mode, err)
		}
	}
	cfg := validConfig()
	cfg.EmailCommands.SMTPTLS = "optional"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "email_commands.smtp_tls") {
		t.Fatalf("invalid SMTP TLS mode error = %v", err)
	}
}

func TestValidateLoggingLevel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error", "DEBUG"} {
		cfg := validConfig()
		cfg.Logging.Level = level
		if err := cfg.Validate(); err != nil {
			t.Errorf("logging level %q rejected: %v", level, err)
		}
	}
	for _, level := range []string{"", "verbose", "warning"} {
		cfg := validConfig()
		cfg.Logging.Level = level
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "logging.level") {
			t.Errorf("invalid logging level %q error = %v", level, err)
		}
	}
}

func TestValidateFilteringRejectMessage(t *testing.T) {
	for _, message := range []string{"", " \t "} {
		cfg := validConfig()
		cfg.Filtering.RejectMessage = message
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "filtering.reject_message") {
			t.Errorf("blank reject message %q error = %v", message, err)
		}
	}
	cfg := validConfig()
	cfg.Filtering.RejectMessage = "Message rejected"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid reject message rejected: %v", err)
	}
}

func TestValidateRejectionHistory(t *testing.T) {
	cfg := validConfig()
	cfg.RejectionHistory.Expiry = Duration(-time.Second)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rejection_history.expiry") {
		t.Fatalf("negative expiry error = %v", err)
	}
	cfg = validConfig()
	cfg.RejectionHistory.Expiry = Duration(time.Hour)
	cfg.RejectionHistory.MaxEntries = 0
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rejection_history.max_entries") {
		t.Fatalf("invalid max entries error = %v", err)
	}
}

func TestValidateSavedRejectionMessages(t *testing.T) {
	defaultConfig := defaults()
	if !defaultConfig.RejectionHistory.SaveMessages {
		t.Fatal("saved rejection messages must be enabled by default")
	}
	cfg := validConfig()
	cfg.RejectionHistory.SaveMessages = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default saved-message settings rejected: %v", err)
	}
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "relative directory", change: func(c *Config) { c.RejectionHistory.MessageDirectory = "rejected-mail" }},
		{name: "zero expiry", change: func(c *Config) { c.RejectionHistory.Expiry = 0 }},
		{name: "byte limit below message limit", change: func(c *Config) { c.RejectionHistory.MessageMaxTotalBytes = c.Milter.MaxMessageSize - 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := cfg
			test.change(&invalid)
			if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "rejection_history") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
	cfg.RejectionHistory.Expiry = 0
	cfg.RejectionHistory.SaveMessages = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled rejection history and message saving rejected: %v", err)
	}
}

func TestValidateSenderDomainAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{
			name: "valid sender domains",
			configure: func(cfg *Config) {
				cfg.Filtering.SenderDomainAllowlist = []string{"amazon.com", "MAIL.EXAMPLE.ORG."}
				cfg.Filtering.SenderDomainAllowlistRequireDKIM = true
			},
		},
		{
			name: "wildcards are rejected",
			configure: func(cfg *Config) {
				cfg.Filtering.SenderDomainAllowlist = []string{"*.amazon.com"}
			},
			wantError: "invalid filtering.sender_domain_allowlist",
		},
		{
			name: "DKIM requirement needs trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Authentication.Mode = AuthenticationModeTrustedHeaders
				cfg.Filtering.SenderDomainAllowlist = []string{"amazon.com"}
				cfg.Filtering.SenderDomainAllowlistRequireDKIM = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
			wantError: "requires correspondents.trusted_authserv_ids",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("validation error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestValidateAuthenticatedOnlySenderDomains(t *testing.T) {
	cfg := validConfig()
	cfg.Filtering.AuthenticatedOnlySenderDomains = []string{"example.com", "MAIL.EXAMPLE.ORG."}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid authenticated-only sender domains rejected: %v", err)
	}

	for _, domain := range []string{"", "*.example.com", "127.0.0.1", "bad_domain.example"} {
		cfg := validConfig()
		cfg.Filtering.AuthenticatedOnlySenderDomains = []string{domain}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "authenticated_only_sender_domains") {
			t.Errorf("invalid domain %q error = %v", domain, err)
		}
	}
}

func TestLoadSenderDomainAllowlistFile(t *testing.T) {
	directory := t.TempDir()
	domainsPath := filepath.Join(directory, "trusted-sender-domains.txt")
	if err := os.WriteFile(domainsPath, []byte("# trusted senders\nAmazon.COM.\n\nebay.com\namazon.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "milterguard.yaml")
	content := "ai:\n  api_key: test-key\n  model: test-model\n  prompt_file: /tmp/test-prompt\nfiltering:\n  sender_domain_allowlist: " + domainsPath + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"amazon.com", "ebay.com"}
	if len(cfg.Filtering.SenderDomainAllowlist) != len(want) {
		t.Fatalf("loaded domains = %q", cfg.Filtering.SenderDomainAllowlist)
	}
	for index := range want {
		if cfg.Filtering.SenderDomainAllowlist[index] != want[index] {
			t.Fatalf("loaded domains = %q, want %q", cfg.Filtering.SenderDomainAllowlist, want)
		}
	}
}

func TestLoadWarnsWhenEmailCommandSenderOwnershipDependsOnPostfix(t *testing.T) {
	for _, test := range []struct {
		name        string
		commands    string
		wantWarning bool
	}{
		{"ordinary users without alias verification", "enabled: true\n  allow_authenticated_users: true\n  verify_sender_via_aliases: false", true},
		{"ordinary users with alias verification", "enabled: true\n  allow_authenticated_users: true\n  verify_sender_via_aliases: true", false},
		{"administrators only", "enabled: true\n  administrators: [admin]\n  allow_authenticated_users: false\n  verify_sender_via_aliases: false", false},
		{"commands disabled", "enabled: false\n  allow_authenticated_users: true\n  verify_sender_via_aliases: false", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "milterguard.yaml")
			content := "ai:\n  api_key: test-key\nfiltering:\n  sender_domain_allowlist: ''\nemail_commands:\n  " + test.commands + "\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			gotWarning := len(cfg.Warnings) == 1 && strings.Contains(cfg.Warnings[0], "smtpd_sender_login_maps")
			if gotWarning != test.wantWarning || len(cfg.Warnings) > 1 {
				t.Fatalf("warnings = %q, want Postfix warning = %t", cfg.Warnings, test.wantWarning)
			}
		})
	}
}

func TestLoadHandlesUnavailableEmptyOrInvalidSenderDomainAllowlistFile(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "milterguard.yaml")
	writeConfig := func(path string) {
		content := "ai:\n  api_key: test-key\n  model: test-model\n  prompt_file: /tmp/test-prompt\nfiltering:\n  sender_domain_allowlist: " + path + "\n"
		if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(filepath.Join(directory, "missing.txt"))
	cfg, err := Load(configPath)
	if err != nil || len(cfg.Warnings) != 1 || len(cfg.Filtering.SenderDomainAllowlist) != 0 {
		t.Fatalf("missing file result: config=%#v error=%v", cfg, err)
	}
	emptyPath := filepath.Join(directory, "empty.txt")
	if err := os.WriteFile(emptyPath, []byte("# no domains configured\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeConfig(emptyPath)
	cfg, err = Load(configPath)
	if err != nil || len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "contains no domains") {
		t.Fatalf("empty file result: warnings=%q error=%v", cfg.Warnings, err)
	}
	writeConfig(directory)
	cfg, err = Load(configPath)
	if err != nil || len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "cannot read") {
		t.Fatalf("unreadable file result: warnings=%q error=%v", cfg.Warnings, err)
	}
	invalidPath := filepath.Join(directory, "invalid.txt")
	if err := os.WriteFile(invalidPath, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeConfig(invalidPath)
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("invalid domain error = %v", err)
	}
}

func TestAttachmentBlockingDefaultsEnabled(t *testing.T) {
	if !defaults().Attachments.BlockExecutables {
		t.Fatal("attachment blocking must match the enabled sample configuration")
	}
}

func TestDefaultsMatchDistributedConfiguration(t *testing.T) {
	content, err := os.ReadFile("../../configs/milterguard.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var sample Config
	if err := yaml.Unmarshal(content, &sample); err != nil {
		t.Fatal(err)
	}
	want := defaults()
	// Credentials must be explicitly supplied even though the sample shows the
	// placeholder and all operational defaults are safe to omit.
	want.AI.APIKey = sample.AI.APIKey
	if !reflect.DeepEqual(want, sample) {
		t.Fatalf("internal defaults differ from distributed configuration:\ninternal: %#v\nsample:   %#v", want, sample)
	}
}

func TestMTAHostnameIsDefaultTrustedAuthenticationService(t *testing.T) {
	trusted := defaults().Correspondents.TrustedAuthservIDs
	if len(trusted) != 1 || trusted[0] != MTAHostnameAuthservID {
		t.Fatalf("default trusted authentication services = %q", trusted)
	}
}

func TestValidateRejectedIPPolicy(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{
			name: "valid IP CIDR and domain allowlists",
			configure: func(cfg *Config) {
				cfg.IPReputation.BlockDuration = Duration(15 * time.Minute)
				cfg.IPReputation.IPAllowlist = []string{"192.0.2.1", "2001:db8::/32", "::ffff:198.51.100.0/120"}
				cfg.IPReputation.DomainAllowlist = []string{"outlook.com", "MAIL.GOOGLE.COM."}
			},
		},
		{
			name: "negative connection DNS timeout",
			configure: func(cfg *Config) {
				cfg.Milter.ConnectionDNSTimeout = Duration(-time.Second)
			},
			wantError: "connection_dns_timeout",
		},
		{
			name: "negative duration",
			configure: func(cfg *Config) {
				cfg.IPReputation.BlockDuration = Duration(-time.Second)
			},
			wantError: "ip_reputation.block_duration",
		},
		{
			name: "negative repeat threshold",
			configure: func(cfg *Config) {
				cfg.IPReputation.RepeatThreshold = -1
			},
			wantError: "ip_reputation.repeat_threshold",
		},
		{
			name: "negative legitimate messages per strike",
			configure: func(cfg *Config) {
				cfg.IPReputation.LegitimatePerStrike = -1
			},
			wantError: "ip_reputation.legitimate_messages_per_strike",
		},
		{
			name: "zero repeat window when escalation enabled",
			configure: func(cfg *Config) {
				cfg.IPReputation.RepeatWindow = 0
			},
			wantError: "ip_reputation.repeat_window",
		},
		{
			name: "zero cache size",
			configure: func(cfg *Config) {
				cfg.IPReputation.MaxEntries = 0
			},
			wantError: "ip_reputation.max_entries",
		},
		{
			name: "invalid allowlist entry",
			configure: func(cfg *Config) {
				cfg.IPReputation.IPAllowlist = []string{"not-an-address"}
			},
			wantError: "ip_reputation.ip_allowlist",
		},
		{
			name: "unrepresentable IPv4-mapped allowlist prefix",
			configure: func(cfg *Config) {
				cfg.IPReputation.IPAllowlist = []string{"::ffff:192.0.2.0/80"}
			},
			wantError: "IPv4-mapped prefix must be /96 or longer",
		},
		{
			name: "invalid domain allowlist entry",
			configure: func(cfg *Config) {
				cfg.IPReputation.DomainAllowlist = []string{"*.outlook.com"}
			},
			wantError: "ip_reputation.domain_allowlist",
		},
		{
			name: "invalid vision mode",
			configure: func(cfg *Config) {
				cfg.AI.VisionMode = "sometimes"
			},
			wantError: "vision_mode",
		},
		{
			name: "enabled attachment policy without detection",
			configure: func(cfg *Config) {
				cfg.Attachments.BlockExecutables = true
				cfg.Attachments.BlockedExtensions = nil
				cfg.Attachments.InspectSignatures = false
			},
			wantError: "requires blocked_extensions",
		},
		{
			name: "invalid blocked attachment extension",
			configure: func(cfg *Config) {
				cfg.Attachments.BlockedExtensions = []string{"tar.gz"}
			},
			wantError: "blocked_extensions",
		},
		{
			name: "invalid attachment limit",
			configure: func(cfg *Config) {
				cfg.Attachments.MaxArchiveFiles = 0
			},
			wantError: "attachments limits",
		},
		{
			name: "invalid encrypted archive action",
			configure: func(cfg *Config) {
				cfg.Attachments.EncryptedArchiveAction = "allow"
			},
			wantError: "encrypted_archive_action",
		},
		{
			name: "invalid unscannable action",
			configure: func(cfg *Config) {
				cfg.Attachments.UnscannableAction = "defer"
			},
			wantError: "unscannable_action",
		},
		{
			name: "invalid MIME action",
			configure: func(cfg *Config) {
				cfg.Attachments.InvalidMIMEAction = "tempfail"
			},
			wantError: "invalid_mime_action",
		},
		{
			name: "invalid correspondent scope",
			configure: func(cfg *Config) {
				cfg.Correspondents.Scope = "user"
			},
			wantError: "correspondents.scope",
		},
		{
			name: "invalid correspondent recipient matching policy",
			configure: func(cfg *Config) {
				cfg.Correspondents.RecipientMatch = "some"
			},
			wantError: "correspondents.recipient_match",
		},
		{
			name: "negative correspondent stale duration",
			configure: func(cfg *Config) {
				cfg.Correspondents.StaleAfter = Duration(-time.Second)
			},
			wantError: "correspondents.stale_after",
		},
		{
			name: "negative correspondent activity update interval",
			configure: func(cfg *Config) {
				cfg.Correspondents.ActivityUpdateInterval = Duration(-time.Second)
			},
			wantError: "correspondents.activity_update_interval",
		},
		{
			name: "zero legitimate sender message threshold",
			configure: func(cfg *Config) {
				cfg.Correspondents.LegitimateSenderMinMessages = 0
			},
			wantError: "legitimate_sender_min_messages",
		},
		{
			name: "invalid legitimate sender score threshold",
			configure: func(cfg *Config) {
				cfg.Correspondents.LegitimateSenderMinScore = 1.01
			},
			wantError: "legitimate_sender_min_score",
		},
		{
			name: "correspondent bypass without use",
			configure: func(cfg *Config) {
				cfg.Correspondents.UseAllowlist = false
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.TrustedAuthservIDs = []string{"mx.example.com"}
			},
			wantError: "bypass_ai requires use_allowlist",
		},
		{
			name: "correspondent bypass without trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Authentication.Mode = AuthenticationModeTrustedHeaders
				cfg.Correspondents.UseAllowlist = true
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.RequireDKIMForBypass = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
			wantError: "requires trusted_authserv_ids",
		},
		{
			name: "DKIM-required legitimate sender learning without trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Authentication.Mode = AuthenticationModeTrustedHeaders
				cfg.Correspondents.BypassAI = false
				cfg.Correspondents.LearnLegitimateSenders = true
				cfg.Correspondents.LegitimateSenderRequireDKIM = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
			wantError: "legitimate_sender_require_dkim requires trusted_authserv_ids",
		},
		{
			name: "disabled legitimate sender learning does not require trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Authentication.Mode = AuthenticationModeTrustedHeaders
				cfg.Correspondents.BypassAI = false
				cfg.Correspondents.LearnLegitimateSenders = false
				cfg.Correspondents.LegitimateSenderRequireDKIM = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
		},
		{
			name: "invalid vision limit",
			configure: func(cfg *Config) {
				cfg.AI.MaxImagePixels = 0
			},
			wantError: "vision limits",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}
