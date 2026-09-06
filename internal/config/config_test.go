package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
ai:
  api_key: test-key
  model: test-model
  prompt_file: /tmp/test-prompt
  max_concurrent: 3
filtering:
  reject_score: 0.8
  add_unwanted_headers: true
attachments:
  block_executables: false
correspondents:
  scope: global
ip_reputation:
  max_entries: 42
persistence:
  flush_interval: 2m
logging:
  level: warn
`
	cfg, err := Load(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AI.MaxConcurrent != 3 || cfg.Filtering.RejectScore != 0.8 || !cfg.Filtering.AddUnwantedHeaders || cfg.Correspondents.Scope != "global" || cfg.IPReputation.MaxEntries != 42 || cfg.Persistence.FlushInterval.Value() != 2*time.Minute {
		t.Fatalf("new configuration sections not loaded: %#v", cfg)
	}

	legacy := valid + "\npolicy:\n  reject_score: 0.9\n"
	if _, err := Load(writeConfig(t, legacy)); err == nil || !strings.Contains(err.Error(), "field policy not found") {
		t.Fatalf("legacy policy section error = %v", err)
	}
}

func TestValidatePersistenceFlushInterval(t *testing.T) {
	if defaults().Persistence.FlushInterval.Value() != time.Minute {
		t.Fatal("persistence flush interval must default to one minute")
	}
	cfg := validConfig()
	cfg.Persistence.FlushInterval = Duration(-time.Second)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "persistence.flush_interval") {
		t.Fatalf("negative persistence interval error = %v", err)
	}
	cfg.Persistence.FlushInterval = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("immediate persistence rejected: %v", err)
	}
}

func validConfig() Config {
	cfg := defaults()
	cfg.AI.APIKey = "test-key"
	cfg.AI.Model = "test-model"
	cfg.AI.PromptFile = "/tmp/test-prompt"
	return cfg
}

func TestAuthenticatedMailScanningDefaultsEnabled(t *testing.T) {
	if !defaults().Filtering.ScanAuthenticated {
		t.Fatal("authenticated mail scanning must default to enabled")
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

func TestValidateRejectionHistory(t *testing.T) {
	cfg := validConfig()
	cfg.RejectionHistory.Expiry = Duration(-time.Second)
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rejection_history.expiry") {
		t.Fatalf("negative expiry error = %v", err)
	}
	cfg = validConfig()
	cfg.RejectionHistory.Expiry = Duration(time.Hour)
	cfg.RejectionHistory.File = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rejection_history.file") {
		t.Fatalf("missing history file error = %v", err)
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

func TestAttachmentBlockingDefaultsDisabled(t *testing.T) {
	if defaults().Attachments.BlockExecutables {
		t.Fatal("attachment blocking must default to disabled for existing configurations")
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
				cfg.IPReputation.IPAllowlist = []string{"192.0.2.1", "2001:db8::/32"}
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
			name: "missing state file when blocking enabled",
			configure: func(cfg *Config) {
				cfg.IPReputation.StateFile = ""
			},
			wantError: "ip_reputation.state_file",
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
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.TrustedAuthservIDs = []string{"mx.example.com"}
			},
			wantError: "bypass_ai requires use_allowlist",
		},
		{
			name: "correspondent bypass without trusted authentication service",
			configure: func(cfg *Config) {
				cfg.Correspondents.UseAllowlist = true
				cfg.Correspondents.BypassAI = true
				cfg.Correspondents.RequireDKIMForBypass = true
				cfg.Correspondents.TrustedAuthservIDs = nil
			},
			wantError: "requires trusted_authserv_ids",
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
