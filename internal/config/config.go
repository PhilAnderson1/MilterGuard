package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"gopkg.in/yaml.v3"
)

const (
	MTAHostnameAuthservID            = "$mta_hostname"
	AuthenticationModeTrustedHeaders = "trusted_headers"
	AuthenticationModeInternal       = "internal"
	AuthenticationTrustDKIM          = "dkim"
	AuthenticationTrustSPF           = "spf"
	AuthenticationTrustEither        = "either"
	AuthenticationTrustBoth          = "both"
	maxMilterMessageSize             = 100 << 20
)

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
func (d Duration) Value() time.Duration { return time.Duration(d) }

type Config struct {
	Mode               string                   `yaml:"mode"`
	Milter             MilterConfig             `yaml:"milter"`
	Authentication     AuthenticationConfig     `yaml:"authentication"`
	AI                 AIConfig                 `yaml:"ai"`
	Activity           ActivityConfig           `yaml:"activity"`
	SenderBlocklist    SenderBlocklistConfig    `yaml:"sender_blocklist"`
	Filtering          FilteringConfig          `yaml:"filtering"`
	Attachments        AttachmentsConfig        `yaml:"attachments"`
	EmailCommands      EmailCommandsConfig      `yaml:"email_commands"`
	Persistence        PersistenceConfig        `yaml:"persistence"`
	RejectionHistory   RejectionHistoryConfig   `yaml:"rejection_history"`
	Correspondents     CorrespondentsConfig     `yaml:"correspondents"`
	IPReputation       IPReputationConfig       `yaml:"ip_reputation"`
	DomainRegistration DomainRegistrationConfig `yaml:"domain_registration"`
	Logging            LoggingConfig            `yaml:"logging"`
	Warnings           []string                 `yaml:"-"`
}

type PersistenceConfig struct {
	DatabaseFile    string   `yaml:"database_file"`
	CleanupInterval Duration `yaml:"cleanup_interval"`
}

type ActivityConfig struct {
	Expiry Duration `yaml:"expiry"`
}

type SenderBlocklistConfig struct {
	Expiry            Duration `yaml:"expiry"`
	MaxEntries        int      `yaml:"max_entries"`
	IncludeSubdomains bool     `yaml:"include_subdomains"`
	RejectMessage     string   `yaml:"reject_message"`
}

type DomainRegistrationConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Timeout    Duration `yaml:"timeout"`
	MaxEntries int      `yaml:"max_entries"`
}

type RejectionHistoryConfig struct {
	Expiry               Duration `yaml:"expiry"`
	MaxEntries           int      `yaml:"max_entries"`
	SaveMessages         bool     `yaml:"save_messages"`
	MessageDirectory     string   `yaml:"message_directory"`
	MessageMaxTotalBytes int64    `yaml:"message_max_total_bytes"`
}

type EmailCommandsConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	Recipient               string   `yaml:"recipient"`
	AllowAuthenticatedUsers bool     `yaml:"allow_authenticated_users"`
	VerifySenderViaAliases  bool     `yaml:"verify_sender_via_aliases"`
	AliasesFile             string   `yaml:"aliases_file"`
	Administrators          []string `yaml:"administrators"`
	SendReplies             bool     `yaml:"send_replies"`
	SMTPHost                string   `yaml:"smtp_host"`
	SMTPTLS                 string   `yaml:"smtp_tls"`
	MaxMessageBytes         int64    `yaml:"max_message_bytes"`
}

type AttachmentsConfig struct {
	BlockExecutables            bool     `yaml:"block_executables"`
	AddIPReputationStrike       bool     `yaml:"add_ip_reputation_strike"`
	BlockedExtensions           []string `yaml:"blocked_extensions"`
	InspectSignatures           bool     `yaml:"inspect_file_signatures"`
	InspectArchives             bool     `yaml:"inspect_archives"`
	MaxAttachmentBytes          int64    `yaml:"max_attachment_bytes"`
	MaxArchiveDepth             int      `yaml:"archive_max_depth"`
	MaxArchiveFiles             int      `yaml:"archive_max_files"`
	MaxArchiveUncompressedBytes int64    `yaml:"archive_max_uncompressed_bytes"`
	EncryptedArchiveAction      string   `yaml:"encrypted_archive_action"`
	UnscannableAction           string   `yaml:"unscannable_action"`
	InvalidMIMEAction           string   `yaml:"invalid_mime_action"`
	RejectMessage               string   `yaml:"reject_message"`
}
type MilterConfig struct {
	Socket               string   `yaml:"socket"`
	Timeout              Duration `yaml:"timeout"`
	ConnectionDNSTimeout Duration `yaml:"connection_dns_timeout"`
	MaxMessageSize       int64    `yaml:"max_message_size"`
	MaxConnections       int      `yaml:"max_connections"`
	AllowedPeerIPs       []string `yaml:"allowed_peer_ips"`
}
type AuthenticationConfig struct {
	Mode               string   `yaml:"mode"`
	TrustRequirement   string   `yaml:"trust_requirement"`
	Timeout            Duration `yaml:"timeout"`
	MaxConcurrent      int      `yaml:"max_concurrent"`
	MessageStorage     string   `yaml:"message_storage"`
	MemoryMessageLimit int      `yaml:"memory_message_limit"`
}
type AIConfig struct {
	Endpoint                   string   `yaml:"endpoint"`
	EndpointType               string   `yaml:"endpoint_type"`
	APIKey                     string   `yaml:"api_key"`
	APIKeyEnv                  string   `yaml:"api_key_env"`
	Model                      string   `yaml:"model"`
	DisableThinking            bool     `yaml:"disable_thinking"`
	PromptFile                 string   `yaml:"prompt_file"`
	Timeout                    Duration `yaml:"timeout"`
	Retries                    int      `yaml:"retries"`
	MaxConcurrent              int      `yaml:"max_concurrent"`
	MaxBodyChars               int      `yaml:"max_body_chars"`
	VisionMode                 string   `yaml:"vision_mode"`
	VisionMinTextChars         int      `yaml:"vision_min_text_chars"`
	MaxImages                  int      `yaml:"max_images"`
	MaxImageBytes              int64    `yaml:"max_image_bytes"`
	MaxImagePixels             int64    `yaml:"max_image_pixels"`
	SiteURL                    string   `yaml:"site_url"`
	AppName                    string   `yaml:"app_name"`
	InputCostPerMillionTokens  float64  `yaml:"input_cost_per_million_tokens"`
	OutputCostPerMillionTokens float64  `yaml:"output_cost_per_million_tokens"`
}
type FilteringConfig struct {
	RejectScore                                float64  `yaml:"reject_score"`
	LegitimateLowConfidenceScore               float64  `yaml:"legitimate_low_confidence_score"`
	AddEmailHeaders                            bool     `yaml:"add_email_headers"`
	AIErrorAction                              string   `yaml:"ai_error_action"`
	RejectMessage                              string   `yaml:"reject_message"`
	ScanAuthenticated                          bool     `yaml:"scan_authenticated"`
	AuthenticatedOnlySenderDomains             []string `yaml:"authenticated_only_sender_domains"`
	SenderDomainAllowlistFile                  string   `yaml:"sender_domain_allowlist"`
	SenderDomainAllowlist                      []string `yaml:"-"`
	SenderDomainAllowlistRequireAuthentication bool     `yaml:"sender_domain_allowlist_require_authentication"`
}
type IPReputationConfig struct {
	RejectMessage          string   `yaml:"reject_message"`
	BlockDuration          Duration `yaml:"block_duration"`
	RepeatThreshold        int      `yaml:"repeat_threshold"`
	RepeatWindow           Duration `yaml:"repeat_window"`
	RepeatBlockDuration    Duration `yaml:"repeat_block_duration"`
	RepeatRefreshOnAttempt bool     `yaml:"repeat_refresh_on_attempt"`
	LegitimatePerStrike    int      `yaml:"legitimate_messages_per_strike"`
	MaxEntries             int      `yaml:"max_entries"`
	IPAllowlist            []string `yaml:"ip_allowlist"`
	DomainAllowlist        []string `yaml:"domain_allowlist"`
}
type LoggingConfig struct {
	Level              string `yaml:"level"`
	IncludeSubject     bool   `yaml:"include_subject"`
	IncludeAIInput     bool   `yaml:"include_ai_input"`
	IncludeConnections bool   `yaml:"include_connections"`
}

type CorrespondentsConfig struct {
	LearnAuthenticatedRecipients          bool     `yaml:"learn_authenticated_recipients"`
	LearnLegitimateSenders                bool     `yaml:"learn_legitimate_senders"`
	LegitimateSenderMinMessages           int      `yaml:"legitimate_sender_min_messages"`
	LegitimateSenderMinScore              float64  `yaml:"legitimate_sender_min_score"`
	LegitimateSenderRequireAuthentication bool     `yaml:"legitimate_sender_require_authentication"`
	UseAllowlist                          bool     `yaml:"use_allowlist"`
	Scope                                 string   `yaml:"scope"`
	RecipientMatch                        string   `yaml:"recipient_match"`
	BypassAI                              bool     `yaml:"bypass_ai"`
	RequireAuthenticationForBypass        bool     `yaml:"require_authentication_for_bypass"`
	TrustedAuthservIDs                    []string `yaml:"trusted_authserv_ids"`
	MaxEntries                            int      `yaml:"max_entries"`
	StaleAfter                            Duration `yaml:"stale_after"`
}

// Load applies defaults, strictly decodes one YAML file, and validates the
// complete configuration before returning it to the executable.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c := defaults()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("configuration file is empty")
		}
		return Config{}, err
	}
	var additionalDocument any
	if err := dec.Decode(&additionalDocument); err == nil {
		return Config{}, fmt.Errorf("configuration file must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("invalid trailing YAML content: %w", err)
	}
	if c.AI.APIKey == "" && c.AI.APIKeyEnv != "" {
		c.AI.APIKey = os.Getenv(c.AI.APIKeyEnv)
	}
	if c.Filtering.SenderDomainAllowlistFile != "" {
		domains, err := loadSenderDomainAllowlist(c.Filtering.SenderDomainAllowlistFile)
		if err != nil {
			var unavailable *senderDomainAllowlistUnavailableError
			if !errors.As(err, &unavailable) && !errors.Is(err, errSenderDomainAllowlistEmpty) {
				return Config{}, err
			}
			c.Warnings = append(c.Warnings, err.Error()+"; trusted sender domain bypass disabled")
		} else {
			c.Filtering.SenderDomainAllowlist = domains
		}
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	if c.EmailCommands.Enabled && c.EmailCommands.AllowAuthenticatedUsers && !c.EmailCommands.VerifySenderViaAliases {
		c.Warnings = append(c.Warnings, "email_commands allows ordinary authenticated users without alias verification; configure Postfix smtpd_sender_login_maps and reject_authenticated_sender_login_mismatch to enforce envelope-sender ownership")
	}
	return c, nil
}

func defaults() Config {
	return Config{
		Mode: "accept",
		Milter: MilterConfig{
			Socket: "tcp:127.0.0.1:8895", Timeout: Duration(time.Minute),
			ConnectionDNSTimeout: Duration(5 * time.Second), MaxMessageSize: 10 << 20, MaxConnections: 64,
			AllowedPeerIPs: []string{"127.0.0.0/8", "::1/128"},
		},
		Authentication: AuthenticationConfig{
			Mode: AuthenticationModeInternal, Timeout: Duration(10 * time.Second), MaxConcurrent: 8,
			TrustRequirement: AuthenticationTrustEither, MessageStorage: "hybrid", MemoryMessageLimit: 8,
		},
		AI: AIConfig{
			Endpoint: "https://openrouter.ai/api/v1/chat/completions", EndpointType: "openrouter",
			Model: "qwen/qwen3.6-35b-a3b", DisableThinking: true,
			PromptFile: "/etc/milterguard/detection-prompt.txt", Timeout: Duration(45 * time.Second),
			Retries: 2, MaxConcurrent: 8, MaxBodyChars: 50000,
			VisionMode: "fallback", VisionMinTextChars: 500,
			MaxImages: 2, MaxImageBytes: 2 << 20, MaxImagePixels: 12_000_000,
			SiteURL: "https://github.com/PhilAnderson1/MilterGuard", AppName: "MilterGuard",
		},
		Activity: ActivityConfig{Expiry: Duration(365 * 24 * time.Hour)},
		SenderBlocklist: SenderBlocklistConfig{
			Expiry: Duration(365 * 24 * time.Hour), MaxEntries: 10000, IncludeSubdomains: true,
			RejectMessage: "Message rejected by recipient sender blocklist",
		},
		Attachments: AttachmentsConfig{
			BlockExecutables: true, AddIPReputationStrike: false,
			BlockedExtensions: []string{"exe", "com", "scr", "pif", "bat", "cmd", "ps1", "vbs", "js", "jse", "msi", "dll", "jar", "lnk", "iso", "7z", "rar"},
			InspectSignatures: true, InspectArchives: true, MaxAttachmentBytes: 10 << 20,
			MaxArchiveDepth: 2, MaxArchiveFiles: 100, MaxArchiveUncompressedBytes: 50 << 20,
			EncryptedArchiveAction: "reject", UnscannableAction: "accept", InvalidMIMEAction: "reject",
			RejectMessage: "Message rejected because it contains a prohibited executable attachment",
		},
		EmailCommands: EmailCommandsConfig{
			Recipient: "milterguard@example.com", VerifySenderViaAliases: true, SendReplies: true,
			SMTPHost: "127.0.0.1:25", SMTPTLS: "opportunistic", MaxMessageBytes: 65536, AliasesFile: "/etc/aliases", Administrators: []string{},
		},
		Persistence: PersistenceConfig{
			DatabaseFile:    "/var/lib/milterguard/milterguard.db",
			CleanupInterval: Duration(10 * time.Minute),
		},
		RejectionHistory: RejectionHistoryConfig{
			Expiry: Duration(30 * 24 * time.Hour), MaxEntries: 100000, SaveMessages: true,
			MessageDirectory: "/var/lib/milterguard/rejected-mail", MessageMaxTotalBytes: 1 << 30,
		},
		Filtering: FilteringConfig{
			RejectScore: .5, LegitimateLowConfidenceScore: .8, AddEmailHeaders: true,
			AIErrorAction: "accept", RejectMessage: "Message rejected as suspected spam or fraud",
			AuthenticatedOnlySenderDomains:             []string{},
			SenderDomainAllowlistFile:                  "/etc/milterguard/trusted-sender-domains.txt",
			SenderDomainAllowlistRequireAuthentication: true,
		},
		IPReputation: IPReputationConfig{
			RejectMessage: "Message rejected because the sending IP address is blocked by this server",
			BlockDuration: Duration(time.Hour), RepeatThreshold: 3, RepeatWindow: Duration(30 * 24 * time.Hour),
			RepeatBlockDuration: Duration(30 * 24 * time.Hour), RepeatRefreshOnAttempt: true,
			LegitimatePerStrike: 1, MaxEntries: 10000,
			IPAllowlist: []string{"127.0.0.0/8", "::1/128"},
			DomainAllowlist: []string{
				"google.com", "outlook.com", "yahoo.com", "yahoo.net", "me.com", "icloud.com",
				"messagingengine.com", "protonmail.ch", "zoho.com", "zohomail.com", "gmx.net", "web.de",
			},
		},
		DomainRegistration: DomainRegistrationConfig{
			Enabled: true, Timeout: Duration(3 * time.Second), MaxEntries: 10000,
		},
		Correspondents: CorrespondentsConfig{
			LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true,
			LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .95, LegitimateSenderRequireAuthentication: true,
			UseAllowlist: true,
			Scope:        "per_sender", RecipientMatch: "all",
			BypassAI: true, RequireAuthenticationForBypass: true,
			TrustedAuthservIDs: []string{MTAHostnameAuthservID}, MaxEntries: 10000,
			StaleAfter: Duration(365 * 24 * time.Hour),
		},
		Logging: LoggingConfig{Level: "info", IncludeSubject: true},
	}
}

const maxSenderDomainAllowlistBytes = 1 << 20

var errSenderDomainAllowlistEmpty = errors.New("filtering.sender_domain_allowlist contains no domains")

type senderDomainAllowlistUnavailableError struct {
	path string
	err  error
}

func (e *senderDomainAllowlistUnavailableError) Error() string {
	return fmt.Sprintf("cannot read filtering.sender_domain_allowlist %s: %v", e.path, e.err)
}

func (e *senderDomainAllowlistUnavailableError) Unwrap() error { return e.err }

func loadSenderDomainAllowlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &senderDomainAllowlistUnavailableError{path: path, err: err}
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, maxSenderDomainAllowlistBytes+1))
	if err != nil {
		return nil, &senderDomainAllowlistUnavailableError{path: path, err: err}
	}
	if len(b) > maxSenderDomainAllowlistBytes {
		return nil, fmt.Errorf("filtering.sender_domain_allowlist exceeds 1 MiB")
	}
	domains := make([]string, 0)
	seen := make(map[string]bool)
	for index, raw := range strings.Split(string(b), "\n") {
		value := strings.TrimSpace(raw)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		value = strings.TrimSuffix(strings.ToLower(value), ".")
		if !validDomainName(value) {
			return nil, fmt.Errorf("invalid domain on line %d of filtering.sender_domain_allowlist: %q", index+1, value)
		}
		if !seen[value] {
			domains = append(domains, value)
			seen[value] = true
		}
	}
	if len(domains) == 0 {
		return nil, errSenderDomainAllowlistEmpty
	}
	return domains, nil
}

func validEmailAddress(value string) bool {
	value = strings.TrimSpace(value)
	normalized := mailaddr.Normalize(value)
	return normalized != "" && strings.EqualFold(value, normalized)
}

func validSMTPHost(value string) bool {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || strings.TrimSpace(host) == "" || strings.ContainsAny(host, " \t\r\n\x00") {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535
}

func validAttachmentAction(value string) bool {
	return value == "accept" || value == "reject" || value == "tempfail"
}

func validDomainName(value string) bool {
	value = netsafety.DNSHostname(value)
	if value == "" {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	return true
}

func (c Config) LogLevel() slog.Level {
	switch strings.ToLower(c.Logging.Level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
