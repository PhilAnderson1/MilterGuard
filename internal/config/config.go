package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const MTAHostnameAuthservID = "$mta_hostname"

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
	Mode             string                 `yaml:"mode"`
	Milter           MilterConfig           `yaml:"milter"`
	AI               AIConfig               `yaml:"ai"`
	Filtering        FilteringConfig        `yaml:"filtering"`
	Attachments      AttachmentsConfig      `yaml:"attachments"`
	EmailCommands    EmailCommandsConfig    `yaml:"email_commands"`
	Persistence      PersistenceConfig      `yaml:"persistence"`
	RejectionHistory RejectionHistoryConfig `yaml:"rejection_history"`
	RejectedMail     RejectedMailConfig     `yaml:"rejected_mail"`
	Correspondents   CorrespondentsConfig   `yaml:"correspondents"`
	IPReputation     IPReputationConfig     `yaml:"ip_reputation"`
	Logging          LoggingConfig          `yaml:"logging"`
	Warnings         []string               `yaml:"-"`
}

type PersistenceConfig struct {
	FlushInterval Duration `yaml:"flush_interval"`
}

type RejectionHistoryConfig struct {
	File       string   `yaml:"file"`
	Expiry     Duration `yaml:"expiry"`
	MaxEntries int      `yaml:"max_entries"`
}

type RejectedMailConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Directory     string   `yaml:"directory"`
	Retention     Duration `yaml:"retention"`
	MaxMessages   int      `yaml:"max_messages"`
	MaxTotalBytes int64    `yaml:"max_total_bytes"`
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
	MaxMessageBytes         int64    `yaml:"max_message_bytes"`
}

type AttachmentsConfig struct {
	BlockExecutables            bool     `yaml:"block_executables"`
	BlockedExtensions           []string `yaml:"blocked_extensions"`
	InspectSignatures           bool     `yaml:"inspect_file_signatures"`
	InspectArchives             bool     `yaml:"inspect_archives"`
	MaxAttachmentBytes          int64    `yaml:"max_attachment_bytes"`
	MaxArchiveDepth             int      `yaml:"archive_max_depth"`
	MaxArchiveFiles             int      `yaml:"archive_max_files"`
	MaxArchiveUncompressedBytes int64    `yaml:"archive_max_uncompressed_bytes"`
	EncryptedArchiveAction      string   `yaml:"encrypted_archive_action"`
	UnscannableAction           string   `yaml:"unscannable_action"`
	RejectMessage               string   `yaml:"reject_message"`
}
type MilterConfig struct {
	Socket               string   `yaml:"socket"`
	Timeout              Duration `yaml:"timeout"`
	ConnectionDNSTimeout Duration `yaml:"connection_dns_timeout"`
	MaxMessageSize       int64    `yaml:"max_message_size"`
}
type AIConfig struct {
	Endpoint           string   `yaml:"endpoint"`
	EndpointType       string   `yaml:"endpoint_type"`
	APIKey             string   `yaml:"api_key"`
	APIKeyEnv          string   `yaml:"api_key_env"`
	Model              string   `yaml:"model"`
	DisableThinking    bool     `yaml:"disable_thinking"`
	PromptFile         string   `yaml:"prompt_file"`
	Timeout            Duration `yaml:"timeout"`
	MaxConcurrent      int      `yaml:"max_concurrent"`
	MaxBodyChars       int      `yaml:"max_body_chars"`
	VisionMode         string   `yaml:"vision_mode"`
	VisionMinTextChars int      `yaml:"vision_min_text_chars"`
	MaxImages          int      `yaml:"max_images"`
	MaxImageBytes      int64    `yaml:"max_image_bytes"`
	MaxImagePixels     int64    `yaml:"max_image_pixels"`
	SiteURL            string   `yaml:"site_url"`
	AppName            string   `yaml:"app_name"`
}
type FilteringConfig struct {
	RejectScore                      float64  `yaml:"reject_score"`
	AddUnwantedHeaders               bool     `yaml:"add_unwanted_headers"`
	AIErrorAction                    string   `yaml:"ai_error_action"`
	RejectMessage                    string   `yaml:"reject_message"`
	ScanAuthenticated                bool     `yaml:"scan_authenticated"`
	SenderDomainAllowlistFile        string   `yaml:"sender_domain_allowlist"`
	SenderDomainAllowlist            []string `yaml:"-"`
	SenderDomainAllowlistRequireDKIM bool     `yaml:"sender_domain_allowlist_require_dkim"`
}
type IPReputationConfig struct {
	BlockDuration          Duration `yaml:"block_duration"`
	RepeatThreshold        int      `yaml:"repeat_threshold"`
	RepeatWindow           Duration `yaml:"repeat_window"`
	RepeatBlockDuration    Duration `yaml:"repeat_block_duration"`
	RepeatRefreshOnAttempt bool     `yaml:"repeat_refresh_on_attempt"`
	LegitimatePerStrike    int      `yaml:"legitimate_messages_per_strike"`
	MaxEntries             int      `yaml:"max_entries"`
	StateFile              string   `yaml:"state_file"`
	IPAllowlist            []string `yaml:"ip_allowlist"`
	DomainAllowlist        []string `yaml:"domain_allowlist"`
}
type LoggingConfig struct {
	Level          string `yaml:"level"`
	IncludeSubject bool   `yaml:"include_subject"`
	IncludeAIInput bool   `yaml:"include_ai_input"`
}

type CorrespondentsConfig struct {
	LearnAuthenticatedRecipients bool     `yaml:"learn_authenticated_recipients"`
	LearnLegitimateSenders       bool     `yaml:"learn_legitimate_senders"`
	LegitimateSenderMinMessages  int      `yaml:"legitimate_sender_min_messages"`
	LegitimateSenderMinScore     float64  `yaml:"legitimate_sender_min_score"`
	LegitimateSenderRequireDKIM  bool     `yaml:"legitimate_sender_require_dkim"`
	UseAllowlist                 bool     `yaml:"use_allowlist"`
	Scope                        string   `yaml:"scope"`
	RecipientMatch               string   `yaml:"recipient_match"`
	BypassAI                     bool     `yaml:"bypass_ai"`
	RequireDKIMForBypass         bool     `yaml:"require_dkim_for_bypass"`
	File                         string   `yaml:"file"`
	TrustedAuthservIDs           []string `yaml:"trusted_authserv_ids"`
	MaxEntries                   int      `yaml:"max_entries"`
	StaleAfter                   Duration `yaml:"stale_after"`
	ActivityUpdateInterval       Duration `yaml:"activity_update_interval"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	c := defaults()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
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
	return c, nil
}

func defaults() Config {
	return Config{
		Mode: "monitor",
		Milter: MilterConfig{
			Socket: "unix:/run/milterguard/milterguard.sock", Timeout: Duration(30 * time.Second),
			ConnectionDNSTimeout: Duration(2 * time.Second), MaxMessageSize: 10 << 20,
		},
		AI: AIConfig{
			Endpoint: "https://openrouter.ai/api/v1/chat/completions", EndpointType: "openrouter", Timeout: Duration(15 * time.Second),
			MaxConcurrent: 8,
			MaxBodyChars:  50000, VisionMode: "off", VisionMinTextChars: 200,
			MaxImages: 2, MaxImageBytes: 2 << 20, MaxImagePixels: 12_000_000, AppName: "MilterGuard",
		},
		Attachments: AttachmentsConfig{
			BlockedExtensions: []string{"exe", "com", "scr", "pif", "bat", "cmd", "ps1", "vbs", "js", "jse", "msi", "dll", "jar", "lnk", "iso", "7z", "rar"},
			InspectSignatures: true, InspectArchives: true, MaxAttachmentBytes: 10 << 20,
			MaxArchiveDepth: 2, MaxArchiveFiles: 100, MaxArchiveUncompressedBytes: 50 << 20,
			EncryptedArchiveAction: "reject", UnscannableAction: "accept",
			RejectMessage: "Message rejected because it contains a prohibited executable attachment",
		},
		EmailCommands: EmailCommandsConfig{
			Recipient: "milterguard@example.com", SendReplies: true,
			SMTPHost: "127.0.0.1:25", MaxMessageBytes: 8192, AliasesFile: "/etc/aliases",
		},
		Persistence: PersistenceConfig{FlushInterval: Duration(time.Minute)},
		RejectionHistory: RejectionHistoryConfig{
			File: "/var/lib/milterguard/rejection-history.json", Expiry: Duration(30 * 24 * time.Hour), MaxEntries: 10000,
		},
		RejectedMail: RejectedMailConfig{
			Directory: "/var/lib/milterguard/rejected-mail", Retention: Duration(30 * 24 * time.Hour),
			MaxMessages: 10000, MaxTotalBytes: 5 << 30,
		},
		Filtering: FilteringConfig{
			RejectScore: .95, AIErrorAction: "accept", RejectMessage: "Message rejected as suspected spam or fraud",
			ScanAuthenticated: true, SenderDomainAllowlistRequireDKIM: true,
		},
		IPReputation: IPReputationConfig{
			RepeatThreshold: 3, RepeatWindow: Duration(30 * 24 * time.Hour),
			RepeatBlockDuration: Duration(30 * 24 * time.Hour), RepeatRefreshOnAttempt: true,
			LegitimatePerStrike: 3, MaxEntries: 10000,
			StateFile: "/var/lib/milterguard/rejected-ip-state.json",
		},
		Correspondents: CorrespondentsConfig{
			LegitimateSenderMinMessages: 5, LegitimateSenderMinScore: .99, LegitimateSenderRequireDKIM: true,
			Scope: "per_sender", RecipientMatch: "all", File: "/var/lib/milterguard/correspondent-allowlist.json",
			TrustedAuthservIDs: []string{MTAHostnameAuthservID}, MaxEntries: 10000,
			StaleAfter: Duration(365 * 24 * time.Hour), ActivityUpdateInterval: Duration(24 * time.Hour),
		},
		Logging: LoggingConfig{Level: "info", IncludeSubject: true},
	}
}

func (c Config) Validate() error {
	if c.Mode != "monitor" && c.Mode != "tag" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be monitor, tag, or enforce")
	}
	if c.Milter.Socket == "" || c.Milter.MaxMessageSize < 1 {
		return fmt.Errorf("invalid milter settings")
	}
	if c.Milter.ConnectionDNSTimeout.Value() < 0 {
		return fmt.Errorf("milter.connection_dns_timeout must not be negative")
	}
	if c.Persistence.FlushInterval.Value() < 0 {
		return fmt.Errorf("persistence.flush_interval must not be negative")
	}
	if c.AI.Endpoint == "" || c.AI.Model == "" || c.AI.PromptFile == "" {
		return fmt.Errorf("ai endpoint, model, and prompt_file are required")
	}
	if c.AI.EndpointType != "openrouter" && c.AI.EndpointType != "llamacpp" && c.AI.EndpointType != "openai" {
		return fmt.Errorf("ai.endpoint_type must be openrouter, llamacpp, or openai")
	}
	if c.AI.APIKey == "" {
		return fmt.Errorf("ai api_key is empty (and api_key_env is unset or empty)")
	}
	if c.AI.Timeout.Value() <= 0 || c.AI.MaxConcurrent < 1 || c.AI.MaxBodyChars < 1 {
		return fmt.Errorf("invalid ai timeout, max_concurrent, or max_body_chars")
	}
	if c.AI.VisionMode != "off" && c.AI.VisionMode != "fallback" && c.AI.VisionMode != "always" {
		return fmt.Errorf("ai.vision_mode must be off, fallback, or always")
	}
	if c.AI.VisionMinTextChars < 0 || c.AI.MaxImages < 1 || c.AI.MaxImageBytes < 1 || c.AI.MaxImagePixels < 1 {
		return fmt.Errorf("invalid AI vision limits")
	}
	attachments := c.Attachments
	if attachments.BlockExecutables && len(attachments.BlockedExtensions) == 0 && !attachments.InspectSignatures {
		return fmt.Errorf("attachments requires blocked_extensions or inspect_file_signatures when block_executables is true")
	}
	if attachments.MaxAttachmentBytes < 1 || attachments.MaxAttachmentBytes > 64<<20 ||
		attachments.MaxArchiveDepth < 1 || attachments.MaxArchiveDepth > 8 ||
		attachments.MaxArchiveFiles < 1 || attachments.MaxArchiveFiles > 10_000 ||
		attachments.MaxArchiveUncompressedBytes < 1 || attachments.MaxArchiveUncompressedBytes > 1<<30 {
		return fmt.Errorf("invalid attachments limits")
	}
	for _, extension := range attachments.BlockedExtensions {
		extension = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(extension)), ".")
		if extension == "" {
			return fmt.Errorf("attachments.blocked_extensions contains an empty extension")
		}
		for _, char := range extension {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') {
				return fmt.Errorf("invalid attachments.blocked_extensions entry %q", extension)
			}
		}
	}
	if !validAttachmentAction(attachments.EncryptedArchiveAction) {
		return fmt.Errorf("attachments.encrypted_archive_action must be accept, reject, or tempfail")
	}
	if !validAttachmentAction(attachments.UnscannableAction) {
		return fmt.Errorf("attachments.unscannable_action must be accept, reject, or tempfail")
	}
	if strings.TrimSpace(attachments.RejectMessage) == "" {
		return fmt.Errorf("attachments.reject_message must not be empty")
	}
	commands := c.EmailCommands
	if commands.MaxMessageBytes < 1 || commands.MaxMessageBytes > 64<<10 {
		return fmt.Errorf("email_commands.max_message_bytes must be between 1 and 65536")
	}
	if commands.Enabled {
		if !validEmailAddress(commands.Recipient) {
			return fmt.Errorf("email_commands.recipient must be a valid email address")
		}
		if !commands.AllowAuthenticatedUsers && len(commands.Administrators) == 0 {
			return fmt.Errorf("email_commands requires an administrator or allow_authenticated_users")
		}
		if commands.SendReplies && !validSMTPHost(commands.SMTPHost) {
			return fmt.Errorf("email_commands.smtp_host must contain a valid host and port")
		}
		if !c.Correspondents.UseAllowlist || strings.TrimSpace(c.Correspondents.File) == "" {
			return fmt.Errorf("email_commands requires correspondents.use_allowlist and correspondents.file")
		}
		if commands.AllowAuthenticatedUsers && commands.VerifySenderViaAliases && !strings.HasPrefix(commands.AliasesFile, "/") {
			return fmt.Errorf("email_commands.aliases_file must be an absolute path")
		}
	}
	for _, identity := range commands.Administrators {
		if strings.TrimSpace(identity) == "" || len(identity) > 1024 || strings.ContainsAny(identity, "\r\n\x00") {
			return fmt.Errorf("email_commands.administrators contains an invalid identity")
		}
	}
	if c.RejectionHistory.Expiry.Value() < 0 {
		return fmt.Errorf("rejection_history.expiry must not be negative")
	}
	if c.RejectionHistory.Expiry.Value() > 0 {
		if strings.TrimSpace(c.RejectionHistory.File) == "" {
			return fmt.Errorf("rejection_history.file is required when rejection history is enabled")
		}
		if c.RejectionHistory.MaxEntries < 1 {
			return fmt.Errorf("rejection_history.max_entries must be positive")
		}
	}
	if c.RejectedMail.Enabled {
		if !filepath.IsAbs(c.RejectedMail.Directory) {
			return fmt.Errorf("rejected_mail.directory must be an absolute path")
		}
		if c.RejectedMail.Retention.Value() <= 0 {
			return fmt.Errorf("rejected_mail.retention must be positive")
		}
		if c.RejectedMail.MaxMessages < 1 {
			return fmt.Errorf("rejected_mail.max_messages must be positive")
		}
		if c.RejectedMail.MaxTotalBytes < c.Milter.MaxMessageSize {
			return fmt.Errorf("rejected_mail.max_total_bytes must be at least milter.max_message_size")
		}
	}
	if c.Filtering.RejectScore < 0 || c.Filtering.RejectScore > 1 {
		return fmt.Errorf("filtering.reject_score must be between 0 and 1")
	}
	if c.Filtering.AIErrorAction != "accept" && c.Filtering.AIErrorAction != "tempfail" {
		return fmt.Errorf("filtering.ai_error_action must be accept or tempfail")
	}
	if c.Filtering.SenderDomainAllowlistFile != "" && !filepath.IsAbs(c.Filtering.SenderDomainAllowlistFile) {
		return fmt.Errorf("filtering.sender_domain_allowlist must be an absolute path")
	}
	for _, domain := range c.Filtering.SenderDomainAllowlist {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid filtering.sender_domain_allowlist entry %q", domain)
		}
	}
	if len(c.Filtering.SenderDomainAllowlist) > 0 && c.Filtering.SenderDomainAllowlistRequireDKIM && len(c.Correspondents.TrustedAuthservIDs) == 0 {
		return fmt.Errorf("filtering.sender_domain_allowlist_require_dkim requires correspondents.trusted_authserv_ids")
	}
	reputation := c.IPReputation
	if reputation.BlockDuration.Value() < 0 {
		return fmt.Errorf("ip_reputation.block_duration must not be negative")
	}
	if reputation.RepeatThreshold < 0 {
		return fmt.Errorf("ip_reputation.repeat_threshold must not be negative")
	}
	if reputation.RepeatWindow.Value() < 0 {
		return fmt.Errorf("ip_reputation.repeat_window must not be negative")
	}
	if reputation.RepeatBlockDuration.Value() < 0 {
		return fmt.Errorf("ip_reputation.repeat_block_duration must not be negative")
	}
	if reputation.LegitimatePerStrike < 0 {
		return fmt.Errorf("ip_reputation.legitimate_messages_per_strike must not be negative")
	}
	if reputation.RepeatThreshold > 0 && (reputation.RepeatWindow.Value() == 0 || reputation.RepeatBlockDuration.Value() == 0) {
		return fmt.Errorf("ip_reputation.repeat_window and repeat_block_duration must be positive when repeat escalation is enabled")
	}
	if (reputation.BlockDuration.Value() > 0 || reputation.RepeatThreshold > 0) && strings.TrimSpace(reputation.StateFile) == "" {
		return fmt.Errorf("ip_reputation.state_file is required when IP blocking is enabled")
	}
	if reputation.MaxEntries < 1 {
		return fmt.Errorf("ip_reputation.max_entries must be positive")
	}
	for _, entry := range reputation.IPAllowlist {
		if _, err := netip.ParsePrefix(entry); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			return fmt.Errorf("invalid ip_reputation.ip_allowlist entry %q", entry)
		}
	}
	for _, domain := range reputation.DomainAllowlist {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid ip_reputation.domain_allowlist entry %q", domain)
		}
	}
	allowlist := c.Correspondents
	if allowlist.Scope != "global" && allowlist.Scope != "per_sender" {
		return fmt.Errorf("correspondents.scope must be global or per_sender")
	}
	if allowlist.RecipientMatch != "all" && allowlist.RecipientMatch != "any" {
		return fmt.Errorf("correspondents.recipient_match must be all or any")
	}
	if allowlist.MaxEntries < 1 {
		return fmt.Errorf("correspondents.max_entries must be positive")
	}
	if allowlist.LegitimateSenderMinMessages < 1 {
		return fmt.Errorf("correspondents.legitimate_sender_min_messages must be positive")
	}
	if allowlist.LegitimateSenderMinScore < 0 || allowlist.LegitimateSenderMinScore > 1 {
		return fmt.Errorf("correspondents.legitimate_sender_min_score must be between 0 and 1")
	}
	if allowlist.StaleAfter.Value() < 0 {
		return fmt.Errorf("correspondents.stale_after must not be negative")
	}
	if allowlist.ActivityUpdateInterval.Value() < 0 {
		return fmt.Errorf("correspondents.activity_update_interval must not be negative")
	}
	if (allowlist.LearnAuthenticatedRecipients || allowlist.UseAllowlist) && strings.TrimSpace(allowlist.File) == "" {
		return fmt.Errorf("correspondents.file is required when the feature is enabled")
	}
	if allowlist.BypassAI && !allowlist.UseAllowlist {
		return fmt.Errorf("correspondents.bypass_ai requires use_allowlist")
	}
	if allowlist.BypassAI && allowlist.RequireDKIMForBypass && len(allowlist.TrustedAuthservIDs) == 0 {
		return fmt.Errorf("correspondents.require_dkim_for_bypass requires trusted_authserv_ids")
	}
	for _, authservID := range allowlist.TrustedAuthservIDs {
		if authservID != MTAHostnameAuthservID && !validDomainName(authservID) {
			return fmt.Errorf("invalid correspondents.trusted_authserv_ids entry %q", authservID)
		}
	}
	return nil
}

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
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, &senderDomainAllowlistUnavailableError{path: path, err: err}
	}
	if len(b) > 1<<20 {
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
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	return err == nil && address.Address == strings.TrimSpace(value) && strings.Contains(address.Address, "@")
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
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
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
