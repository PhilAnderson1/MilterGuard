package config

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

// Validate rejects unsafe, contradictory, or incomplete settings that cannot
// be handled reliably at runtime.
func (c Config) Validate() error {
	if err := validateGeneral(c); err != nil {
		return err
	}
	if err := validateMilter(c.Milter); err != nil {
		return err
	}
	if err := validateAuthentication(c.Authentication); err != nil {
		return err
	}
	if err := validatePersistence(c.Persistence); err != nil {
		return err
	}
	if err := validateDomainRegistration(c.DomainRegistration); err != nil {
		return err
	}
	if err := validateAI(c.AI); err != nil {
		return err
	}
	if err := validateActivity(c.Activity); err != nil {
		return err
	}
	if err := validateAttachments(c.Attachments); err != nil {
		return err
	}
	if err := validateEmailCommands(c.EmailCommands); err != nil {
		return err
	}
	if err := validateRejectionHistory(c.RejectionHistory); err != nil {
		return err
	}
	if err := validateFiltering(c.Filtering); err != nil {
		return err
	}
	if err := validateIPReputation(c.IPReputation); err != nil {
		return err
	}
	if err := validateCorrespondents(c.Correspondents); err != nil {
		return err
	}
	return validateCrossRules(c)
}

func validateGeneral(c Config) error {
	if c.Mode != "accept" && c.Mode != "enforce" {
		return fmt.Errorf("mode must be accept or enforce")
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}
}

func validateMilter(c MilterConfig) error {
	listener, err := ParseMilterSocket(c.Socket)
	if err != nil {
		return err
	}
	if c.MaxMessageSize < 1 || c.MaxMessageSize > maxMilterMessageSize {
		return fmt.Errorf("milter.max_message_size must be between 1 and %d bytes", maxMilterMessageSize)
	}
	if c.Timeout.Value() <= 0 {
		return fmt.Errorf("milter.timeout must be positive")
	}
	if c.ConnectionDNSTimeout.Value() < 0 {
		return fmt.Errorf("milter.connection_dns_timeout must not be negative")
	}
	if c.MaxConnections < 1 {
		return fmt.Errorf("milter.max_connections must be positive")
	}
	if listener.Network == "tcp" && len(c.AllowedPeerIPs) == 0 {
		return fmt.Errorf("milter.allowed_peer_ips must contain at least one address for a TCP listener")
	}
	for _, entry := range c.AllowedPeerIPs {
		if _, err := netsafety.ParseIPPrefix(entry); err != nil {
			return fmt.Errorf("invalid milter.allowed_peer_ips entry %q: %w", entry, err)
		}
	}
	return nil
}

func validateAuthentication(c AuthenticationConfig) error {
	if c.Mode != AuthenticationModeTrustedHeaders && c.Mode != AuthenticationModeInternal {
		return fmt.Errorf("authentication.mode must be trusted_headers or internal")
	}
	switch c.TrustRequirement {
	case AuthenticationTrustDKIM, AuthenticationTrustSPF, AuthenticationTrustEither, AuthenticationTrustBoth:
	default:
		return fmt.Errorf("authentication.trust_requirement must be dkim, spf, either, or both")
	}
	if c.Timeout.Value() <= 0 {
		return fmt.Errorf("authentication.timeout must be positive")
	}
	if c.MaxConcurrent < 1 {
		return fmt.Errorf("authentication.max_concurrent must be positive")
	}
	if c.MessageStorage != "memory" && c.MessageStorage != "file" && c.MessageStorage != "hybrid" {
		return fmt.Errorf("authentication.message_storage must be memory, file, or hybrid")
	}
	if c.MemoryMessageLimit < 1 {
		return fmt.Errorf("authentication.memory_message_limit must be positive")
	}
	return nil
}

func validatePersistence(c PersistenceConfig) error {
	if c.CleanupInterval.Value() < time.Minute {
		return fmt.Errorf("persistence.cleanup_interval must be at least 1m")
	}
	if strings.TrimSpace(c.DatabaseFile) == "" {
		return fmt.Errorf("persistence.database_file is required")
	}
	return nil
}

func validateDomainRegistration(c DomainRegistrationConfig) error {
	if c.Enabled && (c.Timeout.Value() <= 0 || c.MaxEntries < 1) {
		return fmt.Errorf("domain_registration requires a positive timeout and max_entries")
	}
	return nil
}

func validateAI(c AIConfig) error {
	if c.Endpoint == "" || c.Model == "" || c.PromptFile == "" {
		return fmt.Errorf("ai endpoint, model, and prompt_file are required")
	}
	if c.EndpointType != "openrouter" && c.EndpointType != "llamacpp" && c.EndpointType != "openai" {
		return fmt.Errorf("ai.endpoint_type must be openrouter, llamacpp, or openai")
	}
	if c.APIKey == "" {
		return fmt.Errorf("ai api_key is empty (and api_key_env is unset or empty)")
	}
	if c.Timeout.Value() <= 0 || c.MaxConcurrent < 1 || c.MaxBodyChars < 1 {
		return fmt.Errorf("invalid ai timeout, max_concurrent, or max_body_chars")
	}
	if c.Retries < 0 || c.Retries > 10 {
		return fmt.Errorf("ai.retries must be between 0 and 10")
	}
	if math.IsNaN(c.InputCostPerMillionTokens) || math.IsInf(c.InputCostPerMillionTokens, 0) || c.InputCostPerMillionTokens < 0 ||
		math.IsNaN(c.OutputCostPerMillionTokens) || math.IsInf(c.OutputCostPerMillionTokens, 0) || c.OutputCostPerMillionTokens < 0 {
		return fmt.Errorf("ai token prices must be finite and nonnegative")
	}
	if c.VisionMode != "off" && c.VisionMode != "fallback" && c.VisionMode != "always" {
		return fmt.Errorf("ai.vision_mode must be off, fallback, or always")
	}
	if c.VisionMinTextChars < 0 || c.MaxImages < 1 || c.MaxImageBytes < 1 || c.MaxImagePixels < 1 {
		return fmt.Errorf("invalid AI vision limits")
	}
	return nil
}

func validateActivity(c ActivityConfig) error {
	if c.Expiry.Value() <= 0 {
		return fmt.Errorf("activity.expiry must be positive")
	}
	return nil
}

func validateAttachments(c AttachmentsConfig) error {
	if c.BlockExecutables && len(c.BlockedExtensions) == 0 && !c.InspectSignatures {
		return fmt.Errorf("attachments requires blocked_extensions or inspect_file_signatures when block_executables is true")
	}
	if c.MaxAttachmentBytes < 1 || c.MaxAttachmentBytes > 64<<20 ||
		c.MaxArchiveDepth < 1 || c.MaxArchiveDepth > 8 ||
		c.MaxArchiveFiles < 1 || c.MaxArchiveFiles > 10_000 ||
		c.MaxArchiveUncompressedBytes < 1 || c.MaxArchiveUncompressedBytes > 1<<30 {
		return fmt.Errorf("invalid attachments limits")
	}
	for _, extension := range c.BlockedExtensions {
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
	if !validAttachmentAction(c.EncryptedArchiveAction) {
		return fmt.Errorf("attachments.encrypted_archive_action must be accept, reject, or tempfail")
	}
	if !validAttachmentAction(c.UnscannableAction) {
		return fmt.Errorf("attachments.unscannable_action must be accept, reject, or tempfail")
	}
	if c.InvalidMIMEAction != "accept" && c.InvalidMIMEAction != "reject" {
		return fmt.Errorf("attachments.invalid_mime_action must be accept or reject")
	}
	if strings.TrimSpace(c.RejectMessage) == "" {
		return fmt.Errorf("attachments.reject_message must not be empty")
	}
	return nil
}

func validateEmailCommands(c EmailCommandsConfig) error {
	if c.MaxMessageBytes < 1 || c.MaxMessageBytes > 64<<10 {
		return fmt.Errorf("email_commands.max_message_bytes must be between 1 and 65536")
	}
	if c.SMTPTLS != "off" && c.SMTPTLS != "opportunistic" && c.SMTPTLS != "required" {
		return fmt.Errorf("email_commands.smtp_tls must be off, opportunistic, or required")
	}
	if c.Enabled {
		if !validEmailAddress(c.Recipient) {
			return fmt.Errorf("email_commands.recipient must be a valid email address")
		}
		if !c.AllowAuthenticatedUsers && len(c.Administrators) == 0 {
			return fmt.Errorf("email_commands requires an administrator or allow_authenticated_users")
		}
		if c.SendReplies && !validSMTPHost(c.SMTPHost) {
			return fmt.Errorf("email_commands.smtp_host must contain a valid host and port")
		}
		if c.AllowAuthenticatedUsers && c.VerifySenderViaAliases && !strings.HasPrefix(c.AliasesFile, "/") {
			return fmt.Errorf("email_commands.aliases_file must be an absolute path")
		}
	}
	for _, identity := range c.Administrators {
		if strings.TrimSpace(identity) == "" || len(identity) > 1024 || strings.ContainsAny(identity, "\r\n\x00") {
			return fmt.Errorf("email_commands.administrators contains an invalid identity")
		}
	}
	return nil
}

func validateRejectionHistory(c RejectionHistoryConfig) error {
	if c.Expiry.Value() < 0 {
		return fmt.Errorf("rejection_history.expiry must not be negative")
	}
	if c.Expiry.Value() > 0 && c.MaxEntries < 1 {
		return fmt.Errorf("rejection_history.max_entries must be positive")
	}
	if c.SaveMessages {
		if c.Expiry.Value() <= 0 {
			return fmt.Errorf("rejection_history.expiry must be positive when save_messages is enabled")
		}
		if !filepath.IsAbs(c.MessageDirectory) {
			return fmt.Errorf("rejection_history.message_directory must be an absolute path")
		}
	}
	return nil
}

func validateFiltering(c FilteringConfig) error {
	if c.RejectScore < 0.5 || c.RejectScore > 1 {
		return fmt.Errorf("filtering.reject_score must be between 0.5 and 1")
	}
	if c.LegitimateLowConfidenceScore < 0.5 || c.LegitimateLowConfidenceScore > 1 {
		return fmt.Errorf("filtering.legitimate_low_confidence_score must be between 0.5 and 1")
	}
	if strings.TrimSpace(c.RejectMessage) == "" {
		return fmt.Errorf("filtering.reject_message must not be empty")
	}
	if c.AIErrorAction != "accept" && c.AIErrorAction != "tempfail" {
		return fmt.Errorf("filtering.ai_error_action must be accept or tempfail")
	}
	for _, domain := range c.AuthenticatedOnlySenderDomains {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid filtering.authenticated_only_sender_domains entry %q", domain)
		}
	}
	if c.SenderDomainAllowlistFile != "" && !filepath.IsAbs(c.SenderDomainAllowlistFile) {
		return fmt.Errorf("filtering.sender_domain_allowlist must be an absolute path")
	}
	for _, domain := range c.SenderDomainAllowlist {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid filtering.sender_domain_allowlist entry %q", domain)
		}
	}
	return nil
}

func validateIPReputation(c IPReputationConfig) error {
	if strings.TrimSpace(c.RejectMessage) == "" {
		return fmt.Errorf("ip_reputation.reject_message must not be empty")
	}
	if c.BlockDuration.Value() < 0 {
		return fmt.Errorf("ip_reputation.block_duration must not be negative")
	}
	if c.RepeatThreshold < 0 {
		return fmt.Errorf("ip_reputation.repeat_threshold must not be negative")
	}
	if c.RepeatWindow.Value() < 0 {
		return fmt.Errorf("ip_reputation.repeat_window must not be negative")
	}
	if c.RepeatBlockDuration.Value() < 0 {
		return fmt.Errorf("ip_reputation.repeat_block_duration must not be negative")
	}
	if c.LegitimatePerStrike < 0 {
		return fmt.Errorf("ip_reputation.legitimate_messages_per_strike must not be negative")
	}
	if c.RepeatThreshold > 0 && (c.RepeatWindow.Value() == 0 || c.RepeatBlockDuration.Value() == 0) {
		return fmt.Errorf("ip_reputation.repeat_window and repeat_block_duration must be positive when repeat escalation is enabled")
	}
	if c.MaxEntries < 1 {
		return fmt.Errorf("ip_reputation.max_entries must be positive")
	}
	for _, entry := range c.IPAllowlist {
		if _, err := netsafety.ParseIPPrefix(entry); err != nil {
			return fmt.Errorf("invalid ip_reputation.ip_allowlist entry %q: %w", entry, err)
		}
	}
	for _, domain := range c.DomainAllowlist {
		if !validDomainName(domain) {
			return fmt.Errorf("invalid ip_reputation.domain_allowlist entry %q", domain)
		}
	}
	return nil
}

func validateCorrespondents(c CorrespondentsConfig) error {
	if c.Scope != "global" && c.Scope != "per_sender" {
		return fmt.Errorf("correspondents.scope must be global or per_sender")
	}
	if c.RecipientMatch != "all" && c.RecipientMatch != "any" {
		return fmt.Errorf("correspondents.recipient_match must be all or any")
	}
	if c.MaxEntries < 1 {
		return fmt.Errorf("correspondents.max_entries must be positive")
	}
	if c.LegitimateSenderMinMessages < 1 {
		return fmt.Errorf("correspondents.legitimate_sender_min_messages must be positive")
	}
	if c.LegitimateSenderMinScore < 0 || c.LegitimateSenderMinScore > 1 {
		return fmt.Errorf("correspondents.legitimate_sender_min_score must be between 0 and 1")
	}
	if c.StaleAfter.Value() < 0 {
		return fmt.Errorf("correspondents.stale_after must not be negative")
	}
	if c.BypassAI && !c.UseAllowlist {
		return fmt.Errorf("correspondents.bypass_ai requires use_allowlist")
	}
	for _, authservID := range c.TrustedAuthservIDs {
		if authservID != MTAHostnameAuthservID && !validDomainName(authservID) {
			return fmt.Errorf("invalid correspondents.trusted_authserv_ids entry %q", authservID)
		}
	}
	return nil
}

func validateCrossRules(c Config) error {
	if c.EmailCommands.Enabled && !c.Correspondents.UseAllowlist {
		return fmt.Errorf("email_commands requires correspondents.use_allowlist")
	}
	if c.RejectionHistory.SaveMessages && c.RejectionHistory.MessageMaxTotalBytes < c.Milter.MaxMessageSize {
		return fmt.Errorf("rejection_history.message_max_total_bytes must be at least milter.max_message_size")
	}
	trustedHeaders := c.Authentication.Mode == AuthenticationModeTrustedHeaders
	trustedIDsMissing := len(c.Correspondents.TrustedAuthservIDs) == 0
	if trustedHeaders && len(c.Filtering.SenderDomainAllowlist) > 0 && c.Filtering.SenderDomainAllowlistRequireAuthentication && trustedIDsMissing {
		return fmt.Errorf("filtering.sender_domain_allowlist_require_authentication requires correspondents.trusted_authserv_ids")
	}
	if trustedHeaders && c.Correspondents.BypassAI && c.Correspondents.RequireAuthenticationForBypass && trustedIDsMissing {
		return fmt.Errorf("correspondents.require_authentication_for_bypass requires trusted_authserv_ids")
	}
	if trustedHeaders && c.Correspondents.LearnLegitimateSenders && c.Correspondents.LegitimateSenderRequireAuthentication && trustedIDsMissing {
		return fmt.Errorf("correspondents.legitimate_sender_require_authentication requires trusted_authserv_ids when legitimate sender learning is enabled")
	}
	return nil
}
