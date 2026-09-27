// Command authcorpus compares saved Authentication-Results with MilterGuard's
// internal Mox verifier for a directory tree of RFC messages.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth/moxverify"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

var (
	receivedAddressPattern = regexp.MustCompile(`(?i)\[(?:IPv6:)?([0-9a-f:.]+)\]`)
	receivedFromPattern    = regexp.MustCompile(`(?i)(?:^|\s)from\s+([^\s(]+)`)
	receivedByPattern      = regexp.MustCompile(`(?i)\sby\s+([^\s(;]+)`)
	receivedSPFReceiver    = regexp.MustCompile(`(?i)\breceiver\s*=\s*([^\s;]+)`)
)

type methodResult struct {
	Present         bool     `json:"present"`
	Outcome         string   `json:"outcome"`
	Domains         []string `json:"domains,omitempty"`
	PassDomains     []string `json:"pass_domains,omitempty"`
	SPFMechanisms   []string `json:"spf_mechanisms,omitempty"`
	ErrorCategories []string `json:"error_categories,omitempty"`
	Reasons         []string `json:"reasons,omitempty"`
	Aligned         bool     `json:"aligned,omitempty"`
}

type methodComparison struct {
	Saved        methodResult `json:"saved"`
	Internal     methodResult `json:"internal"`
	Compared     bool         `json:"compared"`
	OutcomeMatch bool         `json:"outcome_match"`
	DetailsMatch bool         `json:"details_match"`
}

type record struct {
	File               string                               `json:"file"`
	Category           string                               `json:"category"`
	MetadataComplete   bool                                 `json:"metadata_complete"`
	MissingMetadata    []string                             `json:"missing_metadata,omitempty"`
	SavedResultHeaders int                                  `json:"saved_result_headers"`
	Methods            map[mailauth.Method]methodComparison `json:"methods,omitempty"`
	Differences        []string                             `json:"differences,omitempty"`
	DetailDifferences  []string                             `json:"detail_differences,omitempty"`
	DurationMS         int64                                `json:"duration_ms"`
	Error              string                               `json:"error,omitempty"`
}

type reportSummary struct {
	Messages                int                       `json:"messages"`
	Compared                int                       `json:"compared"`
	MetadataIncomplete      int                       `json:"metadata_incomplete"`
	Errors                  int                       `json:"errors"`
	MessagesDifferent       int                       `json:"messages_different"`
	MessagesDetailDifferent int                       `json:"messages_detail_different"`
	MethodComparisons       map[mailauth.Method]int   `json:"method_comparisons"`
	MethodDifferences       map[mailauth.Method]int   `json:"method_differences"`
	MethodDetailDifferences map[mailauth.Method]int   `json:"method_detail_differences"`
	Categories              map[string]categoryCounts `json:"categories"`
}

type categoryCounts struct {
	Messages  int `json:"messages"`
	Different int `json:"different"`
	Errors    int `json:"errors"`
}

type report struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Corpus      string        `json:"corpus"`
	ReceiverIP  string        `json:"receiver_ip"`
	Storage     string        `json:"message_storage"`
	Records     []record      `json:"records"`
	Summary     reportSummary `json:"summary"`
}

type parsedMessage struct {
	raw                   []byte
	remoteIP              netip.Addr
	helo                  string
	envelopeSender        string
	receiverHostname      string
	visibleFromDomain     string
	smtpUTF8              bool
	authenticationResults []string
	receivedSPF           []string
	trustedAuthservIDs    []string
	missing               []string
}

func main() {
	directory := flag.String("directory", "", "directory tree containing .eml files")
	output := flag.String("output", "", "JSON report path (default stdout)")
	timeout := flag.Duration("timeout", 20*time.Second, "whole-operation timeout per message")
	maxConcurrent := flag.Int("max-concurrent", 8, "maximum simultaneous verification operations")
	receiverIPText := flag.String("receiver-ip", "127.0.0.1", "receiving SMTP interface IP used for SPF macros")
	storage := flag.String("message-storage", "memory", "exact-message storage: memory or file")
	flag.Parse()
	if *directory == "" {
		fatalf("-directory is required")
	}
	receiverIP, err := netip.ParseAddr(*receiverIPText)
	if err != nil {
		fatalf("invalid -receiver-ip: %v", err)
	}
	if *storage != "memory" && *storage != "file" {
		fatalf("invalid -message-storage: must be memory or file")
	}
	files, err := messageFiles(*directory)
	if err != nil {
		fatalf("enumerate corpus: %v", err)
	}
	if len(files) == 0 {
		fatalf("no .eml files found under %s", *directory)
	}
	verifier, err := moxverify.New(moxverify.Options{
		Timeout: *timeout, MaxConcurrent: *maxConcurrent, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		fatalf("create verifier: %v", err)
	}

	records := make([]record, len(files))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(*maxConcurrent, len(files)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				records[index] = compareFile(context.Background(), *directory, files[index], receiverIP, *storage, verifier)
			}
		}()
	}
	for index := range files {
		jobs <- index
	}
	close(jobs)
	workers.Wait()

	report := report{
		GeneratedAt: time.Now().UTC(), Corpus: *directory, ReceiverIP: receiverIP.String(), Storage: *storage, Records: records,
		Summary: summarize(records),
	}
	writer := io.Writer(os.Stdout)
	var file *os.File
	if *output != "" {
		file, err = os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			fatalf("create report: %v", err)
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fatalf("write report: %v", err)
	}
	if *output != "" {
		fmt.Fprintf(os.Stderr, "wrote %s: %d messages, %d different, %d errors, %d with incomplete metadata\n",
			*output, report.Summary.Messages, report.Summary.MessagesDifferent, report.Summary.Errors, report.Summary.MetadataIncomplete)
	}
}

func compareFile(ctx context.Context, root, path string, receiverIP netip.Addr, storage string, verifier mailauth.Verifier) record {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		relative = filepath.Base(path)
	}
	record := record{File: filepath.ToSlash(relative), Category: filepath.Base(filepath.Dir(path))}
	parsed, err := parseMessage(path)
	if err != nil {
		record.Error = err.Error()
		return record
	}
	record.MissingMetadata = parsed.missing
	record.MetadataComplete = len(parsed.missing) == 0
	record.SavedResultHeaders = len(parsed.authenticationResults) + len(parsed.receivedSPF)
	exact, err := mailauth.NewExactMessage(storage, int64(len(parsed.raw)))
	if err != nil {
		record.Error = err.Error()
		return record
	}
	defer exact.Close()
	if err := exact.AddBody(parsed.raw); err != nil {
		record.Error = err.Error()
		return record
	}
	reader, size, err := exact.ReaderAt()
	if err != nil {
		record.Error = err.Error()
		return record
	}
	transaction := mailauth.Transaction{
		RemoteIP: parsed.remoteIP, HELO: parsed.helo, EnvelopeSender: parsed.envelopeSender,
		ReceiverHostname: parsed.receiverHostname, ReceiverIP: receiverIP,
		VisibleFromDomain: parsed.visibleFromDomain, SMTPUTF8: parsed.smtpUTF8,
		Message: reader, MessageSize: size,
	}
	savedTransaction := transaction
	savedTransaction.AuthenticationResults = parsed.authenticationResults
	savedTransaction.ReceivedSPF = parsed.receivedSPF
	savedTransaction.TrustedAuthservIDs = parsed.trustedAuthservIDs
	saved, _ := (mailauth.HeaderVerifier{}).Verify(ctx, savedTransaction)
	started := time.Now()
	internal, verifyErr := verifier.Verify(ctx, transaction)
	record.DurationMS = time.Since(started).Milliseconds()
	if verifyErr != nil {
		record.Error = verifyErr.Error()
	}
	record.Methods = make(map[mailauth.Method]methodComparison)
	for _, method := range []mailauth.Method{mailauth.MethodSPF, mailauth.MethodDKIM, mailauth.MethodDMARC} {
		savedResult := summarizeMethod(saved, method)
		internalResult := summarizeMethod(internal, method)
		compared := savedResult.Present
		outcomeMatch := !compared || savedResult.Outcome == internalResult.Outcome && savedResult.Aligned == internalResult.Aligned
		detailsMatch := outcomeMatch
		if compared && outcomeMatch && savedResult.Outcome == string(mailauth.OutcomePass) && len(savedResult.PassDomains) > 0 {
			detailsMatch = slices.Equal(savedResult.PassDomains, internalResult.PassDomains)
		}
		record.Methods[method] = methodComparison{
			Saved: savedResult, Internal: internalResult, Compared: compared,
			OutcomeMatch: outcomeMatch, DetailsMatch: detailsMatch,
		}
		if compared && !outcomeMatch {
			record.Differences = append(record.Differences, string(method))
		} else if compared && !detailsMatch {
			record.DetailDifferences = append(record.DetailDifferences, string(method))
		}
	}
	return record
}

func parseMessage(path string) (parsedMessage, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return parsedMessage{}, err
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return parsedMessage{}, fmt.Errorf("parse message: %w", err)
	}
	parsed := parsedMessage{
		raw:                   raw,
		authenticationResults: append([]string(nil), message.Header["Authentication-Results"]...),
		receivedSPF:           append([]string(nil), message.Header["Received-Spf"]...),
	}
	parsed.remoteIP, parsed.helo, parsed.receiverHostname = receivedMetadata(message.Header["Received"])
	parsed.envelopeSender = envelopeSender(message.Header.Get("Return-Path"))
	if from := message.Header["From"]; len(from) == 1 {
		parsed.visibleFromDomain = mailaddr.Domain(from[0])
	}
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = len(raw)
	}
	parsed.smtpUTF8 = containsNonASCII([]byte(parsed.envelopeSender)) || containsNonASCII(raw[:headerEnd])
	parsed.trustedAuthservIDs = referenceAuthservIDs(parsed.authenticationResults, parsed.receivedSPF)
	if !parsed.remoteIP.IsValid() {
		parsed.missing = append(parsed.missing, "remote_ip")
	}
	if parsed.helo == "" {
		parsed.missing = append(parsed.missing, "helo")
	}
	if parsed.envelopeSender == "" && message.Header.Get("Return-Path") == "" {
		parsed.missing = append(parsed.missing, "envelope_sender")
	}
	if parsed.receiverHostname == "" {
		parsed.missing = append(parsed.missing, "receiver_hostname")
	}
	if len(message.Header["From"]) != 1 || parsed.visibleFromDomain == "" {
		parsed.missing = append(parsed.missing, "visible_from")
	}
	return parsed, nil
}

func receivedMetadata(headers []string) (remoteIP netip.Addr, helo, receiverHostname string) {
	if len(headers) > 0 {
		if match := receivedByPattern.FindStringSubmatch(headers[0]); len(match) == 2 {
			receiverHostname = netsafety.DNSHostname(match[1])
		}
	}
	for _, header := range headers {
		fromClause := receivedByPattern.Split(header, 2)[0]
		for _, match := range receivedAddressPattern.FindAllStringSubmatch(fromClause, -1) {
			address, err := netip.ParseAddr(match[1])
			if err == nil && netsafety.AddressRoutable(address) {
				remoteIP = netsafety.CanonicalIP(address)
				if from := receivedFromPattern.FindStringSubmatch(fromClause); len(from) == 2 {
					helo = strings.Trim(from[1], "[]")
				}
				return remoteIP, helo, receiverHostname
			}
		}
	}
	return remoteIP, helo, receiverHostname
}

func envelopeSender(value string) string {
	value = strings.TrimSpace(value)
	if value == "<>" {
		return value
	}
	if address, ok := mailaddr.Mailbox(value); ok {
		return address
	}
	return ""
}

func referenceAuthservIDs(authenticationResults, receivedSPF []string) []string {
	seen := make(map[string]bool)
	var identifiers []string
	add := func(value string) {
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if value != "" && !seen[strings.ToLower(value)] {
			seen[strings.ToLower(value)] = true
			identifiers = append(identifiers, value)
		}
	}
	for _, header := range authenticationResults {
		prefix, _, found := strings.Cut(header, ";")
		if !found {
			continue
		}
		if fields := strings.Fields(prefix); len(fields) > 0 {
			add(fields[0])
		}
	}
	for _, header := range receivedSPF {
		if match := receivedSPFReceiver.FindStringSubmatch(header); len(match) == 2 {
			add(match[1])
		}
	}
	return identifiers
}

func summarizeMethod(evidence mailauth.Evidence, method mailauth.Method) methodResult {
	result := methodResult{Outcome: string(mailauth.OutcomeNone)}
	priority := -1
	domains := make(map[string]bool)
	allDomains := make(map[string]bool)
	mechanisms := make(map[string]bool)
	categories := make(map[string]bool)
	reasons := make(map[string]bool)
	for _, candidate := range evidence.Results {
		if candidate.Method != method {
			continue
		}
		result.Present = true
		if current := outcomePriority(candidate.Outcome); current > priority {
			priority = current
			result.Outcome = string(candidate.Outcome)
		}
		if candidate.Outcome == mailauth.OutcomePass && candidate.Domain != "" {
			domains[candidate.Domain] = true
		}
		if candidate.Domain != "" {
			allDomains[candidate.Domain] = true
		}
		if candidate.SPFMechanism != "" {
			mechanisms[candidate.SPFMechanism] = true
		}
		if candidate.ErrorCategory != mailauth.ErrorNone {
			categories[string(candidate.ErrorCategory)] = true
		}
		if candidate.Reason != "" {
			reasons[candidate.Reason] = true
		}
	}
	for domain := range domains {
		result.PassDomains = append(result.PassDomains, domain)
	}
	slices.Sort(result.PassDomains)
	for domain := range allDomains {
		result.Domains = append(result.Domains, domain)
	}
	slices.Sort(result.Domains)
	for mechanism := range mechanisms {
		result.SPFMechanisms = append(result.SPFMechanisms, mechanism)
	}
	slices.Sort(result.SPFMechanisms)
	for category := range categories {
		result.ErrorCategories = append(result.ErrorCategories, category)
	}
	slices.Sort(result.ErrorCategories)
	for reason := range reasons {
		result.Reasons = append(result.Reasons, reason)
	}
	slices.Sort(result.Reasons)
	switch method {
	case mailauth.MethodDKIM:
		result.Aligned = evidence.DKIMAligned
	case mailauth.MethodDMARC:
		result.Aligned = evidence.DMARCAligned
	}
	return result
}

func outcomePriority(outcome mailauth.Outcome) int {
	for index, candidate := range []mailauth.Outcome{
		mailauth.OutcomeNone, mailauth.OutcomeNeutral, mailauth.OutcomeSoftfail,
		mailauth.OutcomeFail, mailauth.OutcomePolicy, mailauth.OutcomePermerror,
		mailauth.OutcomeTemperror, mailauth.OutcomePass,
	} {
		if outcome == candidate {
			return index
		}
	}
	return 0
}

func summarize(records []record) reportSummary {
	summary := reportSummary{
		Messages: len(records), MethodComparisons: make(map[mailauth.Method]int),
		MethodDifferences: make(map[mailauth.Method]int), MethodDetailDifferences: make(map[mailauth.Method]int),
		Categories: make(map[string]categoryCounts),
	}
	for _, record := range records {
		category := summary.Categories[record.Category]
		category.Messages++
		if !record.MetadataComplete {
			summary.MetadataIncomplete++
		}
		if record.Error != "" {
			summary.Errors++
			category.Errors++
		} else {
			summary.Compared++
		}
		if len(record.Differences) > 0 {
			summary.MessagesDifferent++
			category.Different++
			for _, method := range record.Differences {
				summary.MethodDifferences[mailauth.Method(method)]++
			}
		}
		if len(record.DetailDifferences) > 0 {
			summary.MessagesDetailDifferent++
			for _, method := range record.DetailDifferences {
				summary.MethodDetailDifferences[mailauth.Method(method)]++
			}
		}
		for method, comparison := range record.Methods {
			if comparison.Compared {
				summary.MethodComparisons[method]++
			}
		}
		summary.Categories[record.Category] = category
	}
	return summary
}

func messageFiles(directory string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".eml") {
			files = append(files, path)
		}
		return nil
	})
	slices.Sort(files)
	return files, err
}

func containsNonASCII(value []byte) bool {
	for _, character := range value {
		if character >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
