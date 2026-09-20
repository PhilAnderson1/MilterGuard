package admincmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func textResponse(canonical string, render func() string) DeferredResponse {
	return func() Response { return Response{Canonical: canonical, Text: render()} }
}

// Execute performs the database portion of a parsed command and returns a
// deferred renderer. Deferral keeps archived-message parsing off the Milter
// end-of-message path used by email commands.
func (p *Processor) Execute(parent context.Context, command Command, actor Actor) (DeferredResponse, error) {
	ctx, cancel := context.WithTimeout(parent, p.databaseTimeout)
	defer cancel()
	admin := actor.Administrator
	cutoff := command.period.cutoff(p.now().UTC())
	switch command.kind {
	case "parse_error":
		return textResponse(command.canonical, func() string { return command.errorText + ".\n" }), nil
	case "help":
		return textResponse(command.canonical, func() string { return Help(admin, actor.DefaultRecipient) }), nil
	case "rejections":
		page, err := p.rejections.ListRejections(ctx, stores.RejectionListQuery{Recipients: recipientScope(command.recipient), RejectedSince: cutoff, Limit: MaxListRows})
		entries := page.Entries
		if actor.NewestLast {
			reverse(entries)
		}
		return textResponse(command.canonical, func() string { return formatRejectionHistory(entries, page.Truncated) }), err
	case "rejection":
		scope := stores.RecipientScope{Address: normalizeRecipient(actor.DefaultRecipient)}
		if admin {
			scope = stores.RecipientScope{All: true}
		}
		entry, found, err := p.rejections.RejectionByID(ctx, command.rejectionID, scope)
		if err != nil {
			return nil, err
		}
		if !found {
			return textResponse(command.canonical, func() string { return "Rejection record not found.\n" }), nil
		}
		return func() Response {
			response := p.rejectionDetail(entry)
			response.Canonical = command.canonical
			return response
		}, nil
	case "whitelist_list":
		page, err := p.correspondents.ListCorrespondents(ctx, stores.CorrespondentListQuery{Recipients: recipientScope(command.recipient), ActiveSince: cutoff, Limit: MaxListRows})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			reverse(entries)
		}
		return textResponse(command.canonical, func() string { return formatAllowlist(entries, admin && command.recipient == "*", page.Truncated) }), nil
	case "ip_list", "ip_list_lookup":
		page, err := p.ipReputation.ListActiveBlocks(ctx, stores.IPBlockListQuery{ActiveSince: cutoff, Limit: MaxListRows})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			reverse(entries)
		}
		lookup := command.kind == "ip_list_lookup"
		if lookup && p.ipResolver != nil {
			entries = p.ipResolver.ResolveActiveIPHostnames(ctx, entries)
		}
		return textResponse(command.canonical, func() string { return formatActiveIPBlocks(entries, lookup, page.Truncated) }), nil
	case "ip_add":
		block, err := p.ipReputation.AddManualBlock(ctx, command.ip)
		outcome := fmt.Sprintf("blocked %s until %s", block.Address, block.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		return textResponse(command.canonical, func() string { return outcome + ".\n" }), err
	case "ip_delete":
		removed, err := p.ipReputation.Delete(ctx, command.ip)
		outcome := "IP address was not present"
		if removed {
			outcome = "IP reputation record deleted"
		}
		return textResponse(command.canonical, func() string { return outcome + ".\n" }), err
	case "whitelist":
		if command.verb == "ADD" {
			created, err := p.correspondents.AddManual(ctx, command.sender, command.recipient)
			outcome := "allowlist entry already existed and was refreshed"
			if created {
				outcome = "allowlist entry added"
			}
			return textResponse(command.canonical, func() string { return outcome + ".\n" }), err
		}
		removed, err := p.correspondents.DeleteManual(ctx, command.sender, recipientScope(command.recipient))
		outcome := fmt.Sprintf("removed %d allowlist entries", removed)
		return textResponse(command.canonical, func() string { return outcome + ".\n" }), err
	default:
		return nil, fmt.Errorf("unsupported command")
	}
}

// ExecuteLine parses, executes, and immediately renders one command. Terminal
// command mode uses it when no asynchronous response transport is involved.
func (p *Processor) ExecuteLine(ctx context.Context, line string, actor Actor) (Response, error) {
	command, err := p.Parse(strings.TrimSpace(line), actor)
	if err != nil {
		return Response{}, err
	}
	deferred, err := p.Execute(ctx, command, actor)
	if err != nil {
		return Response{Canonical: command.Canonical()}, err
	}
	select {
	case <-ctx.Done():
		return Response{Canonical: command.Canonical()}, ctx.Err()
	default:
	}
	return deferred(), nil
}

func recipientScope(recipient string) stores.RecipientScope {
	if recipient == "*" {
		return stores.RecipientScope{All: true}
	}
	return stores.RecipientScope{Address: recipient}
}
func reverse[T any](values []T) {
	for l, r := 0, len(values)-1; l < r; l, r = l+1, r-1 {
		values[l], values[r] = values[r], values[l]
	}
}
