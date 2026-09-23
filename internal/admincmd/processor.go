package admincmd

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func textResponse(render func() string) DeferredResponse {
	return func() Response { return Response{Text: render()} }
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
		return textResponse(func() string { return command.errorText + ".\n" }), nil
	case "help":
		return textResponse(func() string { return Help(admin, actor.CommandMode) }), nil
	case "rejections":
		page, err := p.rejections.ListRejections(ctx, stores.RejectionListQuery{Recipients: recipientScope(command.recipient), RejectedSince: cutoff, Limit: MaxListRows})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			slices.Reverse(entries)
		}
		return textResponse(func() string { return formatRejectionHistory(entries, page.Truncated) }), nil
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
			return textResponse(func() string { return "Rejection record not found.\n" }), nil
		}
		return func() Response {
			return p.rejectionDetail(entry)
		}, nil
	case "whitelist_list":
		page, err := p.correspondents.ListCorrespondents(ctx, stores.CorrespondentListQuery{Recipients: recipientScope(command.recipient), ActiveSince: cutoff, Limit: MaxListRows})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			slices.Reverse(entries)
		}
		return textResponse(func() string { return formatAllowlist(entries, admin && command.recipient == "*", page.Truncated) }), nil
	case "ip_list", "ip_list_lookup":
		page, err := p.ipReputation.ListActiveBlocks(ctx, stores.IPBlockListQuery{ActiveSince: cutoff, Limit: MaxListRows})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			slices.Reverse(entries)
		}
		lookup := command.kind == "ip_list_lookup"
		if lookup && p.ipResolver != nil {
			entries = p.ipResolver.ResolveActiveIPHostnames(ctx, entries)
		}
		return textResponse(func() string { return formatActiveIPBlocks(entries, lookup, page.Truncated) }), nil
	case "ip_add":
		block, err := p.ipReputation.AddManualBlock(ctx, command.ip)
		if err != nil {
			return nil, err
		}
		outcome := fmt.Sprintf("blocked %s until %s", block.Address, formatUTC(block.ExpiresAt))
		return textResponse(func() string { return outcome + ".\n" }), nil
	case "ip_delete":
		removed, err := p.ipReputation.Delete(ctx, command.ip)
		if err != nil {
			return nil, err
		}
		outcome := "IP address was not present"
		if removed {
			outcome = "IP reputation record deleted"
		}
		return textResponse(func() string { return outcome + ".\n" }), nil
	case "whitelist":
		if command.verb == "ADD" {
			created, err := p.correspondents.AddManual(ctx, command.sender, command.recipient)
			if err != nil {
				return nil, err
			}
			outcome := "allowlist entry already existed and was refreshed"
			if created {
				outcome = "allowlist entry added"
			}
			return textResponse(func() string { return outcome + ".\n" }), nil
		}
		removed, err := p.correspondents.DeleteCorrespondent(ctx, command.sender, recipientScope(command.recipient))
		if err != nil {
			return nil, err
		}
		outcome := fmt.Sprintf("removed %d allowlist entries", removed)
		return textResponse(func() string { return outcome + ".\n" }), nil
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
		return Response{}, err
	}
	select {
	case <-ctx.Done():
		return Response{}, ctx.Err()
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
