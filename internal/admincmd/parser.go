package admincmd

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

type period string

type recipientAuthorization uint8

const (
	periodDay   period = "day"
	periodWeek  period = "week"
	periodMonth period = "month"
	periodYear  period = "year"
	periodAll   period = "all"
)

const (
	recipientAuthorized recipientAuthorization = iota
	recipientInvalid
	recipientWildcardDenied
	recipientOtherDenied
)

type Command struct {
	kind, verb, sender, recipient, canonical, errorText string
	ip                                                  netip.Addr
	period                                              period
	rejectionID                                         uint64
}

func (c Command) Canonical() string { return c.canonical }

func RecognizedLine(line string) bool {
	fields := strings.Fields(line)
	return len(fields) > 0 && (strings.EqualFold(fields[0], "HELP") || strings.EqualFold(fields[0], "IP") ||
		strings.EqualFold(fields[0], "REJECTION") || strings.EqualFold(fields[0], "REJECTIONS") || strings.EqualFold(fields[0], "WHITELIST"))
}

func ParseError(line, text string) Command {
	return Command{kind: "parse_error", canonical: line, errorText: text}
}

func normalizeRecipient(value string) string {
	if strings.TrimSpace(value) == "*" {
		return "*"
	}
	return mailaddr.Normalize(value)
}

func authorizeRecipient(value, authenticatedSender string, admin bool) (string, recipientAuthorization) {
	if strings.TrimSpace(value) == "*" {
		if !admin {
			return "", recipientWildcardDenied
		}
		return "*", recipientAuthorized
	}
	recipient := mailaddr.Normalize(value)
	if recipient == "" {
		return "", recipientInvalid
	}
	if !admin && recipient != authenticatedSender {
		return "", recipientOtherDenied
	}
	return recipient, recipientAuthorized
}

func (p *Processor) Parse(line string, actor Actor) (Command, error) {
	if p == nil {
		return Command{}, fmt.Errorf("command processor is unavailable")
	}
	return parse(strings.TrimSpace(line), normalizeRecipient(actor.DefaultRecipient), actor.Administrator)
}

func parseCommandPeriod(value string) (period, bool) {
	switch period(strings.ToLower(value)) {
	case periodDay, periodWeek, periodMonth, periodYear, periodAll:
		return period(strings.ToLower(value)), true
	default:
		return "", false
	}
}

func (p period) cutoff(now time.Time) time.Time {
	switch p {
	case periodDay:
		return now.Add(-24 * time.Hour)
	case periodMonth:
		return now.AddDate(0, -1, 0)
	case periodYear:
		return now.AddDate(-1, 0, 0)
	case periodAll:
		return time.Time{}
	default:
		return now.Add(-7 * 24 * time.Hour)
	}
}

func parse(text, authenticatedSender string, admin bool) (Command, error) {
	fields := strings.Fields(text)
	if len(fields) == 1 && strings.EqualFold(fields[0], "HELP") {
		return Command{kind: "help", canonical: "HELP"}, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "REJECTION") {
		if len(fields) != 2 {
			return Command{}, fmt.Errorf("REJECTION requires one positive rejection ID")
		}
		id, err := strconv.ParseUint(fields[1], 10, 63)
		if err != nil || id == 0 {
			return Command{}, fmt.Errorf("REJECTION requires one positive rejection ID")
		}
		return Command{kind: "rejection", canonical: "REJECTION " + strconv.FormatUint(id, 10), rejectionID: id}, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "IP") {
		if !admin {
			return Command{}, fmt.Errorf("IP commands are restricted to administrators")
		}
		if len(fields) >= 2 && strings.EqualFold(fields[1], "LIST") {
			kind, canonical, index := "ip_list", "IP LIST", 2
			if len(fields) >= 3 && strings.EqualFold(fields[2], "LOOKUP") {
				kind, canonical, index = "ip_list_lookup", "IP LIST LOOKUP", 3
			}
			pd, err := listPeriod(fields, index)
			if err != nil {
				return Command{}, fmt.Errorf("IP LIST period must be day, week, month, year, or all")
			}
			return Command{kind: kind, canonical: canonical + " " + string(pd), period: pd}, nil
		}
		if len(fields) != 3 || (!strings.EqualFold(fields[1], "ADD") && !strings.EqualFold(fields[1], "DELETE")) {
			return Command{}, fmt.Errorf("IP command must be IP LIST, IP LIST LOOKUP, IP ADD address, or IP DELETE address")
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			return Command{}, fmt.Errorf("IP command requires a valid IPv4 or IPv6 address")
		}
		addr = netsafety.CanonicalIP(addr)
		verb := strings.ToUpper(fields[1])
		return Command{kind: "ip_" + strings.ToLower(verb), canonical: "IP " + verb + " " + addr.String(), ip: addr}, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "REJECTIONS") {
		if len(fields) > 3 {
			return Command{}, fmt.Errorf("REJECTIONS accepts at most one recipient and one period")
		}
		recipient, pd, end := authenticatedSender, periodWeek, len(fields)
		if len(fields) > 1 {
			if parsed, ok := parseCommandPeriod(fields[len(fields)-1]); ok {
				pd, end = parsed, len(fields)-1
			}
		}
		if end == 2 {
			var authorization recipientAuthorization
			recipient, authorization = authorizeRecipient(fields[1], authenticatedSender, admin)
			switch authorization {
			case recipientInvalid:
				return Command{}, fmt.Errorf("rejection-history recipient must be a valid email address")
			case recipientWildcardDenied:
				return Command{}, fmt.Errorf("wildcard rejection history is restricted to administrators")
			case recipientOtherDenied:
				return Command{}, fmt.Errorf("users may view only their own rejection history")
			}
		} else if end > 2 {
			return Command{}, fmt.Errorf("REJECTIONS accepts at most one recipient and one period")
		}
		canonical := "REJECTIONS"
		if end == 2 {
			canonical += " " + recipient
		}
		canonical += " " + string(pd)
		return Command{kind: "rejections", recipient: recipient, canonical: canonical, period: pd}, nil
	}
	if len(fields) >= 2 && strings.EqualFold(fields[0], "WHITELIST") && strings.EqualFold(fields[1], "LIST") {
		if len(fields) > 4 {
			return Command{}, fmt.Errorf("WHITELIST LIST accepts at most one recipient and one period")
		}
		recipient, pd, end := authenticatedSender, periodWeek, len(fields)
		if len(fields) > 2 {
			if parsed, ok := parseCommandPeriod(fields[len(fields)-1]); ok {
				pd, end = parsed, len(fields)-1
			}
		}
		if end == 3 {
			var authorization recipientAuthorization
			recipient, authorization = authorizeRecipient(fields[2], authenticatedSender, admin)
			switch authorization {
			case recipientInvalid:
				return Command{}, fmt.Errorf("allowlist recipient must be a valid email address")
			case recipientWildcardDenied:
				return Command{}, fmt.Errorf("wildcard allowlist listing is restricted to administrators")
			case recipientOtherDenied:
				return Command{}, fmt.Errorf("users may view only their own allowlist")
			}
		} else if end > 3 {
			return Command{}, fmt.Errorf("WHITELIST LIST accepts at most one recipient and one period")
		}
		canonical := "WHITELIST LIST"
		if end == 3 {
			canonical += " " + recipient
		}
		canonical += " " + string(pd)
		return Command{kind: "whitelist_list", recipient: recipient, canonical: canonical, period: pd}, nil
	}
	if len(fields) != 3 && len(fields) != 4 {
		return Command{}, fmt.Errorf("invalid command; send HELP for syntax")
	}
	if !strings.EqualFold(fields[0], "WHITELIST") {
		return Command{}, fmt.Errorf("unknown command; send HELP for syntax")
	}
	verb := strings.ToUpper(fields[1])
	if verb != "ADD" && verb != "DELETE" {
		return Command{}, fmt.Errorf("operation must be ADD or DELETE")
	}
	sender := mailaddr.Normalize(fields[2])
	if sender == "" {
		return Command{}, fmt.Errorf("sender must be a valid email address")
	}
	recipient := authenticatedSender
	if len(fields) == 4 {
		recipient = fields[3]
	}
	if recipient == "*" && verb == "ADD" {
		return Command{}, fmt.Errorf("WHITELIST ADD requires an explicit local recipient")
	}
	var authorization recipientAuthorization
	recipient, authorization = authorizeRecipient(recipient, authenticatedSender, admin)
	switch authorization {
	case recipientInvalid:
		return Command{}, fmt.Errorf("recipient must be a valid email address")
	case recipientWildcardDenied:
		return Command{}, fmt.Errorf("wildcard deletion is restricted to administrators")
	case recipientOtherDenied:
		return Command{}, fmt.Errorf("users may modify only their authenticated envelope sender address")
	}
	canonical := fmt.Sprintf("WHITELIST %s %s %s", verb, sender, recipient)
	return Command{kind: "whitelist", verb: verb, sender: sender, recipient: recipient, canonical: canonical}, nil
}

func listPeriod(fields []string, index int) (period, error) {
	if len(fields) == index {
		return periodWeek, nil
	}
	if len(fields) != index+1 {
		return "", fmt.Errorf("too many arguments")
	}
	p, ok := parseCommandPeriod(fields[index])
	if !ok {
		return "", fmt.Errorf("invalid period")
	}
	return p, nil
}
