package message

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxRecipientGroupRunes = 255

var emptyRecipientGroupPattern = regexp.MustCompile(`^\s*(.+)\s*:[ \t]*;[ \t]*$`)

func writeRecipientInformation(b *strings.Builder, msg *Message) {
	if msg.AuthenticatedSubmission {
		return
	}
	if !msg.toHeaderSeen {
		b.WriteString("\nRECIPIENT INFORMATION:\n")
		b.WriteString("Visible recipient addressing: no To header\n")
		b.WriteString("Possible significance: may indicate BCC delivery, but is not proof that the email is unwanted\n")
		return
	}
	group, ok := emptyRecipientGroup(msg.decodedHeaderValues("to"))
	if !ok {
		return
	}
	b.WriteString("\nRECIPIENT INFORMATION:\n")
	b.WriteString("Visible recipient addressing: no addresses disclosed using an empty To group\n")
	b.WriteString("Visible recipient group: ")
	b.WriteString(promptHeaderValue(group))
	b.WriteByte('\n')
}

// emptyRecipientGroup recognizes the conservative, unambiguous case where a
// single To field consists entirely of one RFC 5322 empty address group.
func emptyRecipientGroup(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	match := emptyRecipientGroupPattern.FindStringSubmatch(values[0])
	if len(match) != 2 {
		return "", false
	}
	label := strings.TrimSpace(match[1])
	parsed, err := mail.ParseAddress(label + " <empty-group@milterguard.invalid>")
	if err != nil || parsed.Address != "empty-group@milterguard.invalid" {
		return "", false
	}
	label = strings.Join(strings.Fields(parsed.Name), " ")
	if label == "" {
		return "", false
	}
	if utf8.RuneCountInString(label) > maxRecipientGroupRunes {
		label = string([]rune(label)[:maxRecipientGroupRunes])
	}
	return label, true
}
