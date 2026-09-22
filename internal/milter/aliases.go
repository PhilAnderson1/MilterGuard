package milter

import (
	"bufio"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
)

const maxAliasesFileBytes = 2 << 20

// senderOwnedViaAliases accepts only simple, single-target local alias chains.
// More expressive aliases are deliberately rejected because they do not prove
// exclusive ownership by one authenticated identity.
func senderOwnedViaAliases(path, envelopeSender, identity, commandRecipient string) error {
	sender := mailaddr.Normalize(envelopeSender)
	command := mailaddr.Normalize(commandRecipient)
	if sender == "" || command == "" {
		return fmt.Errorf("invalid sender or command address")
	}
	senderAddress, senderErr := mail.ParseAddress(sender)
	commandAddress, commandErr := mail.ParseAddress(command)
	if senderErr != nil || commandErr != nil || senderAddress == nil || commandAddress == nil {
		return fmt.Errorf("invalid sender or command address")
	}
	senderParts := strings.Split(senderAddress.Address, "@")
	commandParts := strings.Split(commandAddress.Address, "@")
	if len(senderParts) != 2 || len(commandParts) != 2 || !strings.EqualFold(senderParts[1], commandParts[1]) {
		return fmt.Errorf("sender is not in the command address domain")
	}
	wanted := strings.ToLower(strings.TrimSpace(identity))
	if parsed, err := mail.ParseAddress(wanted); err == nil {
		parts := strings.SplitN(parsed.Address, "@", 2)
		if len(parts) == 2 && strings.EqualFold(parts[1], commandParts[1]) {
			wanted = strings.ToLower(parts[0])
		}
	}
	if !validAliasName(wanted) {
		return fmt.Errorf("authentication identity is not a local alias name")
	}
	current := strings.ToLower(senderParts[0])
	if current == wanted {
		return nil
	}
	aliases, err := readSimpleAliases(path)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for depth := 0; depth < 16; depth++ {
		if seen[current] {
			return fmt.Errorf("alias cycle")
		}
		seen[current] = true
		next, found := aliases[current]
		if !found {
			return fmt.Errorf("no alias mapping for %s", current)
		}
		if next == wanted {
			return nil
		}
		current = next
	}
	return fmt.Errorf("alias chain is too deep")
}

func readSimpleAliases(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || info.Size() > maxAliasesFileBytes {
		return nil, fmt.Errorf("aliases file is unavailable or too large")
	}
	aliases := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.ToLower(strings.TrimSpace(value))
		if !found || !validAliasName(key) || !validAliasName(value) {
			continue
		}
		aliases[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return aliases, nil
}

func validAliasName(value string) bool {
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "@,|/:\\ \t\r\n") {
		return false
	}
	for _, r := range value {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
