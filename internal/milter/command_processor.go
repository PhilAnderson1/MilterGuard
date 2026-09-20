package milter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// CommandActor describes the authority and default local address of a command
// caller. Email commands use the authenticated envelope sender; interactive
// command mode uses administrator authority and a wildcard default.
type CommandActor struct {
	Administrator    bool
	DefaultRecipient string
	NewestLast       bool
}

// CommandAttachment is binary output associated with a command result.
type CommandAttachment struct {
	Filename   string
	MediaType  string
	Contents   []byte
	SourcePath string
}

// CommandResponse is independent of email or terminal transport.
type CommandResponse struct {
	Canonical   string
	Text        string
	Attachments []CommandAttachment
}

// CommandProcessor is the shared parser and executor used by email and
// interactive administration commands.
type CommandProcessor struct {
	server         *Server
	correspondents stores.CorrespondentAdminRepository
	rejections     stores.RejectionRepository
	ipReputation   stores.IPReputationRepository
}

func newCommandProcessor(server *Server) *CommandProcessor {
	if server == nil {
		return &CommandProcessor{}
	}
	return &CommandProcessor{server: server, correspondents: server.correspondents,
		rejections: server.rejectionHistory, ipReputation: server.ipReputation}
}

// OpenCommandProcessor opens the configured persistent state without starting
// a Milter listener. The returned close function releases the SQLite handle.
func OpenCommandProcessor(cfg config.Config, log *slog.Logger) (*CommandProcessor, func() error, error) {
	commandCfg := cfg
	commandCfg.EmailCommands.SendReplies = false
	server := NewServer(commandCfg, nil, log)
	if err := server.StartupError(); err != nil {
		_ = server.Close()
		return nil, nil, err
	}
	return server.commands, server.Close, nil
}

func (p *CommandProcessor) parse(line string, actor CommandActor) (emailCommand, error) {
	if p == nil || p.server == nil {
		return emailCommand{}, fmt.Errorf("command processor is unavailable")
	}
	command, help, err := parseEmailCommand(line, normalizeCommandRecipient(actor.DefaultRecipient), actor.Administrator)
	if err != nil {
		return emailCommand{}, err
	}
	if help {
		command = emailCommand{kind: "help", canonical: "HELP"}
	}
	return command, nil
}

func normalizeCommandRecipient(value string) string {
	if strings.TrimSpace(value) == "*" {
		return "*"
	}
	return normalizeEmailAddress(value)
}

func (p *CommandProcessor) execute(ctx context.Context, command emailCommand, actor CommandActor) (commandResult, error) {
	return p.executeCommand(ctx, command, actor)
}

// ExecuteLine parses and executes one command immediately.
func (p *CommandProcessor) ExecuteLine(ctx context.Context, line string, actor CommandActor) (CommandResponse, error) {
	command, err := p.parse(strings.TrimSpace(line), actor)
	if err != nil {
		return CommandResponse{}, err
	}
	result, err := p.execute(ctx, command, actor)
	if err != nil {
		return CommandResponse{Canonical: command.canonical}, err
	}
	select {
	case <-ctx.Done():
		return CommandResponse{Canonical: command.canonical}, ctx.Err()
	default:
	}
	content := result()
	attachments := make([]CommandAttachment, len(content.Attachments))
	for index, attachment := range content.Attachments {
		attachments[index] = CommandAttachment(attachment)
	}
	return CommandResponse{Canonical: command.canonical, Text: content.Text, Attachments: attachments}, nil
}
