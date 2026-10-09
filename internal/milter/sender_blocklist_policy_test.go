package milter

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type fixedSenderBlocklist struct{ match stores.SenderBlockMatch }

func (r fixedSenderBlocklist) MatchSenderBlocks(context.Context, stores.SenderBlockMatchQuery) (stores.SenderBlockMatch, error) {
	return r.match, nil
}

type recordingRejectionHistory struct{ inputs []stores.NewRejection }

func (r *recordingRejectionHistory) AddRejection(_ context.Context, input stores.NewRejection) (uint64, error) {
	r.inputs = append(r.inputs, input)
	return uint64(len(r.inputs)), nil
}
func (*recordingRejectionHistory) ListRejections(context.Context, stores.RejectionListQuery) (stores.RejectionPage, error) {
	return stores.RejectionPage{}, nil
}
func (*recordingRejectionHistory) RejectionByID(context.Context, uint64, stores.RecipientScope) (stores.Rejection, bool, error) {
	return stores.Rejection{}, false, nil
}
func (*recordingRejectionHistory) Cleanup(context.Context) (int64, error) { return 0, nil }
func (*recordingRejectionHistory) Count(context.Context) (int, error)     { return 0, nil }

type recordingActivity struct{ events []stores.ActivityEvent }

func (r *recordingActivity) AddActivity(_ context.Context, event stores.ActivityEvent) error {
	r.events = append(r.events, event)
	return nil
}

func blocklistTestSession(conn net.Conn, mode string, match stores.SenderBlockMatch, history *recordingRejectionHistory, activity *recordingActivity) *session {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	msg := message.New(4096)
	msg.AddHeader("Message-ID", "<blocklist-test@example.invalid>")
	msg.AddHeader("From", "Blocked Sender <sender@example.com>")
	return &session{
		conn: conn, message: msg, envelopeSender: "<bounce@example.com>",
		envelopeRecipients:  []string{"<alice@local.example>", "<bob@local.example>"},
		senderBlocklistFrom: []string{"sender@example.com"},
		deps: &sessionDependencies{
			mode: mode, log: log, filtering: config.FilteringConfig{RejectMessage: "generic"},
			activity: &activityService{repository: activity, log: log},
			policy: &messagePolicyService{
				log: log, rejectionHistory: history, senderBlocklist: fixedSenderBlocklist{match: match},
				senderBlocklistCfg: config.SenderBlocklistConfig{IncludeSubdomains: true, RejectMessage: "blocked by recipient"},
			},
		},
	}
}

func TestSenderBlocklistFullMatchRejectsOnceWithoutDeleteCapability(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	history := &recordingRejectionHistory{}
	activity := &recordingActivity{}
	ss := blocklistTestSession(serverConn, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example", "bob@local.example"},
		MatchedSender:     "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, history, activity)
	done := make(chan [2]bool, 1)
	go func() {
		handled, keep := ss.applySenderBlocklist(context.Background())
		done <- [2]bool{handled, keep}
	}()
	expectFrame(t, clientConn, "y550 5.7.1 blocked by recipient\x00")
	if got := <-done; got != [2]bool{true, true} {
		t.Fatalf("policy result = %v", got)
	}
	if len(history.inputs) != 1 || !slices.Equal(history.inputs[0].Recipients, []string{"alice@local.example", "bob@local.example"}) {
		t.Fatalf("rejection history = %+v", history.inputs)
	}
	if len(activity.events) != 1 || activity.events[0].EventType != stores.ActivityEventSenderBlocklist || activity.events[0].Outcome != stores.ActivityOutcomeRejected {
		t.Fatalf("activity = %+v", activity.events)
	}
}

func TestSenderBlocklistPartialRemovalIsDeferredUntilAccept(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	history := &recordingRejectionHistory{}
	activity := &recordingActivity{}
	ss := blocklistTestSession(serverConn, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example"}, MatchedSender: "*@example.com", MatchedKind: stores.SenderBlockDomain,
	}, history, activity)
	ss.negotiatedActions = actionDeleteRecipient
	handled, keep := ss.applySenderBlocklist(context.Background())
	if handled || !keep || ss.pendingSenderBlocks == nil || len(history.inputs) != 0 || len(activity.events) != 0 {
		t.Fatalf("deferred policy = handled %t keep %t pending %+v history %+v activity %+v", handled, keep, ss.pendingSenderBlocks, history.inputs, activity.events)
	}
	if got := ss.policyEnvelopeRecipients(); !slices.Equal(got, []string{"bob@local.example"}) {
		t.Fatalf("remaining recipients = %v", got)
	}
	done := make(chan error, 1)
	go func() { done <- ss.writePolicyResponse(actionAccept, "unused") }()
	expectFrame(t, clientConn, "-alice@local.example\x00")
	expectFrame(t, clientConn, "a")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ss.completeSenderBlocklistRemoval(context.Background())
	if len(history.inputs) != 1 || !slices.Equal(history.inputs[0].Recipients, []string{"alice@local.example"}) {
		t.Fatalf("partial history = %+v", history.inputs)
	}
	if len(activity.events) != 1 || activity.events[0].Outcome != stores.ActivityOutcomeAccepted || activity.events[0].Quantity != 1 {
		t.Fatalf("partial activity = %+v", activity.events)
	}
}

func TestSenderBlocklistPartialMatchFailsOpenWithoutCapabilityEveryTime(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, nil))
	ss := blocklistTestSession(nil, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example"}, MatchedSender: "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, &recordingRejectionHistory{}, &recordingActivity{})
	ss.deps.log = log
	ss.deps.policy.log = log
	for range 2 {
		handled, keep := ss.applySenderBlocklist(context.Background())
		if handled || !keep || ss.pendingSenderBlocks != nil {
			t.Fatalf("unenforced match = handled %t keep %t pending %+v", handled, keep, ss.pendingSenderBlocks)
		}
	}
	if count := strings.Count(output.String(), "sender blocklist could not remove selected recipients"); count != 2 {
		t.Fatalf("warning count = %d; logs: %s", count, output.String())
	}
}

func TestSenderBlocklistAcceptModeOnlyReportsProposedDecision(t *testing.T) {
	ss := blocklistTestSession(nil, "accept", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example", "bob@local.example"},
		MatchedSender:     "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, &recordingRejectionHistory{}, &recordingActivity{})
	handled, keep := ss.applySenderBlocklist(context.Background())
	if handled || !keep || ss.pendingSenderBlocks != nil {
		t.Fatalf("accept-mode result = handled %t keep %t pending %+v", handled, keep, ss.pendingSenderBlocks)
	}
}

func TestAuthenticatedSubmissionBypassesSenderBlocklist(t *testing.T) {
	ss := blocklistTestSession(nil, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example", "bob@local.example"},
		MatchedSender:     "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, &recordingRejectionHistory{}, &recordingActivity{})
	ss.authentication.Authenticated = true
	handled, keep := ss.applySenderBlocklist(context.Background())
	if handled || !keep || ss.pendingSenderBlocks != nil {
		t.Fatalf("authenticated result = handled %t keep %t pending %+v", handled, keep, ss.pendingSenderBlocks)
	}
}

func TestLaterWholeMessageRejectionSupersedesPartialSenderBlock(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	history := &recordingRejectionHistory{}
	activity := &recordingActivity{}
	ss := blocklistTestSession(serverConn, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example"}, MatchedSender: "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, history, activity)
	ss.negotiatedActions = actionDeleteRecipient
	ss.deps.attachments = &attachmentPolicyService{cfg: config.AttachmentsConfig{RejectMessage: "attachment blocked"}}
	if handled, _ := ss.applySenderBlocklist(context.Background()); handled || ss.pendingSenderBlocks == nil {
		t.Fatal("partial sender block was not deferred")
	}
	done := make(chan bool, 1)
	go func() {
		done <- ss.finishAttachmentDecision(context.Background(), actionReject, "invoice.exe", "executable attachment", nil, "", false)
	}()
	expectFrame(t, clientConn, "y550 5.7.1 attachment blocked\x00")
	if !<-done {
		t.Fatal("attachment rejection failed")
	}
	if len(history.inputs) != 1 || !slices.Equal(history.inputs[0].Recipients, []string{"<alice@local.example>", "<bob@local.example>"}) ||
		history.inputs[0].Reasons[0] != "executable attachment: invoice.exe" {
		t.Fatalf("whole-message rejection history = %+v", history.inputs)
	}
	for _, event := range activity.events {
		if event.EventType == stores.ActivityEventSenderBlocklist {
			t.Fatalf("partial sender block was counted despite later rejection: %+v", activity.events)
		}
	}
}

func TestStrictVisibleFromMailboxesRejectsMalformedValuesAndKeepsValidMultipleMailboxes(t *testing.T) {
	got := strictVisibleFromMailboxes([]string{
		"One <one@example.com>, Two <two@example.net>",
		"malformed <bad@example.org",
	})
	if !slices.Equal(got, []string{"one@example.com", "two@example.net"}) {
		t.Fatalf("visible mailboxes = %v", got)
	}
}

func TestDeleteRecipientResponse(t *testing.T) {
	if got := string(deleteRecipientResponse("owner@example.com")); got != "-owner@example.com\x00" {
		t.Fatalf("delete-recipient response = %q", got)
	}
}

func TestSenderBlocklistFailureBeforeFinalAcceptIsNotPersisted(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	history := &recordingRejectionHistory{}
	activity := &recordingActivity{}
	ss := blocklistTestSession(serverConn, "enforce", stores.SenderBlockMatch{
		BlockedRecipients: []string{"alice@local.example"}, MatchedSender: "sender@example.com", MatchedKind: stores.SenderBlockExactMailbox,
	}, history, activity)
	ss.negotiatedActions = actionDeleteRecipient
	if handled, _ := ss.applySenderBlocklist(context.Background()); handled {
		t.Fatal("partial match was finalized early")
	}
	_ = clientConn.Close()
	_ = serverConn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	if err := ss.writePolicyResponse(actionAccept, "unused"); err == nil {
		t.Fatal("closed connection unexpectedly accepted writes")
	}
	if len(history.inputs) != 0 || len(activity.events) != 0 {
		t.Fatalf("failed response persisted history/activity: %+v %+v", history.inputs, activity.events)
	}
}
