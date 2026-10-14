package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GhandyP/message-urgency-detection/adapters"
	"github.com/GhandyP/message-urgency-detection/internal/urgency"
)

const fixturePath = "testdata/messages.json"

// exitCodeOf mirrors how main maps an error to an exit code, rather than
// assuming every error carries one. Only a usage error or a withheld routing
// plan returns an *exitError; everything else is an ordinary failure.
//
// Asserting the error type instead of the exit code made five tests fail for the
// wrong reason: the program's behaviour was correct and the helper was not
// reading the contract the program actually offers.
func exitCodeOf(t *testing.T, err error) int {
	t.Helper()

	if err == nil {
		return ExitOK
	}
	var exitErr *exitError
	if errors.As(err, &exitErr) {
		return exitErr.code
	}
	return ExitFailure
}

// approvalArgs is the boundary the shared fixture needs to produce a full plan.
// The fixture deliberately contains one escalation candidate, so without these
// flags the run correctly refuses and exits 3.
var approvalArgs = []string{"-approved-by", "ana", "-approval-ref", "REV-7"}

// runFixture runs the shared fixture with a configured approval boundary, so a
// full routing plan is produced. The refusal path has its own test.
func runFixture(t *testing.T, args ...string) (string, string, int) {
	t.Helper()

	full := append(append([]string{"-in", fixturePath}, args...), approvalArgs...)
	var stdout, stderr bytes.Buffer
	err := run(full, strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), stderr.String(), exitCodeOf(t, err)
}

// runFixtureUnapproved runs the fixture with no approval boundary at all.
func runFixtureUnapproved(t *testing.T) (string, string, int) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", fixturePath}, strings.NewReader(""), &stdout, &stderr)
	return stdout.String(), stderr.String(), exitCodeOf(t, err)
}

func decodeResponse(t *testing.T, stdout string) response {
	t.Helper()

	var res response
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	return res
}

// TestRunOrdersFixturesBySeverity pins the ordering contract on fixed fixtures:
// severity first, then score, then message id.
func TestRunOrdersFixturesBySeverity(t *testing.T) {
	t.Parallel()

	stdout, _, code := runFixture(t)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}

	res := decodeResponse(t, stdout)
	want := []string{
		"threat-es",
		"multilingual-en",
		"deadline-short",
		"ambiguous",
		"incident-es",
		"deadline-day",
		"boundary-guard",
		"multilingual-ja",
		"negated",
		"routine",
	}

	got := make([]string, 0, len(res.Decisions))
	for _, d := range res.Decisions {
		got = append(got, d.ID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("order =\n  %v\nwant\n  %v", got, want)
	}

	if res.Decisions[0].Label != urgency.LabelUrgent {
		t.Errorf("first label = %q, want %q", res.Decisions[0].Label, urgency.LabelUrgent)
	}
	last := res.Decisions[len(res.Decisions)-1]
	if last.Label != urgency.LabelLow {
		t.Errorf("last label = %q, want %q", last.Label, urgency.LabelLow)
	}
	if res.PolicyVersion != urgency.CurrentPolicyVersion {
		t.Errorf("policyVersion = %q, want %q", res.PolicyVersion, urgency.CurrentPolicyVersion)
	}
}

// TestRunFixtureDecisionsAreValidAndSpanTheirOwnText is the end-to-end form of
// the "every message has a valid label, score and evidence span" requirement: it
// re-checks every decision against the exact text it came from.
func TestRunFixtureDecisionsAreValidAndSpanTheirOwnText(t *testing.T) {
	t.Parallel()

	stdout, _, code := runFixture(t)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var request urgency.UrgencyRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	textByID := make(map[string]string, len(request.Messages))
	for _, m := range request.Messages {
		textByID[m.ID] = m.Text
	}

	res := decodeResponse(t, stdout)
	if len(res.Decisions) != len(request.Messages) {
		t.Fatalf("got %d decisions, want one per message (%d)", len(res.Decisions), len(request.Messages))
	}

	for _, d := range res.Decisions {
		text, ok := textByID[d.ID]
		if !ok {
			t.Fatalf("decision %q does not answer any supplied message", d.ID)
		}
		if err := urgency.ValidateDecision(d); err != nil {
			t.Errorf("decision %s is invalid: %v", d.ID, err)
		}
		if err := urgency.VerifySpans(text, d.TriggerSpans); err != nil {
			t.Errorf("decision %s has spans that do not match its text: %v", d.ID, err)
		}
		if len(d.TriggerSpans) == 0 {
			t.Errorf("decision %s carries no evidence span", d.ID)
		}
	}
}

// TestRunFixtureMarksAmbiguityInsteadOfGuessing covers the requirement that
// ambiguous cases are marked for review rather than forced into a label.
func TestRunFixtureMarksAmbiguityInsteadOfGuessing(t *testing.T) {
	t.Parallel()

	stdout, _, code := runFixture(t)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}

	byID := make(map[string]urgency.UrgencyDecision)
	for _, d := range decodeResponse(t, stdout).Decisions {
		byID[d.ID] = d
	}

	review := []string{"threat-es", "multilingual-en", "ambiguous", "multilingual-ja"}
	for _, id := range review {
		if !byID[id].NeedsReview {
			t.Errorf("%s: NeedsReview = false, want true", id)
		}
	}

	quiet := []string{"routine", "negated", "boundary-guard", "deadline-day"}
	for _, id := range quiet {
		if byID[id].NeedsReview {
			t.Errorf("%s: NeedsReview = true, want false", id)
		}
	}
}

// TestRunFixtureRefusesToEscalateWithoutAnApprovalBoundary is the safety rule
// observed end to end on the real fixtures.
func TestRunFixtureRefusesToEscalateWithoutAnApprovalBoundary(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runFixtureUnapproved(t)

	if code != ExitApprovalRequired {
		t.Fatalf("exit code = %d, want %d", code, ExitApprovalRequired)
	}
	// The analysis survives the refusal: a routing rule must not swallow work.
	if got := len(decodeResponse(t, stdout).Decisions); got != 10 {
		t.Errorf("got %d decisions, want all 10 written before the refusal", got)
	}
	if strings.Contains(stderr, "escalations: 1") {
		t.Errorf("stderr = %q, want no plan rendered for an unauthorised escalation", stderr)
	}
}

// TestRunFixturePlanSeparatesReviewFromEscalation pins what the fixture
// actually routes, approved: five messages need a human first and exactly one
// reaches a responder.
func TestRunFixturePlanSeparatesReviewFromEscalation(t *testing.T) {
	t.Parallel()

	stdout, stderr, code := runFixture(t)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitOK, stderr)
	}
	if got := len(decodeResponse(t, stdout).Decisions); got != 10 {
		t.Errorf("got %d decisions, want 10", got)
	}

	for _, want := range []string{
		"held for human review: 5",
		"escalations: 1",
		"approval boundary: ana (REV-7)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr)
		}
	}

	// The only escalation is the short deadline. A held, high impact decision
	// must never appear on the responder side.
	if !strings.Contains(stderr, "-> on-call [high 65]") {
		t.Errorf("stderr does not route the short deadline to on-call:\n%s", stderr)
	}
	if strings.Contains(stderr, "-> on-call [urgent") {
		t.Errorf("an urgent decision reached on-call, but every urgent fixture is held for review:\n%s", stderr)
	}
}

func TestRunRefusesToEscalateWithoutABoundary(t *testing.T) {
	t.Parallel()

	// A short numeric deadline without a review flag is a real escalation
	// candidate, so this batch exercises the refusal path.
	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"El deploy tiene que estar en 20 minutos"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-"}, strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitApprovalRequired {
		t.Fatalf("exit code = %d, want %d", got, ExitApprovalRequired)
	}
	if !errors.Is(err, adapters.ErrApprovalRequired) {
		t.Errorf("error = %v, want it to wrap adapters.ErrApprovalRequired", err)
	}
	// The decisions are still written: a refusal to route loses no analysis.
	if len(decodeResponse(t, stdout.String()).Decisions) != 1 {
		t.Error("the decision was not written before the refusal")
	}
	if strings.Contains(stderr.String(), "escalations: 1") {
		t.Error("stderr reported an escalation that was not authorised")
	}
}

func TestRunEscalatesWithABoundary(t *testing.T) {
	t.Parallel()

	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"El deploy tiene que estar en 20 minutos"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-", "-approved-by", "ana", "-approval-ref", "REV-7"},
		strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", got, ExitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "escalations: 1") {
		t.Errorf("stderr = %q, want one authorised escalation", stderr.String())
	}
	if !strings.Contains(stderr.String(), "REV-7") {
		t.Errorf("stderr = %q, want the review reference recorded", stderr.String())
	}
}

func TestRunDoesNotEscapeMessageText(t *testing.T) {
	t.Parallel()

	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"urgente <b>ya</b> & ahora"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-"}, strings.NewReader(request), &stdout, &stderr)
	if got := exitCodeOf(t, err); got != ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", got, ExitOK, stderr.String())
	}

	if strings.Contains(stdout.String(), `\u003c`) || strings.Contains(stdout.String(), `\u0026`) {
		t.Errorf("stdout escaped HTML characters, which mangles real message text:\n%s", stdout.String())
	}

	res := decodeResponse(t, stdout.String())
	if len(res.Decisions) != 1 || res.Decisions[0].Label != urgency.LabelUrgent {
		t.Fatalf("decisions = %+v, want one urgent decision", res.Decisions)
	}
}

func TestRunRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"hola"}],"surprise":true}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-"}, strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitFailure)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing written on a rejected request", stdout.String())
	}
}

func TestRunRejectsAnInvalidRequest(t *testing.T) {
	t.Parallel()

	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"hola"},{"id":"m1","text":"otra"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-"}, strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("error = %q, want it to name the duplicate id", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing written", stdout.String())
	}
}

// TestRunModelFlagNeedsNoCredentialsWhenRulesSettleTheBatch pins the gate: the
// agent is only built when at least one message is genuinely inconclusive.
func TestRunModelFlagNeedsNoCredentialsWhenRulesSettleTheBatch(t *testing.T) {
	t.Setenv(urgency.APIKeyEnvVar, "")

	// A threat scores 100, is not borderline and has no mixed polarity, so the
	// deterministic pass is conclusive and the model is never reached.
	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"Recibí una amenaza de bomba"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-", "-model"}, strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", got, ExitOK, stderr.String())
	}
}

func TestRunModelFlagReportsMissingCredentials(t *testing.T) {
	t.Setenv(urgency.APIKeyEnvVar, "")

	// Two accents and no recognised term, so this message is inconclusive and
	// the model would be needed.
	request := `{"policyVersion":"1.0.0","messages":[{"id":"m1","text":"¿Confirmamos la reunión del jueves?"}]}`

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-", "-model"}, strings.NewReader(request), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(err.Error(), urgency.APIKeyEnvVar) {
		t.Errorf("error = %q, want it to name %s", err, urgency.APIKeyEnvVar)
	}
}

func TestRunWritesDecisionsToAPath(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "decisions.json")

	stdout, stderr, code := runFixture(t, "-out", outPath)
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, ExitOK, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing when -out names a file", stdout)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(decodeResponse(t, string(raw)).Decisions) == 0 {
		t.Error("the output file holds no decisions")
	}
}

func TestRunHelp(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-h"}, strings.NewReader(""), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitOK {
		t.Fatalf("exit code = %d, want %d", got, ExitOK)
	}
	for _, want := range []string{"-approved-by", "-approval-ref", "-model", "Exit codes", "Safety"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help text does not mention %q", want)
		}
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"extra"}, strings.NewReader(""), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitUsage {
		t.Fatalf("exit code = %d, want %d", got, ExitUsage)
	}
}

func TestRunRejectsAnUnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-nope"}, strings.NewReader(""), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitUsage {
		t.Fatalf("exit code = %d, want %d", got, ExitUsage)
	}
}

func TestRunReportsAMissingInputFile(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", filepath.Join(t.TempDir(), "nope.json")}, strings.NewReader(""), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(err.Error(), "read ") {
		t.Errorf("error = %q, want it to name the unreadable path", err)
	}
}

func TestRunRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-in", "-"}, strings.NewReader("{not json"), &stdout, &stderr)

	if got := exitCodeOf(t, err); got != ExitFailure {
		t.Fatalf("exit code = %d, want %d", got, ExitFailure)
	}
	if !strings.Contains(err.Error(), "decode request") {
		t.Errorf("error = %q, want it to name the decode step", err)
	}
}
