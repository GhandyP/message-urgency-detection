// Command message-urgency-detection classifies supplied messages by urgency.
//
// It reads a UrgencyRequest as JSON, runs the deterministic rules, optionally
// consults the schema constrained ADK agent as a fallback for the messages the
// rules could not settle, writes the decisions ordered by severity, and prints a
// routing plan.
//
// It never pages a responder. Routing is a dry run, and an escalation with no
// configured approval boundary fails closed.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GhandyP/message-urgency-detection/adapters"
	"github.com/GhandyP/message-urgency-detection/internal/urgency"
)

// Exit codes. ExitApprovalRequired exists so a caller can tell "these decisions
// are fine but nothing was authorised to reach a responder" apart from "this
// run failed".
const (
	ExitOK               = 0
	ExitFailure          = 1
	ExitUsage            = 2
	ExitApprovalRequired = 3
)

const usage = `message-urgency-detection classifies messages by urgency.

Usage:
  message-urgency-detection [flags]

Reads a UrgencyRequest as JSON and writes UrgencyDecision values ordered by
severity, score and id. The routing plan is a dry run and is written to stderr.

Flags:
  -in string           path to a UrgencyRequest JSON file, or - for stdin (default "-")
  -out string          path for the UrgencyDecision JSON, or - for stdout (default "-")
  -model               consult the ADK agent for messages the rules could not
                       settle (needs GOOGLE_API_KEY, default false)
  -approved-by string  name of the human who authorised escalation
  -approval-ref string reference to the human review that cleared escalation
  -h, -help            show this help

Input contract:
  {"policyVersion":"1.0.0","messages":[{"id":"m1","text":"..."}]}

Output contract:
  {"policyVersion":"1.0.0","decisions":[{"id","label","score","triggerSpans",
   "rationale","needsReview"}]}

Exit codes:
  0  decisions produced, routing plan produced or not needed
  1  the run failed
  2  usage error
  3  decisions were produced but an escalation had no approval boundary;
     nothing was routed

Safety:
  A message the rules flagged for human review is never escalated. An escalation
  always requires both -approved-by and -approval-ref. This program sends
  nothing: the routing plan is a description of what would happen.
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		var exitErr *exitError
		if errors.As(err, &exitErr) {
			if exitErr.err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", exitErr.err)
			}
			os.Exit(exitErr.code)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(ExitFailure)
	}
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// response is the CLI envelope around the frozen decision contract.
type response struct {
	PolicyVersion string                    `json:"policyVersion"`
	Decisions     []urgency.UrgencyDecision `json:"decisions"`
}

// run is the whole program, with its streams injected so a test can drive it
// in-process and assert exact stdout, stderr and exit code.
//
// It returns an *exitError only when a caller needs a non-default exit code: a
// usage error, or a routing plan withheld for want of an approval boundary.
// Every other error is an ordinary failure, which main maps to ExitFailure.
// Read the code the way main does rather than assuming every error carries one.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("message-urgency-detection", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // usage is rendered below, not by the flag package
	fs.Usage = func() {}

	inputPath := fs.String("in", "-", "path to a UrgencyRequest JSON file, or - for stdin")
	outputPath := fs.String("out", "-", "path for the UrgencyDecision JSON, or - for stdout")
	useModel := fs.Bool("model", false, "consult the ADK agent for inconclusive messages")
	approvedBy := fs.String("approved-by", "", "name of the human who authorised escalation")
	approvalRef := fs.String("approval-ref", "", "reference to the human review that cleared escalation")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stderr, usage)
			return nil
		}
		fmt.Fprint(stderr, usage)
		return &exitError{code: ExitUsage, err: err}
	}
	if fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return &exitError{code: ExitUsage, err: fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}

	raw, err := readInput(*inputPath, stdin)
	if err != nil {
		return err
	}

	var request urgency.UrgencyRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields() // the request contract is closed
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}

	decisions, err := urgency.ClassifyBatch(request)
	if err != nil {
		return err
	}

	if *useModel {
		decisions, err = refineWithModel(context.Background(), decisions, request.Messages)
		if err != nil {
			return fmt.Errorf("agent fallback: %w", err)
		}
	}

	if err := writeDecisions(*outputPath, stdout, response{
		PolicyVersion: request.PolicyVersion,
		Decisions:     decisions,
	}); err != nil {
		return err
	}

	// The decisions are already written, so a refusal here loses no work: it
	// only withholds the part that wanted to reach a responder.
	plan, planErr := adapters.Plan(decisions, adapters.Approval{
		ApprovedBy:      *approvedBy,
		TicketReference: *approvalRef,
	})
	if planErr != nil {
		return &exitError{code: ExitApprovalRequired, err: planErr}
	}

	if err := plan.Render(stderr); err != nil {
		return err
	}
	return nil
}

// refineWithModel consults the agent only for the messages the deterministic
// pass could not settle, and merges each verdict back by id.
func refineWithModel(
	ctx context.Context,
	decisions []urgency.UrgencyDecision,
	messages []urgency.Message,
) ([]urgency.UrgencyDecision, error) {
	textByID := make(map[string]string, len(messages))
	for _, m := range messages {
		textByID[m.ID] = m.Text
	}

	pending := make([]urgency.Message, 0, len(decisions))
	for _, d := range decisions {
		text, ok := textByID[d.ID]
		if !ok {
			continue
		}
		if urgency.NeedsModel(d, text) {
			pending = append(pending, urgency.Message{ID: d.ID, Text: text})
		}
	}

	// A batch the rules settled entirely never needs credentials.
	if len(pending) == 0 {
		return decisions, nil
	}

	classifier, err := urgency.NewAgentClassifier(ctx, urgency.AgentConfig{})
	if err != nil {
		return nil, err
	}

	verdicts, err := classifier.ReviewBatch(ctx, pending)
	if err != nil {
		return nil, err
	}

	position := make(map[string]int, len(decisions))
	for i, d := range decisions {
		position[d.ID] = i
	}

	merged := make([]urgency.UrgencyDecision, len(decisions))
	copy(merged, decisions)
	for _, v := range verdicts {
		i, ok := position[v.ID]
		if !ok {
			continue // an unknown id is discarded by parseVerdicts too
		}
		merged[i] = urgency.ApplyVerdict(merged[i], v)
	}

	urgency.SortDecisions(merged)
	return merged, nil
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return raw, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

func writeDecisions(path string, stdout io.Writer, res response) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// Multi language text is the whole point here, so do not let the encoder
	// rewrite <, > and & into escape sequences inside a message.
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(res); err != nil {
		return fmt.Errorf("encode decisions: %w", err)
	}

	if path == "-" {
		if _, err := stdout.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write stdout: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
