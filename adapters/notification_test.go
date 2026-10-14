package adapters

import (
	"errors"
	"strings"
	"testing"

	"github.com/GhandyP/message-urgency-detection/internal/urgency"
)

func threatDecision() urgency.UrgencyDecision {
	return urgency.UrgencyDecision{
		ID:    "m1",
		Label: urgency.LabelUrgent,
		Score: urgency.WeightThreat,
		TriggerSpans: []urgency.TriggerSpan{{
			Start: 0, End: 4, Term: "bomb", Kind: urgency.KindThreat, Weight: urgency.WeightThreat,
		}},
		Rationale:   "a threat term is present",
		NeedsReview: true,
	}
}

func deadlineDecision() urgency.UrgencyDecision {
	return urgency.UrgencyDecision{
		ID:    "m2",
		Label: urgency.LabelHigh,
		Score: urgency.WeightDeadlineShort,
		TriggerSpans: []urgency.TriggerSpan{{
			Start: 0, End: 13, Term: "en 20 minutos", Kind: urgency.KindDeadline, Weight: urgency.WeightDeadlineShort,
		}},
		Rationale:   "a short numeric deadline",
		NeedsReview: false,
	}
}

func quietDecision() urgency.UrgencyDecision {
	return urgency.UrgencyDecision{
		ID:    "m3",
		Label: urgency.LabelLow,
		Score: 0,
		TriggerSpans: []urgency.TriggerSpan{{
			Start: 0, End: 5, Term: "hola!", Kind: urgency.KindNone, Weight: urgency.WeightNone,
		}},
		Rationale:   "no known trigger term was found",
		NeedsReview: false,
	}
}

// TestPlanNeverEscalatesADecisionHeldForReview is the safety rule of the whole
// repository: a borderline or high impact case reaches a human before it can
// reach a responder.
func TestPlanNeverEscalatesADecisionHeldForReview(t *testing.T) {
	t.Parallel()

	// An approval boundary IS configured here, so nothing else can explain the
	// absence of an escalation.
	approval := Approval{ApprovedBy: "ana", TicketReference: "REV-7"}

	plan, err := Plan([]urgency.UrgencyDecision{threatDecision()}, approval)
	if err != nil {
		t.Fatalf("Plan() = %v, want nil", err)
	}

	if len(plan.Escalations) != 0 {
		t.Fatalf("Escalations = %+v, want none for a decision flagged for human review", plan.Escalations)
	}
	if len(plan.HeldForReview) != 1 {
		t.Fatalf("HeldForReview = %+v, want exactly one item", plan.HeldForReview)
	}
	if got := plan.HeldForReview[0].Destination; got != DestinationHumanReview {
		t.Errorf("destination = %q, want %q", got, DestinationHumanReview)
	}
}

func TestPlanFailsClosedWithoutAnApprovalBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		approval Approval
	}{
		{name: "no boundary at all"},
		{name: "only a name", approval: Approval{ApprovedBy: "ana"}},
		{name: "only a reference", approval: Approval{TicketReference: "REV-7"}},
		{name: "whitespace is not a value", approval: Approval{ApprovedBy: "   ", TicketReference: "  "}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The batch also holds a review item, so the test proves the whole
			// plan is withheld, not just the escalation half.
			plan, err := Plan([]urgency.UrgencyDecision{threatDecision(), deadlineDecision()}, tt.approval)

			if !errors.Is(err, ErrApprovalRequired) {
				t.Fatalf("Plan() = %v, want ErrApprovalRequired", err)
			}
			if len(plan.Escalations) != 0 || len(plan.HeldForReview) != 0 {
				t.Fatalf("plan = %+v, want nothing at all planned when the batch is unauthorised", plan)
			}
			if !plan.Empty() {
				t.Error("Empty() = false, want true for a withheld plan")
			}
			if !strings.Contains(err.Error(), "approvedBy") || !strings.Contains(err.Error(), "ticketReference") {
				t.Errorf("error = %q, want it to name both required fields", err)
			}
		})
	}
}

func TestPlanEscalatesOnlyWithAValidBoundary(t *testing.T) {
	t.Parallel()

	plan, err := Plan([]urgency.UrgencyDecision{deadlineDecision()}, Approval{
		ApprovedBy:      "ana",
		TicketReference: "REV-7",
	})
	if err != nil {
		t.Fatalf("Plan() = %v, want nil", err)
	}

	if len(plan.Escalations) != 1 {
		t.Fatalf("Escalations = %+v, want one item", plan.Escalations)
	}
	item := plan.Escalations[0]
	if item.Destination != DestinationOnCall {
		t.Errorf("destination = %q, want %q", item.Destination, DestinationOnCall)
	}
	if !strings.Contains(item.Reason, "ana") || !strings.Contains(item.Reason, "REV-7") {
		t.Errorf("reason = %q, want it to name the approving human and the review", item.Reason)
	}
}

func TestPlanRoutesNothingWhenNothingQualifies(t *testing.T) {
	t.Parallel()

	plan, err := Plan([]urgency.UrgencyDecision{quietDecision()}, Approval{})
	if err != nil {
		t.Fatalf("Plan() = %v, want nil", err)
	}
	if !plan.Empty() {
		t.Fatalf("plan = %+v, want nothing routed for a quiet decision", plan)
	}
}

func TestPlanRejectsASuspectBatchWhole(t *testing.T) {
	t.Parallel()

	// A decision whose label disagrees with its score is invalid.
	broken := deadlineDecision()
	broken.Label = urgency.LabelLow

	plan, err := Plan([]urgency.UrgencyDecision{threatDecision(), broken}, Approval{
		ApprovedBy:      "ana",
		TicketReference: "REV-7",
	})
	if err == nil {
		t.Fatal("Plan() = nil error, want an error for an invalid decision")
	}
	if !plan.Empty() {
		t.Fatalf("plan = %+v, want nothing planned from a suspect batch", plan)
	}
}

func TestPlanRecordsEvidenceForTheReviewer(t *testing.T) {
	t.Parallel()

	negated := urgency.UrgencyDecision{
		ID:    "m4",
		Label: urgency.LabelHigh,
		Score: 60,
		TriggerSpans: []urgency.TriggerSpan{
			{Start: 0, End: 2, Term: "no", Kind: urgency.KindDeescalation, Weight: 0, Negated: true},
			{Start: 3, End: 10, Term: "urgente", Kind: urgency.KindDeadline, Weight: 0, Negated: true},
		},
		Rationale:   "mixed evidence",
		NeedsReview: true,
	}

	plan, err := Plan([]urgency.UrgencyDecision{negated}, Approval{})
	if err != nil {
		t.Fatalf("Plan() = %v, want nil", err)
	}

	got := strings.Join(plan.HeldForReview[0].Evidence, " | ")
	if !strings.Contains(got, "not urgente") {
		t.Errorf("evidence = %q, want a neutralised term marked as not matched", got)
	}
}

func TestPlanRenderIsStable(t *testing.T) {
	t.Parallel()

	plan, err := Plan([]urgency.UrgencyDecision{threatDecision(), deadlineDecision()}, Approval{
		ApprovedBy:      "ana",
		TicketReference: "REV-7",
	})
	if err != nil {
		t.Fatalf("Plan() = %v, want nil", err)
	}

	var out strings.Builder
	if err := plan.Render(&out); err != nil {
		t.Fatalf("Render() = %v, want nil", err)
	}

	want := strings.Join([]string{
		"routing plan (dry run, nothing was sent)",
		"approval boundary: ana (REV-7)",
		"held for human review: 1",
		"  - m1 -> human-review [urgent 85] flagged for human review before any page or escalation (evidence: bomb)",
		"escalations: 1",
		"  - m2 -> on-call [high 65] high urgency with no review flag, authorised by ana (REV-7) (evidence: en 20 minutos)",
		"",
	}, "\n")

	if out.String() != want {
		t.Errorf("Render() =\n%q\nwant\n%q", out.String(), want)
	}
}

func TestApprovalString(t *testing.T) {
	t.Parallel()

	if got := (Approval{}).String(); got != "not configured" {
		t.Errorf("zero Approval String() = %q, want %q", got, "not configured")
	}
	if got := (Approval{ApprovedBy: "ana", TicketReference: "REV-7"}).String(); got != "ana (REV-7)" {
		t.Errorf("Approval String() = %q, want %q", got, "ana (REV-7)")
	}
}

// TestPipelineKeepsAThreatAwayFromAResponder walks the whole chain, rules then
// routing, on the threat fixture from the rules suite.
func TestPipelineKeepsAThreatAwayFromAResponder(t *testing.T) {
	t.Parallel()

	request := urgency.UrgencyRequest{
		PolicyVersion: urgency.CurrentPolicyVersion,
		Messages: []urgency.Message{
			{ID: "m1", Text: "Recibí una amenaza de bomba"},
			{ID: "m2", Text: "Necesito esto para hoy"},
		},
	}

	decisions, err := urgency.ClassifyBatch(request)
	if err != nil {
		t.Fatalf("ClassifyBatch() = %v, want nil", err)
	}
	if decisions[0].Label != urgency.LabelUrgent || !decisions[0].NeedsReview {
		t.Fatalf("fixture assumption broken: %+v", decisions[0])
	}

	plan, err := Plan(decisions, Approval{})
	if err != nil {
		t.Fatalf("Plan() = %v, want nil: neither decision should need a responder", err)
	}
	if len(plan.Escalations) != 0 {
		t.Fatalf("Escalations = %+v, want none without an approval boundary", plan.Escalations)
	}
	if len(plan.HeldForReview) != 1 || plan.HeldForReview[0].MessageID != "m1" {
		t.Fatalf("HeldForReview = %+v, want the threat held for a human", plan.HeldForReview)
	}
}
