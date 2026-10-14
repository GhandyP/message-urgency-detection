// Package adapters holds the boundary between a decision and the outside world.
//
// Nothing in this package is allowed to page a person on its own. The plan puts
// dry-run notification and routing after the human review rules are proven, so
// this package plans and never sends: there is deliberately no Send, Publish or
// Page method anywhere in it.
package adapters

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/GhandyP/message-urgency-detection/internal/urgency"
)

// ErrApprovalRequired is returned when a decision would reach a responder
// without an approved human review behind it. It is the error that makes the
// safety rule enforceable rather than aspirational.
var ErrApprovalRequired = errors.New("escalation requires a configured approval boundary")

// Destination is where an item would go.
type Destination string

const (
	// DestinationHumanReview is a queue a person reads. It never pages anyone.
	DestinationHumanReview Destination = "human-review"
	// DestinationOnCall reaches a responder, and is therefore the only
	// destination that needs an approval boundary.
	DestinationOnCall Destination = "on-call"
)

// Approval is the configured human approval boundary.
//
// Both fields are mandatory. An empty or half configured boundary is treated as
// absent, because "someone approved it" without a name and a reference to the
// review is not an audit trail.
type Approval struct {
	// ApprovedBy names the human who authorised escalation.
	ApprovedBy string `json:"approvedBy"`
	// TicketReference points at the human review that cleared the escalation.
	TicketReference string `json:"ticketReference"`
}

// Valid reports whether the boundary is actually configured.
func (a Approval) Valid() bool {
	return strings.TrimSpace(a.ApprovedBy) != "" && strings.TrimSpace(a.TicketReference) != ""
}

// String renders the boundary for a log line.
func (a Approval) String() string {
	if !a.Valid() {
		return "not configured"
	}
	return fmt.Sprintf("%s (%s)", strings.TrimSpace(a.ApprovedBy), strings.TrimSpace(a.TicketReference))
}

// Item is one planned notification.
type Item struct {
	MessageID   string               `json:"messageId"`
	Destination Destination          `json:"destination"`
	Label       urgency.UrgencyLabel `json:"label"`
	Score       int                  `json:"score"`
	Reason      string               `json:"reason"`
	// Evidence lists the exact terms the deterministic pass matched, so a
	// reviewer sees why the item is here without opening the message body.
	Evidence []string `json:"evidence"`
}

// RoutingPlan is a dry-run description of what would be routed.
type RoutingPlan struct {
	// HeldForReview are decisions a human must see before any escalation could
	// even be considered.
	HeldForReview []Item `json:"heldForReview"`
	// Escalations are decisions that would reach a responder. They only exist
	// when an approval boundary authorised them.
	Escalations []Item `json:"escalations"`
	// Approval is the boundary that authorised the escalations.
	Approval Approval `json:"approval"`
}

// Empty reports whether nothing at all would be routed.
func (p RoutingPlan) Empty() bool {
	return len(p.HeldForReview) == 0 && len(p.Escalations) == 0
}

// Plan computes what would be routed, and routes nothing.
//
// The name is the contract. The safety rules are:
//
//   - A decision flagged for human review is never escalated. It goes to the
//     review queue and stops there, so a borderline or high impact case cannot
//     reach a responder before a person has seen it.
//   - Any escalation requires a valid approval boundary. Without one, Plan
//     fails closed and returns no plan at all, rather than a partial one, so a
//     caller cannot accidentally use the review half while the escalation half
//     is unauthorised.
//   - Every decision is validated first. A batch containing one malformed
//     decision produces no plan, so nothing is routed from a suspect batch.
func Plan(decisions []urgency.UrgencyDecision, approval Approval) (RoutingPlan, error) {
	for i, d := range decisions {
		if err := urgency.ValidateDecision(d); err != nil {
			return RoutingPlan{}, fmt.Errorf("refusing to route decision %d: %w", i, err)
		}
	}

	plan := RoutingPlan{
		Approval:      approval,
		HeldForReview: make([]Item, 0, len(decisions)),
		Escalations:   make([]Item, 0, len(decisions)),
	}

	var pending []Item
	for _, d := range decisions {
		switch {
		case d.NeedsReview:
			plan.HeldForReview = append(plan.HeldForReview, itemFor(d, DestinationHumanReview,
				"flagged for human review before any page or escalation"))
		case d.Label == urgency.LabelUrgent || d.Label == urgency.LabelHigh:
			pending = append(pending, itemFor(d, DestinationOnCall,
				"high urgency with no review flag"))
		}
	}

	if len(pending) > 0 && !approval.Valid() {
		return RoutingPlan{}, fmt.Errorf(
			"%w: %d decision(s) would reach a responder, set both approvedBy and ticketReference",
			ErrApprovalRequired, len(pending))
	}

	for i := range pending {
		pending[i].Reason = fmt.Sprintf("%s, authorised by %s", pending[i].Reason, approval)
	}
	plan.Escalations = pending

	return plan, nil
}

func itemFor(d urgency.UrgencyDecision, destination Destination, reason string) Item {
	evidence := make([]string, 0, len(d.TriggerSpans))
	for _, s := range d.TriggerSpans {
		term := s.Term
		if s.Negated {
			term = "not " + term
		}
		evidence = append(evidence, term)
	}

	return Item{
		MessageID:   d.ID,
		Destination: destination,
		Label:       d.Label,
		Score:       d.Score,
		Reason:      reason,
		Evidence:    evidence,
	}
}

// Render writes the dry run in a stable, human readable form.
func (p RoutingPlan) Render(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "routing plan (dry run, nothing was sent)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "approval boundary: %s\n", p.Approval); err != nil {
		return err
	}

	if len(p.HeldForReview) == 0 {
		if _, err := fmt.Fprintln(w, "held for human review: none"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "held for human review: %d\n", len(p.HeldForReview)); err != nil {
			return err
		}
		if err := renderItems(w, p.HeldForReview); err != nil {
			return err
		}
	}

	if len(p.Escalations) == 0 {
		_, err := fmt.Fprintln(w, "escalations: none")
		return err
	}
	if _, err := fmt.Fprintf(w, "escalations: %d\n", len(p.Escalations)); err != nil {
		return err
	}
	return renderItems(w, p.Escalations)
}

func renderItems(w io.Writer, items []Item) error {
	for _, it := range items {
		evidence := strings.Join(it.Evidence, " | ")
		if evidence == "" {
			evidence = "no term matched"
		}
		if _, err := fmt.Fprintf(w, "  - %s -> %s [%s %d] %s (evidence: %s)\n",
			it.MessageID, it.Destination, it.Label, it.Score, it.Reason, evidence); err != nil {
			return err
		}
	}
	return nil
}
