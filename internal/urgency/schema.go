// Package urgency holds the frozen urgency contract, the policy that maps
// evidence to labels, and the deterministic rules that classify a message
// before any model is consulted.
//
// The contract in this file is the boundary of the whole program: callers pass
// an UrgencyRequest in and read UrgencyDecision values out. Nothing in this
// package reads a messaging system, pages a responder, or mutates a queue.
package urgency

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// CurrentPolicyVersion is the policy this build implements. A request may carry
// any non-empty version; the value is recorded so a decision can always be
// traced back to the policy that produced it.
const CurrentPolicyVersion = "1.0.0"

// Score bounds. A score is always a whole number in [MinScore, MaxScore].
const (
	MinScore = 0
	MaxScore = 100
)

// Band boundaries. A score at or above the minimum belongs to that band.
const (
	BandUrgentMin = 80
	BandHighMin   = 55
	BandNormalMin = 25

	// BorderlineDelta is the distance to the nearest band boundary within which
	// a score is considered too close to call and is routed to human review.
	BorderlineDelta = 10
)

// UrgencyLabel is the closed set of urgency labels.
type UrgencyLabel string

// The closed label set, fixed by the agent instruction: "Classify the urgency of
// supplied messages as urgent, high, normal, or low."
const (
	LabelUrgent UrgencyLabel = "urgent"
	LabelHigh   UrgencyLabel = "high"
	LabelNormal UrgencyLabel = "normal"
	LabelLow    UrgencyLabel = "low"
)

// Labels returns the closed set in descending severity order.
func Labels() []UrgencyLabel {
	return []UrgencyLabel{LabelUrgent, LabelHigh, LabelNormal, LabelLow}
}

// Valid reports whether the label belongs to the closed set.
func (l UrgencyLabel) Valid() bool {
	return slices.Contains(Labels(), l)
}

// SeverityRank orders labels by severity, lowest number first. It is the
// primary sort key for a batch so that the most severe messages come out on top.
func (l UrgencyLabel) SeverityRank() int {
	switch l {
	case LabelUrgent:
		return 0
	case LabelHigh:
		return 1
	case LabelNormal:
		return 2
	case LabelLow:
		return 3
	default:
		return 4
	}
}

// ParseLabel resolves a label from external input.
func ParseLabel(s string) (UrgencyLabel, error) {
	l := UrgencyLabel(strings.ToLower(strings.TrimSpace(s)))
	if !l.Valid() {
		return "", fmt.Errorf("unknown urgency label %q: want one of %s", s, joinLabels())
	}
	return l, nil
}

func joinLabels() string {
	parts := make([]string, 0, len(Labels()))
	for _, l := range Labels() {
		parts = append(parts, string(l))
	}
	return strings.Join(parts, ", ")
}

// LabelForScore maps a score to its band.
func LabelForScore(score int) UrgencyLabel {
	switch {
	case score >= BandUrgentMin:
		return LabelUrgent
	case score >= BandHighMin:
		return LabelHigh
	case score >= BandNormalMin:
		return LabelNormal
	default:
		return LabelLow
	}
}

// IsBorderline reports whether a score sits within BorderlineDelta of a band
// boundary and is therefore too close to call by score alone.
func IsBorderline(score int) bool {
	for _, boundary := range []int{BandNormalMin, BandHighMin, BandUrgentMin} {
		delta := score - boundary
		if delta < 0 {
			delta = -delta
		}
		if delta <= BorderlineDelta {
			return true
		}
	}
	return false
}

// TriggerKind classifies the evidence a span carries.
type TriggerKind string

// The closed set of trigger kinds.
const (
	KindThreat       TriggerKind = "threat"
	KindIncident     TriggerKind = "incident"
	KindDeadline     TriggerKind = "deadline"
	KindRequest      TriggerKind = "request"
	KindDeescalation TriggerKind = "deescalation"
	// KindNone records that the text held no recognized trigger term. It carries
	// weight 0 and exists so that every decision can point at the evidence it
	// was based on, including the evidence that nothing was found.
	KindNone TriggerKind = "none"
)

// Weights contribute to a score. A deescalation term subtracts.
const (
	WeightThreat       = 60
	WeightIncident     = 45
	WeightDeadline     = 30
	WeightRequest      = 10
	WeightDeescalation = -15
	WeightNone         = 0
)

// Weight returns the score contribution of a trigger kind.
func (k TriggerKind) Weight() int {
	switch k {
	case KindThreat:
		return WeightThreat
	case KindIncident:
		return WeightIncident
	case KindDeadline:
		return WeightDeadline
	case KindRequest:
		return WeightRequest
	case KindDeescalation:
		return WeightDeescalation
	default:
		return WeightNone
	}
}

// Valid reports whether the kind belongs to the closed set.
func (k TriggerKind) Valid() bool {
	switch k {
	case KindThreat, KindIncident, KindDeadline, KindRequest, KindDeescalation, KindNone:
		return true
	default:
		return false
	}
}

// Message is one message to classify.
type Message struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// UrgencyRequest is the frozen input contract.
type UrgencyRequest struct {
	Messages      []Message `json:"messages"`
	PolicyVersion string    `json:"policyVersion"`
}

// TriggerSpan points at the evidence behind a decision.
//
// Start and End are half-open rune offsets: they index []rune(message.Text),
// not bytes. Rune offsets keep a span correct for accented Spanish and for any
// other non-ASCII text, where a byte offset would slice a character in half.
//
// The invariant Term == string([]rune(text)[Start:End]) holds for every span,
// including KindNone. VerifySpans enforces it.
type TriggerSpan struct {
	Start   int         `json:"start"`
	End     int         `json:"end"`
	Term    string      `json:"term"`
	Kind    TriggerKind `json:"kind"`
	Weight  int         `json:"weight"`
	Negated bool        `json:"negated"`
}

// UrgencyDecision is the frozen output contract.
type UrgencyDecision struct {
	ID           string        `json:"id"`
	Label        UrgencyLabel  `json:"label"`
	Score        int           `json:"score"`
	TriggerSpans []TriggerSpan `json:"triggerSpans"`
	Rationale    string        `json:"rationale"`
	NeedsReview  bool          `json:"needsReview"`
}

// Bounds for free-text fields, so a malformed or hostile request cannot produce
// an unbounded decision.
const (
	MaxMessageIDLength = 128
	MaxMessageTextLen  = 8192
)

// ValidateRequest checks the input contract.
func ValidateRequest(r UrgencyRequest) error {
	if strings.TrimSpace(r.PolicyVersion) == "" {
		return errors.New("policyVersion is required")
	}
	if len(r.Messages) == 0 {
		return errors.New("at least one message is required")
	}
	seen := make(map[string]struct{}, len(r.Messages))
	for i, m := range r.Messages {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			return fmt.Errorf("messages[%d]: id is required", i)
		}
		if len(id) > MaxMessageIDLength {
			return fmt.Errorf("messages[%d]: id exceeds %d characters", i, MaxMessageIDLength)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("messages[%d]: duplicate id %q", i, id)
		}
		seen[id] = struct{}{}
		if strings.TrimSpace(m.Text) == "" {
			return fmt.Errorf("messages[%d] (%s): text is required", i, id)
		}
		if len([]rune(m.Text)) > MaxMessageTextLen {
			return fmt.Errorf("messages[%d] (%s): text exceeds %d runes", i, id, MaxMessageTextLen)
		}
	}
	return nil
}

// ValidateDecision checks the output contract.
//
// The rule that ties evidence to a label is deliberate: a decision must carry
// at least one span, and a non-zero score is only allowed when at least one
// span actually contributed to it. A label can therefore never appear without
// the evidence that produced it.
func ValidateDecision(d UrgencyDecision) error {
	if strings.TrimSpace(d.ID) == "" {
		return errors.New("decision id is required")
	}
	if !d.Label.Valid() {
		return fmt.Errorf("decision %s: invalid label %q: want one of %s", d.ID, d.Label, joinLabels())
	}
	if d.Score < MinScore || d.Score > MaxScore {
		return fmt.Errorf("decision %s: score %d out of range [%d, %d]", d.ID, d.Score, MinScore, MaxScore)
	}
	if strings.TrimSpace(d.Rationale) == "" {
		return fmt.Errorf("decision %s: rationale is required", d.ID)
	}
	if len(d.TriggerSpans) == 0 {
		return fmt.Errorf("decision %s: at least one trigger span is required", d.ID)
	}
	if d.Score != 0 {
		var contributed bool
		for _, s := range d.TriggerSpans {
			if s.Weight != 0 {
				contributed = true
				break
			}
		}
		if !contributed {
			return fmt.Errorf("decision %s: score %d has no contributing trigger span", d.ID, d.Score)
		}
	}
	for i, s := range d.TriggerSpans {
		if !s.Kind.Valid() {
			return fmt.Errorf("decision %s: triggerSpans[%d]: invalid kind %q", d.ID, i, s.Kind)
		}
		if s.Start < 0 || s.End <= s.Start {
			return fmt.Errorf("decision %s: triggerSpans[%d]: invalid range [%d, %d)", d.ID, i, s.Start, s.End)
		}
	}
	return nil
}

// VerifySpans enforces the span invariant against the text a decision came from:
// Term must be exactly the runes the span covers. This is what makes a rune
// offset bug impossible to miss, because a byte offset on non-ASCII text
// produces a Term that no longer matches the source.
func VerifySpans(text string, spans []TriggerSpan) error {
	runes := []rune(text)
	for i, s := range spans {
		if s.Start < 0 || s.End > len(runes) || s.End <= s.Start {
			return fmt.Errorf("triggerSpans[%d]: range [%d, %d) outside text of %d runes", i, s.Start, s.End, len(runes))
		}
		if got := string(runes[s.Start:s.End]); got != s.Term {
			return fmt.Errorf("triggerSpans[%d]: term %q does not match text[%d:%d] = %q", i, s.Term, s.Start, s.End, got)
		}
	}
	return nil
}

// Clamp truncates a computed score into the valid range.
func Clamp(score int) int {
	if score < MinScore {
		return MinScore
	}
	if score > MaxScore {
		return MaxScore
	}
	return score
}

// SortDecisions orders a batch by descending severity, then by descending
// score, then by message id so the output is stable across runs.
func SortDecisions(decisions []UrgencyDecision) {
	slices.SortStableFunc(decisions, func(a, b UrgencyDecision) int {
		if c := a.Label.SeverityRank() - b.Label.SeverityRank(); c != 0 {
			return c
		}
		if c := b.Score - a.Score; c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}
