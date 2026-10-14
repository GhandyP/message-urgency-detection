package urgency

import (
	"strconv"
	"strings"
	"testing"
)

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request UrgencyRequest
		wantErr string
	}{
		{
			name: "accepts a well formed request",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages:      []Message{{ID: "m1", Text: "the server is down"}},
			},
		},
		{
			name: "rejects a missing policy version",
			request: UrgencyRequest{
				Messages: []Message{{ID: "m1", Text: "the server is down"}},
			},
			wantErr: "policyVersion is required",
		},
		{
			name: "rejects a blank policy version",
			request: UrgencyRequest{
				PolicyVersion: "   ",
				Messages:      []Message{{ID: "m1", Text: "the server is down"}},
			},
			wantErr: "policyVersion is required",
		},
		{
			name:    "rejects an empty batch",
			request: UrgencyRequest{PolicyVersion: CurrentPolicyVersion},
			wantErr: "at least one message is required",
		},
		{
			name: "rejects a missing id",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages:      []Message{{Text: "the server is down"}},
			},
			wantErr: "messages[0]: id is required",
		},
		{
			name: "rejects a duplicate id",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages: []Message{
					{ID: "m1", Text: "first"},
					{ID: "m1", Text: "second"},
				},
			},
			wantErr: `messages[1]: duplicate id "m1"`,
		},
		{
			name: "rejects blank text",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages:      []Message{{ID: "m1", Text: "   "}},
			},
			wantErr: "text is required",
		},
		{
			name: "rejects an oversized id",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages:      []Message{{ID: strings.Repeat("a", MaxMessageIDLength+1), Text: "hi"}},
			},
			wantErr: "id exceeds 128 characters",
		},
		{
			name: "rejects oversized text",
			request: UrgencyRequest{
				PolicyVersion: CurrentPolicyVersion,
				Messages:      []Message{{ID: "m1", Text: strings.Repeat("á", MaxMessageTextLen+1)}},
			},
			wantErr: "text exceeds 8192 runes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRequest(tt.request)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("ValidateRequest() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("ValidateRequest() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("ValidateRequest() = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRequestCountsRunesNotBytes(t *testing.T) {
	t.Parallel()

	// "á" is two bytes but one rune, so a byte counted limit would reject a
	// message that is exactly at the rune limit.
	request := UrgencyRequest{
		PolicyVersion: CurrentPolicyVersion,
		Messages:      []Message{{ID: "m1", Text: strings.Repeat("á", MaxMessageTextLen)}},
	}

	if err := ValidateRequest(request); err != nil {
		t.Fatalf("ValidateRequest() = %v, want nil for exactly %d runes", err, MaxMessageTextLen)
	}
}

func TestValidateDecision(t *testing.T) {
	t.Parallel()

	valid := UrgencyDecision{
		ID:           "m1",
		Label:        LabelUrgent,
		Score:        WeightThreat,
		TriggerSpans: []TriggerSpan{{Start: 0, End: 4, Term: "bomb", Kind: KindThreat, Weight: WeightThreat}},
		Rationale:    "threat term present",
		NeedsReview:  true,
	}

	tests := []struct {
		name     string
		decision UrgencyDecision
		wantErr  string
	}{
		{name: "accepts a well formed decision", decision: valid},
		{
			name: "rejects a missing id",
			decision: UrgencyDecision{
				Label:        LabelLow,
				Score:        0,
				TriggerSpans: valid.TriggerSpans,
				Rationale:    "no trigger",
			},
			wantErr: "decision id is required",
		},
		{
			name:     "rejects an unknown label",
			decision: withLabel(valid, "critical"),
			wantErr:  `invalid label "critical"`,
		},
		{
			name:     "rejects a negative score",
			decision: withScore(valid, -1),
			wantErr:  "score -1 out of range [0, 100]",
		},
		{
			name:     "rejects a score above the maximum",
			decision: withScore(valid, 101),
			wantErr:  "score 101 out of range [0, 100]",
		},
		{
			name:     "rejects a missing rationale",
			decision: withRationale(valid, "   "),
			wantErr:  "rationale is required",
		},
		{
			name:     "rejects a decision with no span",
			decision: withSpans(valid, nil),
			wantErr:  "at least one trigger span is required",
		},
		{
			name: "accepts a score a model verdict justified rather than a span",
			// Evidence stays deterministic while a verdict is advisory, so a
			// refined score legitimately has no lexical span behind it. The
			// arithmetic rule is pinned on Classify instead.
			decision: UrgencyDecision{
				ID:           "m1",
				Label:        LabelHigh,
				Score:        60,
				TriggerSpans: []TriggerSpan{{Start: 0, End: 3, Term: "sin", Kind: KindNone, Weight: WeightNone}},
				Rationale:    "deterministic pass found nothing; a model review raised this",
			},
		},
		{
			name:     "rejects a label that disagrees with the score",
			decision: withScore(withLabel(valid, LabelLow), 90),
			wantErr:  "does not match score 90",
		},
		{
			name: "rejects an unknown trigger kind",
			decision: withSpans(valid, []TriggerSpan{
				{Start: 0, End: 4, Term: "bomb", Kind: "panic", Weight: WeightThreat},
			}),
			wantErr: `invalid kind "panic"`,
		},
		{
			name: "rejects an empty span range",
			decision: withSpans(valid, []TriggerSpan{
				{Start: 4, End: 4, Term: "", Kind: KindThreat, Weight: WeightThreat},
			}),
			wantErr: "invalid range [4, 4)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateDecision(tt.decision)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("ValidateDecision() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("ValidateDecision() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("ValidateDecision() = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func withLabel(d UrgencyDecision, label UrgencyLabel) UrgencyDecision {
	d.Label = label
	return d
}

func withScore(d UrgencyDecision, score int) UrgencyDecision {
	d.Score = score
	return d
}

func withRationale(d UrgencyDecision, rationale string) UrgencyDecision {
	d.Rationale = rationale
	return d
}

func withSpans(d UrgencyDecision, spans []TriggerSpan) UrgencyDecision {
	d.TriggerSpans = spans
	return d
}

// TestVerifySpansCatchesByteOffsets pins what the span invariant does and does
// not prove.
//
// It proves every span is well formed against its own source: Term is exactly
// the runes the span covers. That is what makes an off-by-N offset visible,
// because on non-ASCII text a byte range lands on the wrong characters or runs
// past the end of the text.
//
// It does not prove a span marks the *right* text. A self consistent span can
// still point at the wrong characters, so the rules tests additionally assert
// the exact expected term and offsets for each trigger.
func TestVerifySpansCatchesByteOffsets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		text    string
		span    TriggerSpan
		wantErr bool
	}{
		{
			name: "accepts a rune offset over an inverted exclamation mark",
			text: "¡Alerta!",
			// runes:    ¡  A l e r t a  !
			// index:    0  1 2 3 4 5 6  7
			span: TriggerSpan{Start: 1, End: 7, Term: "Alerta", Kind: KindIncident, Weight: WeightIncident},
		},
		{
			name: "rejects byte offsets carrying the right term",
			text: "¡Alerta!",
			// The real failure mode of a byte offset: the term is correct but the
			// range is not, so the span points at "lerta!" while claiming "Alerta".
			span:    TriggerSpan{Start: 2, End: 8, Term: "Alerta", Kind: KindIncident, Weight: WeightIncident},
			wantErr: true,
		},
		{
			name: "accepts a self consistent span that marks the wrong text",
			text: "¡Alerta!",
			// Honest limitation: runes[2:8] really is "lerta!", so this span is
			// internally consistent and VerifySpans cannot reject it. Proving a
			// span marks the *right* text is the rules' job, which asserts the
			// exact expected term and offsets. VerifySpans only proves that a
			// span is well formed against its own source.
			span: TriggerSpan{Start: 2, End: 8, Term: "lerta!", Kind: KindIncident, Weight: WeightIncident},
		},
		{
			name: "accepts a rune offset after an emoji",
			text: "🚨 urgente",
			// runes:    🚨 ' '  u r g e n t e
			// index:    0   1  2 3 4 5 6 7 8
			span: TriggerSpan{Start: 2, End: 9, Term: "urgente", Kind: KindDeadline, Weight: WeightDeadline},
		},
		{
			name: "rejects the byte offset after an emoji",
			text: "🚨 urgente",
			// The emoji is 4 bytes but 1 rune, so the byte offset of "urgente"
			// is [5, 12) while its rune offset is [2, 9). The byte values run
			// past the end of a 9 rune text, which is exactly the failure a byte
			// offset produces on non-ASCII input.
			span:    TriggerSpan{Start: 5, End: 12, Term: "urgente", Kind: KindDeadline, Weight: WeightDeadline},
			wantErr: true,
		},
		{
			name:    "rejects a term that does not match its range",
			text:    "the server is down",
			span:    TriggerSpan{Start: 4, End: 10, Term: "server is down", Kind: KindIncident, Weight: WeightIncident},
			wantErr: true,
		},
		{
			name:    "rejects an end past the text",
			text:    "short",
			span:    TriggerSpan{Start: 0, End: 99, Term: "short", Kind: KindNone, Weight: WeightNone},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := VerifySpans(tt.text, []TriggerSpan{tt.span})
			if tt.wantErr && err == nil {
				t.Fatalf("VerifySpans(%q, %+v) = nil, want an error", tt.text, tt.span)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("VerifySpans(%q, %+v) = %v, want nil", tt.text, tt.span, err)
			}
		})
	}
}

func TestLabelForScoreBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		score int
		want  UrgencyLabel
	}{
		{score: 0, want: LabelLow},
		{score: 24, want: LabelLow},
		{score: 25, want: LabelNormal},
		{score: 54, want: LabelNormal},
		{score: 55, want: LabelHigh},
		{score: 79, want: LabelHigh},
		{score: 80, want: LabelUrgent},
		{score: 100, want: LabelUrgent},
	}

	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.score), func(t *testing.T) {
			t.Parallel()

			if got := LabelForScore(tt.score); got != tt.want {
				t.Fatalf("LabelForScore(%d) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}

func TestIsBorderline(t *testing.T) {
	t.Parallel()

	// Pins both edges of every borderline band, so a change to BorderlineDelta
	// has to be deliberate rather than incidental.
	tests := []struct {
		score int
		want  bool
	}{
		{score: 0, want: false},
		{score: 19, want: false},
		{score: 20, want: true},
		{score: 25, want: true},
		{score: 30, want: true},
		{score: 31, want: false},
		{score: 49, want: false},
		{score: 50, want: true},
		{score: 55, want: true},
		{score: 60, want: true},
		{score: 61, want: false},
		{score: 74, want: false},
		{score: 75, want: true},
		{score: 80, want: true},
		{score: 85, want: true},
		{score: 86, want: false},
		{score: 100, want: false},
	}

	for _, tt := range tests {
		if got := IsBorderline(tt.score); got != tt.want {
			t.Errorf("IsBorderline(%d) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestClamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   int
		want int
	}{
		{in: -50, want: 0},
		{in: 0, want: 0},
		{in: 55, want: 55},
		{in: 100, want: 100},
		{in: 250, want: 100},
	}

	for _, tt := range tests {
		if got := Clamp(tt.in); got != tt.want {
			t.Errorf("Clamp(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseLabel(t *testing.T) {
	t.Parallel()

	if got, err := ParseLabel("  URGENT "); err != nil || got != LabelUrgent {
		t.Fatalf("ParseLabel(\"  URGENT \") = (%q, %v), want (%q, nil)", got, err, LabelUrgent)
	}
	if _, err := ParseLabel("critical"); err == nil {
		t.Fatal("ParseLabel(\"critical\") = nil error, want an error naming the closed set")
	} else if !strings.Contains(err.Error(), "urgent, high, normal, low") {
		t.Fatalf("ParseLabel(\"critical\") error = %q, want it to list the closed set", err)
	}
}

func TestSortDecisions(t *testing.T) {
	t.Parallel()

	decisions := []UrgencyDecision{
		{ID: "m4", Label: LabelLow, Score: 0, TriggerSpans: noneSpan(), Rationale: "r"},
		{ID: "m1", Label: LabelUrgent, Score: 60, TriggerSpans: noneSpan(), Rationale: "r"},
		{ID: "m3", Label: LabelHigh, Score: 45, TriggerSpans: noneSpan(), Rationale: "r"},
		{ID: "m2", Label: LabelUrgent, Score: 75, TriggerSpans: noneSpan(), Rationale: "r"},
		{ID: "m5", Label: LabelHigh, Score: 45, TriggerSpans: noneSpan(), Rationale: "r"},
	}

	SortDecisions(decisions)

	want := []string{"m2", "m1", "m3", "m5", "m4"}
	for i, w := range want {
		if decisions[i].ID != w {
			got := make([]string, 0, len(decisions))
			for _, d := range decisions {
				got = append(got, d.ID)
			}
			t.Fatalf("SortDecisions() order = %v, want %v", got, want)
		}
	}
}

func noneSpan() []TriggerSpan {
	return []TriggerSpan{{Start: 0, End: 1, Term: "x", Kind: KindNone, Weight: WeightNone}}
}
