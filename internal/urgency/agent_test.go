package urgency

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/model"
)

// fakeLLM is a model.LLM returning a canned reply.
//
// Because model.LLM is an interface, everything around the model still runs for
// real: the ADK agent, the runner, the in-memory session, the event loop and the
// schema decoding. Only the network call is replaced, which is why the whole
// agent path can be tested without an API key.
type fakeLLM struct {
	reply string
	err   error
	calls int
}

func (f *fakeLLM) Name() string { return "fake-model" }

func (f *fakeLLM) GenerateContent(_ context.Context, _ *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		f.calls++
		if f.err != nil {
			yield(nil, f.err)
			return
		}
		yield(&model.LLMResponse{
			Content: genai.NewContentFromText(f.reply, genai.RoleModel),
		}, nil)
	}
}

// TestAgentConfigHasNoTools pins the safety property the plan asks for: the
// agent is built with no tools, so it has no way to page, notify or write
// anything even if a model asked to.
func TestAgentConfigHasNoTools(t *testing.T) {
	t.Parallel()

	cfg := agentConfig(&fakeLLM{})

	if len(cfg.Tools) != 0 {
		t.Fatalf("agentConfig().Tools has %d tools, want none", len(cfg.Tools))
	}
}

func TestAgentConfigUsesAClosedSchema(t *testing.T) {
	t.Parallel()

	cfg := agentConfig(&fakeLLM{})

	if cfg.GenerateContentConfig == nil {
		t.Fatal("GenerateContentConfig is nil, want a closed response schema")
	}
	if got := cfg.GenerateContentConfig.ResponseMIMEType; got != "application/json" {
		t.Errorf("ResponseMIMEType = %q, want %q", got, "application/json")
	}

	schema := cfg.GenerateContentConfig.ResponseSchema
	if schema == nil {
		t.Fatal("ResponseSchema is nil, want a closed schema")
	}
	if schema.Type != genai.TypeObject {
		t.Errorf("ResponseSchema.Type = %q, want %q", schema.Type, genai.TypeObject)
	}
	if len(schema.Required) != 1 || schema.Required[0] != "verdicts" {
		t.Errorf("ResponseSchema.Required = %v, want [verdicts]", schema.Required)
	}

	verdicts := schema.Properties["verdicts"]
	if verdicts == nil || verdicts.Type != genai.TypeArray || verdicts.Items == nil {
		t.Fatalf("verdicts property is not an array of objects: %+v", verdicts)
	}

	item := verdicts.Items
	labelSchema := item.Properties["label"]
	if labelSchema == nil {
		t.Fatal("verdict item has no label property")
	}

	// The label set in the schema must be exactly the closed label set.
	got := strings.Join(labelSchema.Enum, ",")
	want := strings.Join(labelStrings(), ",")
	if got != want {
		t.Errorf("label enum = %q, want %q", got, want)
	}
	if labelSchema.Format != "enum" {
		t.Errorf("label format = %q, want %q", labelSchema.Format, "enum")
	}

	for _, field := range []string{"id", "label", "score", "rationale", "needsReview"} {
		if _, ok := item.Properties[field]; !ok {
			t.Errorf("verdict schema has no %q property", field)
		}
		if !contains(item.Required, field) {
			t.Errorf("verdict schema does not require %q", field)
		}
	}

	// The model must not be able to describe evidence; spans stay deterministic.
	if _, ok := item.Properties["triggerSpans"]; ok {
		t.Error("verdict schema exposes triggerSpans, but evidence must stay deterministic")
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestReviewBatchRunsTheRealADKPath drives the agent through the actual runner
// with a fake model, so the session, event loop and decode are all exercised.
func TestReviewBatchRunsTheRealADKPath(t *testing.T) {
	t.Parallel()

	llm := &fakeLLM{reply: `{"verdicts":[
		{"id":"m1","label":"high","score":70,"rationale":"reports an outage","needsReview":true},
		{"id":"m2","label":"low","score":0,"rationale":"a social invitation","needsReview":false}
	]}`}

	classifier, err := NewAgentClassifierFromModel(llm)
	if err != nil {
		t.Fatalf("NewAgentClassifierFromModel() = %v, want nil", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	messages := []Message{
		{ID: "m1", Text: "El servidor está caído"},
		{ID: "m2", Text: "¿Vamos a tomar algo el viernes?"},
	}

	got, err := classifier.ReviewBatch(ctx, messages)
	if err != nil {
		t.Fatalf("ReviewBatch() = %v, want nil", err)
	}
	if llm.calls == 0 {
		t.Fatal("the model was never called")
	}
	if len(got) != 2 {
		t.Fatalf("got %d verdicts, want 2: %+v", len(got), got)
	}
	if got[0].ID != "m1" || got[0].Label != LabelHigh || got[0].Score != 70 || !got[0].NeedsReview {
		t.Errorf("verdict[0] = %+v, want m1/high/70/review", got[0])
	}
	if got[1].ID != "m2" || got[1].Label != LabelLow {
		t.Errorf("verdict[1] = %+v, want m2/low", got[1])
	}
}

func TestReviewBatchReportsAModelFailure(t *testing.T) {
	t.Parallel()

	llm := &fakeLLM{err: errors.New("quota exceeded")}
	classifier, err := NewAgentClassifierFromModel(llm)
	if err != nil {
		t.Fatalf("NewAgentClassifierFromModel() = %v, want nil", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = classifier.ReviewBatch(ctx, []Message{{ID: "m1", Text: "El servidor está caído"}})
	if err == nil {
		t.Fatal("ReviewBatch() = nil error, want the model failure surfaced")
	}
}

func TestReviewBatchRejectsAnEmptyBatch(t *testing.T) {
	t.Parallel()

	classifier, err := NewAgentClassifierFromModel(&fakeLLM{})
	if err != nil {
		t.Fatalf("NewAgentClassifierFromModel() = %v, want nil", err)
	}

	if _, err := classifier.ReviewBatch(context.Background(), nil); err == nil {
		t.Fatal("ReviewBatch(nil) = nil error, want an error")
	}
}

func TestNewAgentClassifierWithoutAKeyFailsClearly(t *testing.T) {
	// Not parallel: t.Setenv cannot be used from a parallel test.
	t.Setenv(APIKeyEnvVar, "")

	_, err := NewAgentClassifier(context.Background(), AgentConfig{})
	if err == nil {
		t.Fatal("NewAgentClassifier() = nil error, want a clear missing credentials error")
	}
	if !strings.Contains(err.Error(), APIKeyEnvVar) {
		t.Errorf("error = %q, want it to name %s", err, APIKeyEnvVar)
	}
}

func TestNewAgentClassifierFromModelRejectsNil(t *testing.T) {
	t.Parallel()

	if _, err := NewAgentClassifierFromModel(nil); err == nil {
		t.Fatal("NewAgentClassifierFromModel(nil) = nil error, want an error")
	}
}

func TestParseVerdicts(t *testing.T) {
	t.Parallel()

	messages := []Message{{ID: "m1", Text: "a"}, {ID: "m2", Text: "b"}}

	tests := []struct {
		name      string
		reply     string
		wantIDs   []string
		wantErr   bool
		wantScore int
	}{
		{
			name:    "decodes a plain reply",
			reply:   `{"verdicts":[{"id":"m1","label":"normal","score":150,"rationale":"r","needsReview":false}]}`,
			wantIDs: []string{"m1"},
			// out of range is clamped rather than rejected
			wantScore: 100,
		},
		{
			name:    "decodes a reply wrapped in a markdown fence",
			reply:   "```json\n{\"verdicts\":[{\"id\":\"m1\",\"label\":\"low\",\"score\":0,\"rationale\":\"r\",\"needsReview\":false}]}\n```",
			wantIDs: []string{"m1"},
		},
		{
			name:    "discards an invented id",
			reply:   `{"verdicts":[{"id":"m9","label":"urgent","score":99,"rationale":"r","needsReview":true},{"id":"m2","label":"low","score":0,"rationale":"r","needsReview":false}]}`,
			wantIDs: []string{"m2"},
		},
		{
			name:    "discards a label outside the closed set",
			reply:   `{"verdicts":[{"id":"m1","label":"critical","score":99,"rationale":"r","needsReview":true},{"id":"m2","label":"low","score":0,"rationale":"r","needsReview":false}]}`,
			wantIDs: []string{"m2"},
		},
		{
			name:    "tolerates a partial reply because the rest falls back to the rules",
			reply:   `{"verdicts":[{"id":"m1","label":"high","score":60,"rationale":"r","needsReview":true}]}`,
			wantIDs: []string{"m1"},
		},
		{
			name:    "errors when no verdict is usable",
			reply:   `{"verdicts":[{"id":"m9","label":"urgent","score":99,"rationale":"r","needsReview":true}]}`,
			wantErr: true,
		},
		{
			name:    "errors when the reply has no JSON object",
			reply:   "I am afraid I cannot help with that.",
			wantErr: true,
		},
		{
			name:    "errors when the reply is invalid JSON",
			reply:   `{"verdicts":[`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseVerdicts(tt.reply, messages)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseVerdicts() = %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVerdicts() = %v, want nil", err)
			}

			ids := make([]string, 0, len(got))
			for _, v := range got {
				ids = append(ids, v.ID)
			}
			if strings.Join(ids, ",") != strings.Join(tt.wantIDs, ",") {
				t.Fatalf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if tt.wantScore != 0 && got[0].Score != tt.wantScore {
				t.Errorf("score = %d, want %d", got[0].Score, tt.wantScore)
			}
		})
	}
}

func TestApplyVerdict(t *testing.T) {
	t.Parallel()

	deterministic := func() UrgencyDecision {
		return Classify(Message{ID: "m1", Text: "No es urgente, pero el servidor está caído"})
	}

	t.Run("keeps every deterministic span untouched", func(t *testing.T) {
		t.Parallel()

		d := deterministic()
		before := append([]TriggerSpan(nil), d.TriggerSpans...)

		merged := ApplyVerdict(d, Verdict{ID: "m1", Label: LabelLow, Score: 0, Rationale: "seems fine"})

		if len(merged.TriggerSpans) != len(before) {
			t.Fatalf("got %d spans, want %d", len(merged.TriggerSpans), len(before))
		}
		for i := range before {
			if merged.TriggerSpans[i] != before[i] {
				t.Errorf("spans[%d] changed: %+v -> %+v", i, before[i], merged.TriggerSpans[i])
			}
		}
	})

	t.Run("cannot clear a review flag the rules raised", func(t *testing.T) {
		t.Parallel()

		d := deterministic()
		if !d.NeedsReview {
			t.Fatalf("fixture assumption broken: needsReview is already false for %+v", d)
		}

		merged := ApplyVerdict(d, Verdict{ID: "m1", Label: LabelLow, Score: 0, Rationale: "seems fine"})

		if !merged.NeedsReview {
			t.Fatal("NeedsReview = false, but a verdict must never clear it")
		}
	})

	t.Run("a verdict that disagrees with the label raises a review", func(t *testing.T) {
		t.Parallel()

		d := Classify(Message{ID: "m1", Text: "¿Confirmamos la reunión del jueves a las 10?"})
		if d.NeedsReview {
			t.Fatalf("fixture assumption broken: %+v already needs review", d)
		}

		merged := ApplyVerdict(d, Verdict{ID: "m1", Label: LabelHigh, Score: 60, Rationale: "hidden deadline"})

		if !merged.NeedsReview {
			t.Fatal("NeedsReview = false, but the verdict contradicted the deterministic label")
		}
		if merged.Label != LabelHigh || merged.Score != 60 {
			t.Errorf("merged = %s/%d, want high/60", merged.Label, merged.Score)
		}
	})

	t.Run("ignores a label outside the closed set", func(t *testing.T) {
		t.Parallel()

		d := deterministic()
		merged := ApplyVerdict(d, Verdict{ID: "m1", Label: "critical", Score: 99, Rationale: "panic"})

		if merged.Label != d.Label || merged.Score != d.Score || merged.Rationale != d.Rationale {
			t.Errorf("merged = %+v, want the deterministic decision kept whole", merged)
		}
	})

	t.Run("always produces a decision the contract accepts", func(t *testing.T) {
		t.Parallel()

		d := Classify(Message{ID: "m1", Text: "¿Confirmamos la reunión del jueves a las 10?"})
		for _, v := range []Verdict{
			{ID: "m1", Label: LabelUrgent, Score: 95, Rationale: "a deadline is implied"},
			{ID: "m1", Label: LabelLow, Score: 0},
			{ID: "m1", Label: "nonsense", Score: 40, Rationale: "r"},
			{ID: "m1", Label: LabelNormal, Score: -20, Rationale: "r"},
		} {
			if err := ValidateDecision(ApplyVerdict(d, v)); err != nil {
				t.Errorf("ApplyVerdict(%+v) produced an invalid decision: %v", v, err)
			}
		}
	})
}
