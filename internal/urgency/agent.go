// This file is the only place in the repository that talks to a model.
//
// It follows the plan's ADK layer requirement literally: a closed response
// schema, a batch session, the deterministic rules ahead of the model, and no
// write tools. The agent is constructed with an empty tool list, so it has no
// way to page, route or mutate anything even if a model tried to.
package urgency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/genai"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/runner"
)

const (
	// AgentAppName identifies this application to the ADK session and runner.
	AgentAppName = "message-urgency-detection"

	// DefaultAgentModel is used when no model is configured.
	DefaultAgentModel = "gemini-flash-latest"

	// APIKeyEnvVar holds the Google API key.
	APIKeyEnvVar = "GOOGLE_API_KEY"

	// ModelEnvVar overrides the model name.
	ModelEnvVar = "ADK_MODEL"

	// agentUserID is the single synthetic user every batch runs under.
	agentUserID = "urgency-batch"

	// agentName must be unique in the agent tree and is not the reserved name
	// "user".
	agentName = "urgency_classifier"
)

// agentInstructionBase is preserved verbatim from the original prototype
// because it is what fixes the closed label set to urgent, high, normal and low.
const agentInstructionBase = "Classify the urgency of supplied messages as urgent, high, normal, or low. " +
	"Explain trigger evidence and do not infer deadlines not in the text."

// agentInstruction adds the operating rules the batch session needs on top of
// the preserved instruction: one verdict per supplied id, no invented ids, no
// invented deadlines, and the right to say the case is too close to call.
const agentInstruction = agentInstructionBase + `

You are a fallback. A deterministic keyword pass has already run and you are
only consulted when it was inconclusive, so a message may contain no trigger
term at all.

Return exactly one verdict for each message id you were given, and reuse the id
verbatim. Never invent an id and never omit one.

Rules you must follow:

- Judge only from the text. Never infer a deadline, an owner or an escalation
  that is not written in the message.
- "needsReview" is true when the case is genuinely too close to call, when a
  threat or safety concern is present, or when you are not confident.
- Never set "needsReview" to false just because you are reasonably sure. A human
  reviewer, not you, decides whether a message is safe to page on.
- Give the shortest useful reason in "rationale", naming the words or phrases in
  the text that drove your answer.
- If the text is not in a language you can judge, say so in the rationale and
  set "needsReview" to true.`

// AgentConfig configures the model backed classifier.
type AgentConfig struct {
	// APIKey is the Google API key. Empty means read APIKeyEnvVar.
	APIKey string
	// Model overrides the model name. Empty means read ModelEnvVar, then
	// DefaultAgentModel.
	Model string
}

// Verdict is the whole of what a model is allowed to return for one message.
//
// Note what is missing: there is no field for a trigger span. Evidence is
// deterministic and a model cannot invent, move or delete the term a decision
// points at.
type Verdict struct {
	ID          string       `json:"id"`
	Label       UrgencyLabel `json:"label"`
	Score       int          `json:"score"`
	Rationale   string       `json:"rationale"`
	NeedsReview bool         `json:"needsReview"`
}

// verdictEnvelope is the closed response shape the agent is constrained to.
type verdictEnvelope struct {
	Verdicts []Verdict `json:"verdicts"`
}

// AgentClassifier runs the schema constrained model pass over a batch.
type AgentClassifier struct {
	runner *runner.Runner
}

// NewAgentClassifier builds the classifier from a Gemini model.
//
// It fails fast and clearly when no API key is present, rather than building an
// agent that only fails on the first call.
func NewAgentClassifier(ctx context.Context, cfg AgentConfig) (*AgentClassifier, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv(APIKeyEnvVar))
	}
	if apiKey == "" {
		return nil, fmt.Errorf("no model credentials: set %s to use the agent fallback", APIKeyEnvVar)
	}

	llm, err := gemini.NewModel(ctx, modelName(cfg.Model), &genai.ClientConfig{APIKey: apiKey})
	if err != nil {
		return nil, fmt.Errorf("create gemini model: %w", err)
	}
	return newAgentClassifier(llm)
}

// NewAgentClassifierFromModel builds the classifier from any model.LLM.
//
// model.LLM is an interface, so this is the seam that lets the whole ADK path,
// the runner, the session, the event loop and the schema decoding, be exercised
// by a test without a network call or an API key.
func NewAgentClassifierFromModel(llm model.LLM) (*AgentClassifier, error) {
	if llm == nil {
		return nil, errors.New("model is required")
	}
	return newAgentClassifier(llm)
}

func newAgentClassifier(llm model.LLM) (*AgentClassifier, error) {
	root, err := llmagent.New(agentConfig(llm))
	if err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	r, err := runner.NewInMemory(AgentAppName, root)
	if err != nil {
		return nil, fmt.Errorf("create runner: %w", err)
	}
	return &AgentClassifier{runner: r}, nil
}

func modelName(override string) string {
	if name := strings.TrimSpace(override); name != "" {
		return name
	}
	if name := strings.TrimSpace(os.Getenv(ModelEnvVar)); name != "" {
		return name
	}
	return DefaultAgentModel
}

// agentConfig is separated out so a test can assert the safety property that
// matters most here: the agent is built with no tools at all.
func agentConfig(llm model.LLM) llmagent.Config {
	return llmagent.Config{
		Name:        agentName,
		Description: "Classifies supplied messages by urgency and explains the evidence.",
		Instruction: agentInstruction,
		Model:       llm,
		// No Tools field is set, deliberately. This agent must not be able to
		// page, notify, route or write anywhere.
		GenerateContentConfig: &genai.GenerateContentConfig{
			ResponseMIMEType: "application/json",
			ResponseSchema:   verdictResponseSchema(),
		},
	}
}

// verdictResponseSchema is the closed schema the model is constrained to.
func verdictResponseSchema() *genai.Schema {
	scoreMin, scoreMax := 0.0, 100.0

	return &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"verdicts": {
				Type: genai.TypeArray,
				Items: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"id": {
							Type:        genai.TypeString,
							Description: "The message id exactly as supplied. Never invented.",
						},
						"label": {
							Type:        genai.TypeString,
							Format:      "enum",
							Enum:        labelStrings(),
							Description: "Urgency label. The set is closed.",
						},
						"score": {
							Type:        genai.TypeInteger,
							Minimum:     &scoreMin,
							Maximum:     &scoreMax,
							Description: "Urgency score from 0 to 100.",
						},
						"rationale": {
							Type:        genai.TypeString,
							Description: "Shortest useful reason, naming the words that drove the answer.",
						},
						"needsReview": {
							Type:        genai.TypeBoolean,
							Description: "True when the case is too close to call or a human must look.",
						},
					},
					Required: []string{"id", "label", "score", "rationale", "needsReview"},
				},
			},
		},
		Required: []string{"verdicts"},
	}
}

func labelStrings() []string {
	labels := Labels()
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		out = append(out, string(l))
	}
	return out
}

// promptPayload is the batch handed to the model. Sending the ids as JSON keeps
// them exact rather than re-typed inside a sentence.
type promptPayload struct {
	Messages []Message `json:"messages"`
}

// ReviewBatch asks the model to classify a whole batch in one session.
func (c *AgentClassifier) ReviewBatch(ctx context.Context, messages []Message) ([]Verdict, error) {
	if len(messages) == 0 {
		return nil, errors.New("no messages to review")
	}

	payload, err := json.Marshal(promptPayload{Messages: messages})
	if err != nil {
		return nil, fmt.Errorf("encode batch: %w", err)
	}

	raw, err := c.runOnce(ctx, genai.NewContentFromText(string(payload), genai.RoleUser))
	if err != nil {
		return nil, err
	}
	return parseVerdicts(raw, messages)
}

var batchSeq atomic.Int64

// newSessionID keeps each batch in its own session so one batch can never see
// another batch's history.
func newSessionID() string {
	return fmt.Sprintf("batch-%d-%d", time.Now().UnixNano(), batchSeq.Add(1))
}

// runOnce runs the agent exactly once and returns the text of the final
// response.
func (c *AgentClassifier) runOnce(ctx context.Context, content *genai.Content) (string, error) {
	var text strings.Builder
	var runErr error
	var finals int

	for event, err := range c.runner.Run(ctx, agentUserID, newSessionID(), content, agent.RunConfig{
		StreamingMode: agent.StreamingModeNone,
	}) {
		if err != nil {
			runErr = err
			break
		}
		if event == nil || !event.IsFinalResponse() {
			continue
		}
		finals++
		if event.Content == nil {
			continue
		}
		for _, part := range event.Content.Parts {
			if part != nil {
				text.WriteString(part.Text)
			}
		}
	}

	if runErr != nil {
		return "", fmt.Errorf("agent run: %w", runErr)
	}
	if finals == 0 {
		return "", errors.New("agent produced no final response")
	}
	return text.String(), nil
}

// parseVerdicts decodes the agent reply and keeps only verdicts that are usable
// and that answer a message actually asked about.
//
// A partial reply is tolerated on purpose: a missing verdict leaves the
// deterministic decision for that id untouched, which is the safe direction. A
// reply with nothing usable at all is an error, because silently ignoring the
// model would hide a broken integration.
func parseVerdicts(raw string, messages []Message) ([]Verdict, error) {
	body := extractJSONObject(raw)
	if body == "" {
		return nil, fmt.Errorf("agent reply contained no JSON object: %s", abbreviate(raw, 200))
	}

	var env verdictEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return nil, fmt.Errorf("decode agent reply: %w", err)
	}

	known := make(map[string]struct{}, len(messages))
	for _, m := range messages {
		known[m.ID] = struct{}{}
	}

	out := make([]Verdict, 0, len(env.Verdicts))
	for _, v := range env.Verdicts {
		if _, ok := known[v.ID]; !ok {
			continue // an invented id is discarded, never trusted
		}
		if !v.Label.Valid() {
			continue // the label set is closed
		}
		v.Score = Clamp(v.Score)
		out = append(out, v)
	}

	if len(out) == 0 {
		return nil, errors.New("agent reply contained no usable verdict")
	}
	return out, nil
}

// extractJSONObject returns the outermost JSON object in a reply.
//
// The response schema should already make this unnecessary, but a model that
// wraps its JSON in a markdown fence should degrade into a parse rather than
// into a failure.
func extractJSONObject(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)

	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return ""
	}
	return s[start : end+1]
}

func abbreviate(s string, limit int) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "..."
}

// ApplyVerdict merges an advisory model verdict into a deterministic decision.
//
// The model is a fallback, never an authority:
//
//   - TriggerSpans are never modified. Evidence stays deterministic, so no
//     verdict can invent, move or delete the term a decision points at.
//   - NeedsReview is monotonic. A verdict may raise the flag and can never
//     clear it, so a model cannot talk the system out of a human review, and a
//     verdict that disagrees with the deterministic label always raises one.
//   - An invalid label is ignored and the deterministic decision is kept whole.
//
// The returned decision shares the span slice with d. Neither function ever
// mutates a span, and copying on every merge would cost more than it protects.
func ApplyVerdict(d UrgencyDecision, v Verdict) UrgencyDecision {
	if !v.Label.Valid() {
		return d
	}

	merged := d
	merged.Score = Clamp(v.Score)
	merged.Label = LabelForScore(merged.Score)
	merged.NeedsReview = d.NeedsReview || v.NeedsReview || merged.Label != d.Label

	note := strings.TrimSpace(v.Rationale)
	if note == "" {
		note = "no reason stated"
	}
	merged.Rationale = fmt.Sprintf("%s; model review moved %s/%d to %s/%d: %s",
		d.Rationale, d.Label, d.Score, merged.Label, merged.Score, note)

	return merged
}
