package urgency

import (
	"strings"
	"testing"
)

// probe is the part of a span a reader actually checks: which term matched, what
// kind of evidence it is, and whether a negation neutralised it. Exact offsets
// are pinned separately in TestClassifySpanOffsetsAreRuneOffsets, because
// spelling them out for every fixture would make this table unreadable.
type probe struct {
	Term    string
	Kind    TriggerKind
	Negated bool
}

type classifyCase struct {
	name       string
	text       string
	wantLabel  UrgencyLabel
	wantScore  int
	wantReview bool
	wantModel  bool
	wantLang   Language
	wantSpans  []probe
}

// classifyCases is shared by several tests: the classification table, the score
// invariant, the span invariant and the language check.
var classifyCases = []classifyCase{
	{
		name:       "a threat in Spanish is urgent and goes to a human",
		text:       "Recibí una amenaza de bomba",
		wantLabel:  LabelUrgent,
		wantScore:  100,
		wantReview: true,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "amenaza", Kind: KindThreat},
			{Term: "bomba", Kind: KindThreat},
		},
	},
	{
		name:       "an outage in Spanish is high and borderline",
		text:       "El servidor está caído desde las 3",
		wantLabel:  LabelHigh,
		wantScore:  60,
		wantReview: true,
		wantModel:  true,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "caído", Kind: KindIncident}},
	},
	{
		name:       "a negated trigger plus deescalation stays low and is not reviewed",
		text:       "No es urgente, tranquilo",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "urgente", Kind: KindDeadline, Negated: true},
			{Term: "tranquilo", Kind: KindDeescalation},
		},
	},
	{
		name:       "a negation beside real evidence is high and reviewed",
		text:       "No es urgente, pero el servidor está caído",
		wantLabel:  LabelHigh,
		wantScore:  60,
		wantReview: true,
		wantModel:  true,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "urgente", Kind: KindDeadline, Negated: true},
			{Term: "caído", Kind: KindIncident},
		},
	},
	{
		name:       "a routine request is low and needs no human",
		text:       "¿Podrías revisar esto cuando puedas? Por favor",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "Podrías", Kind: KindRequest},
			{Term: "cuando puedas", Kind: KindDeescalation},
			{Term: "Por favor", Kind: KindRequest},
		},
	},
	{
		name:       "a request with a same day deadline is normal",
		text:       "Necesito esto para hoy",
		wantLabel:  LabelNormal,
		wantScore:  45,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "Necesito", Kind: KindRequest},
			{Term: "hoy", Kind: KindDeadline},
		},
	},
	{
		name:       "a numeric window under an hour is found with no keyword",
		text:       "El deploy tiene que estar en 20 minutos",
		wantLabel:  LabelHigh,
		wantScore:  65,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "en 20 minutos", Kind: KindDeadline}},
	},
	{
		name:       "a numeric window over an hour is only normal",
		text:       "El deploy sale en 3 horas",
		wantLabel:  LabelNormal,
		wantScore:  40,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "en 3 horas", Kind: KindDeadline}},
	},
	{
		name:       "a message with no trigger term is low but asks the model",
		text:       "¿Confirmamos la reunión del jueves a las 10?",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: false,
		wantModel:  true,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "¿Confirmamos la reunión del jueves a las 10?", Kind: KindNone}},
	},
	{
		name:       "a word that merely contains ya does not fire",
		text:       "Estoy en la playa con la familia",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: false,
		wantModel:  true,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "Estoy en la playa con la familia", Kind: KindNone}},
	},
	{
		name:       "a non Latin script is flagged for a human and the model",
		text:       "緊急のメッセージです",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: true,
		wantModel:  true,
		wantLang:   LanguageUnknown,
		wantSpans:  []probe{{Term: "緊急のメッセージです", Kind: KindNone}},
	},
	{
		name:       "an English threat is urgent and reviewed",
		text:       "There is a bomb in the building",
		wantLabel:  LabelUrgent,
		wantScore:  85,
		wantReview: true,
		wantModel:  true,
		wantLang:   LanguageEnglish,
		wantSpans:  []probe{{Term: "bomb", Kind: KindThreat}},
	},
	{
		name:       "deescalation alone stays low",
		text:       "Sin apuro, cuando puedas",
		wantLabel:  LabelLow,
		wantScore:  0,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans: []probe{
			{Term: "Sin apuro", Kind: KindDeescalation},
			{Term: "cuando puedas", Kind: KindDeescalation},
		},
	},
	{
		name:       "a bare request is low",
		text:       "Por favor revisá el ticket",
		wantLabel:  LabelLow,
		wantScore:  5,
		wantReview: false,
		wantModel:  false,
		wantLang:   LanguageSpanish,
		wantSpans:  []probe{{Term: "Por favor", Kind: KindRequest}},
	},
	{
		name:       "an English outage is high and borderline",
		text:       "The service is offline",
		wantLabel:  LabelHigh,
		wantScore:  60,
		wantReview: true,
		wantModel:  true,
		wantLang:   LanguageEnglish,
		wantSpans:  []probe{{Term: "offline", Kind: KindIncident}},
	},
}

func TestClassify(t *testing.T) {
	t.Parallel()

	for _, tt := range classifyCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(Message{ID: "m1", Text: tt.text})

			if got.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", got.Label, tt.wantLabel)
			}
			if got.Score != tt.wantScore {
				t.Errorf("Score = %d, want %d", got.Score, tt.wantScore)
			}
			if got.NeedsReview != tt.wantReview {
				t.Errorf("NeedsReview = %v, want %v", got.NeedsReview, tt.wantReview)
			}
			if gotModel := NeedsModel(got, tt.text); gotModel != tt.wantModel {
				t.Errorf("NeedsModel = %v, want %v", gotModel, tt.wantModel)
			}
			if gotLang := DetectLanguage(tt.text); gotLang != tt.wantLang {
				t.Errorf("DetectLanguage = %q, want %q", gotLang, tt.wantLang)
			}

			if len(got.TriggerSpans) != len(tt.wantSpans) {
				t.Fatalf("got %d spans %+v, want %d spans %+v",
					len(got.TriggerSpans), got.TriggerSpans, len(tt.wantSpans), tt.wantSpans)
			}
			for i, want := range tt.wantSpans {
				s := got.TriggerSpans[i]
				if s.Term != want.Term || s.Kind != want.Kind || s.Negated != want.Negated {
					t.Errorf("spans[%d] = {Term:%q Kind:%q Negated:%v}, want {Term:%q Kind:%q Negated:%v}",
						i, s.Term, s.Kind, s.Negated, want.Term, want.Kind, want.Negated)
				}
			}

			if strings.TrimSpace(got.Rationale) == "" {
				t.Error("Rationale is empty, want a stated reason")
			}
			if strings.TrimSpace(got.ID) != "m1" {
				t.Errorf("ID = %q, want %q", got.ID, "m1")
			}
		})
	}
}

// TestClassifyScoreIsTheClampedSumOfSpanWeights pins the arithmetic contract:
// a score is never a number that floated in from somewhere else, it is the sum
// of the evidence the decision carries.
func TestClassifyScoreIsTheClampedSumOfSpanWeights(t *testing.T) {
	t.Parallel()

	for _, tt := range classifyCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(Message{ID: "m1", Text: tt.text})

			var sum int
			for _, s := range got.TriggerSpans {
				sum += s.Weight
			}
			if want := Clamp(sum); got.Score != want {
				t.Errorf("Score = %d, but the spans sum to %d and Clamp gives %d", got.Score, sum, want)
			}
		})
	}
}

// TestClassifySpansAreWellFormedAgainstTheirOwnText is the guard against a
// byte-offset regression: every span must name exactly the runes it covers.
func TestClassifySpansAreWellFormedAgainstTheirOwnText(t *testing.T) {
	t.Parallel()

	for _, tt := range classifyCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(Message{ID: "m1", Text: tt.text})
			if err := VerifySpans(tt.text, got.TriggerSpans); err != nil {
				t.Fatalf("VerifySpans() = %v, want nil", err)
			}
		})
	}
}

func TestClassifyEveryDecisionPassesValidation(t *testing.T) {
	t.Parallel()

	for _, tt := range classifyCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(Message{ID: "m1", Text: tt.text})
			if err := ValidateDecision(got); err != nil {
				t.Fatalf("ValidateDecision() = %v, want nil", err)
			}
			if got.Label != LabelForScore(got.Score) {
				t.Errorf("Label = %q does not match LabelForScore(%d) = %q",
					got.Label, got.Score, LabelForScore(got.Score))
			}
		})
	}
}

// TestClassifySpanOffsetsAreRuneOffsets spells out the exact offsets on text
// where a byte offset would land somewhere else entirely.
func TestClassifySpanOffsetsAreRuneOffsets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		text  string
		spans []struct {
			start int
			end   int
			term  string
		}
	}{
		{
			name: "two accents before the trigger shift a byte offset",
			// runes: R e c i b í _ u n a _ a m e n a z a _ d e _ b o m b a
			// index: 0 1 2 3 4 5 6 7 8 9 10 ...        11..17     22..26
			// "í" adds one extra byte at index 5, so a byte offset for
			// "amenaza" would be 12 instead of 11.
			text: "Recibí una amenaza de bomba",
			spans: []struct {
				start int
				end   int
				term  string
			}{
				{start: 11, end: 18, term: "amenaza"},
				{start: 22, end: 27, term: "bomba"},
			},
		},
		{
			name: "an emoji after the trigger must not move its offset",
			// runes: R e p o r t é _ q u e _ e l _ s i s t e m a _ e s t á _ c a í d o _ 🚨
			// index: 0 1 2 3 4 5 6 7 ...                          28..32
			text: "Reporté que el sistema está caído 🚨",
			spans: []struct {
				start int
				end   int
				term  string
			}{
				{start: 28, end: 33, term: "caído"},
			},
		},
		{
			name: "an accent before a time window shifts its offset",
			// The time window is found with a byte oriented regex, so this is the
			// case that proves the byte to rune translation is right. "ó" adds a
			// byte, so the byte offset of "en 20 minutos" is 31 while its rune
			// offset is 30.
			// runes: A t e n c i ó n : _ e l _ d e s p l i e g u e _ q u e d a _ e n _ 2 0 _ m i n u t o s
			// index: 0 1 2 3 4 5 6 7 8 9 ...                            30..42
			text: "Atención: el despliegue queda en 20 minutos",
			spans: []struct {
				start int
				end   int
				term  string
			}{
				{start: 30, end: 43, term: "en 20 minutos"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Classify(Message{ID: "m1", Text: tt.text})

			if len(got.TriggerSpans) != len(tt.spans) {
				t.Fatalf("got %d spans %+v, want %d", len(got.TriggerSpans), got.TriggerSpans, len(tt.spans))
			}
			for i, want := range tt.spans {
				s := got.TriggerSpans[i]
				if s.Start != want.start || s.End != want.end || s.Term != want.term {
					t.Errorf("spans[%d] = {Start:%d End:%d Term:%q}, want {Start:%d End:%d Term:%q}",
						i, s.Start, s.End, s.Term, want.start, want.end, want.term)
				}
				// The offset is only useful if it actually selects the term.
				if got := string([]rune(tt.text)[s.Start:s.End]); got != want.term {
					t.Errorf("text[%d:%d] = %q, want %q", s.Start, s.End, got, want.term)
				}
			}
		})
	}
}

func TestDetectLanguage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want Language
	}{
		{name: "Spanish function words", text: "esto pasa cuando el servicio se cae", want: LanguageSpanish},
		{name: "English function words", text: "this happens when the service goes down", want: LanguageEnglish},
		{name: "a non Latin script carries no marker", text: "緊急です", want: LanguageUnknown},
		{name: "empty text carries no marker", text: "   ", want: LanguageUnknown},
		{
			name: "honest limitation: a Latin language sharing Spanish words reads as Spanish",
			// Portuguese "de", "para" and "que" are also Spanish words, so this
			// detector cannot separate the two. The model fallback exists for
			// exactly this gap and the README states the limit.
			text: "isto é para que vejas",
			want: LanguageSpanish,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := DetectLanguage(tt.text); got != tt.want {
				t.Errorf("DetectLanguage(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestClassifyBatch(t *testing.T) {
	t.Parallel()

	t.Run("orders by severity then score then id", func(t *testing.T) {
		t.Parallel()

		req := UrgencyRequest{
			PolicyVersion: CurrentPolicyVersion,
			Messages: []Message{
				{ID: "m4", Text: "¿Confirmamos la reunión del jueves a las 10?"},
				{ID: "m1", Text: "Recibí una amenaza de bomba"},
				{ID: "m3", Text: "El servidor está caído desde las 3"},
				{ID: "m2", Text: "There is a bomb in the building"},
			},
		}

		got, err := ClassifyBatch(req)
		if err != nil {
			t.Fatalf("ClassifyBatch() = %v, want nil", err)
		}

		want := []string{"m1", "m2", "m3", "m4"}
		gotIDs := make([]string, 0, len(got))
		for _, d := range got {
			gotIDs = append(gotIDs, d.ID)
		}
		if strings.Join(gotIDs, ",") != strings.Join(want, ",") {
			t.Fatalf("order = %v, want %v", gotIDs, want)
		}

		if got[0].Label != LabelUrgent || got[3].Label != LabelLow {
			t.Errorf("first label = %q, last label = %q; want urgent first and low last", got[0].Label, got[3].Label)
		}
	})

	t.Run("rejects an invalid request without producing decisions", func(t *testing.T) {
		t.Parallel()

		req := UrgencyRequest{
			PolicyVersion: CurrentPolicyVersion,
			Messages: []Message{
				{ID: "m1", Text: "Recibí una amenaza de bomba"},
				{ID: "m1", Text: "duplicate id"},
			},
		}

		got, err := ClassifyBatch(req)
		if err == nil {
			t.Fatal("ClassifyBatch() = nil error, want an error for a duplicate id")
		}
		if got != nil {
			t.Fatalf("ClassifyBatch() returned %d decisions alongside an error, want none", len(got))
		}
	})
}
