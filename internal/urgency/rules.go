package urgency

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Language is the language the deterministic pass is built for. Anything else
// is reported as unknown and handed to the model.
type Language string

// The languages the deterministic lexicon covers.
const (
	LanguageSpanish Language = "es"
	LanguageEnglish Language = "en"
	LanguageUnknown Language = "unknown"
)

// spanishMarkers and englishMarkers are high frequency function words used to
// tell the two lexicons apart. They are deliberately shallow: this detector only
// has to decide whether the deterministic pass is trustworthy, and the model
// fallback exists for everything it cannot settle.
var spanishMarkers = map[string]struct{}{
	"el": {}, "la": {}, "los": {}, "las": {}, "un": {}, "una": {}, "de": {},
	"del": {}, "que": {}, "y": {}, "es": {}, "está": {}, "esta": {}, "esto": {},
	"por": {}, "para": {}, "con": {}, "sin": {}, "se": {}, "su": {}, "en": {},
	"cuando": {}, "como": {}, "pero": {}, "más": {}, "muy": {}, "hay": {},
	"tengo": {}, "necesito": {}, "puede": {}, "puedas": {}, "hola": {},
	"gracias": {}, "favor": {}, "ticket": {},
}

var englishMarkers = map[string]struct{}{
	"the": {}, "a": {}, "an": {}, "and": {}, "is": {}, "are": {}, "was": {},
	"were": {}, "to": {}, "of": {}, "in": {}, "on": {}, "at": {}, "for": {},
	"with": {}, "this": {}, "that": {}, "you": {}, "we": {}, "it": {},
	"there": {}, "here": {}, "from": {}, "by": {}, "be": {}, "have": {},
	"has": {}, "will": {}, "can": {}, "could": {}, "would": {}, "should": {},
	"please": {}, "need": {}, "no": {}, "not": {}, "when": {},
}

// DetectLanguage guesses which lexicon a message belongs to.
//
// Honest limitation: it separates Spanish and English from anything that shares
// no function word with them, but it cannot separate a Latin alphabet language
// that borrows Spanish function words. Portuguese "de", "para" and "que" are
// Spanish words too, so Portuguese text reads as Spanish here. That gap is what
// the model fallback is for.
func DetectLanguage(text string) Language {
	var spanish, english int
	for _, tok := range tokenize(text) {
		if _, ok := spanishMarkers[tok]; ok {
			spanish++
		}
		if _, ok := englishMarkers[tok]; ok {
			english++
		}
	}

	switch {
	case spanish == 0 && english == 0:
		return LanguageUnknown
	case spanish >= english:
		return LanguageSpanish
	default:
		return LanguageEnglish
	}
}

// tokenize lower cases, folds accents and splits on anything that is not a
// letter or a digit.
func tokenize(text string) []string {
	var out []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			out = append(out, string(current))
			current = current[:0]
		}
	}
	for _, r := range text {
		f := foldRune(r)
		if isWordRune(f) {
			current = append(current, f)
			continue
		}
		flush()
	}
	flush()
	return out
}

// foldRune maps a rune to its comparison form, one rune in and one rune out.
//
// Keeping the mapping length preserving is what lets a match index in the folded
// text be used directly as an index in the original text, so a span can carry
// the original characters, accents and case included, without any offset
// translation step.
func foldRune(r rune) rune {
	lower := unicode.ToLower(r)
	switch lower {
	case 'á', 'à', 'ä', 'â', 'ã', 'å':
		return 'a'
	case 'é', 'è', 'ë', 'ê':
		return 'e'
	case 'í', 'ì', 'ï', 'î':
		return 'i'
	case 'ó', 'ò', 'ö', 'ô', 'õ':
		return 'o'
	case 'ú', 'ù', 'ü', 'û':
		return 'u'
	case 'ñ':
		return 'n'
	case 'ç':
		return 'c'
	}
	return lower
}

func foldRunes(runes []rune) []rune {
	out := make([]rune, len(runes))
	for i, r := range runes {
		out[i] = foldRune(r)
	}
	return out
}

func foldString(s string) string {
	return string(foldRunes([]rune(s)))
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// lexiconGroups is the curated trigger lexicon. It is deliberately small and
// auditable: whole words and whole phrases only, with the variants that matter
// spelled out. Bare substring matching is not used because it would make "ya"
// fire inside "playa".
var lexiconGroups = []struct {
	Kind  TriggerKind
	Terms []string
}{
	{KindThreat, []string{
		"amenaza", "amenazas", "amenazando", "amenazar",
		"bomba", "explosivo", "detonador",
		"arma", "armas", "cuchillo",
		"matar", "mato", "muerte", "muerto", "asesinato",
		"secuestro", "secuestraron", "rehén", "rehenes",
		"agresión", "agredió", "agredido", "golpeó", "golpearon", "violencia",
		"acoso", "acecho", "intimidación",
		"threat", "threats", "threatening", "threatened",
		"bomb", "gun", "weapon", "knife", "kill", "killed", "kidnap", "attack", "attacked",
		"assault", "harassment", "abuse",
	}},
	{KindIncident, []string{
		"caído", "caída", "se cayó", "fuera de servicio", "no responde",
		"sin servicio", "intermitencia", "latencia", "degradado",
		"brecha", "hackeo", "hackeado", "intrusión", "vulnerabilidad",
		"filtración", "robo de datos", "pérdida de datos", "incidente",
		"down", "outage", "offline", "breach", "hacked", "leak",
		"vulnerability", "crash", "crashed", "failing", "data loss", "incident",
	}},
	{KindDeadline, []string{
		"urgente", "urgencia", "urgentemente", "urgent", "urgency",
		"ya", "ahora", "inmediato", "inmediata", "inmediatamente",
		"immediately", "now", "asap", "cuanto antes", "lo antes posible",
		"hoy", "today", "vence", "vencido", "deadline", "expira", "se vence",
	}},
	{KindRequest, []string{
		"por favor", "please", "podrías", "podriamos", "podríamos",
		"necesito", "necesitamos", "could you", "would you", "te pido",
	}},
	{KindDeescalation, []string{
		"sin apuro", "sin prisa", "no hay apuro", "no corre prisa",
		"tranquilo", "tranquila", "no es para tanto", "cuando puedas",
		"whenever", "no rush", "low priority", "not urgent", "no hurry",
	}},
}

type foldedTerm struct {
	Kind TriggerKind
	Text []rune
}

// termIndex groups terms by their first rune so a scan only tests the terms that
// could possibly start at a position.
var termIndex = buildTermIndex()

func buildTermIndex() map[rune][]foldedTerm {
	index := make(map[rune][]foldedTerm)
	for _, group := range lexiconGroups {
		for _, term := range group.Terms {
			folded := []rune(foldString(term))
			if len(folded) == 0 {
				continue
			}
			index[folded[0]] = append(index[folded[0]], foldedTerm{Kind: group.Kind, Text: folded})
		}
	}
	return index
}

var (
	minutesWindowRe = regexp.MustCompile(`(?i)\ben\s+(\d{1,3})\s*(minutos?|mins?|minutes?)\b`)
	hoursWindowRe   = regexp.MustCompile(`(?i)\ben\s+(\d{1,3})\s*(horas?|hours?)\b`)
)

// shortWindowMinutes is the window at or under which a numeric deadline counts
// as the stronger deadlineShort weight.
const shortWindowMinutes = 60

type rawMatch struct {
	start int
	end   int
	kind  TriggerKind
	// short marks a numeric window at or under an hour, which carries the
	// stronger deadlineShort weight.
	short bool
}

// Classify runs the deterministic pass over one message.
//
// It never fails: when the lexicon recognises nothing it still returns a low
// decision whose single KindNone span records that the text was scanned and
// nothing was found. Whether that decision is trustworthy is what NeedsModel
// answers.
func Classify(m Message) UrgencyDecision {
	runes := []rune(m.Text)
	folded := foldRunes(runes)
	trimStart, trimEnd := trimRange(runes)

	matches := resolveOverlaps(append(
		findLexiconMatches(folded),
		findTimeWindows(m.Text)...,
	))

	spans := make([]TriggerSpan, 0, len(matches))
	var sum int
	for _, mt := range matches {
		negated := isNegated(folded, mt.start)
		weight := weightFor(mt, negated)
		sum += weight
		spans = append(spans, TriggerSpan{
			Start:   mt.start,
			End:     mt.end,
			Term:    string(runes[mt.start:mt.end]),
			Kind:    mt.kind,
			Weight:  weight,
			Negated: negated,
		})
	}

	if len(spans) == 0 {
		// No term was recognised. A weight-0 span over the scanned text keeps
		// the "every decision carries its evidence" rule true without
		// inventing a term that was never there.
		spans = append(spans, TriggerSpan{
			Start:  trimStart,
			End:    trimEnd,
			Term:   string(runes[trimStart:trimEnd]),
			Kind:   KindNone,
			Weight: WeightNone,
		})
	}

	score := Clamp(sum)
	label := LabelForScore(score)
	lang := DetectLanguage(m.Text)
	reviewReasons := reviewReasonsFor(spans, score, lang)

	return UrgencyDecision{
		ID:           m.ID,
		Label:        label,
		Score:        score,
		TriggerSpans: spans,
		Rationale:    buildRationale(spans, score, label, lang, reviewReasons),
		NeedsReview:  len(reviewReasons) > 0,
	}
}

// ClassifyBatch validates a request, classifies every message and returns the
// decisions ordered by severity, then score, then id.
func ClassifyBatch(r UrgencyRequest) ([]UrgencyDecision, error) {
	if err := ValidateRequest(r); err != nil {
		return nil, fmt.Errorf("invalid urgency request: %w", err)
	}

	decisions := make([]UrgencyDecision, 0, len(r.Messages))
	for _, m := range r.Messages {
		d := Classify(m)
		if err := ValidateDecision(d); err != nil {
			// A classifier that emits a decision its own contract rejects is a
			// bug, not a caller error, so it must never be silently returned.
			return nil, fmt.Errorf("classifier produced an invalid decision: %w", err)
		}
		// Enforce the span invariant in production, not only in tests. This is
		// the check that turns a byte-offset regression into a loud error: a
		// byte offset yields a span that is well formed but points at the wrong
		// characters, which is exactly the kind of wrong answer that would
		// otherwise look plausible. It is an internal assertion, so a caller
		// cannot trigger it and no unit test can reach it by construction.
		if err := VerifySpans(m.Text, d.TriggerSpans); err != nil {
			return nil, fmt.Errorf("classifier produced spans that do not match their text: %w", err)
		}
		decisions = append(decisions, d)
	}

	SortDecisions(decisions)
	return decisions, nil
}

// NeedsModel reports whether the deterministic pass was inconclusive for the
// message that produced d, in which case the schema constrained agent is worth
// consulting. The text is required because language coverage cannot be read
// back out of a decision.
func NeedsModel(d UrgencyDecision, text string) bool {
	if DetectLanguage(text) == LanguageUnknown {
		return true
	}
	if onlyKindNone(d.TriggerSpans) {
		return true
	}
	if IsBorderline(d.Score) {
		return true
	}
	return mixedPolarity(d.TriggerSpans)
}

func onlyKindNone(spans []TriggerSpan) bool {
	for _, s := range spans {
		if s.Kind != KindNone {
			return false
		}
	}
	return len(spans) > 0
}

// mixedPolarity reports whether a message carries both neutralised and live
// evidence. That combination is genuinely ambiguous: one clause says the thing
// is not urgent while another reports an outage.
func mixedPolarity(spans []TriggerSpan) bool {
	var negated, positive bool
	for _, s := range spans {
		if s.Negated {
			negated = true
		}
		if s.Weight > 0 {
			positive = true
		}
	}
	return negated && positive
}

func hasLiveThreat(spans []TriggerSpan) bool {
	for _, s := range spans {
		if s.Kind == KindThreat && !s.Negated {
			return true
		}
	}
	return false
}

func reviewReasonsFor(spans []TriggerSpan, score int, lang Language) []string {
	var reasons []string
	if lang == LanguageUnknown {
		reasons = append(reasons, "the text is outside the deterministic Spanish and English lexicon")
	}
	if IsBorderline(score) {
		reasons = append(reasons, fmt.Sprintf("the score %d sits within %d of a label boundary", score, BorderlineDelta))
	}
	if hasLiveThreat(spans) {
		reasons = append(reasons, "a threat term is present")
	}
	if mixedPolarity(spans) {
		reasons = append(reasons, "neutralised and live evidence appear in the same message")
	}
	return reasons
}

func weightFor(mt rawMatch, negated bool) int {
	if negated {
		// A negation never inflates a score. The span keeps the kind, so the
		// term that was neutralised is still recoverable from the decision.
		return 0
	}
	if mt.short {
		return WeightDeadlineShort
	}
	return mt.kind.Weight()
}

// trimRange returns the half-open rune range of the text without surrounding
// whitespace.
func trimRange(runes []rune) (int, int) {
	start := 0
	for start < len(runes) && unicode.IsSpace(runes[start]) {
		start++
	}
	end := len(runes)
	for end > start && unicode.IsSpace(runes[end-1]) {
		end--
	}
	if end == start {
		// The text is entirely whitespace. Point at a single rune so the span
		// stays well formed; ValidateRequest rejects this input upstream.
		if len(runes) > 0 {
			return 0, 1
		}
		return 0, 0
	}
	return start, end
}

func findLexiconMatches(folded []rune) []rawMatch {
	var out []rawMatch
	for i := 0; i < len(folded); i++ {
		for _, term := range termIndex[folded[i]] {
			end := i + len(term.Text)
			if end > len(folded) {
				continue
			}
			if !runesEqual(folded[i:end], term.Text) {
				continue
			}
			if !isWordBoundary(folded, i, end) {
				continue
			}
			out = append(out, rawMatch{start: i, end: end, kind: term.Kind})
		}
	}
	return out
}

// findTimeWindows finds an explicit numeric deadline such as "en 20 minutos".
// This is a rule of its own because the phrase contains no dictionary word at
// all, so only the time window can reveal that the message is time bound.
//
// The regex works on bytes, so each match is translated to rune offsets before
// it is used, keeping every span in the same rune coordinate system.
func findTimeWindows(text string) []rawMatch {
	var out []rawMatch

	add := func(re *regexp.Regexp, unitMinutes int) {
		for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
			amount, err := parseAmount(text[loc[2]:loc[3]])
			if err != nil {
				continue
			}
			minutes := amount * unitMinutes
			out = append(out, rawMatch{
				start: utf8.RuneCountInString(text[:loc[0]]),
				end:   utf8.RuneCountInString(text[:loc[1]]),
				kind:  KindDeadline,
				short: minutes <= shortWindowMinutes,
			})
		}
	}

	add(minutesWindowRe, 1)
	add(hoursWindowRe, 60)
	return out
}

func parseAmount(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

func isWordBoundary(folded []rune, start, end int) bool {
	if start > 0 && isWordRune(folded[start-1]) {
		return false
	}
	if end < len(folded) && isWordRune(folded[end]) {
		return false
	}
	return true
}

// resolveOverlaps keeps the longest match at each position and drops anything it
// contains, so "fuera de servicio" wins over a shorter term inside it and no two
// spans ever describe the same characters. The result is returned in text order.
func resolveOverlaps(matches []rawMatch) []rawMatch {
	sorted := make([]rawMatch, len(matches))
	copy(sorted, matches)
	sort.SliceStable(sorted, func(i, j int) bool {
		li, lj := sorted[i].end-sorted[i].start, sorted[j].end-sorted[j].start
		if li != lj {
			return li > lj
		}
		return sorted[i].start < sorted[j].start
	})

	kept := make([]rawMatch, 0, len(sorted))
	for _, m := range sorted {
		overlaps := false
		for _, k := range kept {
			if m.start < k.end && k.start < m.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, m)
		}
	}

	sort.SliceStable(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	return kept
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// negationWindow is how far back from a match a negator is looked for.
const negationWindow = 24

var negators = []string{
	"no", "sin", "nunca", "jamás", "tampoco", "ni",
	"not", "never", "without", "nothing",
}

// isNegated reports whether a negator applies to the match starting at start.
//
// The scan walks backwards and stops at a clause break, so "No, es urgente" is
// not a negation while "no es urgente" is.
func isNegated(folded []rune, start int) bool {
	low := start - negationWindow
	if low < 0 {
		low = 0
	}

	scopeStart := low
	for i := start - 1; i >= low; i-- {
		if isScopeBreak(folded[i]) {
			scopeStart = i + 1
			break
		}
	}
	if scopeStart >= start {
		return false
	}
	return containsWord(folded[scopeStart:start], negators)
}

func isScopeBreak(r rune) bool {
	switch r {
	case '.', '!', '?', ';', ',', '\n', '\r':
		return true
	default:
		return false
	}
}

func containsWord(folded []rune, words []string) bool {
	for _, w := range words {
		needle := []rune(foldString(w))
		if len(needle) == 0 {
			continue
		}
		for i := 0; i+len(needle) <= len(folded); i++ {
			if !runesEqual(folded[i:i+len(needle)], needle) {
				continue
			}
			if i > 0 && isWordRune(folded[i-1]) {
				continue
			}
			end := i + len(needle)
			if end < len(folded) && isWordRune(folded[end]) {
				continue
			}
			return true
		}
	}
	return false
}

func buildRationale(spans []TriggerSpan, score int, label UrgencyLabel, lang Language, reviewReasons []string) string {
	var b strings.Builder

	if onlyKindNone(spans) {
		fmt.Fprintf(&b, "no known trigger term was found in %s text", lang)
	} else {
		counts := make(map[TriggerKind]int)
		order := make([]TriggerKind, 0, len(spans))
		for _, s := range spans {
			if _, seen := counts[s.Kind]; !seen {
				order = append(order, s.Kind)
			}
			counts[s.Kind]++
		}

		parts := make([]string, 0, len(order))
		for _, kind := range order {
			label := string(kind)
			if n := counts[kind]; n > 1 {
				label = fmt.Sprintf("%s x%d", label, n)
			}
			parts = append(parts, label)
		}
		fmt.Fprintf(&b, "matched %s evidence", strings.Join(parts, ", "))
	}

	fmt.Fprintf(&b, "; score %d maps to %s", score, label)

	var negated []string
	for _, s := range spans {
		if s.Negated {
			negated = append(negated, s.Term)
		}
	}
	if len(negated) > 0 {
		fmt.Fprintf(&b, "; neutralised by negation: %s", strings.Join(negated, ", "))
	}

	if len(reviewReasons) > 0 {
		fmt.Fprintf(&b, "; human review because %s", strings.Join(reviewReasons, " and "))
	}
	return b.String()
}
