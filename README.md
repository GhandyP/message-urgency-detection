# message-urgency-detection

Classify supplied messages by urgency, show the exact words that drove each
verdict, and page nobody without a human approval boundary.

Built with **Go 1.26** and **Google ADK Go v2** (Gemini).

This is a text-only decision engine. It does not read a messaging system, notify
a responder, or change a queue. It turns text into a decision a human can audit.

## Why

Routing an alert from free text is a place where a confident wrong answer is
expensive. Two failure modes dominate:

1. A keyword like `urgent` fires inside `not urgent`, or `ya` fires inside
   `playa`.
2. A model returns a fluent label with nothing behind it, and nobody can tell
   what it reacted to.

This repository is built so both are structurally hard. Every decision carries
the exact character range it was based on, and the model is a fallback that can
never touch the evidence.

## Design decisions

**Deterministic rules run first; the model is a fallback.** The keyword pass
resolves the clear cases. The agent is consulted only for the messages the rules
genuinely could not settle: nothing matched, the score sits on a label boundary,
the text is in an unsupported language, or a negation and live evidence appear in
the same message. Most batches never reach the model at all, which is why
`-model` does not even need credentials when the rules settle everything.

**Evidence is deterministic and a model cannot touch it.** A verdict has no field
for a trigger span. `ApplyVerdict` copies the span slice through untouched, so no
model output can invent, move or delete the term a decision points at.

**Spans are rune offsets, not byte offsets.** Matching folds case and accents with
a length preserving mapping, so a match index in the folded text is already an
index into the original text. `Term` therefore always holds the original
characters, accents and case included: the span for `caído` reports `caído`, not
`caido`, and a byte offset would have sliced the character in half.

**Every decision carries at least one span.** A message with no recognised term
gets a single weight-0 `none` span over the scanned text, so "every decision
points at its evidence" holds literally without inventing a term that was never
there.

**The review flag is monotonic.** A model verdict may raise `needsReview` and can
never clear it. A verdict that disagrees with the deterministic label always
raises it. A model cannot talk the system out of a human review.

**The agent has no tools.** `agentConfig` deliberately sets no tool list, and a
test asserts it. The agent has no mechanism to page, notify, route or write.

**Routing fails closed.** An escalation requires both `-approved-by` and
`-approval-ref`. Without them the run exits `3` and produces no plan at all, not
a partial one. A batch containing a single malformed decision produces no plan
either.

## Evidence and thresholds

Score is `0..100`, always the clamped sum of the span weights, and the label is
always derived from the score.

| Evidence | Weight |
| --- | --- |
| `threat` (amenaza, bomba, arma, kill, threat, …) | 85 |
| `incident` (caído, fuera de servicio, breach, outage, …) | 60 |
| `deadline`, numeric window under an hour | 65 |
| `deadline` (urgente, hoy, asap, deadline, …) | 40 |
| `request` (por favor, please, necesito, …) | 5 |
| `deescalation` (sin apuro, cuando puedas, no rush, …) | −15 |
| a negated trigger | 0 |

| Score | Label |
| --- | --- |
| ≥ 80 | `urgent` |
| 55–79 | `high` |
| 25–54 | `normal` |
| < 25 | `low` |

Weights are chosen so one signal alone lands where a reader expects: a threat is
`urgent`, an outage is `high`, a deadline word is `normal`, a bare request is
`low`. A score within 5 of a label boundary is treated as too close to call and
goes to human review.

## Layout

```
.
├── main.go                      batch CLI, exit codes, stream handling
├── main_test.go                 fixtures, ordering, exit codes, exact stdout
├── testdata/messages.json       fixed fixtures: threats, deadlines, negation,
│                                multilingual, ambiguity
├── adapters/notification.go     approval gated dry run routing
└── internal/urgency/
    ├── schema.go                the frozen contract and the score policy
    ├── rules.go                 the deterministic classifier
    ├── agent.go                 the only file that talks to a model
    └── *_test.go
```

## Quick start

```bash
go test ./...
go run . -in testdata/messages.json
```

To use the agent fallback, set an API key:

```bash
export GOOGLE_API_KEY="your-key"
go run . -in testdata/messages.json -model
```

## Contract

Input:

```json
{
  "policyVersion": "1.0.0",
  "messages": [{ "id": "m1", "text": "El servidor está caído" }]
}
```

Output:

```json
{
  "policyVersion": "1.0.0",
  "decisions": [
    {
      "id": "m1",
      "label": "high",
      "score": 60,
      "triggerSpans": [
        { "start": 17, "end": 22, "term": "caído", "kind": "incident", "weight": 60, "negated": false }
      ],
      "rationale": "matched incident evidence; score 60 maps to high; human review because the score 60 sits within 5 of a label boundary",
      "needsReview": true
    }
  ]
}
```

Decisions come back ordered by severity, then score, then message id.

## Usage

```
message-urgency-detection [flags]

  -in string           a UrgencyRequest JSON file, or - for stdin (default "-")
  -out string          where to write the decisions, or - for stdout (default "-")
  -model               consult the agent for the messages the rules could not settle
  -approved-by string  name of the human who authorised escalation
  -approval-ref string reference to the human review that cleared escalation
```

The routing plan is a dry run and goes to stderr. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | decisions produced, routing plan produced or not needed |
| 1 | the run failed |
| 2 | usage error |
| 3 | decisions were produced, but an escalation had no approval boundary |

Without an approval boundary the fixture refuses to route, because one message
in it is a real escalation candidate. The decisions are still written, so the
analysis is never lost to a routing rule:

```console
$ go run . -in testdata/messages.json
error: escalation requires a configured approval boundary: 1 decision(s) would reach a responder, set both approvedBy and ticketReference
$ echo $?
3
```

With a boundary configured, five messages are held for a human and exactly one
reaches a responder:

```console
$ go run . -in testdata/messages.json -approved-by ana -approval-ref REV-7
routing plan (dry run, nothing was sent)
approval boundary: ana (REV-7)
held for human review: 5
  - threat-es -> human-review [urgent 100] flagged for human review before any page or escalation (evidence: amenaza | bomba)
  ... four more held messages ...
escalations: 1
  - deadline-short -> on-call [high 65] high urgency with no review flag, authorised by ana (REV-7) (evidence: en 20 minutos)
```

## Limits

Stated plainly, because a classifier that overstates its coverage is worse than
one that names its gaps.

- **No live model call has been verified.** `GOOGLE_API_KEY` was not available in
  the build environment and the repository performs no network call during
  `go test ./...`. The whole agent path, the ADK agent, runner, session, event
  loop and schema decoding, is exercised by tests through `model.LLM`, which is
  an interface, using a fake model. That covers the plumbing, not the model's
  judgement.
- **The lexicon is curated, not exhaustive.** Whole words and phrases only,
  Spanish and English. A message expressing urgency in words not in the list is
  reported as no trigger found and handed to the model or to a human.
- **Language detection is shallow.** It separates Spanish and English from
  anything sharing no function word with them. It cannot separate a Latin
  alphabet language that borrows Spanish words: Portuguese `de`, `para` and
  `que` are Spanish words too, so Portuguese text reads as Spanish. A test pins
  that limitation rather than pretending otherwise.
- **Routing is a dry run on purpose.** There is no `Send` method anywhere in
  `adapters`. Real notification belongs behind proven review rules, which is a
  later step.

## Testing

```bash
go test ./...
go test ./... -cover
```

The rules suite is verified by mutation, not only by a green run. Two deliberate
breaks were confirmed to fail loudly:

- forcing a byte offset in the time-window rule turns the span into
  `n 20 minutos` instead of `en 20 minutos`;
- collapsing the negation window turns `no es urgente, tranquilo` into `normal`
  with a flagged review.

Both were caught, and both probes were reverted byte for byte.

## License

MIT. See [LICENSE](LICENSE).
