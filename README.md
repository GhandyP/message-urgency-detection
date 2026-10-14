# 19 — Urgency detection in messages

## Goal

Classify supplied messages by urgency and show the textual triggers without automatically paging a person or changing a queue.

## Run the current prototype

From this case directory:

```bash
export GOOGLE_API_KEY="your-key"
go run .
```

`internal/adkhelper.Run` uses ADK Go v2.2.0, Gemini, and `gemini-flash-latest`; set `ADK_MODEL` to override the model.

Sample prompt:

```text
Classify these messages by urgency and list the trigger terms.
```

## What exists now

- `main.go (exists)` sends message text to one focused Gemini ADK agent.
- The output has no stable IDs, closed urgency labels, trigger spans, confidence threshold, or batch ordering.
- This is intentionally text-only: it does not read a messaging system, notify responders, or route incidents.

## Missing elements

- **Contract:** Define `UrgencyRequest{messages[{id,text}], policyVersion}` -> `UrgencyDecision{id, label, score, triggerSpans[], rationale, needsReview}`.
- **ADK layer:** Add a closed response schema and batch session; keep deterministic keyword/time-window rules ahead of the model and avoid write tools.
- **Domain boundary:** Add message ingestion, timezone/SLA policy, and notification/queue adapters behind an explicit decision boundary.
- **Fixtures and validation:** Include threats, deadlines, routine requests, negated trigger words, multilingual text, and ambiguous messages; test thresholds and spans.
- **Safety:** Borderline or high-impact classifications must enter a human review queue before paging or escalation.

## Target structure

```text
19-message-urgency-detection/
├── main.go (exists)
├── README.md (exists)
├── schema.go (next)
├── rules.go (next)
├── adapters/notification.go (next)
├── testdata/messages.json (next)
└── main_test.go (next)
```

## Implementation order

1. Define labels, score ranges, trigger spans, and review thresholds.
2. Implement deterministic rules and a schema-constrained agent fallback.
3. Add a batch session and stable sorting by severity and message ID.
4. Test negation, multilingual text, deadlines, and ambiguity.
5. Add dry-run notification/routing tools after human-review rules are proven.

## Done when

- [ ] Every message has a valid label, score, and evidence span.
- [ ] Ambiguous cases are marked for review rather than forced into a label.
- [ ] Threshold and ordering tests pass on fixed fixtures.
- [ ] Paging or routing cannot occur without the configured approval boundary.

## Next improvement

Implement deterministic trigger extraction and the closed `UrgencyDecision` schema before adding notifications.
