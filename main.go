// Command message-urgency-detection classifies supplied messages by urgency.
//
// This entry point is intentionally minimal: it exists so the module compiles
// from the first commit while the domain contract, the deterministic rules and
// the ADK layer are built. The batch CLI is wired in a later task.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "message-urgency-detection: CLI not wired yet")
	os.Exit(1)
}
