// Command agent-governance-evidence authors the experimental v0.1 deployment
// predicate body from one completed evidence document whose test-result
// statement digest is already bound.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/liatrio/autogov/agent-governance/internal/evidence"
)

func main() {
	os.Exit(execute(os.Args[1:], os.Stderr))
}

func execute(args []string, stderr io.Writer) int {
	err := run(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "agent-governance-evidence:", err)
		return 1
	}
	return 0
}

func run(args []string) error {
	flags := flag.NewFlagSet("agent-governance-evidence", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	evidencePath := flags.String("evidence-path", "", "path to completed, test-result-bound evidence JSON (required)")
	outputPath := flags.String("output", "", "predicate body output path (defaults to stdout)")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "Usage: agent-governance-evidence --evidence-path <evidence.json> [--output <predicate.json>]")
		_, _ = fmt.Fprintln(flags.Output())
		_, _ = fmt.Fprintln(flags.Output(), "Consumes completed, test-result-bound evidence and authors the https://autogov.dev/attestation/agent-governance-deployment/v0.1 predicate body.")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *evidencePath == "" {
		flags.Usage()
		return errors.New("--evidence-path is required")
	}
	return evidence.GenerateAgentGovernanceDeployment(*evidencePath, *outputPath)
}
