package predicate

import (
	pred "github.com/liatrio/autogov/pkg/predicate"
	"github.com/spf13/cobra"
)

var agentGovernanceDeploymentCmd = &cobra.Command{
	Use:   "agent-governance-deployment",
	Short: "Generate an agent-governance deployment attestation predicate from evidence JSON",
	Long: `Generate the predicate body for the experimental runtime-neutral
agent-governance deployment attestation
(https://autogov.dev/attestation/agent-governance-deployment/v0.1).

The command reads one normalized evidence JSON document emitted by a runtime
adapter, normalizes it deterministically (sorted collections, canonical
lowercase digests, UTC-second timestamps), enforces the v0.1 schema contract's
semantic rules (fail-closed on missing or malformed digests, duplicate case
identifiers, contradictory observations, and size bounds), and emits only the
predicate body. A separate signing step wraps the body in an in-toto Statement
whose single subject must match the predicate's agent name and artifact digest.

The evidence must never contain raw prompts, tool arguments, credentials, or
model output — only bounded redacted references and digests.`,
	RunE: runAgentGovernanceDeployment,
}

var (
	agentGovernanceEvidencePath string
	agentGovernanceOutput       string
)

func init() {
	flags := agentGovernanceDeploymentCmd.Flags()
	flags.StringVar(&agentGovernanceEvidencePath, "evidence-path", "", "Path to the normalized agent-governance evidence JSON emitted by a runtime adapter (required)")
	flags.StringVar(&agentGovernanceOutput, "output", "", "Output file path (defaults to stdout)")
	cobra.CheckErr(agentGovernanceDeploymentCmd.MarkFlagRequired("evidence-path"))
}

func runAgentGovernanceDeployment(_ *cobra.Command, _ []string) error {
	return pred.GenerateAgentGovernanceDeployment(agentGovernanceEvidencePath, agentGovernanceOutput)
}
