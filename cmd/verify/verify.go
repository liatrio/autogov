package verify

import (
	"github.com/spf13/cobra"
)

// flag constants shared across verify subcommands
const (
	flagImageDigest        = "image-digest"
	flagBlobPath           = "blob-path"
	flagRepo               = "repo"
	flagCertIdentity       = "cert-identity"
	flagCertIssuer         = "cert-issuer"
	flagSourceRef          = "source-ref"
	flagQuiet              = "quiet"
	flagAttestationsPath   = "attestations-path"
	flagCertIdentityList   = "cert-identity-list"
	flagNoCache            = "no-cache"
	flagPolicyBundlePath   = "policy-bundle-path"
	flagPolicySchemasPath  = "policy-schemas-path"
	flagPolicyDataPath     = "policy-data-path"
	flagPolicyBundleDigest = "policy-bundle-digest"
	flagFailOnPolicyError  = "fail-on-policy-error"
	flagGenerateVSA        = "generate-vsa"
	flagVSAOutput          = "vsa-output"
	flagPolicyURI          = "policy-uri"
	attestationURNFormat   = "urn:attestation:sha256:%s"
)

// build-time vars — set via SetBuildInfo from cmd/root.go
var (
	version    = "dev"
	opaVersion = "v1.8.0"
)

// SetBuildInfo sets build-time version information for VSA generation.
func SetBuildInfo(v, opa string) {
	version = v
	opaVersion = opa
}

// NewVerifyCmdForTesting creates a fresh VerifyCmd instance for use in tests.
func NewVerifyCmdForTesting() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify attestations, commit signatures, source provenance, and policies",
	}
	cmd.AddCommand(newAttestationCmd())
	cmd.AddCommand(newGitCmd())
	cmd.AddCommand(newSourceCmd())
	cmd.AddCommand(newPolicyCmd())
	return cmd
}

// VerifyCmd is the parent command for all verify operations.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify attestations, commit signatures, source provenance, and policies",
	Long: `Commands for verifying artifact attestations, commit signatures, source provenance, and repository policies.

Examples:
  # Verify GitHub artifact attestations
  autogov verify attestation --blob-path artifact.tar.gz --repo org/repo

  # Verify gitsign commit signatures
  autogov verify git HEAD

  # Verify source provenance
  autogov verify source --attestation-path bundle.json --repo-uri https://github.com/org/repo --commit abc123

  # Verify repository policy
  autogov verify policy --ref refs/heads/main`,
}

func init() {
	VerifyCmd.AddCommand(newAttestationCmd())
	VerifyCmd.AddCommand(newGitCmd())
	VerifyCmd.AddCommand(newSourceCmd())
	VerifyCmd.AddCommand(newPolicyCmd())
}
