package verify

import (
	"github.com/spf13/cobra"
)

// flag constants shared across verify subcommands
const (
	flagImageDigest       = "image-digest"
	flagBlobPath          = "blob-path"
	flagRepo              = "repo"
	flagCertIdentity      = "cert-identity"
	flagCertIssuer        = "cert-issuer"
	flagSourceRef         = "source-ref"
	flagQuiet             = "quiet"
	flagAttestationsPath  = "attestations-path"
	flagCertIdentityList  = "cert-identity-list"
	flagNoCache           = "no-cache"
	flagPolicyBundlePath  = "policy-bundle-path"
	flagPolicySchemasPath = "policy-schemas-path"
	flagPolicyDataPath    = "policy-data-path"
	flagFailOnPolicyError = "fail-on-policy-error"
	flagGenerateVSA       = "generate-vsa"
	flagVSAOutput         = "vsa-output"
	flagPolicyURI         = "policy-uri"
	attestationURNFormat  = "urn:attestation:sha256:%s"
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
		Short: "Verify attestations and commit signatures",
	}
	cmd.AddCommand(newAttestationCmd())
	cmd.AddCommand(newGitCmd())
	return cmd
}

// VerifyCmd is the parent command for all verify operations.
var VerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify attestations and commit signatures",
	Long: `Commands for verifying artifact attestations and commit signatures.

Examples:
  # Verify GitHub artifact attestations
  autogov verify attestation --blob-path artifact.tar.gz --repo org/repo

  # Verify gitsign commit signatures
  autogov verify git HEAD`,
}

func init() {
	VerifyCmd.AddCommand(newAttestationCmd())
	VerifyCmd.AddCommand(newGitCmd())
}
