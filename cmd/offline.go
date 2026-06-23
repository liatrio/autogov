package cmd

import (
	"fmt"

	"github.com/liatrio/autogov/pkg/offline"
	"github.com/spf13/cobra"
)

const (
	flagOfflineAttestations = "attestations"
	flagOfflineTrustedRoot  = "trusted-root"
	flagTrustedRootSource   = "trusted-root-source"
)

var offlineCmd = &cobra.Command{
	Use:   "offline",
	Short: "Verify attestations offline using pre-downloaded bundles",
	Long: `Verify GitHub artifact attestations using pre-downloaded Sigstore bundles
and trusted roots. This enables verification in air-gapped environments without
requiring GitHub API access or online Sigstore infrastructure.

Examples:
  # Verify a blob file offline
  autogov offline --blob-path artifact.tar.gz --attestations bundles.jsonl --cert-identity "workflow@ref"

  # Verify against a signer allowlist (URL or file path)
  autogov offline --blob-path artifact.tar.gz --attestations bundles.jsonl --cert-identity-list cert-identities.json

  # Verify with custom trusted root
  autogov offline --blob-path artifact.tar.gz --attestations bundles.jsonl --trusted-root root.json

  # Verify attestations only (no artifact)
  autogov offline --attestations bundles.jsonl --cert-identity "workflow@ref"`,
	RunE: runOffline,
}

func init() {
	offlineCmd.Flags().String(flagBlobPath, "", "Path to artifact file to verify (optional - if not provided, verifies attestations only)")
	offlineCmd.Flags().String(flagImageDigest, "", "Artifact digest to verify (e.g., sha256:abc123... for container images)")
	offlineCmd.Flags().String(flagOfflineAttestations, "", "Path to attestation bundles file (required)")
	offlineCmd.Flags().String(flagCertIdentity, "", "Expected certificate identity (optional; usable with --cert-identity-list as a signer allowlist — if neither is set, any valid signature is accepted)")
	offlineCmd.Flags().String(flagCertIdentityList, "", "Signer allowlist: URL or file path to a certificate identity list. Accepted identities are enforced as a signer allowlist; usable with or without --cert-identity (their union is accepted)")
	offlineCmd.Flags().Bool(flagNoCache, false, "Disable caching of the certificate identity list")
	offlineCmd.Flags().String(flagCertIssuer, "https://token.actions.githubusercontent.com", "Expected certificate issuer")
	offlineCmd.Flags().BoolP(flagQuiet, "q", false, "Only show errors and final results")
	offlineCmd.Flags().String(flagOfflineTrustedRoot, "", "Path to trusted root file (optional, takes precedence over --trusted-root-source)")
	offlineCmd.Flags().String(flagTrustedRootSource, "auto", "Trusted root source: github, public, or auto (default: auto)")

	// VSA generation flags for offline mode
	offlineCmd.Flags().Bool(flagGenerateVSA, false, "Generate Verification Summary Attestation after successful verification")
	offlineCmd.Flags().String(flagVSAOutput, "", "Output path for generated VSA (required if --generate-vsa is used)")
	offlineCmd.Flags().String(flagPolicyURI, "", "Policy URI for VSA generation (required if --generate-vsa is used)")
	offlineCmd.Flags().String(flagPolicyBundlePath, "", "Policy bundle source: local dir, .tar.gz, http(s):// URL, oci://registry/repo:tag, or ghrel://owner/repo[@tag][?asset=bundle.tar.gz]. Without @tag, ghrel:// uses the latest release (GitHub's most recent non-prerelease, non-draft, which may differ from an OCI :latest tag)")
	offlineCmd.Flags().String(flagPolicySchemasPath, "", "JSON schemas source for OPA validation: local dir, .tar.gz, http(s):// URL, oci://, or ghrel://owner/repo[@tag][?asset=schemas.tar.gz] (default asset schemas.tar.gz)")
	offlineCmd.Flags().String(flagPolicyDataPath, "", "Path to JSON file containing additional OPA data (e.g., vulnerability_thresholds)")
	offlineCmd.Flags().String(flagPolicyBundleDigest, "", "Expected SHA-256 of the downloaded policy bundle asset (sha256:...); enforced for ghrel:// bundle paths. Distinct from --image-digest")
	offlineCmd.Flags().Bool(flagFailOnPolicyError, false, "Exit with error when policy evaluation fails (default: false)")
	offlineCmd.Flags().String(flagSourceRef, "", "Source repository ref to verify against (e.g., refs/heads/main)")

	offlineCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		blobPath, _ := cmd.Flags().GetString(flagBlobPath)
		imageDigest, _ := cmd.Flags().GetString(flagImageDigest)

		if blobPath == "" && imageDigest == "" && len(args) == 0 {
			return fmt.Errorf("must specify --%s, --%s, or provide artifact digest as argument", flagBlobPath, flagImageDigest)
		}

		return nil
	}

	if err := offlineCmd.MarkFlagRequired(flagOfflineAttestations); err != nil {
		panic(fmt.Sprintf("failed to mark attestations flag required: %v", err))
	}
}

func runOffline(cmd *cobra.Command, args []string) error {
	return offline.RunCommand(cmd, args)
}
