package offline

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RunCommand handles the offline command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// gets config values
	artifactPath := viper.GetString("blob-path")
	artifactDigest := viper.GetString("artifact-digest")
	attestationsPath := viper.GetString("attestations")
	trustedRootPath := viper.GetString("trusted-root")
	certIdentity := viper.GetString("cert-identity")
	certIssuer := viper.GetString("cert-issuer")
	quiet := viper.GetBool("quiet")

	if attestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// verification options
	verifyOpts := VerifyOptions{
		CertIdentity:   certIdentity,
		CertOIDCIssuer: certIssuer,
		SkipTLogVerify: true, // skip tlog verification in offline mode
	}

	if !quiet {
		if artifactPath != "" {
			fmt.Printf("Verifying artifact: %s\n", artifactPath)
		} else if artifactDigest != "" {
			fmt.Printf("Verifying artifact digest: %s\n", artifactDigest)
		} else {
			fmt.Println("No artifact provided - verifying attestations only")
		}
		fmt.Printf("Using attestations from: %s\n", attestationsPath)
		fmt.Println("Performing offline verification...")
		fmt.Println()
	}

	// creates offline verifier
	verifier, err := NewOfflineVerifier(trustedRootPath, verifyOpts)
	if err != nil {
		return fmt.Errorf("failed to create offline verifier: %w", err)
	}

	// loads attestation bundles
	if err := verifier.LoadBundlesFromFile(attestationsPath); err != nil {
		return fmt.Errorf("failed to load attestation bundles: %w", err)
	}

	if !quiet {
		fmt.Println("Loaded attestation bundles successfully")
	}

	// verifies artifact - pass either path or digest
	var result *VerificationResult
	if artifactPath != "" {
		result, err = verifier.VerifyArtifact(artifactPath)
	} else if artifactDigest != "" {
		result, err = verifier.VerifyArtifactDigest(artifactDigest)
	} else {
		result, err = verifier.VerifyArtifact("")
	}
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// outputs results
	if result.Verified {
		if !quiet {
			fmt.Println("✓ VERIFICATION SUCCESSFUL")
			fmt.Printf("Verified %d attestations\n", len(result.Attestations))
		} else {
			fmt.Println("VERIFICATION_SUCCESSFUL")
		}
	} else {
		if !quiet {
			fmt.Println("✗ VERIFICATION FAILED")
			for _, attestation := range result.Attestations {
				if !attestation.Verified {
					fmt.Printf("  - %s: %s\n", attestation.Type, attestation.Error)
				}
			}
		} else {
			fmt.Println("VERIFICATION_FAILED")
		}
		return fmt.Errorf("offline verification failed")
	}

	return nil
}
