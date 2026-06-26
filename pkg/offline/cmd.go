package offline

import (
	"context"
	"fmt"
	"os"

	"github.com/liatrio/autogov/pkg/certid"
	"github.com/liatrio/autogov/pkg/cli"
	"github.com/liatrio/autogov/pkg/orchestrate"
	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ApplyFailOnPolicyError resolves the fail-on-policy-error setting into viper.
// the env var (FAIL_ON_POLICY_ERROR) is bound to viper in cmd/root.go via BindEnv,
// so it is already present. only overwrite it when the flag was explicitly passed,
// otherwise an unconditional viper.Set with the flag default (false) would clobber
// the env binding. an explicit flag therefore wins over the env var.
func ApplyFailOnPolicyError(cmd *cobra.Command) {
	if cmd.Flags().Changed("fail-on-policy-error") {
		failOnPolicyError, _ := cmd.Flags().GetBool("fail-on-policy-error")
		viper.Set("fail-on-policy-error", failOnPolicyError)
	}
}

// handles the offline command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// gets config values
	quiet, _ := cmd.Flags().GetBool("quiet")

	// propagate CLI flags to viper for pkg code that reads directly from viper
	viper.Set("quiet", quiet)
	ApplyFailOnPolicyError(cmd)
	policyBundleDigest, _ := cmd.Flags().GetString("policy-bundle-digest")
	viper.Set("policy-bundle-digest", policyBundleDigest)
	blobPath, _ := cmd.Flags().GetString("blob-path")
	imageDigest, _ := cmd.Flags().GetString("image-digest")
	attestationsPath, _ := cmd.Flags().GetString("attestations")
	trustedRoot, _ := cmd.Flags().GetString("trusted-root")
	trustedRootSource, _ := cmd.Flags().GetString("trusted-root-source")
	certIdentity, _ := cmd.Flags().GetString("cert-identity")
	certIdentityList, _ := cmd.Flags().GetString("cert-identity-list")
	noCache, _ := cmd.Flags().GetBool("no-cache")
	certIssuer, _ := cmd.Flags().GetString("cert-issuer")
	sourceRef, _ := cmd.Flags().GetString("source-ref")

	// handle positional argument for digest
	if imageDigest == "" && len(args) > 0 {
		imageDigest = args[0]
	}

	if attestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// no identity and no list enforced → accept any valid signature (unsafe).
	// warn once on stderr, ungated by --quiet.
	if certIdentity == "" && certIdentityList == "" {
		fmt.Fprintf(os.Stderr, "warning: no certificate identity enforced — accepting any valid Fulcio signature (unsafe); set --cert-identity and/or --cert-identity-list to enforce a signer allowlist\n")
	}

	// resolve the signer allowlist (union of --cert-identity and the list) once
	certOpts := orchestrate.SetupCertIdentityValidation(certIdentityList, noCache, quiet)
	acceptedIdentities, err := certid.ResolveAcceptedIdentities(cmd.Context(), certIdentity, certOpts)
	if err != nil {
		return fmt.Errorf("failed to resolve accepted certificate identities: %w", err)
	}

	// expand blob paths if provided
	var blobPaths []string
	if blobPath != "" {
		expandedPaths, err := cli.ExpandBlobPaths(blobPath)
		if err != nil {
			return fmt.Errorf("failed to expand blob paths: %w", err)
		}
		blobPaths = expandedPaths
	}

	// process each blob file or verify attestations only if no blobs
	filesToProcess := blobPaths
	if len(filesToProcess) == 0 {
		// no blob files, verify attestations only
		filesToProcess = []string{""}
	}

	for i, artifactPath := range filesToProcess {
		if len(blobPaths) > 1 {
			fmt.Printf("Processing file %d/%d: %s\n", i+1, len(blobPaths), artifactPath)
		}

		// verification options
		verifyOpts := VerifyOptions{
			CertIdentity:       certIdentity,
			CertOIDCIssuer:     certIssuer,
			Quiet:              quiet,
			SourceRef:          sourceRef,
			TrustedRootSource:  trustedRootSource,
			AcceptedIdentities: acceptedIdentities,
		}

		// log what we're verifying
		if !quiet {
			if artifactPath != "" {
				fmt.Printf("Verifying artifact: %s\n", artifactPath)
			} else if imageDigest != "" {
				fmt.Printf("Verifying artifact digest: %s\n", imageDigest)
			} else {
				fmt.Println("No artifact provided - verifying attestations only")
			}
			fmt.Printf("Using attestations from: %s\n", attestationsPath)
			fmt.Println("Performing offline verification...")
			fmt.Println()
		}

		// creates offline verifier
		verifier, err := NewOfflineVerifier(trustedRoot, verifyOpts)
		if err != nil {
			return fmt.Errorf("failed to create offline verifier: %w", err)
		}

		// loads attestation bundles
		if err := verifier.LoadBundlesFromFile(attestationsPath); err != nil {
			return fmt.Errorf("failed to load attestation bundles: %w", err)
		}

		if !quiet {
			fmt.Println("Loaded attestation bundles successfully")
			fmt.Println("Verifying attestations...")
		}

		var result *VerificationResult
		if artifactPath != "" {
			result, err = verifier.VerifyArtifact(artifactPath)
		} else if imageDigest != "" {
			result, err = verifier.VerifyArtifactDigest(imageDigest)
		} else {
			result, err = verifier.VerifyArtifact("")
		}
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}

		// checks if verification actually succeeded
		if !result.Verified {
			// counts failures for better error reporting
			failureCount := 0
			for _, att := range result.Attestations {
				if !att.Verified {
					failureCount++
				}
			}
			return fmt.Errorf("verification failed: %d of %d attestations failed verification", failureCount, len(result.Attestations))
		}

		// outputs results via verification summary
		if !quiet {
			fmt.Println("\nSummary:")
			fmt.Printf("✓ Successfully verified %d attestations\n", len(result.Attestations))
		}

		// attestation types
		if !quiet {
			fmt.Println("\nAttestation Types:")
			i := 1
			for _, att := range result.Attestations {
				if att.Verified {
					fmt.Printf("%d. %s\n", i, att.Type)
					i++
				}
			}
		}

		// VSA generation if requested
		generateVSA, _ := cmd.Flags().GetBool("generate-vsa")
		if generateVSA {
			vsaOutput, _ := cmd.Flags().GetString("vsa-output")
			policyURI, _ := cmd.Flags().GetString("policy-uri")

			if vsaOutput == "" {
				return fmt.Errorf("VSA output path is required when --generate-vsa is used")
			}
			if policyURI == "" {
				return fmt.Errorf("policy URI is required when --generate-vsa is used")
			}

			// attestation types and create VSA subjects
			var attestationTypes []string
			var vsaSubjects []vsa.VSASubject
			var bundlesForOPA []map[string]interface{}

			// reuse already-loaded bundles from verifier (avoids reloading from file)
			bundles := verifier.Bundles()

			// builds VSA subjects from verified attestations and convert for OPA
			subjectsMap := make(map[string]vsa.VSASubject)

			for i, attestation := range result.Attestations {
				if attestation.Verified && attestation.Subject != nil {
					attestationTypes = append(attestationTypes, attestation.Type)

					// creates VSA subject from attestation subject
					subjectKey := attestation.Subject.Name
					if existing, ok := subjectsMap[subjectKey]; ok {
						// merges digests if subject already exists
						for alg, digest := range attestation.Subject.Digest {
							existing.Digest[alg] = digest
						}
						subjectsMap[subjectKey] = existing
					} else {
						subjectsMap[subjectKey] = vsa.VSASubject{
							URI:    attestation.Subject.Name,
							Digest: attestation.Subject.Digest,
						}
					}

					// processes bundles for OPA
					if i < len(bundles) {
						bundle := bundles[i]
						// converts bundle to OPA format
						envelope, err := bundle.Envelope()
						if err == nil && envelope != nil {
							opaBundle := make(map[string]interface{})
							dsseEnvelope := make(map[string]interface{})
							dsseEnvelope["payload"] = envelope.Payload
							dsseEnvelope["payloadType"] = envelope.PayloadType
							opaBundle["dsseEnvelope"] = dsseEnvelope
							bundlesForOPA = append(bundlesForOPA, opaBundle)
						}
					}
				}
			}

			// converts to slice for consistency
			for _, subject := range subjectsMap {
				vsaSubjects = append(vsaSubjects, subject)
			}

			// uses blob path or digest for main subject if no attestation subjects
			if len(vsaSubjects) == 0 {
				if artifactPath != "" {
					// calculate digest from file
					digestBytes, err := cli.CalculateFileDigest(artifactPath)
					if err != nil {
						return fmt.Errorf("failed to calculate digest: %w", err)
					}
					vsaSubjects = append(vsaSubjects, vsa.VSASubject{
						URI: artifactPath,
						Digest: map[string]string{
							"sha256": digestBytes,
						},
					})
				} else if imageDigest != "" {
					vsaSubjects = append(vsaSubjects, vsa.VSASubject{
						URI: imageDigest,
						Digest: map[string]string{
							"sha256": imageDigest,
						},
					})
				}
			}

			// determines resource URI for VSA
			resourceURI := ""
			if artifactPath != "" {
				resourceURI = artifactPath
			} else if len(vsaSubjects) > 0 {
				resourceURI = vsaSubjects[0].URI
			} else {
				resourceURI = "urn:attestation:verification"
			}

			// generates VSA
			ctx := context.Background()
			policyBundlePath, _ := cmd.Flags().GetString("policy-bundle-path")
			policySchemasPath, _ := cmd.Flags().GetString("policy-schemas-path")
			policyDataPath, _ := cmd.Flags().GetString("policy-data-path")

			vsaOptions := vsa.GenerateOptions{
				PolicyBundlePath:  policyBundlePath,
				PolicySchemasPath: policySchemasPath,
				PolicyDataPath:    policyDataPath,
				PolicyURI:         policyURI,
				VSAOutput:         vsaOutput,
				Quiet:             quiet,
			}

			// pass attestations to viper for OPA evaluation
			if len(bundlesForOPA) > 0 {
				viper.Set("offline-attestations", bundlesForOPA)
			}

			vsaOptions.ArtifactDigest = resourceURI
			vsaOptions.VSASubjects = vsaSubjects
			vsaOptions.AttestationTypes = attestationTypes
			vsaOptions.Signatures = nil // no oci signatures in offline mode

			if err := vsa.Generate(ctx, vsaOptions); err != nil {
				return fmt.Errorf("failed to generate VSA: %w", err)
			}

			// VSA is saved if vsaOutput is provided
			if vsaOutput != "" && !quiet {
				fmt.Printf("✓ VSA generated successfully: %s\n", vsaOutput)
			}
		}
	}

	return nil
}
