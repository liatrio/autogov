package offline

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// handles the offline command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// gets config values with error checking
	var (
		artifactPath     string
		imageDigest      string
		attestationsPath string
		trustedRootPath  string
		certIdentity     string
		certIssuer       string
		sourceRef        string
		quiet            bool

		generateVSA       bool
		vsaOutput         string
		policyURI         string
		policyBundlePath  string
		policySchemasPath string
	)
	var err error

	if artifactPath, err = cmd.Flags().GetString("blob-path"); err != nil {
		return fmt.Errorf("failed to read --blob-path flag: %w", err)
	}
	if imageDigest, err = cmd.Flags().GetString("image-digest"); err != nil {
		return fmt.Errorf("failed to read --image-digest flag: %w", err)
	}
	if attestationsPath, err = cmd.Flags().GetString("attestations"); err != nil {
		return fmt.Errorf("failed to read --attestations flag: %w", err)
	}
	if trustedRootPath, err = cmd.Flags().GetString("trusted-root"); err != nil {
		return fmt.Errorf("failed to read --trusted-root flag: %w", err)
	}
	if certIdentity, err = cmd.Flags().GetString("cert-identity"); err != nil {
		return fmt.Errorf("failed to read --cert-identity flag: %w", err)
	}
	if certIssuer, err = cmd.Flags().GetString("cert-issuer"); err != nil {
		return fmt.Errorf("failed to read --cert-issuer flag: %w", err)
	}
	if sourceRef, err = cmd.Flags().GetString("source-ref"); err != nil {
		return fmt.Errorf("failed to read --source-ref flag: %w", err)
	}
	if quiet, err = cmd.Flags().GetBool("quiet"); err != nil {
		return fmt.Errorf("failed to read --quiet flag: %w", err)
	}

	// VSA generation flags
	if generateVSA, err = cmd.Flags().GetBool("generate-vsa"); err != nil {
		return fmt.Errorf("failed to read --generate-vsa flag: %w", err)
	}
	if vsaOutput, err = cmd.Flags().GetString("vsa-output"); err != nil {
		return fmt.Errorf("failed to read --vsa-output flag: %w", err)
	}
	if policyURI, err = cmd.Flags().GetString("policy-uri"); err != nil {
		return fmt.Errorf("failed to read --policy-uri flag: %w", err)
	}
	if policyBundlePath, err = cmd.Flags().GetString("policy-bundle-path"); err != nil {
		return fmt.Errorf("failed to read --policy-bundle-path flag: %w", err)
	}
	if policySchemasPath, err = cmd.Flags().GetString("policy-schemas-path"); err != nil {
		return fmt.Errorf("failed to read --policy-schemas-path flag: %w", err)
	}

	if attestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// verification options
	verifyOpts := VerifyOptions{
		CertIdentity:   certIdentity,
		CertOIDCIssuer: certIssuer,
		SkipTLogVerify: true, // skip tlog verification in offline mode
		Quiet:          quiet,
		SourceRef:      sourceRef,
	}

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

	// verifies artifact and attestations
	if !quiet {
		fmt.Println("Verifying attestations...")
	}

	var result *VerificationResult
	if artifactPath != "" {
		result, err = verifier.VerifyArtifact(artifactPath)
	} else if imageDigest != "" {
		result, err = verifier.VerifyArtifactDigest(imageDigest)
	} else if len(args) > 0 {
		result, err = verifier.VerifyArtifactDigest(args[0])
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

		// attestation types
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
	if generateVSA {
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

		// loads raw bundles to extract payload for OPA
		bundles, err := LoadBundles(attestationsPath)
		if err != nil {
			return fmt.Errorf("failed to reload bundles for OPA: %w", err)
		}

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

				// converts bundle to OPA format (matches createSigstoreBundle)
				if i < len(bundles) {
					bundle := bundles[i]

					// gets the payload from the bundle
					if bundle.GetDsseEnvelope() != nil {
						envelope := bundle.GetDsseEnvelope()

						// creates bundle entry in format expected by OPA
						opaBundle := map[string]interface{}{
							"dsseEnvelope": map[string]interface{}{
								"payload":     base64.StdEncoding.EncodeToString(envelope.GetPayload()),
								"payloadType": envelope.GetPayloadType(),
								"signatures":  envelope.GetSignatures(),
							},
						}
						bundlesForOPA = append(bundlesForOPA, opaBundle)
					}
				}
			}
		}

		// converst map to slice
		for _, subject := range subjectsMap {
			vsaSubjects = append(vsaSubjects, subject)
		}

		// if no subjects from attestations, create from artifact or use a default
		if len(vsaSubjects) == 0 {
			if artifactPath != "" {
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: artifactPath,
				})
			} else if imageDigest != "" {
				// use digest as URI if no artifact path
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: fmt.Sprintf("sha256:%s", imageDigest),
				})
			} else {
				// defaults subject for attestation-only verification
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: "urn:attestation:verification",
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
		vsaOpts := vsa.GenerateOptions{
			ArtifactDigest:   resourceURI, // Use resourceURI as the "artifact digest" parameter
			VSASubjects:      vsaSubjects,
			AttestationTypes: attestationTypes,
			Signatures:       nil, // No OCI signatures in offline mode
			PolicyURI:        policyURI,
			VSAOutput:        vsaOutput,
			PolicyBundlePath: policyBundlePath, // Enable OPA evaluation with attestations
			Quiet:            quiet,
		}

		// pass attestations to viper for OPA evaluation
		if len(bundlesForOPA) > 0 {
			viper.Set("offline-attestations", bundlesForOPA)
		}

		// sets schemas path in viper for VSA generation to use
		if policySchemasPath != "" {
			viper.Set("policy-schemas-path", policySchemasPath)
		}

		if err := vsa.Generate(ctx, vsaOpts); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}

		if !quiet {
			fmt.Printf("\n✓ VSA generated successfully: %s\n", vsaOutput)
		}
	}

	return nil
}
