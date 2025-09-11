package offline

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/vsa"
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
	sourceRef := viper.GetString("source-ref")
	quiet := viper.GetBool("quiet")

	// VSA generation flags
	generateVSA := viper.GetBool("generate-vsa")
	vsaOutput := viper.GetString("vsa-output")
	policyURI := viper.GetString("policy-uri")
	policyBundlePath := viper.GetString("policy-bundle-path")
	policySchemasPath := viper.GetString("policy-schemas-path")

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

	// verifies artifact and attestations
	if !quiet {
		fmt.Println("Verifying attestations...")
	}

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
	// Display verification summary matching online mode format
	if !quiet {
		fmt.Println("\nSummary:")
		fmt.Printf("✓ Successfully verified %d attestations\n", len(result.Attestations))

		// Show attestation types exactly like online mode
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

		// Extract attestation types and create VSA subjects
		var attestationTypes []string
		var vsaSubjects []vsa.VSASubject
		var bundlesForOPA []map[string]interface{}

		// Load raw bundles to extract payload for OPA
		bundles, err := LoadBundles(attestationsPath)
		if err != nil {
			return fmt.Errorf("failed to reload bundles for OPA: %w", err)
		}

		// Build VSA subjects from verified attestations and convert for OPA
		subjectsMap := make(map[string]vsa.VSASubject)

		for i, attestation := range result.Attestations {
			if attestation.Verified && attestation.Subject != nil {
				attestationTypes = append(attestationTypes, attestation.Type)

				// Create VSA subject from attestation subject
				subjectKey := attestation.Subject.Name
				if existing, ok := subjectsMap[subjectKey]; ok {
					// Merge digests if subject already exists
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

				// Convert bundle to OPA format (matching createSigstoreBundle)
				if i < len(bundles) {
					bundle := bundles[i]

					// Get the payload from the bundle
					if bundle.GetDsseEnvelope() != nil {
						envelope := bundle.GetDsseEnvelope()


						// Create bundle entry in format expected by OPA
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


		// Convert map to slice
		for _, subject := range subjectsMap {
			vsaSubjects = append(vsaSubjects, subject)
		}

		// If no subjects from attestations, create from artifact or use a default
		if len(vsaSubjects) == 0 {
			if artifactPath != "" {
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: artifactPath,
				})
			} else if artifactDigest != "" {
				// Use digest as URI if no artifact path
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: fmt.Sprintf("sha256:%s", artifactDigest),
				})
			} else {
				// Default subject for attestation-only verification
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: "urn:attestation:verification",
				})
			}
		}

		// Determine resource URI for VSA
		resourceURI := ""
		if artifactPath != "" {
			resourceURI = artifactPath
		} else if len(vsaSubjects) > 0 {
			resourceURI = vsaSubjects[0].URI
		} else {
			resourceURI = "urn:attestation:verification"
		}

		// Generate VSA
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

		// Pass attestations to viper for OPA evaluation
		if len(bundlesForOPA) > 0 {
			viper.Set("offline-attestations", bundlesForOPA)
		}

		// Set schemas path in viper for VSA generation to use
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
