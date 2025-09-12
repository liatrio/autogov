package offline

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/liatrio/autogov-verify/pkg/cli"
	"github.com/liatrio/autogov-verify/pkg/vsa"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// handles the offline command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	// parse flags using CLI helpers
	common, err := cli.ParseCommonOptions(cmd)
	if err != nil {
		return err
	}

	selector, err := cli.ParseArtifactSelector(cmd, args)
	if err != nil {
		return err
	}

	offlineOpts, err := cli.ParseOfflineOptions(cmd)
	if err != nil {
		return err
	}

	if offlineOpts.AttestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// verification options
	verifyOpts := VerifyOptions{
		CertIdentity:   common.CertIdentity,
		CertOIDCIssuer: common.CertIssuer,
		SkipTLogVerify: true, // skip tlog verification in offline mode
		Quiet:          common.Quiet,
		SourceRef:      common.SourceRef,
	}

	// log what we're verifying
	if len(selector.BlobPaths) > 0 {
		cli.LogInfoln(common.Quiet, "Verifying artifact: %s", selector.BlobPaths[0])
	} else if selector.ImageDigest != "" {
		cli.LogInfoln(common.Quiet, "Verifying artifact digest: %s", selector.ImageDigest)
	} else {
		cli.LogInfoln(common.Quiet, "No artifact provided - verifying attestations only")
	}
	cli.LogInfoln(common.Quiet, "Using attestations from: %s", offlineOpts.AttestationsPath)
	cli.LogInfoln(common.Quiet, "Performing offline verification...")
	cli.LogInfoln(common.Quiet, "")

	// creates offline verifier
	verifier, err := NewOfflineVerifier(offlineOpts.TrustedRoot, verifyOpts)
	if err != nil {
		return fmt.Errorf("failed to create offline verifier: %w", err)
	}

	// loads attestation bundles
	if err := verifier.LoadBundlesFromFile(offlineOpts.AttestationsPath); err != nil {
		return fmt.Errorf("failed to load attestation bundles: %w", err)
	}

	cli.LogInfoln(common.Quiet, "Loaded attestation bundles successfully")

	// verifies artifact and attestations
	cli.LogInfoln(common.Quiet, "Verifying attestations...")

	var result *VerificationResult
	if len(selector.BlobPaths) > 0 {
		result, err = verifier.VerifyArtifact(selector.BlobPaths[0])
	} else if selector.ImageDigest != "" {
		result, err = verifier.VerifyArtifactDigest(selector.ImageDigest)
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
	cli.LogInfoln(common.Quiet, "\nSummary:")
	cli.LogSuccessln(common.Quiet, "Successfully verified %d attestations", len(result.Attestations))

	// attestation types
	cli.LogInfoln(common.Quiet, "\nAttestation Types:")
	i := 1
	for _, att := range result.Attestations {
		if att.Verified {
			cli.LogInfoln(common.Quiet, "%d. %s", i, att.Type)
			i++
		}
	}

	// VSA generation if requested
	if offlineOpts.GenerateVSA {
		if offlineOpts.VSAOutput == "" {
			return fmt.Errorf("VSA output path is required when --generate-vsa is used")
		}
		if offlineOpts.PolicyURI == "" {
			return fmt.Errorf("policy URI is required when --generate-vsa is used")
		}

		// attestation types and create VSA subjects
		var attestationTypes []string
		var vsaSubjects []vsa.VSASubject
		var bundlesForOPA []map[string]interface{}

		// loads raw bundles to extract payload for OPA
		bundles, err := LoadBundles(offlineOpts.AttestationsPath)
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
			if len(selector.BlobPaths) > 0 {
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: selector.BlobPaths[0],
				})
			} else if selector.ImageDigest != "" {
				// use digest as URI if no artifact path
				vsaSubjects = append(vsaSubjects, vsa.VSASubject{
					URI: fmt.Sprintf("sha256:%s", selector.ImageDigest),
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
		if len(selector.BlobPaths) > 0 {
			resourceURI = selector.BlobPaths[0]
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
			PolicyURI:        offlineOpts.PolicyURI,
			VSAOutput:        offlineOpts.VSAOutput,
			PolicyBundlePath: offlineOpts.PolicyBundlePath, // Enable OPA evaluation with attestations
			Quiet:            common.Quiet,
		}

		// pass attestations to viper for OPA evaluation
		if len(bundlesForOPA) > 0 {
			viper.Set("offline-attestations", bundlesForOPA)
		}

		// sets schemas path in viper for VSA generation to use
		if offlineOpts.PolicySchemasPath != "" {
			viper.Set("policy-schemas-path", offlineOpts.PolicySchemasPath)
		}

		if err := vsa.Generate(ctx, vsaOpts); err != nil {
			return fmt.Errorf("failed to generate VSA: %w", err)
		}

		cli.LogSuccessln(common.Quiet, "\nVSA generated successfully: %s", offlineOpts.VSAOutput)
	}

	return nil
}
