package offline

import (
	"context"
	"fmt"
	"os"

	"github.com/liatrio/autogov/pkg/certid"
	"github.com/liatrio/autogov/pkg/cli"
	"github.com/liatrio/autogov/pkg/orchestrate"
	"github.com/liatrio/autogov/pkg/vsa"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// applyBoolFlagToViper resolves a bool flag into viper without clobbering an
// env binding. the key is bound to viper in cmd/root.go via BindEnv, so the env
// value is already present. only overwrite it when the flag was explicitly
// passed, otherwise an unconditional viper.Set with the flag default would
// clobber the env binding. an explicit flag therefore wins over the env var.
func applyBoolFlagToViper(cmd *cobra.Command, flag string) {
	if cmd.Flags().Changed(flag) {
		v, _ := cmd.Flags().GetBool(flag)
		viper.Set(flag, v)
	}
}

// ApplyFailOnPolicyError resolves the fail-on-policy-error setting into viper.
func ApplyFailOnPolicyError(cmd *cobra.Command) {
	applyBoolFlagToViper(cmd, "fail-on-policy-error")
}

// runCommandFlags holds the resolved command-line flags for an offline run.
type runCommandFlags struct {
	quiet             bool
	blobPath          string
	imageDigest       string
	attestationsPath  string
	trustedRoot       string
	trustedRootSource string
	certIdentity      string
	certIdentityList  string
	noCache           bool
	certIssuer        string
	sourceRef         string
}

// resolveRunCommandFlags resolves the offline command flags into viper and a
// local struct. quiet and fail-on-policy-error are resolved without clobbering
// their env bindings: only write the flag value when it was explicitly passed,
// then read the effective value back from viper so local control flow honors
// the env binding too.
func resolveRunCommandFlags(cmd *cobra.Command, args []string) runCommandFlags {
	applyBoolFlagToViper(cmd, "quiet")
	ApplyFailOnPolicyError(cmd)

	policyBundleDigest, _ := cmd.Flags().GetString("policy-bundle-digest")
	viper.Set("policy-bundle-digest", policyBundleDigest)

	f := runCommandFlags{quiet: viper.GetBool("quiet")}
	f.blobPath, _ = cmd.Flags().GetString("blob-path")
	f.imageDigest, _ = cmd.Flags().GetString("image-digest")
	f.attestationsPath, _ = cmd.Flags().GetString("attestations")
	f.trustedRoot, _ = cmd.Flags().GetString("trusted-root")
	f.trustedRootSource, _ = cmd.Flags().GetString("trusted-root-source")
	f.certIdentity, _ = cmd.Flags().GetString("cert-identity")
	f.certIdentityList, _ = cmd.Flags().GetString("cert-identity-list")
	f.noCache, _ = cmd.Flags().GetBool("no-cache")
	f.certIssuer, _ = cmd.Flags().GetString("cert-issuer")
	f.sourceRef, _ = cmd.Flags().GetString("source-ref")

	// handle positional argument for digest
	if f.imageDigest == "" && len(args) > 0 {
		f.imageDigest = args[0]
	}

	return f
}

// resolveFilesToProcess expands the blob path (if any) into the list of files
// to process, returning the expanded blob paths and the iteration list. when no
// blobs are provided the iteration list is a single empty entry (attestations
// only).
func resolveFilesToProcess(blobPath string) (blobPaths, filesToProcess []string, err error) {
	if blobPath != "" {
		expandedPaths, err := cli.ExpandBlobPaths(blobPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to expand blob paths: %w", err)
		}
		blobPaths = expandedPaths
	}

	filesToProcess = blobPaths
	if len(filesToProcess) == 0 {
		// no blob files, verify attestations only
		filesToProcess = []string{""}
	}

	return blobPaths, filesToProcess, nil
}

// logVerificationStart prints the pre-verification banner for an artifact.
func logVerificationStart(artifactPath, imageDigest, attestationsPath string) {
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

// runVerification creates the offline verifier, loads the bundles, and verifies
// the selected artifact. it returns the verifier (for bundle reuse) and result.
func runVerification(f runCommandFlags, artifactPath string, acceptedIdentities []string) (*OfflineVerifier, *VerificationResult, error) {
	// verification options
	verifyOpts := VerifyOptions{
		CertIdentity:       f.certIdentity,
		CertOIDCIssuer:     f.certIssuer,
		Quiet:              f.quiet,
		SourceRef:          f.sourceRef,
		TrustedRootSource:  f.trustedRootSource,
		AcceptedIdentities: acceptedIdentities,
	}

	// log what we're verifying
	if !f.quiet {
		logVerificationStart(artifactPath, f.imageDigest, f.attestationsPath)
	}

	// creates offline verifier
	verifier, err := NewOfflineVerifier(f.trustedRoot, verifyOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create offline verifier: %w", err)
	}

	// loads attestation bundles
	if err := verifier.LoadBundlesFromFile(f.attestationsPath); err != nil {
		return nil, nil, fmt.Errorf("failed to load attestation bundles: %w", err)
	}

	if !f.quiet {
		fmt.Println("Loaded attestation bundles successfully")
		fmt.Println("Verifying attestations...")
	}

	result, err := verifyArtifactByInput(verifier, artifactPath, f.imageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("verification failed: %w", err)
	}

	return verifier, result, nil
}

// verifyArtifactByInput selects the verification mode (artifact path, image
// digest, or attestations-only) and runs it.
func verifyArtifactByInput(verifier *OfflineVerifier, artifactPath, imageDigest string) (*VerificationResult, error) {
	if artifactPath != "" {
		return verifier.VerifyArtifact(artifactPath)
	}
	if imageDigest != "" {
		return verifier.VerifyArtifactDigest(imageDigest)
	}
	return verifier.VerifyArtifact("")
}

// countAttestationFailures returns the number of attestations that did not
// verify.
func countAttestationFailures(result *VerificationResult) int {
	failureCount := 0
	for _, att := range result.Attestations {
		if !att.Verified {
			failureCount++
		}
	}
	return failureCount
}

// logVerificationSummary prints the success summary and verified attestation
// types.
func logVerificationSummary(result *VerificationResult) {
	fmt.Println("\nSummary:")
	fmt.Printf("✓ Successfully verified %d attestations\n", len(result.Attestations))

	fmt.Println("\nAttestation Types:")
	i := 1
	for _, att := range result.Attestations {
		if att.Verified {
			fmt.Printf("%d. %s\n", i, att.Type)
			i++
		}
	}
}

// bundleToOPA converts a verified attestation's bundle into the OPA DSSE map
// shape, returning false when the bundle has no usable envelope.
func bundleToOPA(b *bundle.Bundle) (map[string]interface{}, bool) {
	envelope, err := b.Envelope()
	if err != nil || envelope == nil {
		return nil, false
	}
	dsseEnvelope := make(map[string]interface{})
	dsseEnvelope["payload"] = envelope.Payload
	dsseEnvelope["payloadType"] = envelope.PayloadType
	opaBundle := make(map[string]interface{})
	opaBundle["dsseEnvelope"] = dsseEnvelope
	return opaBundle, true
}

// buildVSAInputs walks the verified attestations to build the attestation type
// list, VSA subjects, and OPA bundle inputs.
func buildVSAInputs(result *VerificationResult, bundles []*bundle.Bundle) (attestationTypes []string, vsaSubjects []vsa.VSASubject, bundlesForOPA []map[string]interface{}) {
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
				if opaBundle, ok := bundleToOPA(bundles[i]); ok {
					bundlesForOPA = append(bundlesForOPA, opaBundle)
				}
			}
		}
	}

	// converts to slice for consistency
	for _, subject := range subjectsMap {
		vsaSubjects = append(vsaSubjects, subject)
	}

	return attestationTypes, vsaSubjects, bundlesForOPA
}

// fallbackVSASubjects returns subjects derived from the artifact path or image
// digest when no attestation subjects were found.
func fallbackVSASubjects(artifactPath, imageDigest string) ([]vsa.VSASubject, error) {
	if artifactPath != "" {
		// calculate digest from file
		digestBytes, err := cli.CalculateFileDigest(artifactPath)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate digest: %w", err)
		}
		return []vsa.VSASubject{{
			URI: artifactPath,
			Digest: map[string]string{
				"sha256": digestBytes,
			},
		}}, nil
	}
	if imageDigest != "" {
		return []vsa.VSASubject{{
			URI: imageDigest,
			Digest: map[string]string{
				"sha256": imageDigest,
			},
		}}, nil
	}
	return nil, nil
}

// resolveVSAResourceURI determines the resource URI for the VSA.
func resolveVSAResourceURI(artifactPath string, vsaSubjects []vsa.VSASubject) string {
	if artifactPath != "" {
		return artifactPath
	}
	if len(vsaSubjects) > 0 {
		return vsaSubjects[0].URI
	}
	return "urn:attestation:verification"
}

// generateOfflineVSA generates the VSA for a verified artifact when requested.
func generateOfflineVSA(cmd *cobra.Command, f runCommandFlags, artifactPath string, verifier *OfflineVerifier, result *VerificationResult) error {
	generateVSA, _ := cmd.Flags().GetBool("generate-vsa")
	if !generateVSA {
		return nil
	}

	vsaOutput, _ := cmd.Flags().GetString("vsa-output")
	policyURI, _ := cmd.Flags().GetString("policy-uri")

	if vsaOutput == "" {
		return fmt.Errorf("VSA output path is required when --generate-vsa is used")
	}
	if policyURI == "" {
		return fmt.Errorf("policy URI is required when --generate-vsa is used")
	}

	// reuse already-loaded bundles from verifier (avoids reloading from file)
	bundles := verifier.Bundles()

	// attestation types and create VSA subjects (also converted for OPA)
	attestationTypes, vsaSubjects, bundlesForOPA := buildVSAInputs(result, bundles)

	// uses blob path or digest for main subject if no attestation subjects
	if len(vsaSubjects) == 0 {
		fallback, err := fallbackVSASubjects(artifactPath, f.imageDigest)
		if err != nil {
			return err
		}
		vsaSubjects = fallback
	}

	// determines resource URI for VSA
	resourceURI := resolveVSAResourceURI(artifactPath, vsaSubjects)

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
		Quiet:             f.quiet,
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
	if vsaOutput != "" && !f.quiet {
		fmt.Printf("✓ VSA generated successfully: %s\n", vsaOutput)
	}

	return nil
}

// processArtifact verifies a single artifact and, when requested, generates its
// VSA.
func processArtifact(cmd *cobra.Command, f runCommandFlags, artifactPath string, acceptedIdentities []string) error {
	verifier, result, err := runVerification(f, artifactPath, acceptedIdentities)
	if err != nil {
		return err
	}

	// checks if verification actually succeeded
	if !result.Verified {
		// counts failures for better error reporting
		failureCount := countAttestationFailures(result)
		return fmt.Errorf("verification failed: %d of %d attestations failed verification", failureCount, len(result.Attestations))
	}

	// outputs results via verification summary
	if !f.quiet {
		logVerificationSummary(result)
	}

	return generateOfflineVSA(cmd, f, artifactPath, verifier, result)
}

// handles the offline command execution
func RunCommand(cmd *cobra.Command, args []string) error {
	f := resolveRunCommandFlags(cmd, args)

	if f.attestationsPath == "" {
		return fmt.Errorf("attestations is required")
	}

	// no identity and no list enforced → accept any valid signature (unsafe).
	// warn once on stderr, ungated by --quiet.
	if f.certIdentity == "" && f.certIdentityList == "" {
		fmt.Fprintf(os.Stderr, "warning: no certificate identity enforced — accepting any valid Fulcio signature (unsafe); set --cert-identity and/or --cert-identity-list to enforce a signer allowlist\n")
	}

	// resolve the signer allowlist (union of --cert-identity and the list) once
	certOpts := orchestrate.SetupCertIdentityValidation(f.certIdentityList, f.noCache, f.quiet)
	acceptedIdentities, err := certid.ResolveAcceptedIdentities(cmd.Context(), f.certIdentity, certOpts)
	if err != nil {
		return fmt.Errorf("failed to resolve accepted certificate identities: %w", err)
	}

	// expand blob paths if provided
	blobPaths, filesToProcess, err := resolveFilesToProcess(f.blobPath)
	if err != nil {
		return err
	}

	for i, artifactPath := range filesToProcess {
		if len(blobPaths) > 1 {
			fmt.Printf("Processing file %d/%d: %s\n", i+1, len(blobPaths), artifactPath)
		}

		if err := processArtifact(cmd, f, artifactPath, acceptedIdentities); err != nil {
			return err
		}
	}

	return nil
}
