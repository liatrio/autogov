package vsa

import (
	"context"
	"fmt"
	"time"

	"github.com/liatrio/autogov/pkg/attestations"
	"github.com/liatrio/autogov/pkg/policy"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/spf13/viper"
)

// contains options for VSA generation
type GenerateOptions struct {
	ArtifactDigest    string
	VSASubjects       []VSASubject
	InputAttestations []ResourceDescriptor
	AttestationTypes  []string
	Signatures        []oci.Signature
	PolicyURI         string
	VSAOutput         string
	PolicyBundlePath  string
	PolicySchemasPath string
	PolicyDataPath    string
	Quiet             bool
	Version           string
	OpaVersion        string
	// IdentityEnforced is true when verification bound the build-provenance
	// signer to a cert-identity / signer allowlist. it gates the SLSA Build L3
	// claim: without an enforced identity the builder is unverified, so the
	// build track stays at L0 even if the provenance signature checked out.
	IdentityEnforced bool
}

// result-map keys shared between buildVerificationResults (producer) and
// generateVSACore (consumer of the build-level signal); kept as consts so the
// contract can't drift silently.
const (
	resultKeySLSAProvenance          = "attestation.slsa_provenance"
	resultKeyProvenanceIdentityBound = "attestation.slsa_provenance.identity_bound"
)

// creates a VSA after successful attestation verification
func Generate(ctx context.Context, opts GenerateOptions) error {
	schemasPath, err := validateGenerateOptions(opts)
	if err != nil {
		return err
	}

	// verification results based on successful attestation verification
	verificationResults := buildVerificationResults(opts.AttestationTypes)

	markIdentityBoundProvenance(verificationResults, opts.IdentityEnforced)

	// OPA policy evaluation
	if !opts.Quiet {
		fmt.Println("Evaluating OPA policy...")
	}

	// require policy bundle for evaluation (policy-uri is just for VSA metadata)
	if opts.PolicyBundlePath == "" {
		return fmt.Errorf("policy evaluation requires --policy-bundle-path (local policy bundle file)")
	}

	// use local policy bundle for evaluation
	policyBundlePath := opts.PolicyBundlePath

	evaluator, err := policy.NewOPAEvaluator(ctx, policyBundlePath, schemasPath, opts.PolicyDataPath)
	if err != nil {
		return fmt.Errorf("failed to create OPA evaluator: %w", err)
	}
	defer evaluator.Stop(ctx)

	// eval policy against attestations
	policyResult, skip, err := evaluatePolicy(ctx, evaluator, opts)
	if err != nil {
		return err
	}
	if skip {
		// no attestations to evaluate / skip policy check
		return nil
	}

	// policy evaluation results
	verificationResults["policy.compliance"] = (policyResult.Result == "PASSED")

	if !opts.Quiet {
		printPolicyEvaluation(policyResult)
	}

	// calculate policy digest from the actual policy content (use the resolved
	// local path so digesting works for remote schemes too, not the raw URI)
	policyDigest, err := policy.CalculateDigest(evaluator.ResolvedPolicyPath())
	if err != nil {
		return fmt.Errorf("failed to calculate policy digest: %w", err)
	}

	// create VSA options with input attestations
	vsaOpts := buildVSAOptions(opts, policyDigest)

	// generate VSA with subjects
	generatedVSA, err := GenerateVSAWithSubjects(opts.ArtifactDigest, opts.VSASubjects, opts.PolicyURI, verificationResults, vsaOpts)
	if err != nil {
		return fmt.Errorf("failed to generate VSA: %w", err)
	}

	// VSA metadata
	if policyResult != nil {
		addPolicyMetadata(generatedVSA, policyResult, policyBundlePath, opts.AttestationTypes)
	}

	// write VSA to file
	if err := WriteToFile(generatedVSA, opts.VSAOutput); err != nil {
		return fmt.Errorf("failed to write VSA: %w", err)
	}

	if !opts.Quiet {
		printVerificationSummary(opts, policyResult)
	}

	// check fail-on-policy-error flag for exit code
	return handlePolicyFailure(policyResult, opts.Quiet)
}

// validates required generate options, emits the introductory log lines, and
// resolves the schemas path (explicit > policy bundle path).
func validateGenerateOptions(opts GenerateOptions) (string, error) {
	// resolve schemas path: explicit > policy bundle path
	schemasPath := opts.PolicySchemasPath
	if schemasPath == "" {
		schemasPath = opts.PolicyBundlePath
	}

	if opts.PolicyURI == "" {
		return "", fmt.Errorf("policy URI is required for VSA generation (use --policy-uri)")
	}

	if opts.VSAOutput == "" {
		return "", fmt.Errorf("VSA output path is required (use --vsa-output)")
	}

	if !opts.Quiet {
		fmt.Println("\n---")
		fmt.Println("Generating Verification Summary Attestation...")
	}

	return schemasPath, nil
}

// builds the verification results map from successful attestation verification,
// mapping each attestation type to its corresponding result key.
func buildVerificationResults(attestationTypes []string) map[string]bool {
	verificationResults := map[string]bool{
		"attestation.verification": true,
		"attestation.signature":    true,
	}

	// specific results for each attestation type
	for _, attType := range attestationTypes {
		switch attType {
		case attestations.PredicateTypeSLSAProvenance:
			verificationResults[resultKeySLSAProvenance] = true
		case attestations.PredicateTypeCycloneDX:
			verificationResults["attestation.sbom"] = true
		case attestations.PredicateTypeVulnerability:
			verificationResults["attestation.vulnerability"] = true
		case attestations.PredicateTypeAutogovCodeScan:
			verificationResults["attestation.code_scan"] = true
		case attestations.PredicateTypeAutogovSourceReview:
			verificationResults["attestation.source_review"] = true
		default:
			verificationResults["attestation."+attType] = true
		}
	}

	return verificationResults
}

// markIdentityBoundProvenance records that build provenance was verified under
// an enforced signer identity (cert-identity / signer allowlist) — the
// precondition for an honest SLSA Build L3 claim. it only sets the key when
// true so the overall PASS/FAIL computation (which fails on any false value) is
// unaffected, and never promotes when provenance wasn't verified or identity
// wasn't enforced.
func markIdentityBoundProvenance(verificationResults map[string]bool, identityEnforced bool) {
	if identityEnforced && verificationResults[resultKeySLSAProvenance] {
		verificationResults[resultKeyProvenanceIdentityBound] = true
	}
}

// prints the policy evaluation completion line and any violations.
func printPolicyEvaluation(policyResult *policy.PolicyResult) {
	fmt.Printf("✓ Policy evaluation completed: %s\n", policyResult.Result)
	if len(policyResult.Violations) > 0 {
		fmt.Printf("  Policy violations: %d\n", len(policyResult.Violations))
		for _, violation := range policyResult.Violations {
			fmt.Printf("    - %s: %s\n", violation.Policy, violation.Message)
		}
	}
}

// builds the VSA options, including the policy digest, OPA version, and autogov
// version (omitted for dev builds).
func buildVSAOptions(opts GenerateOptions, policyDigest string) VSAOptions {
	vsaOpts := VSAOptions{
		InputAttestations: opts.InputAttestations,
		PolicyDigest: map[string]string{
			"sha256": policyDigest,
		},
		AdditionalVerifiers: map[string]string{
			"opa": opts.OpaVersion,
		},
	}

	// add autogov version if not dev build
	if opts.Version != "" && opts.Version != "dev" {
		vsaOpts.AdditionalVerifiers["autogov"] = opts.Version
	}

	return vsaOpts
}

// evaluates the OPA policy against attestations, choosing offline attestations
// (from viper) or online signatures. The returned skip is true when there are no
// attestations to evaluate and the caller should return success without a result.
func evaluatePolicy(ctx context.Context, evaluator *policy.OPAEvaluator, opts GenerateOptions) (*policy.PolicyResult, bool, error) {
	// check if we have offline attestations in viper (set by offline command)
	if offlineAttestations := viper.Get("offline-attestations"); offlineAttestations != nil {
		// use offline attestations directly
		bundlesData, ok := offlineAttestations.([]map[string]interface{})
		if !ok {
			return nil, false, fmt.Errorf("invalid offline attestations format")
		}
		policyResult, err := evaluator.EvaluatePolicyWithBundles(ctx, bundlesData)
		if err != nil {
			return nil, false, fmt.Errorf("failed to evaluate OPA policy with offline attestations: %w", err)
		}
		return policyResult, false, nil
	}

	if opts.Signatures != nil {
		// use online signatures
		policyResult, err := evaluator.EvaluatePolicy(ctx, opts.Signatures)
		if err != nil {
			return nil, false, fmt.Errorf("failed to evaluate OPA policy: %w", err)
		}
		return policyResult, false, nil
	}

	// no attestations to evaluate / skip policy check
	if !opts.Quiet {
		fmt.Println("No attestations available for policy evaluation")
	}
	return nil, true, nil
}

// attaches policy evaluation, violation summary, and compliance metrics metadata
// to the generated VSA.
func addPolicyMetadata(generatedVSA *VSA, policyResult *policy.PolicyResult, policyBundlePath string, attestationTypes []string) {
	if generatedVSA.Metadata == nil {
		generatedVSA.Metadata = make(map[string]interface{})
	}

	// policy evaluation metadata
	violations := policyResult.Violations
	if violations == nil {
		violations = []policy.PolicyViolation{}
	}
	generatedVSA.Metadata["autogov.policy.evaluation"] = map[string]interface{}{
		"result":          policyResult.Result,
		"violations":      violations,
		"evaluation_time": policyResult.Timestamp,
		// policy_bundle is where the policy was loaded from (may be an archive
		// or remote URI). The SLSA predicate.policy.digest is computed over the
		// resolved policy *contents* (the extracted/evaluated .rego/.json/.yaml),
		// NOT the bytes of policy_bundle — policy_digest_scope makes that explicit
		// so an auditor doesn't expect sha256(policy_bundle) == policy.digest.
		"policy_bundle":       policyBundlePath,
		"policy_digest_scope": "resolved policy contents (not archive bytes)",
	}

	// violation summary by policy type
	violationSummary := make(map[string][]string)
	for _, v := range policyResult.Violations {
		violationSummary[v.Policy] = append(violationSummary[v.Policy], v.Message)
	}
	if len(violationSummary) > 0 {
		generatedVSA.Metadata["autogov.policy.violation_summary"] = violationSummary
	}

	// compliance metrics
	metrics := map[string]interface{}{
		"total_attestations":     len(attestationTypes),
		"verified_attestations":  len(attestationTypes),
		"policy_violations":      len(policyResult.Violations),
		"policy_compliance_rate": 100.0,
	}
	if len(policyResult.Violations) > 0 && len(attestationTypes) > 0 {
		rate := float64(len(attestationTypes)-len(policyResult.Violations)) / float64(len(attestationTypes)) * 100.0
		if rate < 0 {
			rate = 0
		}
		metrics["policy_compliance_rate"] = rate
	}
	generatedVSA.Metadata["autogov.policy.metrics"] = metrics
}

// prints the human-readable verification summary to stdout.
func printVerificationSummary(opts GenerateOptions, policyResult *policy.PolicyResult) {
	fmt.Printf("✓ VSA saved to: %s\n", opts.VSAOutput)
	fmt.Println("\n=== Verification Summary ===")
	fmt.Printf("Artifact: %s\n", opts.ArtifactDigest)
	fmt.Printf("Attestations Verified: %d\n", len(opts.AttestationTypes))
	if policyResult != nil {
		fmt.Printf("Policy Compliance: %s\n", policyResult.Result)
		fmt.Printf("  Evaluation Time: %s\n", policyResult.Timestamp.Format(time.RFC3339))
		fmt.Printf("  Policy Violations: %d\n", len(policyResult.Violations))
		fmt.Printf("  Policy Evaluation: %s\n", policyResult.Result)
	}
	fmt.Println()
}

// honors the fail-on-policy-error flag: returns an error when policy evaluation
// failed and the flag is set, otherwise logs a warning and returns success.
func handlePolicyFailure(policyResult *policy.PolicyResult, quiet bool) error {
	failOnError := viper.GetBool("fail-on-policy-error")

	// check if we have a policy result
	if policyResult != nil && policyResult.Result == "FAILED" {
		if failOnError {
			// exit with error
			return fmt.Errorf("policy evaluation failed with %d violations", len(policyResult.Violations))
		}
		// logs warning / return success
		if !quiet {
			fmt.Printf("⚠ warning: policy evaluation failed with %d violations (exit code 0 due to --fail-on-policy-error=false)\n", len(policyResult.Violations))
		}
	}

	return nil
}
