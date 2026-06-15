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
}

// creates a VSA after successful attestation verification
func Generate(ctx context.Context, opts GenerateOptions) error {
	// resolve schemas path: explicit > policy bundle path
	schemasPath := opts.PolicySchemasPath
	if schemasPath == "" {
		schemasPath = opts.PolicyBundlePath
	}

	if opts.PolicyURI == "" {
		return fmt.Errorf("policy URI is required for VSA generation (use --policy-uri)")
	}

	if opts.VSAOutput == "" {
		return fmt.Errorf("VSA output path is required (use --vsa-output)")
	}

	if !opts.Quiet {
		fmt.Println("\n---")
		fmt.Println("Generating Verification Summary Attestation...")
	}

	// verification results based on successful attestation verification
	verificationResults := map[string]bool{
		"attestation.verification": true,
		"attestation.signature":    true,
	}

	// specific results for each attestation type
	for _, attType := range opts.AttestationTypes {
		switch attType {
		case attestations.PredicateTypeSLSAProvenance:
			verificationResults["attestation.slsa_provenance"] = true
		case attestations.PredicateTypeCycloneDX:
			verificationResults["attestation.sbom"] = true
		case attestations.PredicateTypeVulnerability:
			verificationResults["attestation.vulnerability"] = true
		default:
			verificationResults["attestation."+attType] = true
		}
	}

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
	var policyResult *policy.PolicyResult

	// check if we have offline attestations in viper (set by offline command)
	if offlineAttestations := viper.Get("offline-attestations"); offlineAttestations != nil {
		// use offline attestations directly
		if bundlesData, ok := offlineAttestations.([]map[string]interface{}); ok {
			policyResult, err = evaluator.EvaluatePolicyWithBundles(ctx, bundlesData)
			if err != nil {
				return fmt.Errorf("failed to evaluate OPA policy with offline attestations: %w", err)
			}
		} else {
			return fmt.Errorf("invalid offline attestations format")
		}
	} else if opts.Signatures != nil {
		// use online signatures
		policyResult, err = evaluator.EvaluatePolicy(ctx, opts.Signatures)
		if err != nil {
			return fmt.Errorf("failed to evaluate OPA policy: %w", err)
		}
	} else {
		// no attestations to evaluate / skip policy check
		if !opts.Quiet {
			fmt.Println("No attestations available for policy evaluation")
		}
		return nil
	}

	// policy evaluation results
	verificationResults["policy.compliance"] = (policyResult.Result == "PASSED")

	if !opts.Quiet {
		fmt.Printf("✓ Policy evaluation completed: %s\n", policyResult.Result)
		if len(policyResult.Violations) > 0 {
			fmt.Printf("  Policy violations: %d\n", len(policyResult.Violations))
			for _, violation := range policyResult.Violations {
				fmt.Printf("    - %s: %s\n", violation.Policy, violation.Message)
			}
		}
	}

	// calculate policy digest from the actual policy content (use the resolved
	// local path so digesting works for remote schemes too, not the raw URI)
	policyDigest, err := policy.CalculateDigest(evaluator.ResolvedPolicyPath())
	if err != nil {
		return fmt.Errorf("failed to calculate policy digest: %w", err)
	}

	// create VSA options with input attestations
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

	// generate VSA with subjects
	generatedVSA, err := GenerateVSAWithSubjects(opts.ArtifactDigest, opts.VSASubjects, opts.PolicyURI, verificationResults, vsaOpts)
	if err != nil {
		return fmt.Errorf("failed to generate VSA: %w", err)
	}

	// VSA metadata
	if policyResult != nil {
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
			"total_attestations":     len(opts.AttestationTypes),
			"verified_attestations":  len(opts.AttestationTypes),
			"policy_violations":      len(policyResult.Violations),
			"policy_compliance_rate": 100.0,
		}
		if len(policyResult.Violations) > 0 && len(opts.AttestationTypes) > 0 {
			rate := float64(len(opts.AttestationTypes)-len(policyResult.Violations)) / float64(len(opts.AttestationTypes)) * 100.0
			if rate < 0 {
				rate = 0
			}
			metrics["policy_compliance_rate"] = rate
		}
		generatedVSA.Metadata["autogov.policy.metrics"] = metrics
	}

	// write VSA to file
	if err := WriteToFile(generatedVSA, opts.VSAOutput); err != nil {
		return fmt.Errorf("failed to write VSA: %w", err)
	}

	if !opts.Quiet {
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

	// check fail-on-policy-error flag for exit code
	failOnError := viper.GetBool("fail-on-policy-error")

	// check if we have a policy result
	if policyResult != nil && policyResult.Result == "FAILED" {
		if failOnError {
			// exit with error
			return fmt.Errorf("policy evaluation failed with %d violations", len(policyResult.Violations))
		}
		// logs warning / return success
		if !opts.Quiet {
			fmt.Printf("⚠ warning: policy evaluation failed with %d violations (exit code 0 due to --fail-on-policy-error=false)\n", len(policyResult.Violations))
		}
	}

	return nil
}
