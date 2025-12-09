package vsa

import (
	"context"
	"fmt"
	"time"

	"github.com/liatrio/autogov-verify/pkg/attestations"
	"github.com/liatrio/autogov-verify/pkg/policy"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/spf13/viper"
)

const (
	flagPolicyURI         = "policy-uri"
	flagVSAOutput         = "vsa-output"
	flagPolicyBundlePath  = "policy-bundle-path"
	flagPolicySchemasPath = "policy-schemas-path"
	flagPolicyDataPath    = "policy-data-path"
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
	PolicyDataPath    string
	Quiet             bool
	Version           string
	OpaVersion        string
}

// creates a VSA after successful attestation verification
func Generate(ctx context.Context, opts GenerateOptions) error {
	if opts.PolicyURI == "" {
		opts.PolicyURI = viper.GetString(flagPolicyURI)
	}
	if opts.VSAOutput == "" {
		opts.VSAOutput = viper.GetString(flagVSAOutput)
	}
	if opts.PolicyBundlePath == "" {
		opts.PolicyBundlePath = viper.GetString(flagPolicyBundlePath)
	}

	// get schemas path for policy validation
	schemasPath := viper.GetString(flagPolicySchemasPath)
	if schemasPath == "" {
		schemasPath = viper.GetString(flagPolicyBundlePath)
	}

	// get data path for OPA data (e.g., vulnerability_thresholds)
	if opts.PolicyDataPath == "" {
		opts.PolicyDataPath = viper.GetString(flagPolicyDataPath)
	}

	if opts.PolicyURI == "" {
		return fmt.Errorf("policy URI is required for VSA generation (use --%s)", flagPolicyURI)
	}

	if opts.VSAOutput == "" {
		return fmt.Errorf("VSA output path is required (use --%s)", flagVSAOutput)
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

	// calculate policy digest from the actual policy content
	policyDigest, err := policy.CalculateDigest(policyBundlePath)
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

	// add autogov-verify version if not dev build
	if opts.Version != "" && opts.Version != "dev" {
		vsaOpts.AdditionalVerifiers["autogov-verify"] = opts.Version
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
			"policy_bundle":   policyBundlePath,
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
			metrics["policy_compliance_rate"] = float64(len(opts.AttestationTypes)-len(policyResult.Violations)) / float64(len(opts.AttestationTypes)) * 100.0
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
