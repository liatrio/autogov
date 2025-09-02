package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/sdk"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

// OPAEvaluator handles OPA policy evaluation using the OPA Go SDK
type OPAEvaluator struct {
	opa        *sdk.OPA
	policyPath string
}

// PolicyResult represents the result of OPA policy evaluation
type PolicyResult struct {
	Result     string                 `json:"result"` // "PASSED" or "FAILED"
	Violations []PolicyViolation      `json:"violations"`
	Details    map[string]interface{} `json:"details"`
	Timestamp  time.Time              `json:"timestamp"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	Policy  string `json:"policy"`
	Message string `json:"message"`
}

// NewOPAEvaluator creates a new OPA evaluator with policy bundle
func NewOPAEvaluator(ctx context.Context, policyBundlePath string) (*OPAEvaluator, error) {
	// For now, create a simple OPA instance without bundle loading
	// TODO: Implement proper bundle loading from policyBundlePath
	opa, err := sdk.New(ctx, sdk.Options{
		ID: "autogov-verify-opa",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA instance: %w", err)
	}

	return &OPAEvaluator{
		opa:        opa,
		policyPath: policyBundlePath,
	}, nil
}

// Stop shuts down the OPA evaluator
func (e *OPAEvaluator) Stop(ctx context.Context) {
	if e.opa != nil {
		e.opa.Stop(ctx)
	}
}

// EvaluatePolicy evaluates OPA policy against attestations
func (e *OPAEvaluator) EvaluatePolicy(ctx context.Context, signatures []oci.Signature) (*PolicyResult, error) {
	// Convert signatures to the format expected by OPA policies
	bundleData, err := e.createSigstoreBundle(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore bundle: %w", err)
	}

	// Evaluate governance.allow rule
	allowResult, err := e.opa.Decision(ctx, sdk.DecisionOptions{
		Path:  "data.governance.allow",
		Input: bundleData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate governance.allow: %w", err)
	}

	// Determine result status
	result := "FAILED"
	if allow, ok := allowResult.Result.(bool); ok && allow {
		result = "PASSED"
	}

	// If failed, get violations
	var violations []PolicyViolation
	if result == "FAILED" {
		violationsResult, err := e.opa.Decision(ctx, sdk.DecisionOptions{
			Path:  "data.governance.violations",
			Input: bundleData,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate governance.violations: %w", err)
		}

		violations = e.parseViolations(violationsResult.Result)
	}

	return &PolicyResult{
		Result:     result,
		Violations: violations,
		Details: map[string]interface{}{
			"policy_path":        e.policyPath,
			"evaluation_time":    time.Now().UTC(),
			"input_attestations": len(signatures),
		},
		Timestamp: time.Now().UTC(),
	}, nil
}

// createSigstoreBundle converts OCI signatures to the Sigstore bundle format expected by OPA policies
func (e *OPAEvaluator) createSigstoreBundle(signatures []oci.Signature) (interface{}, error) {
	var bundles []map[string]interface{}

	for _, sig := range signatures {
		// Get the payload from the signature
		payload, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get signature payload: %w", err)
		}

		// Decode base64 payload to get the attestation
		decodedPayload, err := base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			return nil, fmt.Errorf("failed to decode payload: %w", err)
		}

		// Parse the attestation statement
		var statement map[string]interface{}
		if err := json.Unmarshal(decodedPayload, &statement); err != nil {
			return nil, fmt.Errorf("failed to parse statement: %w", err)
		}

		// Create bundle entry in the format expected by OPA policies
		bundle := map[string]interface{}{
			"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
			"content": map[string]interface{}{
				"messageSignature": map[string]interface{}{
					"messageSignature": map[string]interface{}{
						"signature": "", // Would need actual signature data
					},
				},
				"dsseEnvelope": map[string]interface{}{
					"payload":     string(payload),
					"payloadType": "application/vnd.in-toto+json",
					"signatures": []map[string]interface{}{
						{
							"sig": "", // Would need actual signature
						},
					},
				},
			},
			// Include the decoded statement for easier policy access
			"statement": statement,
		}

		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// parseViolations converts OPA violations result to structured violations
func (e *OPAEvaluator) parseViolations(result interface{}) []PolicyViolation {
	var violations []PolicyViolation

	// Handle different violation result formats
	switch v := result.(type) {
	case []interface{}:
		for _, violation := range v {
			if violationMap, ok := violation.(map[string]interface{}); ok {
				policy := ""
				message := ""

				if p, exists := violationMap["policy"]; exists {
					if pStr, ok := p.(string); ok {
						policy = pStr
					}
				}

				if m, exists := violationMap["message"]; exists {
					if mStr, ok := m.(string); ok {
						message = mStr
					}
				}

				if policy != "" || message != "" {
					violations = append(violations, PolicyViolation{
						Policy:  policy,
						Message: message,
					})
				}
			}
		}
	case map[string]interface{}:
		// Handle single violation or violation map
		for policy, messages := range v {
			if msgList, ok := messages.([]interface{}); ok {
				for _, msg := range msgList {
					if msgStr, ok := msg.(string); ok {
						violations = append(violations, PolicyViolation{
							Policy:  policy,
							Message: msgStr,
						})
					}
				}
			}
		}
	}

	return violations
}

// GetPolicyDetails returns details about the loaded policy
func (e *OPAEvaluator) GetPolicyDetails() map[string]interface{} {
	return map[string]interface{}{
		"policy_path": e.policyPath,
		"opa_version": "v1.8.0", // Could be made dynamic
	}
}
