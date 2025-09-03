package policy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

const (
	tempDirCleanupWarning = "Warning: failed to clean up temp directory: %v\n"
)

// OPAEvaluator handles OPA policy evaluation using the Rego API
type OPAEvaluator struct {
	policyPath string
	prepared   *rego.PreparedEvalQuery
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

// NewOPAEvaluator creates a new OPA evaluator instance
func NewOPAEvaluator(ctx context.Context, policyBundlePath string) (*OPAEvaluator, error) {
	// Download and extract bundle if it's a URL
	var bundlePath string
	if strings.HasPrefix(policyBundlePath, "http") {
		var err error
		bundlePath, err = downloadBundle(ctx, policyBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to download bundle: %w", err)
		}
		// Don't defer cleanup here - we need the files for OPA
	} else {
		bundlePath = policyBundlePath
	}

	// Create OPA instance using Rego API to load policies directly
	policies, err := loadPoliciesFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Build Rego modules for OPA
	var modules []func(*rego.Rego)
	for path, content := range policies {
		modules = append(modules, rego.Module(path, content))
	}

	// Create Rego instance with all policies and queries
	r := rego.New(
		append(modules,
			rego.Query("data.governance.allow"),
			rego.Query("data.governance.violations"),
		)...,
	)

	// Prepare the query for compilation
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare Rego for evaluation: %w", err)
	}

	fmt.Printf("OPA evaluator created with %d policies loaded\n", len(policies))

	return &OPAEvaluator{
		policyPath: policyBundlePath,
		prepared:   &prepared,
	}, nil
}

// downloadBundle downloads a bundle from URL and extracts it to a temp directory
func downloadBundle(ctx context.Context, url string) (string, error) {
	// Use default bundle URL if none provided
	if url == "" {
		url = "https://github.com/liatrio/liatrio-rego-policy-library/releases/download/v0.7.1/bundle.tar.gz"
	}

	// Create HTTP request with authentication if GitHub token is available
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add GitHub token if available (check multiple env vars)
	var token string
	for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if token = os.Getenv(key); token != "" {
			break
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	// Download bundle
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download bundle: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download bundle: HTTP %d", resp.StatusCode)
	}

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "opa-bundle-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Extract tar.gz
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		if err := os.RemoveAll(tempDir); err != nil {
			fmt.Printf(tempDirCleanupWarning, err)
		}
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			fmt.Printf("Warning: failed to close gzip reader: %v\n", err)
		}
	}()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if err := os.RemoveAll(tempDir); err != nil {
				fmt.Printf(tempDirCleanupWarning, err)
			}
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		path := filepath.Join(tempDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				if err := os.RemoveAll(tempDir); err != nil {
					fmt.Printf(tempDirCleanupWarning, err)
				}
				return "", fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				if err := os.RemoveAll(tempDir); err != nil {
					fmt.Printf(tempDirCleanupWarning, err)
				}
				return "", fmt.Errorf("failed to create parent directory: %w", err)
			}

			file, err := os.Create(filepath.Join(tempDir, header.Name))
			if err != nil {
				if err := os.RemoveAll(tempDir); err != nil {
					fmt.Printf(tempDirCleanupWarning, err)
				}
				return "", fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(file, tr); err != nil {
				if err := file.Close(); err != nil {
					fmt.Printf("Warning: failed to close file: %v\n", err)
				}
				return "", fmt.Errorf("failed to write file: %w", err)
			}
			if err := file.Close(); err != nil {
				fmt.Printf("Warning: failed to close file: %v\n", err)
			}
		}
	}

	return tempDir, nil
}

// loadPoliciesFromPath loads all .rego files from a directory
func loadPoliciesFromPath(path string) (map[string]string, error) {
	policies := make(map[string]string)

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(filePath, ".rego") {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read policy file %s: %w", filePath, err)
			}

			// Use relative path as policy ID
			relPath, err := filepath.Rel(path, filePath)
			if err != nil {
				relPath = filepath.Base(filePath)
			}

			policies[relPath] = string(content)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk policy directory: %w", err)
	}

	return policies, nil
}

// Stop shuts down the OPA evaluator (no-op for Rego API)
func (e *OPAEvaluator) Stop(ctx context.Context) {
	// No cleanup needed for Rego API
}

// EvaluatePolicy evaluates OPA policy against attestations
func (e *OPAEvaluator) EvaluatePolicy(ctx context.Context, signatures []oci.Signature) (*PolicyResult, error) {
	// Convert OCI signatures to Sigstore bundle format for OPA evaluation
	bundleData, err := e.createSigstoreBundle(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore bundle: %w", err)
	}

	// Use prepared Rego query to evaluate governance.allow
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(bundleData))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	result := &PolicyResult{
		Result:    "FAILED",
		Details:   make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	// Parse results to find governance.allow and governance.violations
	var allow bool
	var violations []interface{}

	for _, r := range rs {
		for _, expr := range r.Expressions {
			if path, ok := expr.Value.(map[string]interface{}); ok {
				if governance, ok := path["governance"].(map[string]interface{}); ok {
					if allowVal, exists := governance["allow"]; exists {
						if allowBool, ok := allowVal.(bool); ok {
							allow = allowBool
						}
					}
					if violationsVal, exists := governance["violations"]; exists {
						if violationsArray, ok := violationsVal.([]interface{}); ok {
							violations = violationsArray
						}
					}
					if detailsVal, exists := governance["details"]; exists {
						if detailsMap, ok := detailsVal.(map[string]interface{}); ok {
							result.Details["details"] = detailsMap
						}
					}
				}
			}
		}
	}

	if allow {
		result.Result = "PASSED"
	}

	// Parse violations if policy failed
	if !allow && len(violations) > 0 {
		for _, v := range violations {
			if violationMap, ok := v.(map[string]interface{}); ok {
				violation := PolicyViolation{
					Policy:  fmt.Sprintf("%v", violationMap["policy"]),
					Message: fmt.Sprintf("%v", violationMap["message"]),
				}
				result.Violations = append(result.Violations, violation)
			}
		}
	}

	// Add evaluation details
	result.Details["allow"] = allow
	result.Details["input_bundle"] = bundleData
	result.Details["raw_results"] = rs

	return result, nil
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

		// Create bundle entry in the format expected by OPA policies
		// The policy expects a dsseEnvelope.payload field with base64-encoded data
		bundle := map[string]interface{}{
			"dsseEnvelope": map[string]interface{}{
				"payload":     string(payload), // Keep as base64-encoded string
				"payloadType": "application/vnd.in-toto+json",
			},
		}

		bundles = append(bundles, bundle)
	}

	return bundles, nil
}


// GetPolicyDetails returns details about the loaded policy
func (e *OPAEvaluator) GetPolicyDetails() map[string]interface{} {
	return map[string]interface{}{
		"policy_path": e.policyPath,
		"opa_version": "v1.8.0", // Could be made dynamic
	}
}
