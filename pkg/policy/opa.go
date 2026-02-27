package policy

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/liatrio/autogov/pkg/digest"
	"github.com/liatrio/autogov/pkg/github"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/spf13/viper"
)

// handles OPA policy evaluation using the Rego API
type OPAEvaluator struct {
	policyPath string
	opaVersion string
	prepared   *rego.PreparedEvalQuery
}

// result of OPA policy evaluation
type PolicyResult struct {
	Result     string                 `json:"result"` // "PASSED" or "FAILED"
	Violations []PolicyViolation      `json:"violations"`
	Details    map[string]interface{} `json:"details"`
	Timestamp  time.Time              `json:"timestamp"`
}

// policy violation
type PolicyViolation struct {
	Policy  string `json:"policy"`
	Message string `json:"message"`
}

// creates a new OPA evaluator instance
func NewOPAEvaluator(ctx context.Context, policyBundlePath string, schemasPath string, dataPath string) (*OPAEvaluator, error) {
	// download and extract bundle if it's a URL
	var bundlePath string
	if strings.HasPrefix(policyBundlePath, "http") {
		var err error
		bundlePath, err = downloadBundle(ctx, policyBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to download bundle: %w", err)
		}
	} else if strings.HasSuffix(policyBundlePath, ".tar.gz") || strings.HasSuffix(policyBundlePath, ".tgz") {
		// extract local tar.gz bundle
		var err error
		bundlePath, err = extractBundle(policyBundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to extract bundle: %w", err)
		}
	} else {
		bundlePath = policyBundlePath
	}

	// creates OPA instance w/ Rego API to load policies directly
	policies, err := loadPoliciesFromPath(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// builds rego modules for OPA
	var modules []func(*rego.Rego)
	for path, content := range policies {
		modules = append(modules, rego.Module(path, content))
	}

	// add query
	modules = append(modules, rego.Query("data.governance"))

	// add schemas if provided
	if schemasPath != "" {
		// check if it's a tar.gz file that needs extraction
		var actualSchemasPath string
		if strings.HasSuffix(schemasPath, ".tar.gz") || strings.HasSuffix(schemasPath, ".tgz") {
			// extract schemas archive
			extractedPath, err := extractBundle(schemasPath)
			if err != nil {
				log.Printf("warning: failed to extract schemas archive: %v", err)
				actualSchemasPath = schemasPath // fallback to original path
			} else {
				actualSchemasPath = extractedPath
			}
		} else {
			actualSchemasPath = schemasPath
		}

		if _, err := os.Stat(actualSchemasPath); err == nil {
			// load schemas from directory
			schemas, err := loadSchemasFromPath(actualSchemasPath)
			if err == nil && len(schemas) > 0 {
				// convert to SchemaSet
				schemaSet := ast.NewSchemaSet()
				for name, schema := range schemas {
					// schema names with hyphens need to be quoted for OPA refs
					var refStr string
					if strings.Contains(name, "-") {
						refStr = fmt.Sprintf(`schema["%s"]`, name)
					} else {
						refStr = fmt.Sprintf("schema.%s", name)
					}
					schemaSet.Put(ast.MustParseRef(refStr), schema)
				}
				modules = append(modules, rego.Schemas(schemaSet))
				if !viper.GetBool("quiet") {
					fmt.Printf("Loaded %d schemas for validation\n", len(schemas))
				}
			}
		}
	}

	// load additional data file if provided (e.g., vulnerability_thresholds.json)
	if dataPath != "" {
		dataContent, err := loadDataFromPath(dataPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy data from %s: %w", dataPath, err)
		}
		if dataContent != nil {
			store := inmem.NewFromObject(dataContent)
			modules = append(modules, rego.Store(store))
			if !viper.GetBool("quiet") {
				fmt.Printf("Loaded policy data from %s\n", dataPath)
			}
		}
	}

	// rego instance with all policies and queries
	r := rego.New(modules...)

	// query for compilation
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare Rego for evaluation: %w", err)
	}

	if !viper.GetBool("quiet") {
		fmt.Printf("OPA evaluator created with %d policies loaded\n", len(policies))
	}

	return &OPAEvaluator{
		policyPath: policyBundlePath,
		opaVersion: viper.GetString("opa-version"),
		prepared:   &prepared,
	}, nil
}

// downloads a bundle from URL and extracts it to a temp dir
func downloadBundle(ctx context.Context, url string) (string, error) {
	// default bundle URL if none provided
	if url == "" {
		url = "https://github.com/liatrio/liatrio-rego-policy-library/releases/download/v0.7.1/bundle.tar.gz"
	}

	// HTTP request with authentication if gh token is available
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// use gh token if available from centralized client
	if token := github.GetToken(); token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	// downloads bundle
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download bundle: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("warning: failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download bundle: HTTP %d", resp.StatusCode)
	}

	// temp dir using digest package
	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	// note: cleanup will be called when extraction fails, but directory is returned on success
	_ = cleanup

	// extracts tar.gz
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			log.Printf("warning: failed to close gzip reader: %v", err)
		}
	}()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// validate path to prevent path traversal attacks
		path := filepath.Join(tempDir, header.Name)
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(tempDir)+string(os.PathSeparator)) {
			cleanup()
			return "", fmt.Errorf("invalid path in archive (path traversal attempt): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create parent directory: %w", err)
			}

			file, err := os.Create(path)
			if err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(file, tr); err != nil {
				if err := file.Close(); err != nil {
					log.Printf("warning: failed to close file: %v", err)
				}
				cleanup()
				return "", fmt.Errorf("failed to write file: %w", err)
			}
			if err := file.Close(); err != nil {
				log.Printf("warning: failed to close file: %v", err)
			}
		}
	}

	return tempDir, nil
}

// extracts a local tar.gz bundle to a temp directory
func extractBundle(bundlePath string) (string, error) {
	// open the tar.gz file
	file, err := os.Open(bundlePath)
	if err != nil {
		return "", fmt.Errorf("failed to open bundle file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("warning: failed to close bundle file: %v", err)
		}
	}()

	// create temp dir for extraction
	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// extract tar.gz
	gzr, err := gzip.NewReader(file)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			log.Printf("warning: failed to close gzip reader: %v", err)
		}
	}()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// validate path to prevent path traversal attacks
		path := filepath.Join(tempDir, header.Name)
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(tempDir)+string(os.PathSeparator)) {
			cleanup()
			return "", fmt.Errorf("invalid path in archive (path traversal attempt): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.Create(path)
			if err != nil {
				cleanup()
				return "", fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				if err := outFile.Close(); err != nil {
					log.Printf("warning: failed to close file: %v", err)
				}
				cleanup()
				return "", fmt.Errorf("failed to write file: %w", err)
			}
			if err := outFile.Close(); err != nil {
				log.Printf("warning: failed to close file: %v", err)
			}
		}
	}

	return tempDir, nil
}

// loads all .json schema files from a directory
func loadSchemasFromPath(path string) (map[string]interface{}, error) {
	schemas := make(map[string]interface{})

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(filePath, ".json") {
			content, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read schema file %s: %w", filePath, err)
			}

			var schema interface{}
			if err := json.Unmarshal(content, &schema); err != nil {
				return fmt.Errorf("failed to parse schema %s: %w", filePath, err)
			}

			// use filename without extension as key
			schemaName := strings.TrimSuffix(filepath.Base(filePath), ".json")
			schemas[schemaName] = schema
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk schema directory: %w", err)
	}

	return schemas, nil
}

// loadDataFromPath loads a JSON file and returns it as a map for OPA data store
func loadDataFromPath(path string) (map[string]interface{}, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read data file %s: %w", path, err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse data file %s: %w", path, err)
	}

	return data, nil
}

// loads all .rego files from a directory
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

			// relative path as policy ID
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

// shuts down the OPA evaluator (no-op for Rego API)
func (e *OPAEvaluator) Stop(ctx context.Context) {
}

// evaluates OPA policy against attestations
func (e *OPAEvaluator) EvaluatePolicy(ctx context.Context, signatures []oci.Signature) (*PolicyResult, error) {
	// convert OCI signatures to Sigstore bundle format for OPA eval
	bundleData, err := e.createSigstoreBundle(signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore bundle: %w", err)
	}

	return e.evaluatePolicyWithBundleData(ctx, bundleData)
}

// evaluates OPA policy with pre-formatted bundle data (for offline mode)
func (e *OPAEvaluator) EvaluatePolicyWithBundles(ctx context.Context, bundles []map[string]interface{}) (*PolicyResult, error) {
	return e.evaluatePolicyWithBundleData(ctx, bundles)
}

// internal method to evaluate policy with bundle data
func (e *OPAEvaluator) evaluatePolicyWithBundleData(ctx context.Context, bundleData interface{}) (*PolicyResult, error) {
	// rego query to evaluate policy with signature bundle as input
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(bundleData))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	result := &PolicyResult{
		Result:    "FAILED",
		Details:   make(map[string]interface{}),
		Timestamp: time.Now(),
	}

	// results to find governance.allow and governance.violations
	var allow bool
	var violations map[string]interface{}

	for _, r := range rs {
		for _, expr := range r.Expressions {
			// for data.governance query, get the whole governance module
			if expr.Text == "data.governance" {
				if govData, ok := expr.Value.(map[string]interface{}); ok {
					// get allow and violations from governance data
					if allowVal, exists := govData["allow"]; exists {
						if allowBool, ok := allowVal.(bool); ok {
							allow = allowBool
						}
					}
					if violationsVal, exists := govData["violations"]; exists {
						if violationsMap, ok := violationsVal.(map[string]interface{}); ok {
							violations = violationsMap
						}
					}
				}
			}
		}
	}

	if allow {
		result.Result = "PASSED"
	}

	// violations if policy failed
	if !allow && violations != nil {
		// iterate over violation categories (sbom, provenance, etc.)
		for category, categoryViolations := range violations {
			// handle sets/arrays of violations
			if violationSet, ok := categoryViolations.([]interface{}); ok {
				for _, v := range violationSet {
					violation := PolicyViolation{
						Policy:  category,
						Message: fmt.Sprintf("%v", v),
					}
					result.Violations = append(result.Violations, violation)
				}
			} else if categoryViolations != nil {
				// handle single violation or non-empty value
				if msg := fmt.Sprintf("%v", categoryViolations); msg != "[]" && msg != "<nil>" {
					violation := PolicyViolation{
						Policy:  category,
						Message: msg,
					}
					result.Violations = append(result.Violations, violation)
				}
			}
		}
	}

	// evaluation details
	result.Details["allow"] = allow
	result.Details["input_bundle"] = bundleData
	result.Details["raw_results"] = rs

	return result, nil
}

// converts OCI signatures to the Sigstore bundle format expected by OPA policies
func (e *OPAEvaluator) createSigstoreBundle(signatures []oci.Signature) (interface{}, error) {
	var bundles []map[string]interface{}

	for _, sig := range signatures {
		// payload from the signature
		payload, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("failed to get signature payload: %w", err)
		}

		// creates bundle entry in the format expected by OPA policies with a dsseEnvelope.payload field with base64-encoded data
		bundle := map[string]interface{}{
			"dsseEnvelope": map[string]interface{}{
				"payload":     string(payload), // keep as base64-encoded string
				"payloadType": "application/vnd.in-toto+json",
			},
		}

		bundles = append(bundles, bundle)
	}

	return bundles, nil
}

// computes SHA256 hash of policy bundle content
func CalculateDigest(policyPath string) (string, error) {
	// check if it's a directory or file
	info, err := os.Stat(policyPath)
	if err != nil {
		// if path doesn't exist locally, it might be a URL - download and hash content
		if strings.HasPrefix(policyPath, "http") {
			return calculateRemoteDigest(policyPath)
		}
		return "", fmt.Errorf("policy path not found: %w", err)
	}

	if info.IsDir() {
		// hash directory contents with policy-specific extensions
		return digest.CalculateDirectory(policyPath, []string{".rego", ".json", ".yaml"})
	}

	// single file - use digest package
	hexDigest, err := digest.CalculateFile(policyPath)
	if err != nil {
		return "", fmt.Errorf("failed to calculate policy digest: %w", err)
	}
	// strip the "sha256:" prefix to match original format
	_, hex, _ := digest.Parse(hexDigest)
	return hex, nil
}

// downloads policy content from URL and hashes it
func calculateRemoteDigest(url string) (string, error) {
	// create HTTP request
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download policy from %s: %w", url, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("warning: failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download policy: HTTP %d", resp.StatusCode)
	}

	// use digest package to hash the response body
	hexDigest, err := digest.CalculateReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read policy content: %w", err)
	}

	// strip the "sha256:" prefix to match original format
	_, hex, _ := digest.Parse(hexDigest)
	return hex, nil
}

// returns details about the loaded policy
func (e *OPAEvaluator) GetPolicyDetails() map[string]interface{} {
	version := e.opaVersion
	if version == "" {
		version = "unknown"
	}
	return map[string]interface{}{
		"policy_path": e.policyPath,
		"opa_version": version,
	}
}
