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
	policyPath   string   // original URI (for display/GetPolicyDetails)
	resolvedPath string   // resolved local path (for CalculateDigest)
	opaVersion   string
	prepared     *rego.PreparedEvalQuery
	cleanups     []func() // collected cleanup functions, called in Stop()
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
	// collect cleanup functions from all path resolutions; called in Stop()
	var cleanups []func()

	// if construction fails after we've already extracted/downloaded into a temp
	// dir, Stop() is never reached — run the collected cleanups here so the temp
	// dirs don't leak. This also honors the dispatcher contract for future schemes
	// that may return a non-nil cleanup alongside an error.
	success := false
	defer func() {
		if !success {
			for _, cleanup := range cleanups {
				if cleanup != nil {
					cleanup()
				}
			}
		}
	}()

	// resolve the bundle path (URL download, tar.gz extraction, or local dir)
	bundlePath, bundleCleanup, err := resolveBundlePath(ctx, policyBundlePath, &ResolveOptions{DefaultAsset: "bundle.tar.gz"})
	cleanups = append(cleanups, bundleCleanup)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve bundle path: %w", err)
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
		var actualSchemasPath string
		if schemasPath == policyBundlePath {
			// schemas default to the bundle path (generate.go). Reuse the already
			// resolved bundle directory instead of resolving it a second time —
			// otherwise an http(s):// bundle would be downloaded twice.
			actualSchemasPath = bundlePath
		} else {
			// resolve the schemas path (URL download, tar.gz extraction, or local dir).
			// preserve graceful degradation: on failure, log a warning and fall back to
			// the original path rather than failing evaluator construction.
			resolvedSchemas, schemasCleanup, err := resolveBundlePath(ctx, schemasPath, &ResolveOptions{DefaultAsset: "schemas.tar.gz"})
			if err != nil {
				log.Printf("warning: failed to resolve schemas path: %v", err)
				resolvedSchemas = schemasPath // fallback to original path
				schemasCleanup = func() {}
			}
			cleanups = append(cleanups, schemasCleanup)
			actualSchemasPath = resolvedSchemas
		}

		if _, err := os.Stat(actualSchemasPath); err == nil {
			// load schemas from directory
			schemas, err := loadSchemasFromPath(actualSchemasPath)
			if err != nil {
				// a malformed schema should be visible, not silently disable all
				// type checking
				log.Printf("warning: failed to load schemas from %s: %v", actualSchemasPath, err)
			} else if len(schemas) > 0 {
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

	// construction succeeded — keep the temp dirs alive for Stop() to clean up
	success = true

	return &OPAEvaluator{
		policyPath:   policyBundlePath,
		resolvedPath: bundlePath,
		opaVersion:   viper.GetString("opa-version"),
		prepared:     &prepared,
		cleanups:     cleanups,
	}, nil
}

// isGitHubHost reports whether the GitHub token may be sent to host h. Scoped
// to github.com hosts so the token is never leaked to an arbitrary download URL.
func isGitHubHost(h string) bool {
	switch strings.ToLower(h) {
	case "github.com", "api.github.com":
		return true
	default:
		return false
	}
}

// downloads a bundle from URL and extracts it to a temp dir
func downloadBundle(ctx context.Context, url string) (string, func(), error) {
	// HTTP request with authentication if gh token is available
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}

	// use gh token if available — but ONLY for GitHub hosts, so a non-GitHub
	// --policy-bundle-path URL can never receive the token. (net/http also strips
	// Authorization across host redirects, so this covers the initial request.)
	if token := github.GetToken(); token != "" && isGitHubHost(req.URL.Hostname()) {
		req.Header.Set("Authorization", "token "+token)
	}

	// downloads bundle
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to download bundle: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("warning: failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("failed to download bundle: HTTP %d", resp.StatusCode)
	}

	// temp dir using digest package
	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	if err := extractTarGz(resp.Body, tempDir); err != nil {
		cleanup()
		return "", nil, err
	}

	return tempDir, cleanup, nil
}

// extracts a local tar.gz bundle to a temp directory
func extractBundle(bundlePath string) (string, func(), error) {
	// open the tar.gz file
	file, err := os.Open(bundlePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open bundle file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("warning: failed to close bundle file: %v", err)
		}
	}()

	// create temp dir for extraction
	tempDir, cleanup, err := digest.CreateTempDir("opa-bundle-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	if err := extractTarGz(file, tempDir); err != nil {
		cleanup()
		return "", nil, err
	}

	return tempDir, cleanup, nil
}

// extractTarGz extracts a gzip-compressed tar stream into dest (which must
// already exist), guarding against path-traversal entries. Shared by
// downloadBundle (HTTP body) and extractBundle (local file) so the security
// guard lives in exactly one place.
func extractTarGz(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
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
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// validate path to prevent path traversal attacks
		path := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid path in archive (path traversal attempt): %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.Create(path)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				if err := outFile.Close(); err != nil {
					log.Printf("warning: failed to close file: %v", err)
				}
				return fmt.Errorf("failed to write file: %w", err)
			}
			if err := outFile.Close(); err != nil {
				log.Printf("warning: failed to close file: %v", err)
			}
		}
	}

	return nil
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

// shuts down the OPA evaluator, removing any temp directories created during
// path resolution
func (e *OPAEvaluator) Stop(ctx context.Context) {
	for _, cleanup := range e.cleanups {
		if cleanup != nil {
			cleanup()
		}
	}
}

// returns the resolved local path of the policy bundle (for digest calculation).
// unlike policyPath (the original URI used for display), this is a local
// filesystem path after resolution.
//
// WARNING: for downloaded/extracted bundles this points into a temp directory
// that Stop() removes. Read it before calling Stop() (as generate.go does); a
// path read after Stop() may no longer exist.
func (e *OPAEvaluator) ResolvedPolicyPath() string {
	return e.resolvedPath
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

// downloads policy content from URL and hashes it. Mirrors downloadBundle's
// auth: the GitHub token is attached only for GitHub hosts (never leaked to an
// arbitrary URL), so this no longer diverges from the authenticated download path.
func calculateRemoteDigest(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for %s: %w", url, err)
	}
	if token := github.GetToken(); token != "" && isGitHubHost(req.URL.Hostname()) {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := http.DefaultClient.Do(req)
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
