package predicate

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-github/v88/github"
	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/metadata-schema.json
var embeddedMetadataSchema string

//go:embed schemas/dependency-vulnerability-schema.json
var embeddedDepscanSchema string

// PolicyRepo represents policy repository configuration.
type PolicyRepo struct {
	Owner string
	Name  string
	Ref   string
}

// Config holds application configuration.
type Config struct {
	PolicyRepo  PolicyRepo
	SchemasPath string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		PolicyRepo: PolicyRepo{
			Owner: GetEnvOrDefault(EnvPolicyRepoOwner, "liatrio"),
			Name:  GetEnvOrDefault(EnvPolicyRepoName, "demo-gh-autogov-policy-library"),
			Ref:   GetEnvOrDefault(EnvPolicyVersion, "main"),
		},
		SchemasPath: GetEnvOrDefault(EnvSchemasPath, "schemas/"),
	}
	return cfg, nil
}

// getEmbeddedSchema returns the embedded schema content by name.
func getEmbeddedSchema(schemaName string) string {
	switch schemaName {
	case "metadata-schema.json":
		return embeddedMetadataSchema
	case "dependency-vulnerability-schema.json":
		return embeddedDepscanSchema
	default:
		return ""
	}
}

// fetchSchemaContent fetches a schema from GitHub or falls back to embedded.
func fetchSchemaContent(schemaName string) (string, error) {
	// try github api first
	if token, err := GetGitHubToken(); err == nil && token != "" {
		cfg, err := LoadConfig()
		if err != nil {
			return "", fmt.Errorf("failed to load config: %w", err)
		}

		client, err := github.NewClient(github.WithAuthToken(token))
		if err != nil {
			return "", fmt.Errorf("failed to create GitHub client: %w", err)
		}
		path := fmt.Sprintf("%s%s", cfg.SchemasPath, schemaName)
		content, _, resp, err := client.Repositories.GetContents(
			context.Background(),
			cfg.PolicyRepo.Owner,
			cfg.PolicyRepo.Name,
			path,
			&github.RepositoryContentGetOptions{Ref: cfg.PolicyRepo.Ref},
		)

		if err == nil && resp.StatusCode == 200 && content != nil {
			if schemaContent, err := content.GetContent(); err == nil {
				return schemaContent, nil
			}
		}
		fmt.Fprintf(os.Stderr, "warning: failed to fetch schema from GitHub API, falling back to embedded\n")
	}

	// fallback to embedded
	if schema := getEmbeddedSchema(schemaName); schema != "" {
		return schema, nil
	}

	return "", fmt.Errorf("failed to fetch schema %s: no schema sources available", schemaName)
}

// ValidateJSON validates JSON data against a named schema.
func ValidateJSON(data []byte, schemaName string) error {
	schemaContent, err := fetchSchemaContent(schemaName)
	if err != nil {
		return err
	}

	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(schemaContent), &schema); err != nil {
		return fmt.Errorf("failed to parse schema: %w", err)
	}

	predicateSchema := schema
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		if predicateObj, ok := props["predicate"].(map[string]interface{}); ok {
			predicateSchema = predicateObj
		}
	}

	schemaData, err := json.Marshal(predicateSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal schema: %w", err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewStringLoader(string(schemaData)),
		gojsonschema.NewBytesLoader(data),
	)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		errs := make([]string, 0, len(result.Errors()))
		for _, e := range result.Errors() {
			errs = append(errs, e.String())
		}
		return fmt.Errorf("validation failed: %v", errs)
	}

	return nil
}

// ValidateMetadata validates metadata attestation data against its schema.
func ValidateMetadata(data []byte) error {
	return ValidateJSON(data, "metadata-schema.json")
}

// ValidateDepscan validates dependency scan attestation data against its schema.
func ValidateDepscan(data []byte) error {
	return ValidateJSON(data, "dependency-vulnerability-schema.json")
}
