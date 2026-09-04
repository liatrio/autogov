package evidence

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed schemas/agent-governance-deployment-schema.json
var embeddedAgentGovernanceDeploymentSchema string

//go:embed schemas/test-result-schema.json
var embeddedTestResultSchema string

// ValidateAgentGovernanceDeployment validates a v0.1 predicate body against
// the companion-owned schema. It never fetches a remote schema.
func ValidateAgentGovernanceDeployment(data []byte) error {
	return validateJSONAgainstSchema(data, embeddedAgentGovernanceDeploymentSchema)
}

// ValidateEmbeddedTestResult validates the companion's standard test-result
// wire body against its local schema copy.
func ValidateEmbeddedTestResult(data []byte) error {
	return validateJSONAgainstSchema(data, embeddedTestResultSchema)
}

// validateJSONAgainstSchema accepts the repository's full Statement-shaped
// schemas while validating only the predicate body emitted by the companion.
func validateJSONAgainstSchema(data []byte, schemaContent string) error {
	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(schemaContent), &schema); err != nil {
		return fmt.Errorf("failed to parse schema: %w", err)
	}

	predicateSchema := schema
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		if predicate, ok := properties["predicate"].(map[string]interface{}); ok {
			predicateSchema = predicate
			if definitions, ok := schema["definitions"]; ok {
				if _, exists := predicateSchema["definitions"]; !exists {
					predicateSchema["definitions"] = definitions
				}
			}
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
	if result.Valid() {
		return nil
	}

	errors := make([]string, 0, len(result.Errors()))
	for _, validationErr := range result.Errors() {
		errors = append(errors, validationErr.String())
	}
	return fmt.Errorf("validation failed: %v", errors)
}
