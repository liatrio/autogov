package mutate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig reads a mutation config from a YAML or JSON file
func LoadConfig(path string) (*MutationConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read mutation config %s: %w", path, err)
	}

	config := &MutationConfig{}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML mutation config %s: %w", path, err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON mutation config %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("unsupported mutation config format: %s (use .yaml, .yml, or .json)", ext)
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid mutation config %s: %w", path, err)
	}

	return config, nil
}

// validateConfig checks that all rules have required fields and valid types
func validateConfig(config *MutationConfig) error {
	if len(config.Rules) == 0 {
		return fmt.Errorf("no mutation rules defined")
	}

	for i, rule := range config.Rules {
		if rule.Path == "" {
			return fmt.Errorf("rule %d: path is required", i)
		}
		if rule.Type == "" {
			return fmt.Errorf("rule %d: type is required", i)
		}
		if rule.Field == "" {
			return fmt.Errorf("rule %d: field is required", i)
		}

		// validate type is registered
		if _, err := GetMutator(rule.Type); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}

		// pre-validate regex patterns at config load time
		if rule.Type == "regexReplace" {
			if _, err := regexp.Compile(rule.Field); err != nil {
				return fmt.Errorf("rule %d: invalid regex pattern %q: %w", i, rule.Field, err)
			}
		}

		// validate path doesn't escape repo root
		cleaned := filepath.Clean(rule.Path)
		if strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
			return fmt.Errorf("rule %d: path %q must be relative and within repository root", i, rule.Path)
		}
	}

	return nil
}
