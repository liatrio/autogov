package mutate

import "fmt"

// MutationRule defines a single file mutation to perform
type MutationRule struct {
	Path    string `json:"path" yaml:"path"`                           // file path relative to repo root
	Type    string `json:"type" yaml:"type"`                           // jsonPath, yamlPath, tomlKey, regexReplace
	Field   string `json:"field" yaml:"field"`                         // path expression (dot-notation or regex pattern)
	Replace string `json:"replace,omitempty" yaml:"replace,omitempty"` // replacement template (for regex)
	Global  bool   `json:"global,omitempty" yaml:"global,omitempty"`   // replace all matches (regex only)
}

// MutationConfig holds the full mutation configuration
type MutationConfig struct {
	Rules []MutationRule `json:"mutations" yaml:"mutations"`
}

// MutationResult captures the outcome of a single mutation
type MutationResult struct {
	Rule     MutationRule `json:"rule" yaml:"rule"`
	OldValue string       `json:"old_value" yaml:"old_value"`
	NewValue string       `json:"new_value" yaml:"new_value"`
	Applied  bool         `json:"applied" yaml:"applied"`
	Error    string       `json:"error,omitempty" yaml:"error,omitempty"`
	Diff     string       `json:"diff,omitempty" yaml:"diff,omitempty"`
}

// Mutator is the interface each file-type mutator implements
type Mutator interface {
	// Apply performs the mutation on file content, returning updated content and result
	Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error)
}

// mutatorRegistry maps mutation type names to their implementations
var mutatorRegistry = map[string]Mutator{}

// RegisterMutator adds a mutator to the registry
func RegisterMutator(name string, m Mutator) {
	mutatorRegistry[name] = m
}

// GetMutator returns the mutator for the given type name
func GetMutator(mutationType string) (Mutator, error) {
	m, ok := mutatorRegistry[mutationType]
	if !ok {
		return nil, fmt.Errorf("unknown mutation type: %s (available: jsonPath, yamlPath, tomlKey, regexReplace)", mutationType)
	}
	return m, nil
}

// ValidMutationTypes returns the list of registered mutation type names
func ValidMutationTypes() []string {
	types := make([]string, 0, len(mutatorRegistry))
	for k := range mutatorRegistry {
		types = append(types, k)
	}
	return types
}
