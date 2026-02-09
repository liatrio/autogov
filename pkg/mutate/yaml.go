package mutate

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

func init() {
	RegisterMutator("yamlPath", &yamlPathMutator{})
}

// yamlPathMutator updates YAML files using dot-notation field paths
// uses yaml.v3 Node API to locate the value, then text-level replacement
// to preserve original indentation, comments, and line endings
type yamlPathMutator struct{}

func (m *yamlPathMutator) Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil, fmt.Errorf("expected YAML document node")
	}

	parts := strings.Split(field, ".")
	node, err := findYAMLNode(doc.Content[0], parts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find YAML field %q: %w", field, err)
	}

	oldValue := node.Value
	// node.Line is 1-indexed
	line := node.Line
	col := node.Column

	// use line/column from the node to do a targeted text replacement
	// this preserves original indentation, comments, and line endings
	updated, err := replaceYAMLValue(content, line, col, oldValue, newValue)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to replace YAML value at line %d: %w", line, err)
	}

	result := &MutationResult{
		Rule:     rule,
		OldValue: oldValue,
		NewValue: newValue,
		Applied:  true,
	}
	return updated, result, nil
}

// replaceYAMLValue replaces a value at a specific line/column in YAML content
// line and col are 1-indexed (from yaml.Node)
func replaceYAMLValue(content []byte, line, col int, oldValue, newValue string) ([]byte, error) {
	text := string(content)
	lines := strings.Split(text, "\n")

	if line < 1 || line > len(lines) {
		return nil, fmt.Errorf("line %d out of range (file has %d lines)", line, len(lines))
	}

	targetLine := lines[line-1]
	colIdx := col - 1 // convert to 0-indexed

	if colIdx < 0 || colIdx > len(targetLine) {
		return nil, fmt.Errorf("column %d out of range for line %d", col, line)
	}

	// the value starts at colIdx; find how far it extends
	// handle both quoted and unquoted values, and inline comments
	valueSpan := targetLine[colIdx:]
	oldLen := findYAMLValueLength(valueSpan, oldValue)

	// rebuild the line with the new value
	lines[line-1] = targetLine[:colIdx] + newValue + targetLine[colIdx+oldLen:]

	return []byte(strings.Join(lines, "\n")), nil
}

// findYAMLValueLength determines how many characters the old value occupies
// handles quoted strings, unquoted scalars, and values followed by comments
func findYAMLValueLength(valueSpan, oldValue string) int {
	// check for quoted value
	if len(valueSpan) > 0 && (valueSpan[0] == '\'' || valueSpan[0] == '"') {
		quote := valueSpan[0]
		end := strings.IndexByte(valueSpan[1:], quote)
		if end >= 0 {
			return end + 2 // include both quotes
		}
	}

	// unquoted: value extends until comment marker or end of line
	// but must at least match the old value length
	commentIdx := strings.Index(valueSpan, " #")
	if commentIdx >= 0 {
		// trim trailing whitespace before comment
		return len(strings.TrimRight(valueSpan[:commentIdx], " \t"))
	}

	return len(strings.TrimRight(valueSpan, " \t\r"))
}

// findYAMLNode walks a YAML node tree using dot-notation path segments
func findYAMLNode(node *yaml.Node, parts []string) (*yaml.Node, error) {
	if len(parts) == 0 {
		return node, nil
	}

	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node, got kind %d", node.Kind)
	}

	key := parts[0]
	// mapping nodes have alternating key/value pairs in Content
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			if len(parts) == 1 {
				return node.Content[i+1], nil
			}
			return findYAMLNode(node.Content[i+1], parts[1:])
		}
	}

	return nil, fmt.Errorf("key %q not found", key)
}
