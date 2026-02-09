package mutate

import (
	"fmt"
	"regexp"
	"strings"
)

func init() {
	RegisterMutator("tomlKey", &tomlKeyMutator{})
}

// tomlKeyMutator updates TOML files using dotted key paths
// uses line-level text manipulation to preserve formatting and comments
// (TOML encoders tend to reorder keys, so we avoid marshal/unmarshal round-trips)
type tomlKeyMutator struct{}

func (m *tomlKeyMutator) Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error) {
	parts := strings.Split(field, ".")
	text := string(content)
	lines := strings.Split(text, "\n")

	var oldValue string
	replaced := false

	// try dotted key syntax first (e.g., `package.version = "1.0.0"`)
	if len(parts) > 1 {
		oldValue, replaced, lines = replaceTOMLDottedKey(lines, field, newValue)
	}

	if !replaced {
		if len(parts) == 1 {
			// top-level key: find `key = "value"` or `key = value`
			oldValue, replaced, lines = replaceTOMLKey(lines, parts[0], newValue, "")
		} else {
			// section + key: find [section] then key within it
			section := strings.Join(parts[:len(parts)-1], ".")
			key := parts[len(parts)-1]
			oldValue, replaced, lines = replaceTOMLKey(lines, key, newValue, section)
		}
	}

	if !replaced {
		return nil, nil, fmt.Errorf("TOML key %q not found", field)
	}

	result := &MutationResult{
		Rule:     rule,
		OldValue: oldValue,
		NewValue: newValue,
		Applied:  true,
	}
	return []byte(strings.Join(lines, "\n")), result, nil
}

// replaceTOMLDottedKey handles dotted key syntax like `package.version = "1.0.0"`
func replaceTOMLDottedKey(lines []string, dottedKey, newValue string) (string, bool, []string) {
	escapedKey := regexp.QuoteMeta(dottedKey)
	keyPattern := regexp.MustCompile(`^(\s*` + escapedKey + `\s*=\s*)(.+)$`)

	for i, line := range lines {
		if matches := keyPattern.FindStringSubmatch(line); matches != nil {
			oldRaw := strings.TrimSpace(matches[2])
			oldValue := unquoteTOML(oldRaw)
			if isQuoted(oldRaw) {
				lines[i] = matches[1] + `"` + newValue + `"`
			} else {
				lines[i] = matches[1] + newValue
			}
			return oldValue, true, lines
		}
	}
	return "", false, lines
}

// replaceTOMLKey finds and replaces a key's value in TOML lines
// if section is non-empty, only replaces within that [section]
func replaceTOMLKey(lines []string, key, newValue, section string) (string, bool, []string) {
	inSection := section == ""
	sectionPattern := buildSectionPattern(section)

	// pattern matches: key = "value", key = 'value', key = value
	escapedKey := regexp.QuoteMeta(key)
	keyPattern := regexp.MustCompile(`^(\s*` + escapedKey + `\s*=\s*)(.+)$`)
	sectionHeader := regexp.MustCompile(`^\s*\[`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// track section boundaries
		if sectionPattern != nil && sectionPattern.MatchString(trimmed) {
			inSection = true
			continue
		}
		// if we're in the target section and hit another section header, stop
		if inSection && section != "" && sectionHeader.MatchString(trimmed) && (sectionPattern == nil || !sectionPattern.MatchString(trimmed)) {
			inSection = false
			continue
		}

		if !inSection {
			continue
		}

		if matches := keyPattern.FindStringSubmatch(line); matches != nil {
			oldRaw := strings.TrimSpace(matches[2])
			oldValue := unquoteTOML(oldRaw)
			// preserve quoting style
			if isQuoted(oldRaw) {
				lines[i] = matches[1] + `"` + newValue + `"`
			} else {
				lines[i] = matches[1] + newValue
			}
			return oldValue, true, lines
		}
	}
	return "", false, lines
}

// buildSectionPattern creates a regex for matching a TOML section header
func buildSectionPattern(section string) *regexp.Regexp {
	if section == "" {
		return nil
	}
	escaped := regexp.QuoteMeta(section)
	return regexp.MustCompile(`^\s*\[\s*` + escaped + `\s*\]`)
}

// unquoteTOML strips surrounding quotes from a TOML value
func unquoteTOML(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// isQuoted returns true if the value is surrounded by quotes
func isQuoted(s string) bool {
	return len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\''))
}
