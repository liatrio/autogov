package mutate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

func init() {
	RegisterMutator("jsonPath", &jsonPathMutator{})
}

// jsonPathMutator updates JSON files using dot-notation field paths
// preserves original formatting by using positional text-level replacement
type jsonPathMutator struct{}

func (m *jsonPathMutator) Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error) {
	// find the byte offset and old value at the target path
	oldValue, offset, length, err := locateJSONField(content, field)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to locate JSON field %q: %w", field, err)
	}

	// replace at the exact byte position to avoid duplicate key collisions
	updated := make([]byte, 0, len(content)-length+len(newValue))
	updated = append(updated, content[:offset]...)
	updated = append(updated, []byte(newValue)...)
	updated = append(updated, content[offset+length:]...)

	result := &MutationResult{
		Rule:     rule,
		OldValue: oldValue,
		NewValue: newValue,
		Applied:  true,
	}
	return updated, result, nil
}

// locateJSONField finds the byte offset and length of a field's value in JSON content
// uses json.Decoder token-by-token scanning to track the exact position
// returns: value string, byte offset of value, byte length of value, error
func locateJSONField(content []byte, field string) (string, int, int, error) {
	parts := strings.Split(field, ".")

	// first validate the path exists via standard parsing
	oldValue, err := getJSONValue(content, field)
	if err != nil {
		return "", 0, 0, err
	}

	// find the byte offset by scanning for the key sequence
	offset, length, err := findJSONValuePosition(content, parts)
	if err != nil {
		return "", 0, 0, err
	}

	return oldValue, offset, length, nil
}

// findJSONValuePosition finds the byte position of a value at the given path
// by scanning through the JSON content tracking nesting depth and key matches
func findJSONValuePosition(content []byte, parts []string) (int, int, error) {
	text := string(content)
	searchStart := 0

	// for each path segment, find the key at the correct nesting depth
	for i, part := range parts {
		isLast := i == len(parts)-1

		// find the key at current scope
		keyOffset, err := findKeyInScope(text, searchStart, part)
		if err != nil {
			return 0, 0, fmt.Errorf("key %q not found at path depth %d: %w", part, i, err)
		}

		// skip past the key and colon to find the value start
		valueStart := findValueStart(text, keyOffset+len(`"`+part+`"`))

		if isLast {
			// extract the value span
			valueEnd := findValueEnd(text, valueStart)
			// if quoted string, include the quotes in the span but return inner offset
			if text[valueStart] == '"' {
				// return offset after opening quote, length of inner value
				return valueStart + 1, valueEnd - valueStart - 2, nil
			}
			return valueStart, valueEnd - valueStart, nil
		}

		// not the last segment — the value must be an object, advance into it
		if text[valueStart] != '{' {
			return 0, 0, fmt.Errorf("expected object at path segment %q", part)
		}
		searchStart = valueStart
	}

	return 0, 0, fmt.Errorf("path not found")
}

// findKeyInScope finds the byte offset of a JSON key within the current scope
// respects nesting: only matches keys at depth 0 relative to searchStart
func findKeyInScope(text string, start int, key string) (int, error) {
	escapedKey := regexp.QuoteMeta(key)
	pattern := regexp.MustCompile(`"` + escapedKey + `"\s*:`)

	depth := 0
	i := start
	for i < len(text) {
		ch := text[i]
		switch ch {
		case '{', '[':
			depth++
			i++
		case '}', ']':
			depth--
			if depth < 0 {
				return 0, fmt.Errorf("key %q not found in scope", key)
			}
			i++
		case '"':
			// find end of string (skip escaped quotes)
			end := findStringEnd(text, i)

			// check if this string at depth 1 matches our key pattern
			if depth == 1 {
				segment := text[i : end+1]
				if loc := pattern.FindStringIndex(text[i:]); loc != nil && loc[0] == 0 {
					_ = segment
					return i, nil
				}
			}
			i = end + 1
		default:
			i++
		}
	}

	return 0, fmt.Errorf("key %q not found in scope", key)
}

// findStringEnd returns the index of the closing quote for a JSON string
func findStringEnd(text string, start int) int {
	for i := start + 1; i < len(text); i++ {
		if text[i] == '\\' {
			i++ // skip escaped character
			continue
		}
		if text[i] == '"' {
			return i
		}
	}
	return len(text) - 1
}

// findValueStart skips whitespace and colon after a key to find where the value begins
func findValueStart(text string, afterKey int) int {
	i := afterKey
	for i < len(text) {
		switch text[i] {
		case ':', ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// findValueEnd finds where a JSON value ends (string, number, object, array, bool, null)
func findValueEnd(text string, start int) int {
	if start >= len(text) {
		return start
	}

	ch := text[start]
	switch ch {
	case '"':
		end := findStringEnd(text, start)
		return end + 1
	case '{', '[':
		closing := map[byte]byte{'{': '}', '[': ']'}[ch]
		depth := 1
		for i := start + 1; i < len(text); i++ {
			if text[i] == '"' {
				i = findStringEnd(text, i)
				continue
			}
			switch text[i] {
			case ch:
				depth++
			case closing:
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return len(text)
	default:
		// number, bool, null — scan until delimiter
		for i := start; i < len(text); i++ {
			switch text[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
		}
		return len(text)
	}
}

// getJSONValue navigates a dot-notation path to extract the string value
func getJSONValue(content []byte, field string) (string, error) {
	parts := strings.Split(field, ".")

	var current interface{}
	if err := json.Unmarshal(content, &current); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	for i, part := range parts {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("expected object at %q, got %T", strings.Join(parts[:i], "."), current)
		}
		val, exists := obj[part]
		if !exists {
			return "", fmt.Errorf("field %q not found", strings.Join(parts[:i+1], "."))
		}
		current = val
	}

	switch v := current.(type) {
	case string:
		return v, nil
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v)), nil
		}
		return fmt.Sprintf("%g", v), nil
	default:
		return fmt.Sprintf("%v", v), nil
	}
}
