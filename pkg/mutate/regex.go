package mutate

import (
	"fmt"
	"regexp"
	"strings"
)

func init() {
	RegisterMutator("regexReplace", &regexReplaceMutator{})
}

// regexReplaceMutator handles generic files using regex pattern matching
// supports ${version} substitution in the replacement template
type regexReplaceMutator struct{}

func (m *regexReplaceMutator) Apply(content []byte, field string, newValue string, rule MutationRule) ([]byte, *MutationResult, error) {
	re, err := regexp.Compile(field)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid regex pattern %q: %w", field, err)
	}

	text := string(content)

	// find the first match to capture old value
	match := re.FindString(text)
	if match == "" {
		return nil, nil, fmt.Errorf("regex pattern %q did not match any content", field)
	}

	// build replacement string: substitute ${version} with newValue
	replacement := rule.Replace
	if replacement == "" {
		replacement = newValue
	} else {
		replacement = strings.ReplaceAll(replacement, "${version}", newValue)
	}

	var replaced string
	var matchCount int
	if rule.Global {
		matches := re.FindAllString(text, -1)
		matchCount = len(matches)
		replaced = re.ReplaceAllString(text, replacement)
	} else {
		matchCount = 1
		replaced = re.ReplaceAllStringFunc(text, func(s string) string {
			if matchCount == 1 {
				matchCount = 0 // only replace first match
				return re.ReplaceAllString(s, replacement)
			}
			return s
		})
		matchCount = 1
	}

	result := &MutationResult{
		Rule:     rule,
		OldValue: match,
		NewValue: replacement,
		Applied:  true,
		Diff:     fmt.Sprintf("matched %d occurrence(s)", matchCount),
	}
	return []byte(replaced), result, nil
}
