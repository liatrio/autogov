package gitpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignerMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		required string
		seen     map[string]bool
		expected bool
	}{
		{
			name:     "exact match",
			required: "user@example.com",
			seen:     map[string]bool{"user@example.com": true},
			expected: true,
		},
		{
			name:     "case insensitive match",
			required: "User@Example.com",
			seen:     map[string]bool{"user@example.com": true},
			expected: true,
		},
		{
			name:     "prefix match with path boundary",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo/.github/workflows/ci.yml": true},
			expected: true,
		},
		{
			name:     "prefix match with @ boundary",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo@refs/heads/main": true},
			expected: true,
		},
		{
			name:     "no match",
			required: "user@example.com",
			seen:     map[string]bool{"other@example.com": true},
			expected: false,
		},
		{
			name:     "prefix without boundary does not match",
			required: "https://github.com/org/repo",
			seen:     map[string]bool{"https://github.com/org/repo-evil": true},
			expected: false,
		},
		{
			name:     "empty seen map",
			required: "user@example.com",
			seen:     map[string]bool{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, signerMatchesAny(tt.required, tt.seen))
		})
	}
}
