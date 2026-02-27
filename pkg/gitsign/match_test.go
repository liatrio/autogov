package gitsign

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_matchIdentity(t *testing.T) {
	tests := []struct {
		name     string
		signer   string
		expected string
		want     bool
	}{
		{
			"exact email match",
			"user@example.com",
			"user@example.com",
			true,
		},
		{
			"exact URI match",
			"https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main",
			"https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main",
			true,
		},
		{
			"prefix match with path boundary",
			"https://github.com/org/repo/.github/workflows/ci.yml",
			"https://github.com/org/repo",
			true,
		},
		{
			"prefix match with @ boundary",
			"https://github.com/org/repo@refs/heads/main",
			"https://github.com/org/repo",
			true,
		},
		{
			"rejects prefix without path boundary",
			"https://github.com/org/repo-evil/.github/workflows/ci.yml",
			"https://github.com/org/repo",
			false,
		},
		{
			"rejects arbitrary substring",
			"https://evil.com/inject?q=org/repo",
			"org/repo",
			false,
		},
		{
			"email mismatch",
			"user@example.com",
			"other@example.com",
			false,
		},
		{
			"empty signer no match",
			"",
			"user@example.com",
			false,
		},
		{
			"both empty is exact match",
			"",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchIdentity(tt.signer, tt.expected))
		})
	}
}
