package mutate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegexReplaceMutatorSingleMatch(t *testing.T) {
	content := []byte(`VERSION := 1.0.0
BUILD := 42
`)

	rule := MutationRule{
		Path:    "Makefile",
		Type:    "regexReplace",
		Field:   `VERSION\s*:=\s*(\S+)`,
		Replace: "VERSION := ${version}",
	}

	m := &regexReplaceMutator{}
	updated, result, err := m.Apply(content, rule.Field, "2.0.0", rule)

	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), "VERSION := 2.0.0")
	assert.Contains(t, string(updated), "BUILD := 42")
}

func TestRegexReplaceMutatorGlobalMatch(t *testing.T) {
	content := []byte(`FROM alpine:3.18
LABEL version="1.0.0"
ARG VERSION=1.0.0
ENV APP_VERSION=1.0.0
`)

	rule := MutationRule{
		Path:    "Dockerfile",
		Type:    "regexReplace",
		Field:   `1\.0\.0`,
		Replace: "${version}",
		Global:  true,
	}

	m := &regexReplaceMutator{}
	updated, result, err := m.Apply(content, rule.Field, "2.0.0", rule)

	require.NoError(t, err)
	assert.True(t, result.Applied)
	// all 3 occurrences replaced
	assert.NotContains(t, string(updated), "1.0.0")
	assert.Contains(t, string(updated), "2.0.0")
}

func TestRegexReplaceMutatorNoMatch(t *testing.T) {
	content := []byte(`nothing here`)

	rule := MutationRule{
		Path:  "file.txt",
		Type:  "regexReplace",
		Field: `VERSION=(\S+)`,
	}

	m := &regexReplaceMutator{}
	_, _, err := m.Apply(content, rule.Field, "1.0.0", rule)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not match")
}

func TestRegexReplaceMutatorInvalidRegex(t *testing.T) {
	rule := MutationRule{
		Path:  "file.txt",
		Type:  "regexReplace",
		Field: `[invalid`,
	}

	m := &regexReplaceMutator{}
	_, _, err := m.Apply([]byte("test"), rule.Field, "1.0.0", rule)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestRegexReplaceMutatorDockerfile(t *testing.T) {
	content := []byte(`FROM golang:1.21 AS builder
ARG VERSION=0.5.0
RUN echo "building"
`)

	rule := MutationRule{
		Path:    "Dockerfile",
		Type:    "regexReplace",
		Field:   `ARG VERSION=(\S+)`,
		Replace: "ARG VERSION=${version}",
	}

	m := &regexReplaceMutator{}
	updated, result, err := m.Apply(content, rule.Field, "1.0.0", rule)

	require.NoError(t, err)
	assert.True(t, result.Applied)
	assert.Contains(t, string(updated), "ARG VERSION=1.0.0")
	assert.Contains(t, string(updated), "FROM golang:1.21")
}
