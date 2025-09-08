package main

import (
	"os"
	"strings"
	"testing"
)

const errMissingArtifact = "either --artifact-digest or --blob-path must be provided"

func TestRun(t *testing.T) {
	// save current env
	savedEnv := make(map[string]string)
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN", "CERT_IDENTITY"} {
		savedEnv[key] = os.Getenv(key)
	}

	// restore env after test
	defer func() {
		for key, value := range savedEnv {
			if value == "" {
				if err := os.Unsetenv(key); err != nil {
					t.Logf("Warning: failed to unset environment variable %s: %v", key, err)
				}
			} else {
				if err := os.Setenv(key, value); err != nil {
					t.Logf("Warning: failed to restore environment variable %s: %v", key, err)
				}
			}
		}
	}()

	tests := []struct {
		name    string
		args    []string
		envVars map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "no args",
			args: []string{},
			envVars: map[string]string{
				"GITHUB_TOKEN": "",
				"GH_TOKEN":     "",
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
		{
			name: "missing token",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--artifact-digest", "liatrio/repo@sha256:abc123",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "",
				"GH_TOKEN":     "",
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
		{
			name: "missing artifact digest and blob path",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
		{
			name: "invalid artifact digest",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--artifact-digest", "invalid-digest",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
		{
			name: "invalid blob path",
			args: []string{
				"--cert-identity", "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main",
				"--blob-path", "/nonexistent/path",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "mock-token",
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set env vars for test
			for key := range savedEnv {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("Failed to unset environment variable %s: %v", key, err)
				}
			}
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", key, err)
				}
			}

			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("run() error = %v, want error containing %v", err, tt.errMsg)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	// save current env
	savedEnv := make(map[string]string)
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN", "CERT_IDENTITY"} {
		savedEnv[key] = os.Getenv(key)
	}

	// restore env after test
	defer func() {
		for key, value := range savedEnv {
			if value == "" {
				if err := os.Unsetenv(key); err != nil {
					t.Logf("Warning: failed to unset environment variable %s: %v", key, err)
				}
			} else {
				if err := os.Setenv(key, value); err != nil {
					t.Logf("Warning: failed to restore environment variable %s: %v", key, err)
				}
			}
		}
	}()

	// unset all env vars for test
	for key := range savedEnv {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Failed to unset environment variable %s: %v", key, err)
		}
	}

	// test help output
	rootCmd.SetArgs([]string{"--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("Execute() error = %v", err)
	}
}
