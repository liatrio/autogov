package main

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

const (
	testCertIdentity     = "https://github.com/liatrio/autogov-verify/.github/workflows/test.yml@refs/heads/main"
	testRepo             = "liatrio/repo"
	testToken            = "mock-token"
	testFlagCertIdentity = "--cert-identity"
	testFlagImageDigest  = "--image-digest"
	testFlagRepo         = "--repo"
)

const errMissingArtifact = "either --image-digest, --blob-path, or a positional argument must be provided"

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
				testFlagCertIdentity, testCertIdentity,
				testFlagImageDigest, "liatrio/repo@sha256:abc123",
				testFlagRepo, testRepo,
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": "",
				"GH_TOKEN":     "",
			},
			wantErr: true,
			errMsg:  "GH_TOKEN, GITHUB_TOKEN or GITHUB_AUTH_TOKEN environment variable is required",
		},
		{
			name: "missing artifact digest and blob path",
			args: []string{
				testFlagCertIdentity, testCertIdentity,
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": testToken,
			},
			wantErr: true,
			errMsg:  errMissingArtifact,
		},
		{
			name: "invalid artifact digest - short sha",
			args: []string{
				testFlagCertIdentity, testCertIdentity,
				testFlagImageDigest, "liatrio/repo@sha256:abc123",
				testFlagRepo, testRepo,
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": testToken,
			},
			wantErr: true,
			errMsg:  "invalid digest format",
		},
		{
			name: "invalid artifact digest - bad format",
			args: []string{
				testFlagCertIdentity, testCertIdentity,
				testFlagImageDigest, "sha256:test",
				testFlagRepo, testRepo,
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": testToken,
			},
			wantErr: true,
			errMsg:  "invalid digest format",
		},
		{
			name: "invalid blob path",
			args: []string{
				testFlagCertIdentity, testCertIdentity,
				"--blob-path", "/nonexistent/path",
				testFlagRepo, "liatrio/test-repo",
			},
			envVars: map[string]string{
				"GITHUB_TOKEN": testToken,
			},
			wantErr: true,
			errMsg:  "no such file or directory",
		},
		{
			name: "invalid_blob_path",
			args: []string{"--blob-path", "/nonexistent/path", testFlagRepo, testRepo},
			envVars: map[string]string{
				"GITHUB_TOKEN": testToken,
			},
			wantErr: true,
			errMsg:  "no such file or directory",
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

			// Reset command state by clearing parsed values
			rootCmd.Flags().VisitAll(func(flag *pflag.Flag) {
				_ = flag.Value.Set(flag.DefValue)
				flag.Changed = false
			})
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
