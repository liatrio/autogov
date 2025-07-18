package github

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

// helper function to save original environment variables
func saveOriginalEnvVars() map[string]string {
	return map[string]string{
		"GITHUB_TOKEN":      os.Getenv("GITHUB_TOKEN"),
		"GH_TOKEN":          os.Getenv("GH_TOKEN"),
		"GITHUB_AUTH_TOKEN": os.Getenv("GITHUB_AUTH_TOKEN"),
	}
}

// helper function to clear all GitHub token environment variables
func clearTokenEnvVars(t *testing.T) {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_AUTH_TOKEN"} {
		if err := os.Unsetenv(key); err != nil {
			t.Logf("Warning: failed to unset environment variable %s: %v", key, err)
		}
	}
}

// helper function to restore original environment variables
func restoreEnvVars(t *testing.T, originalVars map[string]string) {
	for key, value := range originalVars {
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
}

// helper function to setup test environment with clean state
func setupTestEnv(t *testing.T) (cleanup func()) {
	originalVars := saveOriginalEnvVars()
	viper.Reset()
	clearTokenEnvVars(t)

	return func() {
		viper.Reset()
		restoreEnvVars(t, originalVars)
	}
}

func TestGetToken(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	tests := []struct {
		name          string
		viperToken    string
		envVars       map[string]string
		expectedToken string
	}{
		{
			name:          "no token available",
			viperToken:    "",
			envVars:       map[string]string{},
			expectedToken: "",
		},
		{
			name:          "viper token takes precedence",
			viperToken:    "viper-token",
			envVars:       map[string]string{"GITHUB_TOKEN": "env-token"},
			expectedToken: "viper-token",
		},
		{
			name:          "GITHUB_TOKEN env var",
			viperToken:    "",
			envVars:       map[string]string{"GITHUB_TOKEN": "github-token"},
			expectedToken: "github-token",
		},
		{
			name:          "GH_TOKEN env var",
			viperToken:    "",
			envVars:       map[string]string{"GH_TOKEN": "gh-token"},
			expectedToken: "gh-token",
		},
		{
			name:          "GITHUB_AUTH_TOKEN env var",
			viperToken:    "",
			envVars:       map[string]string{"GITHUB_AUTH_TOKEN": "auth-token"},
			expectedToken: "auth-token",
		},
		{
			name:       "GITHUB_TOKEN takes precedence over GH_TOKEN",
			viperToken: "",
			envVars: map[string]string{
				"GITHUB_TOKEN": "github-token",
				"GH_TOKEN":     "gh-token",
			},
			expectedToken: "github-token",
		},
		{
			name:       "GH_TOKEN takes precedence over GITHUB_AUTH_TOKEN",
			viperToken: "",
			envVars: map[string]string{
				"GH_TOKEN":          "gh-token",
				"GITHUB_AUTH_TOKEN": "auth-token",
			},
			expectedToken: "gh-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set viper token
			if tt.viperToken != "" {
				viper.Set("token", tt.viperToken)
			}

			// set environment variables
			for key, value := range tt.envVars {
				if err := os.Setenv(key, value); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", key, err)
				}
			}

			// test GetToken
			token := GetToken()
			if token != tt.expectedToken {
				t.Errorf("Expected token %q, got %q", tt.expectedToken, token)
			}

			// cleanup for next test
			viper.Reset()
			for key := range tt.envVars {
				if err := os.Unsetenv(key); err != nil {
					t.Logf("Warning: failed to unset environment variable %s: %v", key, err)
				}
			}
		})
	}
}

func TestGetTokenOrPanic(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	t.Run("panic when no token", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("Expected panic but none occurred")
				return
			}
			// verify panic message content
			expectedMsg := "no GitHub token found. Set GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN environment variable or use --token flag"
			if r != expectedMsg {
				t.Errorf("Expected panic message %q, got %q", expectedMsg, r)
			}
		}()
		GetTokenOrPanic()
	})

	t.Run("return token when available", func(t *testing.T) {
		if err := os.Setenv("GITHUB_TOKEN", "test-token"); err != nil {
			t.Fatalf("Failed to set GITHUB_TOKEN: %v", err)
		}

		token := GetTokenOrPanic()
		if token != "test-token" {
			t.Errorf("Expected token 'test-token', got %q", token)
		}
	})
}

func TestNewClient(t *testing.T) {
	cleanup := setupTestEnv(t)
	defer cleanup()

	t.Run("creates client without token", func(t *testing.T) {
		client := NewClient()
		if client == nil {
			t.Error("Expected client to be created")
		}
	})

	t.Run("creates client with token", func(t *testing.T) {
		if err := os.Setenv("GITHUB_TOKEN", "test-token"); err != nil {
			t.Fatalf("Failed to set GITHUB_TOKEN: %v", err)
		}

		client := NewClient()
		if client == nil {
			t.Error("Expected client to be created")
		}
		// note: we can't easily test that the token is actually set without making API calls
	})
}

func TestNewClientWithToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "with token",
			token: "test-token",
		},
		{
			name:  "without token",
			token: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClientWithToken(tt.token)
			if client == nil {
				t.Error("Expected client to be created")
			}
			// note: we can't easily test that the token is actually set without making API calls
			// the important thing is that the client is created successfully with both valid and empty tokens
		})
	}
}
