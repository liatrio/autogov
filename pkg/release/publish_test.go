package release

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	gogithub "github.com/google/go-github/v82/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


// TestFindDraftReleaseByTag tests finding a draft release by explicit tag.
// Uses ListReleases mock because GetReleaseByTag does not return draft releases.
func TestFindDraftReleaseByTag(t *testing.T) {
	tests := []struct {
		name         string
		tag          string
		mockReleases []*gogithub.RepositoryRelease
		mockErr      error
		wantErr      bool
		errContains  string
	}{
		{
			name: "found draft release by tag",
			tag:  "v1.2.0",
			mockReleases: []*gogithub.RepositoryRelease{
				{
					ID:      gogithub.Ptr(int64(42)),
					TagName: gogithub.Ptr("v1.2.0"),
					Draft:   gogithub.Ptr(true),
				},
			},
			wantErr: false,
		},
		{
			name:        "tag not in release list",
			tag:         "v9.9.9",
			mockReleases: []*gogithub.RepositoryRelease{},
			wantErr:     true,
			errContains: "no draft release found for tag v9.9.9",
		},
		{
			name: "release found but already published",
			tag:  "v1.0.0",
			mockReleases: []*gogithub.RepositoryRelease{
				{
					ID:      gogithub.Ptr(int64(10)),
					TagName: gogithub.Ptr("v1.0.0"),
					Draft:   gogithub.Ptr(false),
				},
			},
			wantErr:     true,
			errContains: "already published",
		},
		{
			name:        "API error",
			tag:         "v1.0.0",
			mockErr:     fmt.Errorf("API rate limit"),
			wantErr:     true,
			errContains: "failed to list releases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockReleaseService{}
			mock.listReleases = tt.mockReleases
			mock.listReleasesErr = tt.mockErr

			opts := &PublishOptions{
				Tag:        tt.tag,
				ReleaseAPI: mock,
			}

			release, err := findDraftRelease(context.Background(), opts, "owner", "repo")

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, release)
				assert.Equal(t, tt.tag, release.GetTagName())
				assert.True(t, release.GetDraft())
			}
		})
	}
}

// TestFindLatestDraftRelease tests finding the latest draft release
func TestFindLatestDraftRelease(t *testing.T) {
	tests := []struct {
		name         string
		mockReleases []*gogithub.RepositoryRelease
		mockErr      error
		wantTag      string
		wantErr      bool
		errContains  string
	}{
		{
			name: "found latest draft",
			mockReleases: []*gogithub.RepositoryRelease{
				{
					ID:      gogithub.Ptr(int64(3)),
					TagName: gogithub.Ptr("v1.3.0"),
					Draft:   gogithub.Ptr(false),
				},
				{
					ID:      gogithub.Ptr(int64(2)),
					TagName: gogithub.Ptr("v1.2.0"),
					Draft:   gogithub.Ptr(true),
				},
				{
					ID:      gogithub.Ptr(int64(1)),
					TagName: gogithub.Ptr("v1.1.0"),
					Draft:   gogithub.Ptr(false),
				},
			},
			wantTag: "v1.2.0",
			wantErr: false,
		},
		{
			name: "no draft releases exist",
			mockReleases: []*gogithub.RepositoryRelease{
				{
					ID:      gogithub.Ptr(int64(1)),
					TagName: gogithub.Ptr("v1.0.0"),
					Draft:   gogithub.Ptr(false),
				},
			},
			wantErr:     true,
			errContains: "no draft releases found",
		},
		{
			name:        "empty release list",
			mockReleases: []*gogithub.RepositoryRelease{},
			wantErr:     true,
			errContains: "no draft releases found",
		},
		{
			name:        "API error",
			mockErr:     fmt.Errorf("API rate limit"),
			wantErr:     true,
			errContains: "failed to list releases",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockReleaseService{}
			mock.listReleases = tt.mockReleases
			mock.listReleasesErr = tt.mockErr

			opts := &PublishOptions{
				Latest:     true,
				ReleaseAPI: mock,
			}

			release, err := findDraftRelease(context.Background(), opts, "owner", "repo")

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, release)
				assert.Equal(t, tt.wantTag, release.GetTagName())
				assert.True(t, release.GetDraft())
			}
		})
	}
}

// TestPublishOptionsValidation tests validation of PublishOptions
func TestPublishOptionsValidation(t *testing.T) {
	tests := []struct {
		name        string
		opts        *PublishOptions
		wantErr     bool
		errContains string
	}{
		{
			name: "tag specified - valid",
			opts: &PublishOptions{
				Tag:   "v1.0.0",
				Token: "test-token",
			},
			wantErr: false,
		},
		{
			name: "latest specified - valid",
			opts: &PublishOptions{
				Latest: true,
				Token:  "test-token",
			},
			wantErr: false,
		},
		{
			name: "both tag and latest - invalid",
			opts: &PublishOptions{
				Tag:    "v1.0.0",
				Latest: true,
				Token:  "test-token",
			},
			wantErr:     true,
			errContains: "mutually exclusive",
		},
		{
			name: "neither tag nor latest - invalid",
			opts: &PublishOptions{
				Token: "test-token",
			},
			wantErr:     true,
			errContains: "either --tag or --latest must be specified",
		},
		{
			name: "no token - invalid",
			opts: &PublishOptions{
				Tag: "v1.0.0",
			},
			wantErr:     true,
			errContains: "GitHub token required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePublishOptions(tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestExecutePublish tests the full publish orchestration
func TestExecutePublish(t *testing.T) {
	tests := []struct {
		name        string
		opts        *PublishOptions
		setupMock   func(*mockReleaseService)
		wantErr     bool
		errContains string
		validate    func(*testing.T, *PublishResult)
	}{
		{
			name: "successful publish by tag",
			opts: &PublishOptions{
				Tag:   "v1.2.0",
				Token: "test-token",
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{
					{
						ID:      gogithub.Ptr(int64(42)),
						TagName: gogithub.Ptr("v1.2.0"),
						Draft:   gogithub.Ptr(true),
					},
				}
				m.updateRelease = &gogithub.RepositoryRelease{
					ID:      gogithub.Ptr(int64(42)),
					TagName: gogithub.Ptr("v1.2.0"),
					Draft:   gogithub.Ptr(false),
					HTMLURL: gogithub.Ptr("https://github.com/owner/repo/releases/tag/v1.2.0"),
				}
			},
			validate: func(t *testing.T, result *PublishResult) {
				assert.Equal(t, "v1.2.0", result.TagName)
				assert.Equal(t, int64(42), result.ReleaseID)
				assert.True(t, result.Published)
				assert.False(t, result.DryRun)
				assert.Contains(t, result.ReleaseURL, "v1.2.0")
			},
		},
		{
			name: "successful publish by latest",
			opts: &PublishOptions{
				Latest: true,
				Token:  "test-token",
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{
					{
						ID:      gogithub.Ptr(int64(50)),
						TagName: gogithub.Ptr("v2.0.0"),
						Draft:   gogithub.Ptr(true),
					},
				}
				m.updateRelease = &gogithub.RepositoryRelease{
					ID:      gogithub.Ptr(int64(50)),
					TagName: gogithub.Ptr("v2.0.0"),
					Draft:   gogithub.Ptr(false),
					HTMLURL: gogithub.Ptr("https://github.com/owner/repo/releases/tag/v2.0.0"),
				}
			},
			validate: func(t *testing.T, result *PublishResult) {
				assert.Equal(t, "v2.0.0", result.TagName)
				assert.Equal(t, int64(50), result.ReleaseID)
				assert.True(t, result.Published)
			},
		},
		{
			name: "dry-run does not publish",
			opts: &PublishOptions{
				Tag:    "v1.0.0",
				Token:  "test-token",
				DryRun: true,
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{
					{
						ID:      gogithub.Ptr(int64(10)),
						TagName: gogithub.Ptr("v1.0.0"),
						Draft:   gogithub.Ptr(true),
					},
				}
			},
			validate: func(t *testing.T, result *PublishResult) {
				assert.Equal(t, "v1.0.0", result.TagName)
				assert.True(t, result.DryRun)
				assert.False(t, result.Published)
			},
		},
		{
			name: "release not found",
			opts: &PublishOptions{
				Tag:   "v9.9.9",
				Token: "test-token",
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{}
			},
			wantErr:     true,
			errContains: "no draft release found for tag v9.9.9",
		},
		{
			name: "release already published",
			opts: &PublishOptions{
				Tag:   "v1.0.0",
				Token: "test-token",
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{
					{
						ID:      gogithub.Ptr(int64(10)),
						TagName: gogithub.Ptr("v1.0.0"),
						Draft:   gogithub.Ptr(false),
					},
				}
			},
			wantErr:     true,
			errContains: "already published",
		},
		{
			name: "update API fails",
			opts: &PublishOptions{
				Tag:   "v1.0.0",
				Token: "test-token",
			},
			setupMock: func(m *mockReleaseService) {
				m.listReleases = []*gogithub.RepositoryRelease{
					{
						ID:      gogithub.Ptr(int64(10)),
						TagName: gogithub.Ptr("v1.0.0"),
						Draft:   gogithub.Ptr(true),
					},
				}
				m.updateErr = fmt.Errorf("API error")
			},
			wantErr:     true,
			errContains: "failed to publish release",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// set up test repo with remote configured
			dir, repo := setupTestRepo(t)
			_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
				Name: "origin",
				URLs: []string{"https://github.com/owner/repo.git"},
			})
			require.NoError(t, err)

			mock := &mockReleaseService{}
			if tt.setupMock != nil {
				tt.setupMock(mock)
			}

			tt.opts.RepoPath = dir
			tt.opts.ReleaseAPI = mock

			result, err := ExecutePublish(tt.opts)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestVerifyTagExists tests remote tag verification using a local bare repo
func TestVerifyTagExists(t *testing.T) {
	// create a local bare repo to serve as the remote
	bareDir := t.TempDir()
	_, err := git.PlainInit(bareDir, true)
	require.NoError(t, err)

	// create a local repo and push the v1.0.0 tag to the bare repo
	localDir, localRepo := setupTestRepo(t) // has v1.0.0 tag
	_ = localDir
	_, err = localRepo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{bareDir},
	})
	require.NoError(t, err)

	err = localRepo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []gitconfig.RefSpec{"refs/tags/v1.0.0:refs/tags/v1.0.0"},
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		repoFn      func() *git.Repository
		tagName     string
		wantErr     bool
		errContains string
	}{
		{
			name:    "tag exists on remote",
			repoFn:  func() *git.Repository { return localRepo },
			tagName: "v1.0.0",
			wantErr: false,
		},
		{
			name:        "tag not found on remote",
			repoFn:      func() *git.Repository { return localRepo },
			tagName:     "v9.9.9",
			wantErr:     true,
			errContains: "does not exist on remote",
		},
		{
			name: "no remote configured - warn and proceed",
			repoFn: func() *git.Repository {
				_, repo := setupTestRepo(t)
				return repo
			},
			tagName: "v1.0.0",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &PublishOptions{}
			err := verifyTagExists(tt.repoFn(), opts, tt.tagName)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestExecutePublishVerifyTagExistsError exercises the integration path where
// verifyTagExists returns a real error (tag not on remote) through ExecutePublish.
// Uses a local bare repo so remote.List() succeeds but the tag is absent.
func TestExecutePublishVerifyTagExistsError(t *testing.T) {
	// bare repo as remote — push v1.0.0 so it's non-empty, but v2.0.0 is absent
	bareDir := t.TempDir()
	_, err := git.PlainInit(bareDir, true)
	require.NoError(t, err)

	// local repo with origin pointing at the bare repo
	dir, repo := setupTestRepo(t) // has v1.0.0 tag
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{bareDir},
	})
	require.NoError(t, err)

	// push v1.0.0 so the bare repo has refs (avoids "remote repository is empty")
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []gitconfig.RefSpec{"refs/tags/v1.0.0:refs/tags/v1.0.0"},
	})
	require.NoError(t, err)

	// mock returns a draft for v2.0.0, but that tag does not exist on the bare remote
	mock := &mockReleaseService{
		listReleases: []*gogithub.RepositoryRelease{
			{
				ID:      gogithub.Ptr(int64(99)),
				TagName: gogithub.Ptr("v2.0.0"),
				Draft:   gogithub.Ptr(true),
			},
		},
	}

	opts := &PublishOptions{
		Tag:        "v2.0.0",
		Token:      "test-token",
		RepoPath:   dir,
		ReleaseAPI: mock,
	}

	_, err = ExecutePublish(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "v2.0.0 does not exist on remote")
}
