package release

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	gogithub "github.com/google/go-github/v88/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListTagsFromAPI verifies tag fetching and semver sorting.
func TestListTagsFromAPI(t *testing.T) {
	t.Run("returns sorted semver tags descending", func(t *testing.T) {
		mock := &mockReleaseService{
			listTagsResult: []*gogithub.RepositoryTag{
				{Name: gogithub.Ptr("v1.0.0")},
				{Name: gogithub.Ptr("v2.0.0")},
				{Name: gogithub.Ptr("v1.5.0")},
				{Name: gogithub.Ptr("not-semver")},
			},
		}
		tags, err := listTagsFromAPI(context.Background(), mock, "owner", "repo")
		require.NoError(t, err)
		require.Len(t, tags, 3)
		assert.Equal(t, "v2.0.0", tags[0])
		assert.Equal(t, "v1.5.0", tags[1])
		assert.Equal(t, "v1.0.0", tags[2])
	})

	t.Run("empty repository returns empty list", func(t *testing.T) {
		mock := &mockReleaseService{listTagsResult: []*gogithub.RepositoryTag{}}
		tags, err := listTagsFromAPI(context.Background(), mock, "owner", "repo")
		require.NoError(t, err)
		assert.Empty(t, tags)
	})

	t.Run("API error is returned", func(t *testing.T) {
		mock := &mockReleaseService{listTagsErr: fmt.Errorf("connection refused")}
		_, err := listTagsFromAPI(context.Background(), mock, "owner", "repo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused")
	})
}

// TestFilterFirstParent verifies first-parent filtering with merge commits.
func TestFilterFirstParent(t *testing.T) {
	t.Run("filters out merge branch commits", func(t *testing.T) {
		// Topology (head→base): E → B (merge commit) → A (base tag, not in API results)
		// B has two parents: A (first/main-line) and D (merged branch)
		// Compare API returns D, B, E — A is the base tag and is not returned.
		// First-parent walk: E → B → A (not in list, stop). Result: B, E (skip D).
		commits := []*gogithub.RepositoryCommit{
			{
				SHA:    gogithub.Ptr("D"),
				Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: branch work")},
				Parents: []*gogithub.Commit{
					{SHA: gogithub.Ptr("A")},
				},
			},
			{
				SHA:    gogithub.Ptr("B"),
				Commit: &gogithub.Commit{Message: gogithub.Ptr("fix: merge branch")},
				Parents: []*gogithub.Commit{
					{SHA: gogithub.Ptr("A")}, // first parent is main line
					{SHA: gogithub.Ptr("D")}, // second parent is merged branch
				},
			},
			{
				SHA:    gogithub.Ptr("E"),
				Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: after merge")},
				Parents: []*gogithub.Commit{
					{SHA: gogithub.Ptr("B")},
				},
			},
		}

		result := filterFirstParent(commits, "E")
		require.Len(t, result, 2, "should return only B and E (first-parent chain from head)")
		assert.Equal(t, "B", result[0].SHA, "chronological: B before E")
		assert.Equal(t, "E", result[1].SHA)
	})

	t.Run("linear history returns all commits", func(t *testing.T) {
		commits := []*gogithub.RepositoryCommit{
			{
				SHA:    gogithub.Ptr("A"),
				Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: first")},
			},
			{
				SHA:     gogithub.Ptr("B"),
				Commit:  &gogithub.Commit{Message: gogithub.Ptr("fix: second")},
				Parents: []*gogithub.Commit{{SHA: gogithub.Ptr("A")}},
			},
			{
				SHA:     gogithub.Ptr("C"),
				Commit:  &gogithub.Commit{Message: gogithub.Ptr("feat: third")},
				Parents: []*gogithub.Commit{{SHA: gogithub.Ptr("B")}},
			},
		}

		result := filterFirstParent(commits, "C")
		require.Len(t, result, 3)
		assert.Equal(t, "A", result[0].SHA)
		assert.Equal(t, "B", result[1].SHA)
		assert.Equal(t, "C", result[2].SHA)
	})

	t.Run("empty commits returns empty result", func(t *testing.T) {
		result := filterFirstParent(nil, "HEAD")
		assert.Empty(t, result)
	})

	t.Run("unknown head SHA returns empty", func(t *testing.T) {
		commits := []*gogithub.RepositoryCommit{
			{SHA: gogithub.Ptr("A"), Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: something")}},
		}
		result := filterFirstParent(commits, "UNKNOWN")
		assert.Empty(t, result)
	})
}

// TestGetBranchTipFromAPI verifies branch tip SHA retrieval.
func TestGetBranchTipFromAPI(t *testing.T) {
	t.Run("returns tip SHA", func(t *testing.T) {
		mock := &mockReleaseService{
			getBranchResult: &gogithub.Branch{
				Name: gogithub.Ptr("main"),
				Commit: &gogithub.RepositoryCommit{
					SHA: gogithub.Ptr("abc123"),
				},
			},
		}
		sha, err := getBranchTipFromAPI(context.Background(), mock, "owner", "repo", "main")
		require.NoError(t, err)
		assert.Equal(t, "abc123", sha)
	})

	t.Run("API error is returned", func(t *testing.T) {
		mock := &mockReleaseService{getBranchErr: fmt.Errorf("branch not found")}
		_, err := getBranchTipFromAPI(context.Background(), mock, "owner", "repo", "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "branch not found")
	})

	t.Run("nil commit returns error", func(t *testing.T) {
		mock := &mockReleaseService{
			getBranchResult: &gogithub.Branch{Name: gogithub.Ptr("main"), Commit: nil},
		}
		_, err := getBranchTipFromAPI(context.Background(), mock, "owner", "repo", "main")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no commits")
	})
}

// TestParseRawCommits verifies that raw API commits are parsed to ParsedCommit correctly.
func TestParseRawCommits(t *testing.T) {
	commits := []rawCommit{
		{SHA: "abc1234567890", Message: "feat(api): add new endpoint"},
		{SHA: "def1234567890", Message: "fix: repair broken auth"},
		{SHA: "ghi1234567890", Message: "not a conventional commit"},
	}

	parsed := parseRawCommits(commits)
	require.Len(t, parsed, 3)

	assert.Equal(t, "feat", parsed[0].Type)
	assert.Equal(t, "api", parsed[0].Scope)
	assert.Equal(t, "add new endpoint", parsed[0].Subject)

	assert.Equal(t, "fix", parsed[1].Type)
	assert.Equal(t, "repair broken auth", parsed[1].Subject)

	assert.Equal(t, "other", parsed[2].Type)
	assert.Equal(t, "not a conventional commit", parsed[2].Subject)
}

// TestGetCommitsFromAPITruncated verifies that truncated Compare API responses are detected.
func TestGetCommitsFromAPITruncated(t *testing.T) {
	totalCommits := 300
	mock := &mockReleaseService{
		compareResult: &gogithub.CommitsComparison{
			TotalCommits: gogithub.Ptr(totalCommits),
			Commits: []*gogithub.RepositoryCommit{
				{SHA: gogithub.Ptr("A"), Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: one")}},
			},
		},
	}

	_, err := getCommitsFromAPI(context.Background(), mock, "owner", "repo", "v1.0.0", "HEAD")
	require.Error(t, err)
	assert.ErrorIs(t, err, errTruncated)
	assert.Contains(t, err.Error(), "300 total")
}

// TestGetCommitsFromAPINonTruncated verifies normal Compare API responses succeed.
func TestGetCommitsFromAPINonTruncated(t *testing.T) {
	mock := &mockReleaseService{
		compareResult: &gogithub.CommitsComparison{
			TotalCommits: gogithub.Ptr(2),
			Commits: []*gogithub.RepositoryCommit{
				{
					SHA:    gogithub.Ptr("A"),
					Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: first")},
				},
				{
					SHA:     gogithub.Ptr("B"),
					Commit:  &gogithub.Commit{Message: gogithub.Ptr("fix: second")},
					Parents: []*gogithub.Commit{{SHA: gogithub.Ptr("A")}},
				},
			},
		},
	}

	commits, err := getCommitsFromAPI(context.Background(), mock, "owner", "repo", "v1.0.0", "B")
	require.NoError(t, err)
	assert.Len(t, commits, 2)
}

// addTestOrigin adds a GitHub HTTPS origin remote to a test repo.
func addTestOrigin(t *testing.T, repo *git.Repository, url string) {
	t.Helper()
	_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{url},
	})
	require.NoError(t, err)
}

// TestAPIModeFallbackOnNetworkError verifies auto mode falls back to local git on network failure.
func TestAPIModeFallbackOnNetworkError(t *testing.T) {
	dir, repo := setupTestRepo(t)
	addTestOrigin(t, repo, "https://github.com/test/repo.git")

	mock := &mockReleaseService{listTagsErr: fmt.Errorf("connection refused")}

	opts := &PlanOptions{
		RepoPath:   dir,
		Mode:       ModeAuto,
		ReleaseAPI: mock,
	}

	// auto mode: API fails → falls back to local go-git → succeeds
	plan, err := GeneratePlan(opts)
	require.NoError(t, err)
	assert.NotNil(t, plan)
}

// TestAPIModeFallbackOnExpiredToken verifies auto mode falls back on auth errors.
func TestAPIModeFallbackOnExpiredToken(t *testing.T) {
	dir, repo := setupTestRepo(t)
	addTestOrigin(t, repo, "https://github.com/test/repo.git")

	mock := &mockReleaseService{listTagsErr: fmt.Errorf("401 Unauthorized")}

	opts := &PlanOptions{
		RepoPath:   dir,
		Mode:       ModeAuto,
		ReleaseAPI: mock,
	}

	plan, err := GeneratePlan(opts)
	require.NoError(t, err)
	assert.NotNil(t, plan)
}

// TestGeneratePlanAPIModeSuccess verifies API mode discovers the latest tag and walks
// commits via the API (no full local clone) and yields the bumped next version — the
// path the release build relies on to stamp the accurate tag before it exists.
func TestGeneratePlanAPIModeSuccess(t *testing.T) {
	dir, repo := setupTestRepo(t)
	addTestOrigin(t, repo, "https://github.com/test/repo.git")

	// the API commit-walk filters the first-parent chain from the local HEAD sha, so
	// the compared commit must carry that sha to be counted.
	head, err := repo.Head()
	require.NoError(t, err)
	headSHA := head.Hash().String()

	mock := &mockReleaseService{
		listTagsResult: []*gogithub.RepositoryTag{
			{Name: gogithub.Ptr("v1.0.0")},
		},
		compareResult: &gogithub.CommitsComparison{
			TotalCommits: gogithub.Ptr(1),
			Commits: []*gogithub.RepositoryCommit{
				{SHA: gogithub.Ptr(headSHA), Commit: &gogithub.Commit{Message: gogithub.Ptr("feat: add a thing")}},
			},
		},
	}

	plan, err := GeneratePlan(&PlanOptions{
		RepoPath:   dir,
		Mode:       ModeAPI,
		ReleaseAPI: mock,
	})
	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.True(t, plan.ReleaseNeeded)
	assert.Equal(t, "v1.1.0", plan.NextVersion) // minor bump from a feat over v1.0.0
}

// TestGeneratePlanBuildsAPIClientFromToken verifies a token (with no explicit ReleaseAPI)
// builds the GitHub API client — the wiring the `plan` command uses for `--mode api`.
func TestGeneratePlanBuildsAPIClientFromToken(t *testing.T) {
	dir, repo := setupTestRepo(t)
	addTestOrigin(t, repo, "https://github.com/test/repo.git")

	// Mode=local so no API call is made; the client is still built from the token
	// (construction runs before the mode branch) and must not error.
	plan, err := GeneratePlan(&PlanOptions{
		RepoPath: dir,
		Mode:     ModeLocal,
		Token:    "ghs_faketokenforconstruction",
	})
	require.NoError(t, err)
	require.NotNil(t, plan)
}
