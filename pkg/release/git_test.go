package release

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to create a test git repository with commits and tags
func createTestRepo(t *testing.T) (string, *git.Repository) {
	t.Helper()

	dir, err := os.MkdirTemp("", "test-repo-*")
	require.NoError(t, err)

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	// create a test file
	testFile := filepath.Join(dir, "test.txt")
	err = os.WriteFile(testFile, []byte("initial content"), 0644)
	require.NoError(t, err)

	// add and commit
	wt, err := repo.Worktree()
	require.NoError(t, err)

	_, err = wt.Add("test.txt")
	require.NoError(t, err)

	sig := &object.Signature{
		Name:  "Test User",
		Email: "test@example.com",
		When:  time.Now(),
	}

	_, err = wt.Commit("initial commit", &git.CommitOptions{
		Author: sig,
	})
	require.NoError(t, err)

	return dir, repo
}

// helper to add a commit to the test repo
func addCommit(t *testing.T, repo *git.Repository, dir string, message string) plumbing.Hash {
	t.Helper()

	wt, err := repo.Worktree()
	require.NoError(t, err)

	// modify the test file
	testFile := filepath.Join(dir, "test.txt")
	content, _ := os.ReadFile(testFile)
	err = os.WriteFile(testFile, append(content, []byte("\n"+message)...), 0644)
	require.NoError(t, err)

	_, err = wt.Add("test.txt")
	require.NoError(t, err)

	sig := &object.Signature{
		Name:  "Test User",
		Email: "test@example.com",
		When:  time.Now(),
	}

	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: sig,
	})
	require.NoError(t, err)

	return hash
}

// helper to create a tag
func createTag(t *testing.T, repo *git.Repository, name string) {
	t.Helper()

	head, err := repo.Head()
	require.NoError(t, err)

	_, err = repo.CreateTag(name, head.Hash(), nil)
	require.NoError(t, err)
}

func TestOpenRepository(t *testing.T) {
	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	repo, err := OpenRepository(dir)
	require.NoError(t, err)
	assert.NotNil(t, repo)
}

func TestOpenRepositoryInvalidPath(t *testing.T) {
	_, err := OpenRepository("/nonexistent/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open repository")
}

func TestDiscoverLatestTagNoTags(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	ver, name, err := DiscoverLatestTag(repo, false)
	require.NoError(t, err)
	assert.Nil(t, ver)
	assert.Empty(t, name)
}

func TestDiscoverLatestTagSingleTag(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")

	ver, name, err := DiscoverLatestTag(repo, false)
	require.NoError(t, err)
	require.NotNil(t, ver)
	assert.Equal(t, "v1.0.0", ver.String())
	assert.Equal(t, "v1.0.0", name)
}

func TestDiscoverLatestTagMultipleTags(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	// create tags in non-chronological order to test sorting
	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "commit 2")
	createTag(t, repo, "v2.0.0")
	addCommit(t, repo, dir, "commit 3")
	createTag(t, repo, "v1.5.0")

	ver, name, err := DiscoverLatestTag(repo, false)
	require.NoError(t, err)
	require.NotNil(t, ver)
	assert.Equal(t, "v2.0.0", ver.String())
	assert.Equal(t, "v2.0.0", name)
}

func TestDiscoverLatestTagSkipsNonSemver(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "not-a-version")
	addCommit(t, repo, dir, "commit 2")
	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "commit 3")
	createTag(t, repo, "release-candidate")

	ver, name, err := DiscoverLatestTag(repo, false)
	require.NoError(t, err)
	require.NotNil(t, ver)
	assert.Equal(t, "v1.0.0", ver.String())
	assert.Equal(t, "v1.0.0", name)
}

func TestGetCommitsSinceTagNoTag(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	addCommit(t, repo, dir, "commit 2")
	addCommit(t, repo, dir, "commit 3")

	commits, err := GetCommitsSinceTag(repo, "", "HEAD", false)
	require.NoError(t, err)
	assert.Len(t, commits, 3) // initial + 2 more
}

func TestGetCommitsSinceTagWithTag(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "feat: new feature")
	addCommit(t, repo, dir, "fix: bug fix")

	commits, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", false)
	require.NoError(t, err)
	assert.Len(t, commits, 2)
}

func TestGetRepositoryNameUnknown(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	// no remotes configured
	name := GetRepositoryName(repo)
	assert.Equal(t, "unknown", name)
}

func TestParseRepoNameFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "ssh format",
			url:  "git@github.com:owner/repo.git",
			want: "owner/repo",
		},
		{
			name: "https format",
			url:  "https://github.com/owner/repo.git",
			want: "owner/repo",
		},
		{
			name: "https without .git",
			url:  "https://github.com/owner/repo",
			want: "owner/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRepoNameFromURL(tt.url)
			assert.Equal(t, tt.want, got)
		})
	}
}
