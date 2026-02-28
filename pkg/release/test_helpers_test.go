package release

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
