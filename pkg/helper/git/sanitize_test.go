package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireRealGit skips the test if the real git binary isn't on PATH (the
// sanitize workaround shells out to it; these tests exercise that path
// against a repo created by go-git's PlainInit, which real git can read).
func requireRealGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found on PATH")
	}
}

// runGitConfig runs `git -C dir config <args...>` against a real repo,
// failing the test on error.
func runGitConfig(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "config"}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git config %v: %s", args, out)
}

func TestSanitizeBranchMergeRefs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "unrelated lines untouched",
			in: "[core]\n\tbare = false\n[user]\n\tname = Test User\n\temail = test@example.com\n" +
				"[remote \"origin\"]\n\turl = https://example.com/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
			want: "[core]\n\tbare = false\n[user]\n\tname = Test User\n\temail = test@example.com\n" +
				"[remote \"origin\"]\n\turl = https://example.com/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
		},
		{
			name: "valid branch merge ref untouched",
			in:   "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
			want: "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
		},
		{
			name: "invalid branch merge ref dropped",
			in:   "[branch \"pr-test\"]\n\tremote = origin\n\tmerge = refs/pull/999/head\n",
			want: "[branch \"pr-test\"]\n\tremote = origin\n",
		},
		{
			name: "multiple branches, only invalid ones sanitized",
			in: "[branch \"pr-1\"]\n\tremote = origin\n\tmerge = refs/pull/111/head\n" +
				"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n" +
				"[branch \"pr-2\"]\n\tremote = origin\n\tmerge = refs/pull/222/head\n",
			want: "[branch \"pr-1\"]\n\tremote = origin\n" +
				"[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n" +
				"[branch \"pr-2\"]\n\tremote = origin\n",
		},
		{
			name: "merge-like key outside a branch subsection is untouched",
			in:   "[custom]\n\tmerge = refs/pull/999/head\n",
			want: "[custom]\n\tmerge = refs/pull/999/head\n",
		},
		{
			name: "description and rebase fields in a sanitized branch survive",
			in: "[branch \"pr-test\"]\n\tremote = origin\n\tmerge = refs/pull/999/head\n" +
				"\trebase = true\n\tdescription = a PR branch\n",
			want: "[branch \"pr-test\"]\n\tremote = origin\n" +
				"\trebase = true\n\tdescription = a PR branch\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeBranchMergeRefs([]byte(tt.in))
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestOpenRepository_StandardCloneUnaffected(t *testing.T) {
	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	before := sanitizeAttempts.Load()

	repo, err := OpenRepository(dir)
	require.NoError(t, err)
	require.NotNil(t, repo)

	assert.Equal(t, before, sanitizeAttempts.Load(), "fast path must not invoke the sanitize workaround")
}

func TestOpenRepository_InvalidBranchMergeRef(t *testing.T) {
	requireRealGit(t)

	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	runGitConfig(t, dir, "branch.pr-test.remote", "origin")
	runGitConfig(t, dir, "branch.pr-test.merge", "refs/pull/999/head")

	// confirm this reproduces the documented go-git failure before our fix
	// engages, so the test would fail loudly if the repro stopped working.
	_, plainErr := git.PlainOpen(dir)
	require.Error(t, plainErr)
	require.Contains(t, plainErr.Error(), "branch config:")

	before := sanitizeAttempts.Load()

	repo, err := OpenRepository(dir)
	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.Greater(t, sanitizeAttempts.Load(), before, "expected the sanitize workaround to have run")

	// smoke test: HEAD, tags, and commits are still readable
	head, err := repo.Head()
	require.NoError(t, err)

	commit, err := repo.CommitObject(head.Hash())
	require.NoError(t, err)
	assert.Equal(t, "initial commit", commit.Message)

	tags, err := repo.Tags()
	require.NoError(t, err)
	require.NoError(t, tags.ForEach(func(_ *plumbing.Reference) error { return nil }))

	// the sanitized branch's Merge field reads empty/absent; Remote is kept
	cfg, err := repo.Config()
	require.NoError(t, err)
	require.Contains(t, cfg.Branches, "pr-test")
	assert.Empty(t, cfg.Branches["pr-test"].Merge)
	assert.Equal(t, "origin", cfg.Branches["pr-test"].Remote)
}

func TestOpenRepository_MultipleInvalidBranches(t *testing.T) {
	requireRealGit(t)

	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	runGitConfig(t, dir, "branch.pr-1.remote", "origin")
	runGitConfig(t, dir, "branch.pr-1.merge", "refs/pull/111/head")
	runGitConfig(t, dir, "branch.pr-2.remote", "origin")
	runGitConfig(t, dir, "branch.pr-2.merge", "refs/pull/222/head")
	runGitConfig(t, dir, "branch.valid-branch.remote", "origin")
	runGitConfig(t, dir, "branch.valid-branch.merge", "refs/heads/main")

	repo, err := OpenRepository(dir)
	require.NoError(t, err)
	require.NotNil(t, repo)

	cfg, err := repo.Config()
	require.NoError(t, err)

	require.Contains(t, cfg.Branches, "pr-1")
	require.Contains(t, cfg.Branches, "pr-2")
	require.Contains(t, cfg.Branches, "valid-branch")

	assert.Empty(t, cfg.Branches["pr-1"].Merge)
	assert.Empty(t, cfg.Branches["pr-2"].Merge)
	assert.Equal(t, "refs/heads/main", cfg.Branches["valid-branch"].Merge.String())
}

func TestOpenRepository_GitBinaryUnavailable(t *testing.T) {
	requireRealGit(t)

	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	runGitConfig(t, dir, "branch.pr-test.remote", "origin")
	runGitConfig(t, dir, "branch.pr-test.merge", "refs/pull/999/head")

	// point PATH somewhere with no git binary; t.Setenv restores it after the test
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	_, err := OpenRepository(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "branch config:", "original go-git error must still surface")
	assert.Contains(t, err.Error(), "workaround also failed")
}

func TestOpenRepository_NonMergeRefConfigErrorPassesThrough(t *testing.T) {
	requireRealGit(t)

	dir, _ := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	// a malformed fetch refspec fails go-git's config parsing for a reason
	// unrelated to branch merge validation; sanitization must not apply.
	runGitConfig(t, dir, "remote.origin.url", "https://example.com/repo.git")
	runGitConfig(t, dir, "remote.origin.fetch", "not-a-valid-refspec")

	before := sanitizeAttempts.Load()

	_, err := OpenRepository(dir)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "branch config:")
	assert.NotContains(t, err.Error(), "workaround also failed")
	assert.Equal(t, before, sanitizeAttempts.Load(), "sanitize workaround must not engage for unrelated config errors")
}

func TestOpenRepository_NotAGitRepoUnaffected(t *testing.T) {
	dir := t.TempDir()

	before := sanitizeAttempts.Load()

	_, err := OpenRepository(filepath.Join(dir, "does-not-exist"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "workaround also failed")
	assert.Equal(t, before, sanitizeAttempts.Load(), "sanitize workaround must not engage when the repo simply doesn't exist")
}
