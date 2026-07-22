package git

import (
	"io"
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

// NOTE: These test helpers are duplicated in pkg/release/test_helpers_test.go.
// Go's test package scoping prevents sharing _test.go helpers across packages
// without creating a dedicated testutil package. Keep both copies in sync.

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

// helper to create a merge commit combining two branch tips
func createMergeCommit(t *testing.T, repo *git.Repository, dir string, parent1, parent2 plumbing.Hash, message string) plumbing.Hash {
	t.Helper()

	wt, err := repo.Worktree()
	require.NoError(t, err)

	// modify file so the tree differs from parents
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
		Author:  sig,
		Parents: []plumbing.Hash{parent1, parent2},
	})
	require.NoError(t, err)

	return hash
}

func TestGetCommitsSinceTagMergeFirstParentVsAll(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	// A - tag it
	addCommit(t, repo, dir, "feat: feature A")
	createTag(t, repo, "v1.0.0")

	// B on main branch
	hashB := addCommit(t, repo, dir, "feat: feature B")

	// create a side branch from A (parent of B)
	commitB, err := repo.CommitObject(hashB)
	require.NoError(t, err)
	parentA, err := commitB.Parent(0)
	require.NoError(t, err)

	// checkout the side branch at A
	wt, err := repo.Worktree()
	require.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{
		Hash:   parentA.Hash,
		Create: false,
		Force:  true,
	})
	require.NoError(t, err)

	// C on side branch
	_ = addCommit(t, repo, dir, "fix: fix C")
	// D on side branch
	hashD := addCommit(t, repo, dir, "fix: fix D")

	// go back to B
	err = wt.Checkout(&git.CheckoutOptions{
		Hash:  hashB,
		Force: true,
	})
	require.NoError(t, err)

	// merge commit with parents B and D
	createMergeCommit(t, repo, dir, hashB, hashD, "chore: merge side branch")

	// firstParent=true: should only walk merge -> B (2 commits)
	fpCommits, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", true)
	require.NoError(t, err)

	// firstParent=false: should walk all reachable: merge, B, D, C (4 commits)
	allCommits, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", false)
	require.NoError(t, err)

	assert.Len(t, fpCommits, 2, "first-parent should see merge + B")
	assert.Len(t, allCommits, 4, "all-parents should see merge + B + D + C")

	// verify first-parent only has merge and B
	fpMessages := make([]string, len(fpCommits))
	for i, c := range fpCommits {
		fpMessages[i] = c.Message
	}
	assert.Contains(t, fpMessages[0], "merge side branch")
	assert.Contains(t, fpMessages[1], "feature B")
}

// captureStderr swaps os.Stderr for a pipe for the duration of fn, returning
// everything fn wrote to stderr. Restoration happens via t.Cleanup, so this
// must not be used from a t.Parallel test (os.Stderr is process-global).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = orig
	})

	fn()

	require.NoError(t, w.Close())
	os.Stderr = orig

	captured, err := io.ReadAll(r)
	require.NoError(t, err)
	_ = r.Close()
	return string(captured)
}

func TestGetCommitsSinceTagReversedRangeFirstParent(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "feat: feature B")
	createTag(t, repo, "v2.0.0")

	// reversed: --from v2.0.0 (newer) --to v1.0.0 (older)
	commits, err := GetCommitsSinceTag(repo, "v2.0.0", "v1.0.0", true)
	require.NoError(t, err)
	assert.Empty(t, commits)
}

func TestGetCommitsSinceTagReversedRangeAllParents(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "feat: feature B")
	createTag(t, repo, "v2.0.0")

	// reversed: --from v2.0.0 (newer) --to v1.0.0 (older)
	commits, err := GetCommitsSinceTag(repo, "v2.0.0", "v1.0.0", false)
	require.NoError(t, err)
	assert.Empty(t, commits)
}

func TestGetCommitsSinceTagDivergentRangeAllParents(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	root, err := repo.Head()
	require.NoError(t, err)

	// side branch off root, tagged
	addCommit(t, repo, dir, "fix: side branch commit")
	createTag(t, repo, "v-side")

	// back to root, build a divergent main path that never merges the side branch back in
	wt, err := repo.Worktree()
	require.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{
		Hash:  root.Hash(),
		Force: true,
	})
	require.NoError(t, err)
	addCommit(t, repo, dir, "feat: main A")
	addCommit(t, repo, dir, "feat: main B")

	// neither ref is an ancestor of the other
	commits, err := GetCommitsSinceTag(repo, "v-side", "HEAD", false)
	require.NoError(t, err)
	assert.Empty(t, commits)
}

func TestGetCommitsSinceTagFirstParentMergedInFrom(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	// A - tag it (base)
	addCommit(t, repo, dir, "feat: feature A")
	createTag(t, repo, "v1.0.0")

	// B on main branch
	hashB := addCommit(t, repo, dir, "feat: feature B")

	commitB, err := repo.CommitObject(hashB)
	require.NoError(t, err)
	parentA, err := commitB.Parent(0)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{
		Hash:  parentA.Hash,
		Force: true,
	})
	require.NoError(t, err)

	// C, D on a side branch off A; D is tagged and only reachable via the merge's non-first parent
	_ = addCommit(t, repo, dir, "fix: fix C")
	_ = addCommit(t, repo, dir, "fix: fix D")
	createTag(t, repo, "v-side")

	hashD, err := repo.Head()
	require.NoError(t, err)

	// back to B, merge the side branch in
	err = wt.Checkout(&git.CheckoutOptions{
		Hash:  hashB,
		Force: true,
	})
	require.NoError(t, err)
	createMergeCommit(t, repo, dir, hashB, hashD.Hash(), "chore: merge side branch")

	// first-parent walk from HEAD (merge -> B -> A -> root) never encounters v-side (on D)
	commits, err := GetCommitsSinceTag(repo, "v-side", "HEAD", true)
	require.NoError(t, err)
	assert.Empty(t, commits, "first-parent walk must not silently fall through to root")
}

func TestGetCommitsSinceTagSameRefNoWarning(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "feat: feature B")

	var commits []*object.Commit
	var err error
	stderrOutput := captureStderr(t, func() {
		commits, err = GetCommitsSinceTag(repo, "v1.0.0", "v1.0.0", false)
	})

	require.NoError(t, err)
	assert.Empty(t, commits)
	assert.Empty(t, stderrOutput, "from == to must not print a warning (matches git A..A)")
}

func TestGetCommitsSinceTagReversedRangeWarnsOnStderr(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	createTag(t, repo, "v1.0.0")
	addCommit(t, repo, dir, "feat: feature B")
	createTag(t, repo, "v2.0.0")

	var commits []*object.Commit
	var err error
	stderrOutput := captureStderr(t, func() {
		commits, err = GetCommitsSinceTag(repo, "v2.0.0", "v1.0.0", true)
	})

	require.NoError(t, err)
	assert.Empty(t, commits)
	assert.Contains(t, stderrOutput, "warning:")
	assert.Contains(t, stderrOutput, "v1.0.0")
	assert.Contains(t, stderrOutput, "v2.0.0")
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
			got := ParseRepoNameFromURL(tt.url)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCommits(t *testing.T) {
	dir, repo := createTestRepo(t)
	defer func() { _ = os.RemoveAll(dir) }()

	addCommit(t, repo, dir, "feat: new feature")
	addCommit(t, repo, dir, "fix: bug fix")
	addCommit(t, repo, dir, "not a conventional commit")

	commits, err := GetCommitsSinceTag(repo, "", "HEAD", false)
	require.NoError(t, err)

	parsed := ParseCommits(commits)
	assert.Len(t, parsed, 4) // initial + 3 more

	// verify conventional commits are parsed correctly
	typeMap := make(map[string]int)
	for _, pc := range parsed {
		typeMap[pc.Type]++
	}
	assert.Equal(t, 1, typeMap["feat"])
	assert.Equal(t, 1, typeMap["fix"])
	assert.Equal(t, 2, typeMap["other"]) // initial commit + non-conventional
}
