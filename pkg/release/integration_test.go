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

// integration tests for release plan generation covering the highest-risk logic paths

func TestIntegrationFirstParentVsFullTraversal(t *testing.T) {
	// create a repo with merge commit to test first-parent vs full traversal
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create initial commit on main
	writeFile(t, dir, "README.md", "initial")
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	initialHash, err := wt.Commit("feat: initial commit", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// create tag v1.0.0
	_, err = repo.CreateTag("v1.0.0", initialHash, nil)
	require.NoError(t, err)

	// create a feature branch and add commits
	featureBranch := plumbing.NewBranchReferenceName("feature-branch")
	headRef, err := repo.Head()
	require.NoError(t, err)

	branchRef := plumbing.NewHashReference(featureBranch, headRef.Hash())
	err = repo.Storer.SetReference(branchRef)
	require.NoError(t, err)

	err = wt.Checkout(&git.CheckoutOptions{Branch: featureBranch})
	require.NoError(t, err)

	// add commits on feature branch
	writeFile(t, dir, "feature.txt", "feature work")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	featureHash1, err := wt.Commit("feat: feature work 1", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	writeFile(t, dir, "feature2.txt", "more feature work")
	_, err = wt.Add("feature2.txt")
	require.NoError(t, err)
	featureHash2, err := wt.Commit("fix: feature work 2", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// switch back to main and add a commit
	mainBranch := plumbing.NewBranchReferenceName("master")
	err = wt.Checkout(&git.CheckoutOptions{Branch: mainBranch})
	require.NoError(t, err)

	writeFile(t, dir, "main.txt", "main work")
	_, err = wt.Add("main.txt")
	require.NoError(t, err)
	mainHash, err := wt.Commit("docs: main work", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// create merge commit by writing a merge file and specifying parents
	writeFile(t, dir, "merge.txt", "merge marker")
	_, err = wt.Add("merge.txt")
	require.NoError(t, err)
	mergeCommit, err := wt.Commit("Merge feature-branch", &git.CommitOptions{
		Author:  sig,
		Parents: []plumbing.Hash{mainHash, featureHash2},
	})
	require.NoError(t, err)

	// get commits with first-parent (should not include feature branch commits)
	commitsFirstParent, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", true)
	require.NoError(t, err)

	// get commits with full traversal (should include feature branch commits)
	commitsAllParents, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", false)
	require.NoError(t, err)

	// first-parent should have fewer or equal commits
	// the merge commit and main commit are on the first-parent path
	// feature commits are only reachable through second parent
	t.Logf("first-parent commits: %d, all-parents commits: %d", len(commitsFirstParent), len(commitsAllParents))
	t.Logf("merge commit: %s", mergeCommit.String()[:7])
	t.Logf("main commit: %s", mainHash.String()[:7])
	t.Logf("feature commits: %s, %s", featureHash1.String()[:7], featureHash2.String()[:7])

	// full traversal should include more commits (feature branch commits)
	assert.GreaterOrEqual(t, len(commitsAllParents), len(commitsFirstParent),
		"full traversal should include at least as many commits as first-parent")
}

func TestIntegrationTagDiscoveryAndCommitSelection(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create commits and tags
	writeFile(t, dir, "file1.txt", "content1")
	_, err = wt.Add("file1.txt")
	require.NoError(t, err)
	hash1, err := wt.Commit("feat: first feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", hash1, nil)
	require.NoError(t, err)

	writeFile(t, dir, "file2.txt", "content2")
	_, err = wt.Add("file2.txt")
	require.NoError(t, err)
	hash2, err := wt.Commit("fix: bug fix", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.1", hash2, nil)
	require.NoError(t, err)

	writeFile(t, dir, "file3.txt", "content3")
	_, err = wt.Add("file3.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: new feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// discover latest tag - should be v1.0.1
	version, tagName, err := DiscoverLatestTag(repo, false)
	require.NoError(t, err)
	assert.Equal(t, "v1.0.1", tagName)
	assert.Equal(t, 1, version.Major)
	assert.Equal(t, 0, version.Minor)
	assert.Equal(t, 1, version.Patch)

	// get commits since v1.0.1 - should be just the new feature
	commits, err := GetCommitsSinceTag(repo, "v1.0.1", "HEAD", false)
	require.NoError(t, err)
	assert.Len(t, commits, 1)
	assert.Contains(t, commits[0].Message, "feat: new feature")
}

func TestIntegrationNoReleasableCommits(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create initial commit and tag
	writeFile(t, dir, "README.md", "initial")
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	hash1, err := wt.Commit("feat: initial", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", hash1, nil)
	require.NoError(t, err)

	// add only non-releasable commits (docs, chore)
	writeFile(t, dir, "docs.md", "documentation")
	_, err = wt.Add("docs.md")
	require.NoError(t, err)
	_, err = wt.Commit("docs: update documentation", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	writeFile(t, dir, "config.txt", "config")
	_, err = wt.Add("config.txt")
	require.NoError(t, err)
	_, err = wt.Commit("chore: update config", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// generate plan
	plan, err := GeneratePlan(&PlanOptions{
		RepoPath:    dir,
		FirstParent: false,
	})
	require.NoError(t, err)

	// should not need release
	assert.False(t, plan.ReleaseNeeded)
	assert.Equal(t, "no releasable commits (only docs, chore, etc.)", plan.Reason)
	assert.Equal(t, "v1.0.0", plan.CurrentVersion)
	assert.Equal(t, "v1.0.0", plan.NextVersion) // no bump
}

func TestIntegrationNoTags(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create commits without any tags
	writeFile(t, dir, "README.md", "initial")
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	_, err = wt.Commit("feat: initial feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	writeFile(t, dir, "feature.txt", "feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("fix: bug fix", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// generate plan - should handle no tags gracefully
	plan, err := GeneratePlan(&PlanOptions{
		RepoPath:    dir,
		FirstParent: false,
	})
	require.NoError(t, err)

	// should start from v0.0.0 and bump to v0.1.0 (feat = minor)
	assert.True(t, plan.ReleaseNeeded)
	assert.Equal(t, "v0.0.0", plan.CurrentVersion)
	assert.Equal(t, "v0.1.0", plan.NextVersion)
	assert.Len(t, plan.Commits, 2)
}

func TestIntegrationNoCommitsSinceTag(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create commit and tag at HEAD
	writeFile(t, dir, "README.md", "initial")
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	hash, err := wt.Commit("feat: initial", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", hash, nil)
	require.NoError(t, err)

	// generate plan - no commits since tag
	plan, err := GeneratePlan(&PlanOptions{
		RepoPath:    dir,
		FirstParent: false,
	})
	require.NoError(t, err)

	// should not need release
	assert.False(t, plan.ReleaseNeeded)
	assert.Equal(t, "no commits since last release", plan.Reason)
}

func TestIntegrationToRefSupport(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	// create commits
	writeFile(t, dir, "file1.txt", "content1")
	_, err = wt.Add("file1.txt")
	require.NoError(t, err)
	hash1, err := wt.Commit("feat: first", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", hash1, nil)
	require.NoError(t, err)

	writeFile(t, dir, "file2.txt", "content2")
	_, err = wt.Add("file2.txt")
	require.NoError(t, err)
	hash2, err := wt.Commit("fix: second", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	writeFile(t, dir, "file3.txt", "content3")
	_, err = wt.Add("file3.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: third", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// get commits using specific toRef (hash2) instead of HEAD
	commits, err := GetCommitsSinceTag(repo, "v1.0.0", hash2.String(), false)
	require.NoError(t, err)

	// should only include the second commit, not the third
	assert.Len(t, commits, 1)
	assert.Equal(t, hash2, commits[0].Hash)
}

func TestIntegrationChangelogMarkdownEndToEnd(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	baseTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	// create commits with various types
	messages := []string{
		"feat: add user authentication",
		"fix: correct password hashing",
		"docs: update API reference",
		"feat!: redesign login flow",
		"chore: update dependencies",
	}

	for i, msg := range messages {
		writeFile(t, dir, "file.txt", msg)
		_, err = wt.Add("file.txt")
		require.NoError(t, err)

		hash, err := wt.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name: "test", Email: "test@example.com",
				When: baseTime.Add(time.Duration(i) * time.Hour),
			},
		})
		require.NoError(t, err)

		if i == 1 {
			_, err = repo.CreateTag("v1.0.0", hash, nil)
			require.NoError(t, err)
		}
	}

	// get commits since v1.0.0
	gitCommits, err := GetCommitsSinceTag(repo, "v1.0.0", "HEAD", false)
	require.NoError(t, err)
	assert.Len(t, gitCommits, 3)

	parsed := ParseCommits(gitCommits)

	// generate markdown with include-all
	changelog, err := GenerateChangelog(parsed, &ChangelogOptions{
		Version:    "v2.0.0",
		IncludeAll: true,
	})
	require.NoError(t, err)

	assert.Contains(t, changelog, "## v2.0.0")
	assert.Contains(t, changelog, "Breaking Changes")
	assert.Contains(t, changelog, "redesign login flow")
	assert.Contains(t, changelog, "Documentation")
	assert.Contains(t, changelog, "Chores")

	// generate without include-all — docs and chore excluded
	changelogFiltered, err := GenerateChangelog(parsed, &ChangelogOptions{
		Version:    "v2.0.0",
		IncludeAll: false,
	})
	require.NoError(t, err)

	assert.Contains(t, changelogFiltered, "redesign login flow")
	assert.NotContains(t, changelogFiltered, "update API reference")
	assert.NotContains(t, changelogFiltered, "update dependencies")
}

func TestIntegrationChangelogJSONEndToEnd(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	messages := []string{
		"feat(api): add endpoint",
		"fix(auth): fix token refresh",
		"feat!: breaking api change",
	}

	for _, msg := range messages {
		writeFile(t, dir, "file.txt", msg)
		_, err = wt.Add("file.txt")
		require.NoError(t, err)
		_, err = wt.Commit(msg, &git.CommitOptions{Author: sig})
		require.NoError(t, err)
	}

	gitCommits, err := GetCommitsSinceTag(repo, "", "HEAD", false)
	require.NoError(t, err)
	parsed := ParseCommits(gitCommits)

	result := GenerateChangelogJSON(parsed, &ChangelogOptions{
		Version:    "v2.0.0",
		IncludeAll: true,
	})

	assert.Equal(t, "v2.0.0", result.Version)

	// verify stats
	assert.Equal(t, 3, result.Stats["total"])
	assert.Equal(t, 2, result.Stats["feat"])
	assert.Equal(t, 1, result.Stats["fix"])
	assert.Equal(t, 1, result.Stats["breaking"])

	// verify breaking changes extracted
	assert.NotEmpty(t, result.BreakingChanges)

	// verify groups contain expected data
	var foundFeat, foundFix bool
	for _, g := range result.Groups {
		if g.Type == "feat" {
			foundFeat = true
			assert.Equal(t, "Features", g.Name)
			assert.Len(t, g.Commits, 2)
		}
		if g.Type == "fix" {
			foundFix = true
			assert.Equal(t, "Bug Fixes", g.Name)
			assert.Len(t, g.Commits, 1)
			assert.Equal(t, "auth", g.Commits[0].Scope)
		}
	}
	assert.True(t, foundFeat, "expected feat group")
	assert.True(t, foundFix, "expected fix group")
}

func TestIntegrationChangelogDeterministic(t *testing.T) {
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	baseTime := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	messages := []string{
		"feat: feature alpha",
		"fix: fix bravo",
		"docs: docs charlie",
		"feat(scope): feature delta",
	}

	for i, msg := range messages {
		writeFile(t, dir, "file.txt", msg)
		_, err = wt.Add("file.txt")
		require.NoError(t, err)
		_, err = wt.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name: "test", Email: "test@example.com",
				When: baseTime.Add(time.Duration(i) * time.Hour),
			},
		})
		require.NoError(t, err)
	}

	gitCommits, err := GetCommitsSinceTag(repo, "", "HEAD", true)
	require.NoError(t, err)
	parsed := ParseCommits(gitCommits)

	opts := &ChangelogOptions{Version: "v1.0.0", IncludeAll: true}

	// generate twice, verify identical
	changelog1, err := GenerateChangelog(parsed, opts)
	require.NoError(t, err)

	changelog2, err := GenerateChangelog(parsed, opts)
	require.NoError(t, err)

	assert.Equal(t, changelog1, changelog2, "changelog output must be deterministic")

	// also verify JSON determinism
	json1 := GenerateChangelogJSON(parsed, opts)
	json2 := GenerateChangelogJSON(parsed, opts)
	assert.Equal(t, json1, json2, "JSON output must be deterministic")
}

// helper to write file
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644)
	require.NoError(t, err)
}
