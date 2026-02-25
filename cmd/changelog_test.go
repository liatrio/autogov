package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/liatrio/autogov-verify/pkg/release"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newChangelogCmd creates a fresh changelog command for testing, avoiding
// mutation of the package-level changelogCmd between tests.
func newChangelogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "changelog",
		Short: "Generate changelog from conventional commits",
		RunE:  runChangelog,
	}
	cmd.Flags().String("from", "", "Starting ref")
	cmd.Flags().String("to", "HEAD", "Ending ref")
	cmd.Flags().StringP("output", "o", "", "Output file path")
	cmd.Flags().String("format", "markdown", "Output format: markdown, json")
	cmd.Flags().String("repo-path", ".", "Path to git repository")
	cmd.Flags().Bool("include-all", false, "Include non-releasable commit types")
	cmd.Flags().Bool("first-parent", false, "Follow only first parent")
	cmd.Flags().String("version", "", "Version header")
	return cmd
}

// executeChangelogCmd runs a fresh changelog command with the given args and captures output.
func executeChangelogCmd(t *testing.T, args []string) (string, error) {
	t.Helper()

	root := &cobra.Command{Use: "autogov"}
	root.AddCommand(newChangelogCmd())

	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(append([]string{"changelog"}, args...))

	err := root.Execute()
	return buf.String(), err
}

// createTestRepo creates a temp git repo with conventional commits and optional tags
func createTestRepo(t *testing.T, commits []string, tags map[string]int) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	// create initial file
	err = os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0o644)
	require.NoError(t, err)

	_, err = wt.Add("README.md")
	require.NoError(t, err)

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	for i, msg := range commits {
		// modify file to create changes
		content := []byte("# test\ncommit " + msg + "\n")
		err = os.WriteFile(filepath.Join(dir, "README.md"), content, 0o644)
		require.NoError(t, err)
		_, err = wt.Add("README.md")
		require.NoError(t, err)

		hash, err := wt.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@test.com",
				When:  baseTime.Add(time.Duration(i) * time.Hour),
			},
		})
		require.NoError(t, err)

		for tagName, commitIdx := range tags {
			if commitIdx == i {
				_, err = repo.CreateTag(tagName, hash, nil)
				require.NoError(t, err)
			}
		}
	}

	return dir
}

func TestRunChangelogMarkdown(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: add user auth",
		"fix: correct login bug",
		"chore: update deps",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--include-all", "--version", "v1.0.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "v1.0.0")
	assert.Contains(t, out, "Features")
	assert.Contains(t, out, "add user auth")
	assert.Contains(t, out, "Bug Fixes")
	assert.Contains(t, out, "correct login bug")
}

func TestRunChangelogJSON(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: add api endpoint",
		"fix: handle nil pointer",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--format", "json", "--version", "v1.0.0"})
	require.NoError(t, err)

	var result release.ChangelogJSON
	err = json.Unmarshal([]byte(out), &result)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", result.Version)
	assert.NotEmpty(t, result.Groups)
	assert.NotEmpty(t, result.Stats)
	assert.Equal(t, 2, result.Stats["total"])
}

func TestRunChangelogTagRange(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: initial feature",
		"fix: first fix",
		"feat: second feature",
		"fix: second fix",
	}, map[string]int{
		"v1.0.0": 1,
	})

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--from", "v1.0.0", "--version", "v1.1.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "v1.1.0")
	assert.Contains(t, out, "second feature")
	assert.Contains(t, out, "second fix")
	assert.NotContains(t, out, "initial feature")
	assert.NotContains(t, out, "first fix")
}

func TestRunChangelogFileOutput(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: new feature",
	}, nil)

	outFile := filepath.Join(t.TempDir(), "CHANGELOG.md")

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--output", outFile, "--version", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "Changelog written to")

	content, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "new feature")
}

func TestRunChangelogIncludeAll(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: a feature",
		"docs: update readme",
		"chore: cleanup",
		"test: add tests",
	}, nil)

	// without --include-all: docs, chore, test should be excluded
	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--version", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "a feature")
	assert.NotContains(t, out, "update readme")
	assert.NotContains(t, out, "cleanup")

	// with --include-all: all types included
	out, err = executeChangelogCmd(t, []string{"--repo-path", dir, "--include-all", "--version", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "a feature")
	assert.Contains(t, out, "update readme")
	assert.Contains(t, out, "cleanup")
}

func TestRunChangelogFirstParent(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: initial",
		"feat: second",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--first-parent", "--version", "v1.0.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "initial")
	assert.Contains(t, out, "second")
}

func TestRunChangelogVersionDerivedFromTag(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: feature one",
		"feat: feature two",
	}, map[string]int{
		"v1.0.0": 0,
		"v1.1.0": 1,
	})

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--from", "v1.0.0", "--to", "v1.1.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "v1.1.0")
}

func TestRunChangelogVersionExplicit(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: my feature",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--version", "v2.0.0-rc.1"})
	require.NoError(t, err)
	assert.Contains(t, out, "v2.0.0-rc.1")
}

func TestRunChangelogVersionOmitted(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: my feature",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir})
	require.NoError(t, err)
	assert.Contains(t, out, "my feature")
}

func TestRunChangelogErrorMissingRepo(t *testing.T) {
	_, err := executeChangelogCmd(t, []string{"--repo-path", "/nonexistent/path"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changelog:")
}

func TestRunChangelogErrorBadFromRef(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: something",
	}, nil)

	_, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--from", "nonexistent-tag"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changelog:")
}

func TestRunChangelogErrorUnwritableOutput(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: something",
	}, nil)

	_, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--output", "/nonexistent/dir/CHANGELOG.md", "--version", "v1.0.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changelog: writing output file:")
}

func TestRunChangelogErrorUnsupportedFormat(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: something",
	}, nil)

	_, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--format", "xml", "--version", "v1.0.0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestRunChangelogNoCommitsInRange(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: tagged commit",
	}, map[string]int{
		"v1.0.0": 0,
	})

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--from", "v1.0.0", "--to", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "No changes found")
}

func TestRunChangelogEmptyRepoError(t *testing.T) {
	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = executeChangelogCmd(t, []string{"--repo-path", dir})
	require.Error(t, err)
}

func TestRunChangelogStdout(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: stdout test",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--version", "v0.1.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "stdout test")
}

func TestRunChangelogDiscoverLatestTag(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: before tag",
		"fix: after tag",
	}, map[string]int{
		"v1.0.0": 0,
	})

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--version", "v1.1.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "after tag")
	assert.NotContains(t, out, "before tag")
}

func TestRunChangelogToRefAsTag(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: first",
		"feat: second",
		"feat: third",
	}, map[string]int{
		"v1.0.0": 0,
		"v1.1.0": 1,
	})

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--from", "v1.0.0", "--to", "v1.1.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "second")
	assert.NotContains(t, out, "first")
	assert.NotContains(t, out, "third")
}

func TestRunChangelogToRefAsBranch(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: main feature",
	}, nil)

	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	err = repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName("test-branch"), head.Hash()))
	require.NoError(t, err)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--to", "test-branch", "--version", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "main feature")
}

func TestRunChangelogMdFormatAlias(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: alias test",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--format", "md", "--version", "v1.0.0"})
	require.NoError(t, err)
	assert.Contains(t, out, "alias test")
}

func TestRunChangelogBreakingChangesMarkdown(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat: normal feature",
		"feat!: redesign the API",
		"fix: minor fix",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--version", "v2.0.0"})
	require.NoError(t, err)

	assert.Contains(t, out, "Breaking Changes")
	assert.Contains(t, out, "redesign the API")
	assert.Contains(t, out, "normal feature")
	assert.Contains(t, out, "minor fix")
}

func TestRunChangelogBreakingChangesJSON(t *testing.T) {
	dir := createTestRepo(t, []string{
		"feat!: breaking api change",
		"fix: normal fix",
	}, nil)

	out, err := executeChangelogCmd(t, []string{"--repo-path", dir, "--format", "json", "--version", "v2.0.0"})
	require.NoError(t, err)

	var result release.ChangelogJSON
	err = json.Unmarshal([]byte(out), &result)
	require.NoError(t, err)

	assert.NotEmpty(t, result.BreakingChanges)
	assert.Equal(t, 1, result.Stats["breaking"])
}

func TestRunChangelogHelpOutput(t *testing.T) {
	out, err := executeChangelogCmd(t, []string{"--help"})
	require.NoError(t, err)

	assert.Contains(t, out, "--from")
	assert.Contains(t, out, "--to")
	assert.Contains(t, out, "--output")
	assert.Contains(t, out, "--format")
	assert.Contains(t, out, "--repo-path")
	assert.Contains(t, out, "--include-all")
	assert.Contains(t, out, "--first-parent")
	assert.Contains(t, out, "--version")
}
