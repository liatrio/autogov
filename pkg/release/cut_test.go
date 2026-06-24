package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	gogithub "github.com/google/go-github/v88/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func mockResp(code int) *gogithub.Response {
	return &gogithub.Response{Response: &http.Response{StatusCode: code, Body: http.NoBody}}
}

// mockReleaseService implements ReleaseService for testing
type mockReleaseService struct {
	// release operations
	getRelease        *gogithub.RepositoryRelease
	getReleaseErr     error
	getReleaseByID    *gogithub.RepositoryRelease
	getReleaseByIDErr error
	createRelease     *gogithub.RepositoryRelease
	createErr         error
	updateRelease     *gogithub.RepositoryRelease
	updateErr         error
	listReleases      []*gogithub.RepositoryRelease
	listReleasesErr   error

	// read operations
	listTagsResult  []*gogithub.RepositoryTag
	listTagsErr     error
	compareResult   *gogithub.CommitsComparison
	compareErr      error
	getBranchResult *gogithub.Branch
	getBranchErr    error

	// git data operations
	createTreeResult   *gogithub.Tree
	createTreeErr      error
	createCommitResult *gogithub.Commit
	createCommitErr    error
	createTagResult    *gogithub.Tag
	createTagErr       error
	lastCreateTagArg   gogithub.CreateTag // captured for assertions
	createRefResult    *gogithub.Reference
	createRefErr       error
	updateRefResult    *gogithub.Reference
	updateRefErr       error
	deleteRefErr       error
	deletedRefs        []string // captured for assertions

	// asset operations
	uploadAssetErr       error
	uploadAssetFailAfter int // with uploadAssetErr set, succeed this many uploads before failing
	uploadedAssetNames   []string
	uploadedAssetLabels  []string
}

func (m *mockReleaseService) GetReleaseByTag(_ context.Context, _, _, _ string) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	code := 200
	if m.getReleaseErr != nil {
		code = 404
	}
	return m.getRelease, mockResp(code), m.getReleaseErr
}

func (m *mockReleaseService) GetRelease(_ context.Context, _, _ string, _ int64) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	code := 200
	if m.getReleaseByIDErr != nil {
		code = 404
	}
	return m.getReleaseByID, mockResp(code), m.getReleaseByIDErr
}

func (m *mockReleaseService) ListTags(_ context.Context, _, _ string, _ *gogithub.ListOptions) ([]*gogithub.RepositoryTag, *gogithub.Response, error) {
	code := 200
	if m.listTagsErr != nil {
		code = 500
	}
	return m.listTagsResult, mockResp(code), m.listTagsErr
}

func (m *mockReleaseService) CompareCommits(_ context.Context, _, _, _, _ string, _ *gogithub.ListOptions) (*gogithub.CommitsComparison, *gogithub.Response, error) {
	code := 200
	if m.compareErr != nil {
		code = 500
	}
	return m.compareResult, mockResp(code), m.compareErr
}

func (m *mockReleaseService) GetBranch(_ context.Context, _, _, _ string, _ int) (*gogithub.Branch, *gogithub.Response, error) {
	code := 200
	if m.getBranchErr != nil {
		code = 404
	}
	return m.getBranchResult, mockResp(code), m.getBranchErr
}

func (m *mockReleaseService) CreateRelease(_ context.Context, _, _ string, _ *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	code := 201
	if m.createErr != nil {
		code = 500
	}
	return m.createRelease, mockResp(code), m.createErr
}

func (m *mockReleaseService) UpdateRelease(_ context.Context, _, _ string, _ int64, _ *gogithub.RepositoryRelease) (*gogithub.RepositoryRelease, *gogithub.Response, error) {
	code := 200
	if m.updateErr != nil {
		code = 500
	}
	return m.updateRelease, mockResp(code), m.updateErr
}

func (m *mockReleaseService) ListReleases(_ context.Context, _, _ string, _ *gogithub.ListOptions) ([]*gogithub.RepositoryRelease, *gogithub.Response, error) {
	code := 200
	if m.listReleasesErr != nil {
		code = 500
	}
	return m.listReleases, mockResp(code), m.listReleasesErr
}

func (m *mockReleaseService) UploadReleaseAsset(_ context.Context, _, _ string, _ int64, opts *gogithub.UploadOptions, _ *os.File) (*gogithub.ReleaseAsset, *gogithub.Response, error) {
	if m.uploadAssetErr != nil && len(m.uploadedAssetNames) >= m.uploadAssetFailAfter {
		return nil, mockResp(500), m.uploadAssetErr
	}
	m.uploadedAssetNames = append(m.uploadedAssetNames, opts.Name)
	m.uploadedAssetLabels = append(m.uploadedAssetLabels, opts.Label)
	return &gogithub.ReleaseAsset{Name: gogithub.Ptr(opts.Name)}, mockResp(201), nil
}

func (m *mockReleaseService) CreateTree(_ context.Context, _, _, _ string, _ []*gogithub.TreeEntry) (*gogithub.Tree, *gogithub.Response, error) {
	return m.createTreeResult, mockResp(201), m.createTreeErr
}

func (m *mockReleaseService) CreateCommit(_ context.Context, _, _ string, _ gogithub.Commit, _ *gogithub.CreateCommitOptions) (*gogithub.Commit, *gogithub.Response, error) {
	return m.createCommitResult, mockResp(201), m.createCommitErr
}

func (m *mockReleaseService) CreateTag(_ context.Context, _, _ string, tag gogithub.CreateTag) (*gogithub.Tag, *gogithub.Response, error) {
	m.lastCreateTagArg = tag
	return m.createTagResult, mockResp(201), m.createTagErr
}

func (m *mockReleaseService) CreateRef(_ context.Context, _, _ string, _ gogithub.CreateRef) (*gogithub.Reference, *gogithub.Response, error) {
	return m.createRefResult, mockResp(201), m.createRefErr
}

func (m *mockReleaseService) UpdateRef(_ context.Context, _, _, _ string, _ gogithub.UpdateRef) (*gogithub.Reference, *gogithub.Response, error) {
	return m.updateRefResult, mockResp(200), m.updateRefErr
}

func (m *mockReleaseService) DeleteRef(_ context.Context, _, _, ref string) (*gogithub.Response, error) {
	if m.deleteRefErr != nil {
		return mockResp(500), m.deleteRefErr
	}
	m.deletedRefs = append(m.deletedRefs, ref)
	return mockResp(204), nil
}

// helper to create a test repo with an initial commit and tag
func setupTestRepo(t *testing.T) (string, *git.Repository) {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	writeFile(t, dir, "README.md", "# test repo")
	_, err = wt.Add("README.md")
	require.NoError(t, err)

	hash, err := wt.Commit("feat: initial commit", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", hash, nil)
	require.NoError(t, err)

	return dir, repo
}

func TestValidateWorktreeClean(t *testing.T) {
	dir, repo := setupTestRepo(t)

	// clean worktree should pass
	err := validateWorktree(repo, "master")
	assert.NoError(t, err)

	// dirty worktree should fail
	writeFile(t, dir, "dirty.txt", "uncommitted")
	err = validateWorktree(repo, "master")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not clean")
}

func TestValidateWorktreeWrongBranch(t *testing.T) {
	_, repo := setupTestRepo(t)

	// expect "main" but we're on "master" (go-git default)
	err := validateWorktree(repo, "main")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected branch")
}

func TestValidateWorktreeEmptyBranch(t *testing.T) {
	_, repo := setupTestRepo(t)

	// empty branch name means skip branch check
	err := validateWorktree(repo, "")
	assert.NoError(t, err)
}

func TestValidateWorktreeDetachedHead(t *testing.T) {
	_, repo := setupTestRepo(t)

	// get the HEAD commit hash
	head, err := repo.Head()
	require.NoError(t, err)

	// detach HEAD by checking out the commit hash directly
	wt, err := repo.Worktree()
	require.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{Hash: head.Hash()})
	require.NoError(t, err)

	// detached HEAD at the same commit as "master" should pass
	err = validateWorktree(repo, "master")
	assert.NoError(t, err)

	// detached HEAD should still fail for a non-existent branch
	err = validateWorktree(repo, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected branch")
}

func TestValidateWorktreeDetachedHeadRemoteRef(t *testing.T) {
	// simulate CI: clone a repo, checkout by SHA (detached HEAD with only remote refs)
	upstreamDir, upstreamRepo := setupTestRepo(t)
	_ = upstreamDir

	// get the commit hash from upstream
	upstreamHead, err := upstreamRepo.Head()
	require.NoError(t, err)

	// clone into a new directory
	cloneDir := t.TempDir()
	clonedRepo, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL: upstreamDir,
	})
	require.NoError(t, err)

	// detach HEAD by checking out the SHA directly (like CI does)
	wt, err := clonedRepo.Worktree()
	require.NoError(t, err)
	err = wt.Checkout(&git.CheckoutOptions{Hash: upstreamHead.Hash()})
	require.NoError(t, err)

	// delete local branch to simulate CI (only remote refs remain)
	err = clonedRepo.Storer.RemoveReference(plumbing.NewBranchReferenceName("master"))
	require.NoError(t, err)

	// should pass by finding origin/master remote ref
	err = validateWorktree(clonedRepo, "master")
	assert.NoError(t, err)
}

func TestCheckImmutabilityTagExists(t *testing.T) {
	dir, repo := setupTestRepo(t)

	opts := &CutOptions{RepoPath: dir, Remote: "origin"}

	// v1.0.0 tag already exists locally
	err := checkImmutability(repo, opts, "v1.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists locally")
}

func TestCheckImmutabilityTagDoesNotExist(t *testing.T) {
	dir, repo := setupTestRepo(t)

	opts := &CutOptions{RepoPath: dir, Remote: "origin"}

	// v2.0.0 doesn't exist, but remote listing will fail (no remote configured)
	// immutability check should still pass for local check
	err := checkImmutability(repo, opts, "v2.0.0")
	assert.NoError(t, err)
}

func TestLoadPlanFromFileJSON(t *testing.T) {
	dir := t.TempDir()

	plan := &ReleasePlan{
		GeneratedAt:    time.Now(),
		Repository:     "test/repo",
		CurrentVersion: "v1.0.0",
		NextVersion:    "v1.1.0",
		BumpType:       "minor",
		ReleaseNeeded:  true,
	}

	data, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)

	planPath := filepath.Join(dir, "plan.json")
	err = os.WriteFile(planPath, data, 0644)
	require.NoError(t, err)

	loaded, err := loadPlanFromFile(planPath)
	require.NoError(t, err)

	assert.Equal(t, "v1.0.0", loaded.CurrentVersion)
	assert.Equal(t, "v1.1.0", loaded.NextVersion)
	assert.Equal(t, "minor", loaded.BumpType)
	assert.True(t, loaded.ReleaseNeeded)
}

func TestLoadPlanFromFileYAML(t *testing.T) {
	dir := t.TempDir()

	plan := &ReleasePlan{
		Repository:     "test/repo",
		CurrentVersion: "v2.0.0",
		NextVersion:    "v3.0.0",
		BumpType:       "major",
		ReleaseNeeded:  true,
	}

	data, err := yaml.Marshal(plan)
	require.NoError(t, err)

	planPath := filepath.Join(dir, "plan.yaml")
	err = os.WriteFile(planPath, data, 0644)
	require.NoError(t, err)

	loaded, err := loadPlanFromFile(planPath)
	require.NoError(t, err)

	assert.Equal(t, "v2.0.0", loaded.CurrentVersion)
	assert.Equal(t, "v3.0.0", loaded.NextVersion)
	assert.True(t, loaded.ReleaseNeeded)
}

func TestLoadPlanFromFileNotFound(t *testing.T) {
	_, err := loadPlanFromFile("/nonexistent/plan.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read plan file")
}

func TestLoadPlanFromFileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "bad.json")
	err := os.WriteFile(planPath, []byte("not json"), 0644)
	require.NoError(t, err)

	_, err = loadPlanFromFile(planPath)
	assert.Error(t, err)
}

func TestBuildCommitMessage(t *testing.T) {
	plan := &ReleasePlan{
		NextVersion: "v1.2.0",
		FileMutations: []FileMutation{
			{Path: "package.json", Type: "jsonPath", OldValue: "1.1.0", NewValue: "1.2.0"},
			{Path: "Chart.yaml", Type: "yamlPath", OldValue: "1.1.0", NewValue: "1.2.0"},
		},
	}

	msg := buildCommitMessage(plan)
	assert.Contains(t, msg, "chore(release): v1.2.0")
	assert.Contains(t, msg, "Release v1.2.0")
	assert.Contains(t, msg, "package.json: 1.1.0 → 1.2.0")
	assert.Contains(t, msg, "Chart.yaml: 1.1.0 → 1.2.0")
}

func TestBuildCommitMessageNoMutations(t *testing.T) {
	plan := &ReleasePlan{NextVersion: "v1.0.1"}

	msg := buildCommitMessage(plan)
	assert.Contains(t, msg, "chore(release): v1.0.1")
	assert.NotContains(t, msg, "Files modified")
	assert.Contains(t, msg, "[skip ci]")
}

func TestBuildCommitMessageSkipsErrors(t *testing.T) {
	plan := &ReleasePlan{
		NextVersion: "v2.0.0",
		FileMutations: []FileMutation{
			{Path: "ok.json", Type: "jsonPath", OldValue: "1.0.0", NewValue: "2.0.0"},
			{Path: "bad.toml", Type: "error", OldValue: "", NewValue: "file not found"},
		},
	}

	msg := buildCommitMessage(plan)
	assert.Contains(t, msg, "ok.json")
	assert.NotContains(t, msg, "bad.toml")
}

func TestExecuteCutNoReleaseNeeded(t *testing.T) {
	dir, _ := setupTestRepo(t)

	// no commits since v1.0.0 tag, so no release needed
	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
	}

	result, err := ExecuteCut(opts)
	assert.NoError(t, err)
	assert.True(t, result.NoRelease)
	assert.NotEmpty(t, result.Reason)
}

func TestExecuteCutDryRun(t *testing.T) {
	dir, repo := setupTestRepo(t)

	// add a releasable commit
	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add new feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
		DryRun:   true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)

	assert.True(t, result.DryRun)
	assert.Equal(t, "v1.1.0", result.TagName)
	assert.True(t, result.Draft)
	// dry run should not create tag
	_, tagErr := repo.Tag("v1.1.0")
	assert.Error(t, tagErr, "tag should not exist after dry-run")
}

func TestExecuteCutImmutabilityBlocksExistingTag(t *testing.T) {
	dir, repo := setupTestRepo(t)

	// pre-create v2.0.0 tag, then use a plan file that targets v2.0.0
	initialRef, err := repo.Tag("v1.0.0")
	require.NoError(t, err)
	_, err = repo.CreateTag("v2.0.0", initialRef.Hash(), nil)
	require.NoError(t, err)

	// write plan file targeting the conflicting tag
	tmpDir := t.TempDir()
	plan := &ReleasePlan{
		NextVersion:   "v2.0.0",
		ReleaseNeeded: true,
	}
	planData, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)

	planPath := filepath.Join(tmpDir, "plan.json")
	err = os.WriteFile(planPath, planData, 0644)
	require.NoError(t, err)

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
		PlanFile: planPath,
	}

	_, err = ExecuteCut(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "immutability check failed")
	assert.Contains(t, err.Error(), "already exists locally")
}

func TestExecuteCutDirtyWorktree(t *testing.T) {
	dir, _ := setupTestRepo(t)

	// make worktree dirty
	writeFile(t, dir, "dirty.txt", "uncommitted file")

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
	}

	_, err := ExecuteCut(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "worktree validation failed")
}

func TestExecuteCutFullFlowViaAPI(t *testing.T) {
	dir, repo := setupTestRepo(t)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// add remote so parseOwnerRepo works
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	commitSHA := "abc123def456789012345678901234567890abcd"
	tagSHA := "def456789012345678901234567890abcdef1234"

	mock := &mockReleaseService{
		createTreeResult:   &gogithub.Tree{SHA: gogithub.Ptr("tree-sha-123")},
		createCommitResult: &gogithub.Commit{SHA: gogithub.Ptr(commitSHA)},
		createTagResult:    &gogithub.Tag{SHA: gogithub.Ptr(tagSHA)},
		createRefResult:    &gogithub.Reference{},
		updateRefResult:    &gogithub.Reference{},
		createRelease: &gogithub.RepositoryRelease{
			ID:      gogithub.Ptr(int64(42)),
			HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		},
		getReleaseErr: fmt.Errorf("not found"),
	}

	opts := &CutOptions{
		RepoPath:     dir,
		Branch:       "master",
		Remote:       "origin",
		CommitAuthor: "testbot",
		CommitEmail:  "testbot@test.com",
		Token:        "test-token",
		ReleaseAPI:   mock,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)

	assert.Equal(t, "v1.1.0", result.TagName)
	assert.Equal(t, "1.1.0", result.Version)
	assert.Equal(t, commitSHA, result.CommitSHA)
	assert.True(t, result.Draft)
	assert.Equal(t, int64(42), result.ReleaseID)
	assert.Equal(t, "https://github.com/test/repo/releases/tag/v1.1.0", result.ReleaseURL)
}

// When the branch-ref update fails after the tag was created, the just-created tag must
// be rolled back so a retry is not blocked by the immutability check.
func TestExecuteCutBranchRefFailureRollsBackTag(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.updateRefErr = fmt.Errorf("422 Update is not a fast forward")

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
	}

	_, err := ExecuteCut(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update branch ref")
	assert.Equal(t, []string{"refs/tags/v1.1.0"}, mock.deletedRefs, "orphan tag must be rolled back")
	assert.Contains(t, err.Error(), "rolled back tag v1.1.0")
}

// If the branch-ref update fails AND the tag rollback also fails, the error must name the
// orphan tag and the manual recovery step explicitly.
func TestExecuteCutBranchRefFailureRollbackFailsSurfacesRecovery(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.updateRefErr = fmt.Errorf("422 Update is not a fast forward")
	mock.deleteRefErr = fmt.Errorf("403 forbidden")

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
	}

	_, err := ExecuteCut(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update branch ref")
	assert.Contains(t, err.Error(), "delete refs/tags/v1.1.0 before retrying",
		"must name the orphan tag and the manual recovery step")
}

func TestExecuteCutRequiresTokenForNonDryRun(t *testing.T) {
	dir, repo := setupTestRepo(t)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}

	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	// no token, no ReleaseAPI — should fail
	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
	}

	_, err = ExecuteCut(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub token is required")
}

func TestExecuteCutWithPlanFile(t *testing.T) {
	dir, _ := setupTestRepo(t)

	// write plan file OUTSIDE the repo to keep worktree clean
	tmpDir := t.TempDir()
	plan := &ReleasePlan{
		CurrentVersion:   "v1.0.0",
		NextVersion:      "v2.0.0",
		BumpType:         "major",
		ReleaseNeeded:    true,
		ChangelogPreview: "## v2.0.0\n\n### Features\n- add feature",
	}
	planData, err := json.MarshalIndent(plan, "", "  ")
	require.NoError(t, err)

	planPath := filepath.Join(tmpDir, "plan.json")
	err = os.WriteFile(planPath, planData, 0644)
	require.NoError(t, err)

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
		PlanFile: planPath,
		DryRun:   true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)

	// should use version from plan file, not auto-computed
	assert.Equal(t, "v2.0.0", result.TagName)
}

func TestCheckImmutabilityPublishedRelease(t *testing.T) {
	dir, repo := setupTestRepo(t)

	// mock: published (non-draft) release exists
	mock := &mockReleaseService{
		getRelease: &gogithub.RepositoryRelease{
			ID:    gogithub.Ptr(int64(99)),
			Draft: gogithub.Ptr(false),
		},
	}

	// need a remote so GetRepositoryName can parse owner/repo
	_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	opts := &CutOptions{RepoPath: dir, Remote: "origin", ReleaseAPI: mock}

	err = checkImmutability(repo, opts, "v2.0.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "published release already exists")
}

func TestCheckImmutabilityDraftReleaseAllowed(t *testing.T) {
	dir, repo := setupTestRepo(t)

	// mock: draft release exists (should be allowed)
	mock := &mockReleaseService{
		getRelease: &gogithub.RepositoryRelease{
			ID:    gogithub.Ptr(int64(50)),
			Draft: gogithub.Ptr(true),
		},
	}

	_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	opts := &CutOptions{RepoPath: dir, Remote: "origin", ReleaseAPI: mock}

	// v2.0.0 doesn't exist locally, draft release is allowed
	err = checkImmutability(repo, opts, "v2.0.0")
	assert.NoError(t, err)
}

func TestCreateDraftRelease(t *testing.T) {
	dir, repo := setupTestRepo(t)

	_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	mock := &mockReleaseService{
		createRelease: &gogithub.RepositoryRelease{
			ID:      gogithub.Ptr(int64(42)),
			HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		},
	}

	opts := &CutOptions{RepoPath: dir, Remote: "origin", ReleaseAPI: mock}
	plan := &ReleasePlan{NextVersion: "v1.1.0", ChangelogPreview: "## v1.1.0\n- feature"}

	url, id, err := createDraftRelease(repo, opts, plan)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/test/repo/releases/tag/v1.1.0", url)
	assert.Equal(t, int64(42), id)
}

func TestCreateDraftReleaseError(t *testing.T) {
	dir, repo := setupTestRepo(t)

	_, err := repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	mock := &mockReleaseService{
		createErr: fmt.Errorf("API rate limit exceeded"),
	}

	opts := &CutOptions{RepoPath: dir, Remote: "origin", ReleaseAPI: mock}
	plan := &ReleasePlan{NextVersion: "v1.1.0"}

	_, _, err = createDraftRelease(repo, opts, plan)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create GitHub release")
}

func TestCutResultToJSON(t *testing.T) {
	result := &CutResult{
		TagName:       "v1.2.0",
		Version:       "1.2.0",
		CommitSHA:     "abc123def456",
		ReleaseURL:    "https://github.com/test/repo/releases/tag/v1.2.0",
		ReleaseID:     42,
		Draft:         true,
		FilesModified: []string{"package.json", "Chart.yaml"},
	}

	data, err := result.ToJSON()
	require.NoError(t, err)

	var parsed CutResult
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "v1.2.0", parsed.TagName)
	assert.Equal(t, int64(42), parsed.ReleaseID)
	assert.True(t, parsed.Draft)
	assert.Len(t, parsed.FilesModified, 2)
}

// TestExecuteCutWithPublish verifies that --publish creates a non-draft release directly.
func TestExecuteCutWithPublish(t *testing.T) {
	dir, repo := setupTestRepo(t)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	commitSHA := "abc123def456789012345678901234567890abcd"
	tagSHA := "def456789012345678901234567890abcdef1234"

	mock := &mockReleaseService{
		createTreeResult:   &gogithub.Tree{SHA: gogithub.Ptr("tree-sha-123")},
		createCommitResult: &gogithub.Commit{SHA: gogithub.Ptr(commitSHA)},
		createTagResult:    &gogithub.Tag{SHA: gogithub.Ptr(tagSHA)},
		createRefResult:    &gogithub.Reference{},
		updateRefResult:    &gogithub.Reference{},
		createRelease: &gogithub.RepositoryRelease{
			ID:      gogithub.Ptr(int64(99)),
			Draft:   gogithub.Ptr(false),
			HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		},
		getReleaseErr: fmt.Errorf("not found"),
	}

	opts := &CutOptions{
		RepoPath:     dir,
		Branch:       "master",
		Remote:       "origin",
		CommitAuthor: "testbot",
		CommitEmail:  "testbot@test.com",
		Token:        "test-token",
		ReleaseAPI:   mock,
		Publish:      true, // directly published, no draft
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)

	assert.Equal(t, "v1.1.0", result.TagName)
	assert.False(t, result.Draft, "release should not be a draft when --publish is set")
	assert.True(t, result.Published, "result.Published should be true when --publish is set")
}

// TestExecuteCutTagPlacement verifies the tag points to the HEAD (trigger) commit,
// not the release commit — per SLSA v1.2 cert-identity requirements.
func TestExecuteCutTagPlacement(t *testing.T) {
	dir, repo := setupTestRepo(t)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)

	// capture HEAD SHA before cut — the tag must point here, not the release commit
	head, err := repo.Head()
	require.NoError(t, err)
	expectedTagObjectSHA := head.Hash().String()

	releaseCommitSHA := "release00def456789012345678901234567890ab"
	tagSHA := "tag0000def456789012345678901234567890abcd"

	mock := &mockReleaseService{
		createTreeResult:   &gogithub.Tree{SHA: gogithub.Ptr("tree-sha")},
		createCommitResult: &gogithub.Commit{SHA: gogithub.Ptr(releaseCommitSHA)},
		createTagResult:    &gogithub.Tag{SHA: gogithub.Ptr(tagSHA)},
		createRefResult:    &gogithub.Reference{},
		updateRefResult:    &gogithub.Reference{},
		createRelease: &gogithub.RepositoryRelease{
			ID:      gogithub.Ptr(int64(77)),
			HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		},
		getReleaseErr: fmt.Errorf("not found"),
	}

	opts := &CutOptions{
		RepoPath:     dir,
		Branch:       "master",
		Remote:       "origin",
		CommitAuthor: "testbot",
		CommitEmail:  "testbot@test.com",
		Token:        "test-token",
		ReleaseAPI:   mock,
	}

	_, err = ExecuteCut(opts)
	require.NoError(t, err)

	// the tag's Object SHA must be the trigger (HEAD before mutations), not the release commit
	assert.Equal(t, expectedTagObjectSHA, mock.lastCreateTagArg.Object,
		"tag must point to trigger commit (HEAD before release commit), not the release commit")
	assert.NotEqual(t, releaseCommitSHA, mock.lastCreateTagArg.Object,
		"tag must NOT point to the release commit")
}

func TestDefaultCutOptions(t *testing.T) {
	opts := DefaultCutOptions()

	assert.Equal(t, ".", opts.RepoPath)
	assert.Equal(t, "main", opts.Branch)
	assert.Equal(t, "origin", opts.Remote)
	assert.Equal(t, "autogov[bot]", opts.CommitAuthor)
	assert.False(t, opts.DryRun)
}

func TestValidateMode(t *testing.T) {
	assert.NoError(t, ValidateMode(ModeAuto))
	assert.NoError(t, ValidateMode(ModeAPI))
	assert.NoError(t, ValidateMode(ModeLocal))
	assert.NoError(t, ValidateMode("")) // empty defaults to auto behavior

	err := ValidateMode("garbage")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --mode")
}

func TestExecuteCutInvalidMode(t *testing.T) {
	dir, _ := setupTestRepo(t)

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
		Mode:     "invalid",
	}

	_, err := ExecuteCut(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --mode")
}

func TestExecuteCutAPIModeRequiresToken(t *testing.T) {
	dir, _ := setupTestRepo(t)

	opts := &CutOptions{
		RepoPath: dir,
		Branch:   "master",
		Remote:   "origin",
		Mode:     ModeAPI,
	}

	_, err := ExecuteCut(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--mode=api requires a GitHub token")
}

func TestValidateAssets(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "asset.txt")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))

	t.Run("nil list is ok", func(t *testing.T) {
		require.NoError(t, validateAssets(nil, nil))
	})
	t.Run("existing file is ok", func(t *testing.T) {
		require.NoError(t, validateAssets([]string{existing}, nil))
	})
	t.Run("missing file errors", func(t *testing.T) {
		err := validateAssets([]string{filepath.Join(dir, "nope.txt")}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "asset not found")
	})
	t.Run("non-regular file (directory) errors", func(t *testing.T) {
		err := validateAssets([]string{dir}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})
	t.Run("empty file errors", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.bin")
		require.NoError(t, os.WriteFile(empty, nil, 0o600))
		err := validateAssets([]string{empty}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})
	t.Run("label matching an asset name is ok", func(t *testing.T) {
		require.NoError(t, validateAssets([]string{existing}, map[string]string{"asset.txt": "My Asset"}))
	})
	t.Run("duplicate base names error", func(t *testing.T) {
		sub := filepath.Join(dir, "sub")
		require.NoError(t, os.Mkdir(sub, 0o750))
		dup := filepath.Join(sub, "asset.txt")
		require.NoError(t, os.WriteFile(dup, []byte("y"), 0o600))
		err := validateAssets([]string{existing, dup}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "same name")
	})
	t.Run("label not matching any asset errors", func(t *testing.T) {
		err := validateAssets([]string{existing}, map[string]string{"nope": "x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match any")
	})
}

func TestUploadAssets(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "bin")
	vsaPath := filepath.Join(dir, "vsa.json")
	require.NoError(t, os.WriteFile(binPath, []byte("a"), 0o600))
	require.NoError(t, os.WriteFile(vsaPath, []byte("b"), 0o600))

	t.Run("uploads each asset, mapping labels by base name", func(t *testing.T) {
		mock := &mockReleaseService{}
		labels := map[string]string{"bin": "Linux x86_64"}
		uploaded, err := uploadAssets(context.Background(), mock, "o", "r", 42, []string{binPath, vsaPath}, labels)
		require.NoError(t, err)
		assert.Equal(t, []string{"bin", "vsa.json"}, uploaded)
		assert.Equal(t, []string{"bin", "vsa.json"}, mock.uploadedAssetNames)
		assert.Equal(t, []string{"Linux x86_64", ""}, mock.uploadedAssetLabels)
	})
	t.Run("propagates upload error with asset name", func(t *testing.T) {
		mock := &mockReleaseService{uploadAssetErr: fmt.Errorf("boom")}
		uploaded, err := uploadAssets(context.Background(), mock, "o", "r", 42, []string{binPath}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to upload asset bin")
		assert.Empty(t, uploaded)
	})
	t.Run("errors when a file cannot be opened", func(t *testing.T) {
		mock := &mockReleaseService{}
		_, err := uploadAssets(context.Background(), mock, "o", "r", 42, []string{filepath.Join(dir, "missing")}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open asset")
	})
}

// setupCutScenario builds a repo with a release-worthy commit + remote and a mock
// wired for a full API cut, for ExecuteCut-level asset tests.
func setupCutScenario(t *testing.T) (string, *mockReleaseService) {
	t.Helper()
	dir, repo := setupTestRepo(t)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	writeFile(t, dir, "feature.txt", "new feature")
	_, err = wt.Add("feature.txt")
	require.NoError(t, err)
	_, err = wt.Commit("feat: add feature", &git.CommitOptions{Author: sig})
	require.NoError(t, err)
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	require.NoError(t, err)
	mock := &mockReleaseService{
		createTreeResult:   &gogithub.Tree{SHA: gogithub.Ptr("tree-sha-123")},
		createCommitResult: &gogithub.Commit{SHA: gogithub.Ptr("abc123def456789012345678901234567890abcd")},
		createTagResult:    &gogithub.Tag{SHA: gogithub.Ptr("def456789012345678901234567890abcdef1234")},
		createRefResult:    &gogithub.Reference{},
		updateRefResult:    &gogithub.Reference{},
		createRelease: &gogithub.RepositoryRelease{
			ID:      gogithub.Ptr(int64(99)),
			HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		},
		getReleaseErr: fmt.Errorf("not found"),
	}
	return dir, mock
}

func TestExecuteCutUploadsAssets(t *testing.T) {
	dir, mock := setupCutScenario(t)
	a := filepath.Join(t.TempDir(), "autogov")
	b := filepath.Join(t.TempDir(), "vsa.json")
	require.NoError(t, os.WriteFile(a, []byte("bin"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("{}"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets:      []string{a, b},
		AssetLabels: map[string]string{"autogov": "Linux x86_64"},
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.Equal(t, []string{"autogov", "vsa.json"}, result.UploadedAssets)
	assert.Equal(t, []string{"autogov", "vsa.json"}, mock.uploadedAssetNames, "uploads use base names")
	assert.Equal(t, []string{"Linux x86_64", ""}, mock.uploadedAssetLabels, "label mapped by base name")
}

// A failed upload with --publish must leave the release as an unpublished draft and
// return the partial result (release URL/ID + assets uploaded so far) for recovery.
func TestExecuteCutPartialUploadFailureReturnsDraftResult(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.uploadAssetErr = fmt.Errorf("network blip")
	mock.uploadAssetFailAfter = 1 // first asset uploads, second fails
	a := filepath.Join(t.TempDir(), "first")
	b := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(a, []byte("1"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("2"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets:  []string{a, b},
		Publish: true,
	}

	result, err := ExecuteCut(opts)
	require.Error(t, err)
	require.NotNil(t, result, "partial result must be returned, not nil")
	assert.Equal(t, int64(99), result.ReleaseID)
	assert.NotEmpty(t, result.ReleaseURL)
	assert.Equal(t, []string{"first"}, result.UploadedAssets, "reports the asset that did upload")
	assert.True(t, result.Draft, "a failed upload must leave the release as a draft")
	assert.False(t, result.Published, "must not publish when an asset failed to upload")
}

func TestExecuteCutDryRunSkipsUpload(t *testing.T) {
	dir, mock := setupCutScenario(t)
	a := filepath.Join(t.TempDir(), "autogov")
	require.NoError(t, os.WriteFile(a, []byte("bin"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets: []string{a},
		DryRun: true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	assert.Empty(t, mock.uploadedAssetNames, "dry-run must not upload assets")
	assert.Empty(t, result.UploadedAssets)
}

// A cut interrupted after the draft release was created (some assets uploaded) must
// resume: reuse the existing draft, upload only the missing assets, and publish if
// requested — without recreating the commit or tag.
func TestExecuteCutResumeUploadsMissingAssets(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.listReleases = []*gogithub.RepositoryRelease{{
		ID:      gogithub.Ptr(int64(777)),
		TagName: gogithub.Ptr("v1.1.0"),
		HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		Draft:   gogithub.Ptr(true),
		Assets:  []*gogithub.ReleaseAsset{{Name: gogithub.Ptr("first"), State: gogithub.Ptr("uploaded")}},
	}}

	a := filepath.Join(t.TempDir(), "first")
	b := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(a, []byte("1"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("2"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets:  []string{a, b},
		Publish: true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.Equal(t, int64(777), result.ReleaseID, "reuses the existing draft release")
	assert.Equal(t, []string{"second"}, mock.uploadedAssetNames, "uploads only the missing asset")
	assert.Equal(t, []string{"second"}, result.UploadedAssets)
	assert.True(t, result.Published, "publishes once assets are complete")
	assert.False(t, result.Draft)
	assert.Empty(t, mock.lastCreateTagArg.Tag, "resume must not recreate the tag")
	assert.Empty(t, mock.deletedRefs, "resume must not roll back any ref")
}

// Resuming when every requested asset is already attached uploads nothing and just flips
// the draft to published — covers both resume-after-publish-failure and an idempotent
// re-run of a completed-but-unpublished cut.
func TestExecuteCutResumePublishesWhenAllAssetsPresent(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.listReleases = []*gogithub.RepositoryRelease{{
		ID:      gogithub.Ptr(int64(777)),
		TagName: gogithub.Ptr("v1.1.0"),
		HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		Draft:   gogithub.Ptr(true),
		Assets: []*gogithub.ReleaseAsset{
			{Name: gogithub.Ptr("first"), State: gogithub.Ptr("uploaded")},
			{Name: gogithub.Ptr("second"), State: gogithub.Ptr("uploaded")},
		},
	}}

	a := filepath.Join(t.TempDir(), "first")
	b := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(a, []byte("1"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("2"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets:  []string{a, b},
		Publish: true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.Empty(t, mock.uploadedAssetNames, "no re-upload when all assets are already present")
	assert.Empty(t, result.UploadedAssets)
	assert.True(t, result.Published)
}

// An asset left in a non-"uploaded" state by an interrupted upload must be re-uploaded on
// resume, not skipped — otherwise resume would publish a release with a half-written asset.
func TestExecuteCutResumeReuploadsIncompleteAsset(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.listReleases = []*gogithub.RepositoryRelease{{
		ID:      gogithub.Ptr(int64(777)),
		TagName: gogithub.Ptr("v1.1.0"),
		HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		Draft:   gogithub.Ptr(true),
		Assets:  []*gogithub.ReleaseAsset{{Name: gogithub.Ptr("first"), State: gogithub.Ptr("open")}},
	}}

	a := filepath.Join(t.TempDir(), "first")
	require.NoError(t, os.WriteFile(a, []byte("1"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets: []string{a},
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.Equal(t, []string{"first"}, mock.uploadedAssetNames, "a non-uploaded asset must be re-uploaded, not skipped")
	assert.Equal(t, []string{"first"}, result.UploadedAssets)
}

// A published (non-draft) release for the computed tag is immutable: the cut must fail
// fast and must not resume or recreate a tag.
func TestExecuteCutResumeRejectsPublishedRelease(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.getReleaseErr = nil
	published := &gogithub.RepositoryRelease{
		ID:      gogithub.Ptr(int64(99)),
		TagName: gogithub.Ptr("v1.1.0"),
		Draft:   gogithub.Ptr(false),
	}
	mock.getRelease = published                                  // checkImmutability path
	mock.listReleases = []*gogithub.RepositoryRelease{published} // detectResume must NOT resume a published release

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
	}

	_, err := ExecuteCut(opts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "published release already exists")
	assert.Empty(t, mock.lastCreateTagArg.Tag, "must not create a tag for a published release")
}

// Dry-run on a resumable state reports the draft it would resume and performs no writes.
func TestExecuteCutResumeDryRunMakesNoWrites(t *testing.T) {
	dir, mock := setupCutScenario(t)
	mock.listReleases = []*gogithub.RepositoryRelease{{
		ID:      gogithub.Ptr(int64(777)),
		TagName: gogithub.Ptr("v1.1.0"),
		HTMLURL: gogithub.Ptr("https://github.com/test/repo/releases/tag/v1.1.0"),
		Draft:   gogithub.Ptr(true),
	}}

	a := filepath.Join(t.TempDir(), "first")
	require.NoError(t, os.WriteFile(a, []byte("1"), 0o600))

	opts := &CutOptions{
		RepoPath: dir, Branch: "master", Remote: "origin",
		CommitAuthor: "testbot", CommitEmail: "testbot@test.com",
		Token: "test-token", ReleaseAPI: mock,
		Assets:  []string{a},
		Publish: true,
		DryRun:  true,
	}

	result, err := ExecuteCut(opts)
	require.NoError(t, err)
	assert.True(t, result.DryRun)
	assert.Equal(t, int64(777), result.ReleaseID, "reports the draft it would resume")
	assert.Empty(t, mock.uploadedAssetNames, "dry-run resume must not upload")
	assert.False(t, result.Published, "dry-run must not publish")
}
