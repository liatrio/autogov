package predicate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	gh "github.com/google/go-github/v88/github"
	"github.com/liatrio/autogov/pkg/attestations"
)

// --- test fixtures -----------------------------------------------------------

const (
	srSourceSHA = "mergesha0000000000000000000000000000abcd" // source revision (merge commit)
	srHeadSHA   = "headsha00000000000000000000000000000face" // PR branch head
	srOldSHA    = "oldsha000000000000000000000000000000beef" // a superseded commit
	srAuthorID  = int64(1)
)

var srBaseTime = time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)

// mockReviewService implements ReviewService for unit tests.
type mockReviewService struct {
	prs        []*gh.PullRequest
	prsErr     error
	reviews    []*gh.PullRequestReview
	reviewsErr error
	protection *gh.Protection
	protErr    error
	rules      *gh.BranchRules
	rulesErr   error
}

func srResp() *gh.Response {
	return &gh.Response{Response: &http.Response{StatusCode: 200, Body: http.NoBody}}
}

func (m *mockReviewService) ListPullRequestsWithCommit(_ context.Context, _, _, _ string, _ *gh.ListOptions) ([]*gh.PullRequest, *gh.Response, error) {
	return m.prs, srResp(), m.prsErr
}

func (m *mockReviewService) ListReviews(_ context.Context, _, _ string, _ int, _ *gh.ListOptions) ([]*gh.PullRequestReview, *gh.Response, error) {
	return m.reviews, srResp(), m.reviewsErr
}

func (m *mockReviewService) GetBranchProtection(_ context.Context, _, _, _ string) (*gh.Protection, *gh.Response, error) {
	return m.protection, srResp(), m.protErr
}

func (m *mockReviewService) ListRulesForBranch(_ context.Context, _, _, _ string, _ *gh.ListOptions) (*gh.BranchRules, *gh.Response, error) {
	return m.rules, srResp(), m.rulesErr
}

func srUser(login string, id int64, typ string) *gh.User {
	return &gh.User{Login: gh.Ptr(login), ID: gh.Ptr(id), Type: gh.Ptr(typ)}
}

func srReview(u *gh.User, state, commitID string, at time.Time) *gh.PullRequestReview {
	return &gh.PullRequestReview{
		ID:                gh.Ptr(at.UnixNano()),
		User:              u,
		State:             gh.Ptr(state),
		SubmittedAt:       &gh.Timestamp{Time: at},
		CommitID:          gh.Ptr(commitID),
		AuthorAssociation: gh.Ptr("MEMBER"),
	}
}

// srMergedPR builds the merged PR whose merge produced srSourceSHA.
func srMergedPR() *gh.PullRequest {
	return &gh.PullRequest{
		Number:         gh.Ptr(7),
		User:           srUser("author", srAuthorID, "User"),
		Head:           &gh.PullRequestBranch{SHA: gh.Ptr(srHeadSHA)},
		Base:           &gh.PullRequestBranch{Ref: gh.Ptr("main")},
		MergeCommitSHA: gh.Ptr(srSourceSHA),
		MergedAt:       &gh.Timestamp{Time: srBaseTime.Add(time.Hour)},
		HTMLURL:        gh.Ptr("https://github.com/liatrio/autogov/pull/7"),
		Title:          gh.Ptr("a change"),
	}
}

func srOpts() SourceReviewOptions {
	return SourceReviewOptions{
		Owner:            "liatrio",
		Repo:             "autogov",
		CommitSHA:        srSourceSHA,
		Ref:              "refs/heads/main",
		IncludeApprovers: true,
		Type:             ArtifactTypeContainerImage,
		SubjectName:      "ghcr.io/liatrio/autogov",
		Digest:           "sha256:deadbeef",
	}
}

func srBuild(t *testing.T, m *mockReviewService, opts SourceReviewOptions) *SourceReview {
	t.Helper()
	c, err := NewSourceReview(context.Background(), m, opts)
	if err != nil {
		t.Fatalf("NewSourceReview: %v", err)
	}
	return c
}

func srValidate(t *testing.T, c *SourceReview) {
	t.Helper()
	out, err := c.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := ValidateSourceReview(out); err != nil {
		t.Errorf("ValidateSourceReview: %v", err)
	}
}

// --- tests -------------------------------------------------------------------

func TestNewSourceReview_HappyPath(t *testing.T) {
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("bob", 3, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if !c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = false, want true")
	}
	if c.Summary.DistinctApprovers != 2 || c.Summary.Approvals != 2 {
		t.Errorf("approvals=%d distinct=%d, want 2/2", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
	if c.Summary.ChangesRequested != 0 {
		t.Errorf("changesRequested = %d, want 0", c.Summary.ChangesRequested)
	}
	if !c.ApproversIncluded || len(c.Approvers) != 2 {
		t.Errorf("approversIncluded=%v approvers=%d, want true/2", c.ApproversIncluded, len(c.Approvers))
	}
	if c.PullRequest == nil || c.PullRequest.Number != 7 || c.PullRequest.MergeCommitSha != srSourceSHA {
		t.Errorf("pullRequest = %+v, want number 7 / merge %s", c.PullRequest, srSourceSHA)
	}
	if c.SourceRevision != srSourceSHA || c.Ref != "main" {
		t.Errorf("sourceRevision=%q ref=%q", c.SourceRevision, c.Ref)
	}
	srValidate(t, c)
}

func TestNewSourceReview_SelfApprovalExcluded(t *testing.T) {
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			// author self-approves (excluded) + one real approver.
			srReview(srUser("author", srAuthorID, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if !c.Summary.SelfApprovalExcluded {
		t.Error("selfApprovalExcluded = false, want true")
	}
	if c.Summary.DistinctApprovers != 1 || c.Summary.Approvals != 1 {
		t.Errorf("approvals=%d distinct=%d, want 1/1 (author excluded)", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
	for _, a := range c.Approvers {
		if a.Login == "author" {
			t.Error("author must not appear in approvers[]")
		}
	}
}

func TestNewSourceReview_LatestStatePerUserID_ChangesRequestedSurfaced(t *testing.T) {
	// alice APPROVES then later REQUESTS CHANGES -> latest state wins.
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("alice", 2, "User"), reviewStateChangesRequested, srHeadSHA, srBaseTime.Add(5*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.ChangesRequested != 1 {
		t.Errorf("changesRequested = %d, want 1 (latest state)", c.Summary.ChangesRequested)
	}
	if c.Summary.DistinctApprovers != 0 || c.Summary.Approvals != 0 {
		t.Errorf("approvals=%d distinct=%d, want 0/0 (alice's latest is changes-requested)", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
}

func TestNewSourceReview_ChangesRequestedClearedByDismiss(t *testing.T) {
	// bob requests changes, then it is dismissed -> no longer blocking.
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("bob", 3, "User"), reviewStateChangesRequested, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("bob", 3, "User"), reviewStateDismissed, srHeadSHA, srBaseTime.Add(4*time.Minute)),
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.ChangesRequested != 0 {
		t.Errorf("changesRequested = %d, want 0 (dismissed clears it)", c.Summary.ChangesRequested)
	}
	if c.Summary.DistinctApprovers != 1 {
		t.Errorf("distinct = %d, want 1 (alice)", c.Summary.DistinctApprovers)
	}
}

func TestNewSourceReview_DismissedNoResurrect(t *testing.T) {
	// alice APPROVES then her review is DISMISSED -> must not count.
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("alice", 2, "User"), reviewStateDismissed, srHeadSHA, srBaseTime.Add(3*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.DistinctApprovers != 0 || c.Summary.Approvals != 0 {
		t.Errorf("approvals=%d distinct=%d, want 0/0 (dismissed approval not resurrected)", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
}

func TestNewSourceReview_StaleSquashRebaseGuard(t *testing.T) {
	// dismiss_stale off (no protection). alice approved ON the PR head -> NOT
	// stale even though head != source revision (the squash/rebase guard: we
	// compare commit_id to pr.head.sha, never to the source revision). carol
	// approved on a superseded commit -> stale.
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("carol", 4, "User"), reviewStateApproved, srOldSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.DistinctApprovers != 1 || c.Summary.Approvals != 2 {
		t.Errorf("approvals=%d distinct=%d, want 2/1 (carol stale)", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
	byLogin := map[string]SourceReviewApprover{}
	for _, a := range c.Approvers {
		byLogin[a.Login] = a
	}
	if byLogin["alice"].Stale {
		t.Error("alice (on PR head) must not be stale even though head != source revision")
	}
	if !byLogin["carol"].Stale {
		t.Error("carol (on a superseded commit) must be stale")
	}
}

func TestNewSourceReview_DismissStaleReviewsNotMarkedStale(t *testing.T) {
	// when the branch dismisses stale reviews, GitHub auto-dismisses; we must not
	// independently re-mark an approval stale (avoids double handling).
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srOldSHA, srBaseTime.Add(1*time.Minute)),
		},
		protection: &gh.Protection{RequiredPullRequestReviews: &gh.PullRequestReviewsEnforcement{
			RequiredApprovingReviewCount: 1,
			DismissStaleReviews:          true,
		}},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.DistinctApprovers != 1 {
		t.Errorf("distinct = %d, want 1 (dismiss_stale on -> not re-marked stale)", c.Summary.DistinctApprovers)
	}
	if len(c.Approvers) != 1 || c.Approvers[0].Stale {
		t.Errorf("approver stale=%v, want false", c.Approvers[0].Stale)
	}
}

func TestNewSourceReview_BotExcluded(t *testing.T) {
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("dependabot[bot]", 5, "Bot"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.DistinctApprovers != 1 || c.Summary.Approvals != 2 {
		t.Errorf("approvals=%d distinct=%d, want 2/1 (bot excluded from distinct)", c.Summary.Approvals, c.Summary.DistinctApprovers)
	}
	var sawBot bool
	for _, a := range c.Approvers {
		if a.IsBot {
			sawBot = true
		}
	}
	if !sawBot {
		t.Error("bot approver should be present in approvers[] flagged isBot")
	}
}

func TestNewSourceReview_BotChangesRequestedNotCounted(t *testing.T) {
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("scanner[bot]", 6, "Bot"), reviewStateChangesRequested, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())
	if c.Summary.ChangesRequested != 0 {
		t.Errorf("changesRequested = %d, want 0 (bot changes-request excluded)", c.Summary.ChangesRequested)
	}
}

func TestNewSourceReview_NoMergedPR_Incomplete(t *testing.T) {
	// genuine direct push OR default-branch quirk: zero PRs -> incompleteness.
	c := srBuild(t, &mockReviewService{prs: nil}, srOpts())
	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true, want false (no merged PR)")
	}
	if c.PullRequest != nil {
		t.Errorf("pullRequest = %+v, want nil", c.PullRequest)
	}
	if c.Summary.DistinctApprovers != 0 {
		t.Errorf("distinct = %d, want 0", c.Summary.DistinctApprovers)
	}
	srValidate(t, c)
}

func TestNewSourceReview_OnlyOpenPRs_QuirkIncomplete(t *testing.T) {
	// the ListPullRequestsWithCommit default-branch quirk returns only OPEN PRs
	// for a SHA not on the default branch -> incompleteness, NOT a false hard fail.
	open := &gh.PullRequest{
		Number: gh.Ptr(9),
		User:   srUser("author", srAuthorID, "User"),
		Head:   &gh.PullRequestBranch{SHA: gh.Ptr(srHeadSHA)},
		Base:   &gh.PullRequestBranch{Ref: gh.Ptr("main")},
		// no MergedAt, no matching MergeCommitSHA -> not selected.
	}
	c := srBuild(t, &mockReviewService{prs: []*gh.PullRequest{open}}, srOpts())
	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true, want false (only-open-PRs quirk)")
	}
}

func TestNewSourceReview_ListPRsError_Incomplete(t *testing.T) {
	c := srBuild(t, &mockReviewService{prsErr: errBoom}, srOpts())
	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true, want false (PR list failed)")
	}
}

func TestNewSourceReview_ListReviewsError_Incomplete(t *testing.T) {
	m := &mockReviewService{prs: []*gh.PullRequest{srMergedPR()}, reviewsErr: errBoom}
	c := srBuild(t, m, srOpts())
	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true, want false (reviews unfetchable)")
	}
	if c.PullRequest == nil {
		t.Error("pullRequest should still be populated when reviews fail")
	}
}

func TestNewSourceReview_RequiredCountMaxOfSources(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		protection: &gh.Protection{RequiredPullRequestReviews: &gh.PullRequestReviewsEnforcement{
			RequiredApprovingReviewCount: 2,
		}},
		rules: &gh.BranchRules{PullRequest: []*gh.PullRequestBranchRule{
			{Parameters: gh.PullRequestRuleParameters{RequiredApprovingReviewCount: 3, RequireCodeOwnerReview: true}},
		}},
	}
	c := srBuild(t, m, srOpts())

	if c.Summary.RequiredApprovals != 3 {
		t.Errorf("requiredApprovals = %d, want 3 (max of 2 and 3)", c.Summary.RequiredApprovals)
	}
	if c.BranchProtection == nil || c.BranchProtection.RequiredApprovingReviewCount != 3 {
		t.Errorf("branchProtection = %+v, want required 3", c.BranchProtection)
	}
	if !c.BranchProtection.RequireCodeownerReview {
		t.Error("requireCodeownerReview = false, want true (from ruleset)")
	}
	if c.Summary.RequirementMet {
		t.Error("requirementMet = true, want false (1 approval < required 3)")
	}
}

func TestNewSourceReview_BranchProtectionAbsentStillComplete(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		protErr: errBoom, // e.g. 404 / no admin
	}
	c := srBuild(t, m, srOpts())

	if !c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = false; branch-protection absence is best-effort, not incompleteness")
	}
	if c.Summary.RequiredApprovals != 0 || c.BranchProtection != nil {
		t.Errorf("required=%d bp=%+v, want 0/nil", c.Summary.RequiredApprovals, c.BranchProtection)
	}
	// requirementMet is trivially true when no requirement is known (evidence only).
	if !c.Summary.RequirementMet {
		t.Error("requirementMet should be true when requiredApprovals is 0")
	}
}

func TestNewSourceReview_ApproversExcludedSummaryStillComputed(t *testing.T) {
	opts := srOpts()
	opts.IncludeApprovers = false
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("bob", 3, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, opts)

	if c.ApproversIncluded {
		t.Error("approversIncluded = true, want false")
	}
	if c.Approvers != nil {
		t.Errorf("approvers = %+v, want nil when excluded", c.Approvers)
	}
	if c.Summary.DistinctApprovers != 2 {
		t.Errorf("distinct = %d, want 2 (summary computed even without approvers[])", c.Summary.DistinctApprovers)
	}
	srValidate(t, c)
}

func TestNewSourceReview_CodeownerReviewMetNullInV01(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if c.Summary.CodeownerReviewMet != nil {
		t.Errorf("codeownerReviewMet = %v, want nil (tri-state, REST-only v0.1)", *c.Summary.CodeownerReviewMet)
	}
	// must serialize as JSON null
	out, _ := c.Generate()
	if !strings.Contains(string(out), `"codeownerReviewMet": null`) {
		t.Error("codeownerReviewMet should serialize as null")
	}
}

func TestNewSourceReview_RequiresArgs(t *testing.T) {
	m := &mockReviewService{}
	cases := []SourceReviewOptions{
		{Repo: "autogov", CommitSHA: srSourceSHA},  // missing owner
		{Owner: "liatrio", CommitSHA: srSourceSHA}, // missing repo
		{Owner: "liatrio", Repo: "autogov"},        // missing commit SHA
	}
	for i, opts := range cases {
		if _, err := NewSourceReview(context.Background(), m, opts); err == nil {
			t.Errorf("case %d: expected error for incomplete options", i)
		}
	}
}

func TestNewSourceReview_ApproversDeterministicOrder(t *testing.T) {
	m := &mockReviewService{
		prs: []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{
			srReview(srUser("zoe", 9, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(1*time.Minute)),
			srReview(srUser("amy", 8, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(2*time.Minute)),
		},
	}
	c := srBuild(t, m, srOpts())
	if len(c.Approvers) != 2 || c.Approvers[0].Login != "amy" || c.Approvers[1].Login != "zoe" {
		t.Errorf("approvers not sorted by login: %+v", c.Approvers)
	}
}

func TestNewSourceReview_BoundsUntrustedStrings(t *testing.T) {
	longLogin := strings.Repeat("L", 5000)
	pr := srMergedPR()
	pr.HTMLURL = gh.Ptr("https://example.com/" + strings.Repeat("u", 5000))
	m := &mockReviewService{
		prs:     []*gh.PullRequest{pr},
		reviews: []*gh.PullRequestReview{srReview(srUser(longLogin, 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if got := len([]rune(c.Approvers[0].Login)); got > srMaxStringLen {
		t.Errorf("login len = %d, want <= %d", got, srMaxStringLen)
	}
	if got := len([]rune(c.PullRequest.URL)); got > srMaxStringLen {
		t.Errorf("url len = %d, want <= %d", got, srMaxStringLen)
	}
	srValidate(t, c)
}

func TestNormalizeAssociation(t *testing.T) {
	cases := map[string]string{
		"OWNER": "OWNER", "member": "MEMBER", "Collaborator": "COLLABORATOR",
		"NONE": "NONE", "": "", "SOMETHING_NEW": "",
	}
	for in, want := range cases {
		if got := normalizeAssociation(in); got != want {
			t.Errorf("normalizeAssociation(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewSourceReview_PRNumberDoesNotBypassMergeMatch(t *testing.T) {
	// adversarial: a well-reviewed PR whose merge_commit_sha does NOT match the
	// queried source revision (and is not even merged) must NOT be bound to it via
	// --pr-number. Otherwise an unreviewed commit could borrow another PR's approvals.
	wellReviewedButUnrelated := &gh.PullRequest{
		Number:         gh.Ptr(99),
		User:           srUser("author", srAuthorID, "User"),
		Head:           &gh.PullRequestBranch{SHA: gh.Ptr(srHeadSHA)},
		Base:           &gh.PullRequestBranch{Ref: gh.Ptr("main")},
		MergeCommitSHA: gh.Ptr("a-totally-different-commit-sha"),
		// not merged (zero MergedAt)
	}
	opts := srOpts()
	opts.PRNumber = 99
	m := &mockReviewService{
		prs:     []*gh.PullRequest{wellReviewedButUnrelated},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, opts)

	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true: --pr-number must not bypass the merge_commit_sha binding")
	}
	if c.PullRequest != nil {
		t.Errorf("pullRequest = %+v, want nil (no PR whose merge produced the source revision)", c.PullRequest)
	}
	if c.Summary.DistinctApprovers != 0 {
		t.Errorf("distinct = %d, want 0 (unrelated PR's approvals must not bind)", c.Summary.DistinctApprovers)
	}
}

func TestNewSourceReview_EmptyCommitIDIsStale(t *testing.T) {
	// an approval with no commit_id cannot be confirmed on the head -> stale (fail closed).
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, "", srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if c.Summary.DistinctApprovers != 0 {
		t.Errorf("distinct = %d, want 0 (empty commit_id is stale)", c.Summary.DistinctApprovers)
	}
	if len(c.Approvers) != 1 || !c.Approvers[0].Stale {
		t.Errorf("approver stale=%v, want true for empty commit_id", c.Approvers[0].Stale)
	}
}

func TestNewSourceReview_RecordsRequireLastPushApproval(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		protection: &gh.Protection{RequiredPullRequestReviews: &gh.PullRequestReviewsEnforcement{
			RequiredApprovingReviewCount: 1,
			RequireLastPushApproval:      true,
		}},
	}
	c := srBuild(t, m, srOpts())
	if c.BranchProtection == nil || !c.BranchProtection.RequireLastPushApproval {
		t.Errorf("branchProtection.requireLastPushApproval not recorded: %+v", c.BranchProtection)
	}
	srValidate(t, c)
}

// TestSourceReview_PredicateTypeConsistency locks the predicate type URI across
// the Go const, the embedded schema const, the verify-side registry, and the
// docs table. A drift in any one silently breaks gating, so it must fail the build.
func TestSourceReview_PredicateTypeConsistency(t *testing.T) {
	const want = "https://autogov.dev/attestation/source-review/v0.1"

	if SourceReviewPredicateTypeURI != want {
		t.Errorf("SourceReviewPredicateTypeURI = %q, want %q", SourceReviewPredicateTypeURI, want)
	}
	if attestations.PredicateTypeAutogovSourceReview != want {
		t.Errorf("registry const = %q, want %q", attestations.PredicateTypeAutogovSourceReview, want)
	}
	info, ok := attestations.PredicateTypeRegistry[want]
	if !ok || info.ShortName != "AutoGov Source Review" {
		t.Errorf("registry entry = %+v (ok=%v), want ShortName 'AutoGov Source Review'", info, ok)
	}

	var schema map[string]any
	if err := json.Unmarshal([]byte(getEmbeddedSchema("source-review-schema.json")), &schema); err != nil {
		t.Fatalf("parse embedded schema: %v", err)
	}
	props := schema["properties"].(map[string]any)
	pt := props["predicateType"].(map[string]any)
	if pt["const"] != want {
		t.Errorf("schema predicateType const = %v, want %q", pt["const"], want)
	}

	doc, err := os.ReadFile("../../docs/predicate-types.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	if !strings.Contains(string(doc), want) {
		t.Errorf("docs/predicate-types.md missing %q", want)
	}
}

var errBoom = errBoomError("boom")

type errBoomError string

func (e errBoomError) Error() string { return string(e) }
