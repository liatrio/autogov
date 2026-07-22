package predicate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	gh "github.com/google/go-github/v89/github"
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
	prs              []*gh.PullRequest
	prsErr           error
	reviews          []*gh.PullRequestReview
	reviewsErr       error
	protection       *gh.Protection
	protErr          error
	rules            *gh.BranchRules
	rulesErr         error
	rulesPages       [][]*gh.PullRequestBranchRule // if set, ListRulesForBranch returns these page-by-page
	rulesBranchPages []*gh.BranchRules             // if set, ListRulesForBranch returns full BranchRules page-by-page
	rulesCall        int
	rulesets         map[int64]*gh.RepositoryRuleset // keyed by rulesetID, returned by GetRuleset
	rulesetErr       error

	// continuity fixtures.
	history       map[int64][]*RulesetVersion              // ruleset id -> version metas (newest first)
	historyErr    map[int64]error                          // per-ruleset history error (403/404/unreadable)
	historyPages  map[int64][][]*RulesetVersion            // ruleset id -> paginated metas (forces NextPage)
	historyCall   map[int64]int                            // per-ruleset page cursor
	versions      map[int64]map[int64]*RulesetVersionState // ruleset id -> version id -> state
	versionErr    map[int64]error                          // per-ruleset version-state error
	commits       []*gh.RepositoryCommit                   // ListCommits result (newest first)
	commitsPages  [][]*gh.RepositoryCommit                 // paginated ListCommits (forces NextPage)
	commitsCall   int
	commitsErr    error
	defaultBranch string // GetRepository default branch ("" => "main" via helper)
	repoErr       error  // GetRepository error

	// merged-by supplemental fetch (best-effort). getPR is the PR returned by
	// GetPullRequest (nil => no merger recorded); getPRErr forces the error path.
	getPR    *gh.PullRequest
	getPRErr error
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
	if m.rulesErr != nil {
		return nil, srResp(), m.rulesErr
	}
	if m.rulesBranchPages != nil {
		page := m.rulesCall
		m.rulesCall++
		if page >= len(m.rulesBranchPages) {
			return &gh.BranchRules{}, srResp(), nil
		}
		resp := srResp()
		if page+1 < len(m.rulesBranchPages) {
			resp.NextPage = page + 1
		}
		return m.rulesBranchPages[page], resp, nil
	}
	if m.rulesPages != nil {
		page := m.rulesCall
		m.rulesCall++
		if page >= len(m.rulesPages) {
			return &gh.BranchRules{}, srResp(), nil
		}
		resp := srResp()
		if page+1 < len(m.rulesPages) {
			resp.NextPage = page + 1
		}
		return &gh.BranchRules{PullRequest: m.rulesPages[page]}, resp, nil
	}
	return m.rules, srResp(), nil
}

func (m *mockReviewService) GetRuleset(_ context.Context, _, _ string, id int64, _ bool) (*gh.RepositoryRuleset, *gh.Response, error) {
	if m.rulesetErr != nil {
		return nil, srResp(), m.rulesetErr
	}
	return m.rulesets[id], srResp(), nil
}

func (m *mockReviewService) GetRulesetHistory(_ context.Context, _, _ string, id int64, opts *gh.ListOptions) ([]*RulesetVersion, *gh.Response, error) {
	if m.historyErr != nil {
		if err, ok := m.historyErr[id]; ok && err != nil {
			return nil, srResp(), err
		}
	}
	if m.historyPages != nil {
		if pages, ok := m.historyPages[id]; ok {
			if m.historyCall == nil {
				m.historyCall = map[int64]int{}
			}
			page := m.historyCall[id]
			m.historyCall[id]++
			if page >= len(pages) {
				return nil, srResp(), nil
			}
			resp := srResp()
			if page+1 < len(pages) {
				resp.NextPage = page + 1
			}
			return pages[page], resp, nil
		}
	}
	return m.history[id], srResp(), nil
}

func (m *mockReviewService) GetRulesetVersion(_ context.Context, _, _ string, id, versionID int64) (*RulesetVersionState, *gh.Response, error) {
	if m.versionErr != nil {
		if err, ok := m.versionErr[id]; ok && err != nil {
			return nil, srResp(), err
		}
	}
	if states, ok := m.versions[id]; ok {
		if st, ok := states[versionID]; ok {
			return st, srResp(), nil
		}
	}
	return nil, srResp(), fmt.Errorf("no version state fixture for ruleset %d version %d", id, versionID)
}

func (m *mockReviewService) ListCommits(_ context.Context, _, _ string, _ *gh.CommitsListOptions) ([]*gh.RepositoryCommit, *gh.Response, error) {
	if m.commitsErr != nil {
		return nil, srResp(), m.commitsErr
	}
	if m.commitsPages != nil {
		page := m.commitsCall
		m.commitsCall++
		if page >= len(m.commitsPages) {
			return nil, srResp(), nil
		}
		resp := srResp()
		if page+1 < len(m.commitsPages) {
			resp.NextPage = page + 1
		}
		return m.commitsPages[page], resp, nil
	}
	return m.commits, srResp(), nil
}

func (m *mockReviewService) GetRepository(_ context.Context, _, _ string) (*gh.Repository, *gh.Response, error) {
	if m.repoErr != nil {
		return nil, srResp(), m.repoErr
	}
	db := m.defaultBranch
	if db == "" {
		db = "main"
	}
	return &gh.Repository{DefaultBranch: gh.Ptr(db)}, srResp(), nil
}

func (m *mockReviewService) GetPullRequest(_ context.Context, _, _ string, _ int) (*gh.PullRequest, *gh.Response, error) {
	if m.getPRErr != nil {
		return nil, srResp(), m.getPRErr
	}
	// nil getPR is the default: the best-effort caller tolerates a nil PR and simply
	// records no merger, so existing tests that never set getPR do not panic.
	return m.getPR, srResp(), nil
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

// srBypassActor builds a ruleset bypass actor for the technical-controls tests.
func srBypassActor(actorType string, id int64, mode string) *gh.BypassActor {
	at := gh.BypassActorType(actorType)
	bm := gh.BypassMode(mode)
	return &gh.BypassActor{ActorID: gh.Ptr(id), ActorType: &at, BypassMode: &bm}
}

func TestFetchTechnicalControls(t *testing.T) {
	statusCheckRule := &gh.RequiredStatusChecksBranchRule{
		BranchRuleMetadata: gh.BranchRuleMetadata{RulesetID: 5},
		Parameters: gh.RequiredStatusChecksRuleParameters{
			RequiredStatusChecks: []*gh.RuleStatusCheck{
				{Context: "test"},
				{Context: "build"},
			},
		},
	}
	allRules := &gh.BranchRules{
		NonFastForward:        []*gh.BranchRuleMetadata{{RulesetID: 5}},
		RequiredLinearHistory: []*gh.BranchRuleMetadata{{RulesetID: 5}},
		Deletion:              []*gh.BranchRuleMetadata{{RulesetID: 5}},
		RequiredSignatures:    []*gh.BranchRuleMetadata{{RulesetID: 5}},
		RequiredStatusChecks:  []*gh.RequiredStatusChecksBranchRule{statusCheckRule},
	}
	rulesets := map[int64]*gh.RepositoryRuleset{
		5: {BypassActors: []*gh.BypassActor{
			srBypassActor("RepositoryRole", 5, "always"),
			srBypassActor("Integration", 801323, "always"),
		}},
	}

	t.Run("all controls present, sorted + formatted", func(t *testing.T) {
		m := &mockReviewService{rules: allRules, rulesets: rulesets}
		tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main")
		if tc == nil {
			t.Fatal("expected non-nil technical controls")
		}
		if !tc.ForcePushBlocked || !tc.RequiredLinearHistory || !tc.DeletionBlocked || !tc.RequiredSignatures {
			t.Errorf("bools = %+v, want all true", tc)
		}
		if !reflect.DeepEqual(tc.RequiredStatusChecks, []string{"build", "test"}) {
			t.Errorf("status checks = %v, want sorted [build test]", tc.RequiredStatusChecks)
		}
		if !reflect.DeepEqual(tc.BypassActors, []string{"Integration:801323:always", "RepositoryRole:5:always"}) {
			t.Errorf("bypass actors = %v, want sorted+formatted", tc.BypassActors)
		}
		if !tc.BypassActorsComplete {
			t.Error("expected BypassActorsComplete true (rules fully read + ruleset resolved)")
		}
	})

	t.Run("partial controls; rulesetID 0 not fetched", func(t *testing.T) {
		m := &mockReviewService{rules: &gh.BranchRules{NonFastForward: []*gh.BranchRuleMetadata{{RulesetID: 0}}}}
		tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main")
		if tc == nil || !tc.ForcePushBlocked {
			t.Fatalf("expected ForcePushBlocked, got %+v", tc)
		}
		if tc.RequiredLinearHistory || tc.DeletionBlocked || tc.RequiredSignatures {
			t.Errorf("other bools should be false, got %+v", tc)
		}
		if len(tc.BypassActors) != 0 {
			t.Errorf("bypass actors should be empty, got %v", tc.BypassActors)
		}
	})

	t.Run("GetRuleset denied is fail-soft (keeps other controls)", func(t *testing.T) {
		m := &mockReviewService{rules: allRules, rulesetErr: errors.New("403 Resource not accessible: Administration:read")}
		tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main")
		if tc == nil || !tc.ForcePushBlocked || !tc.RequiredSignatures {
			t.Fatalf("controls should survive GetRuleset denial, got %+v", tc)
		}
		if len(tc.BypassActors) != 0 {
			t.Errorf("bypass actors should be empty on denial, got %v", tc.BypassActors)
		}
		if !reflect.DeepEqual(tc.RequiredStatusChecks, []string{"build", "test"}) {
			t.Errorf("status checks should survive, got %v", tc.RequiredStatusChecks)
		}
		if tc.BypassActorsComplete {
			t.Error("expected BypassActorsComplete false on GetRuleset denial (empty != none)")
		}
	})

	t.Run("paginated rules aggregated across pages, bypass unioned", func(t *testing.T) {
		// page 1 contributes ForcePushBlocked + ruleset 5; page 2 contributes
		// RequiredSignatures + ruleset 6. Both must be captured + bypass unioned.
		m := &mockReviewService{
			rulesBranchPages: []*gh.BranchRules{
				{NonFastForward: []*gh.BranchRuleMetadata{{RulesetID: 5}}},
				{RequiredSignatures: []*gh.BranchRuleMetadata{{RulesetID: 6}}},
			},
			rulesets: map[int64]*gh.RepositoryRuleset{
				5: {BypassActors: []*gh.BypassActor{srBypassActor("Integration", 801323, "always")}},
				6: {BypassActors: []*gh.BypassActor{srBypassActor("Team", 42, "always")}},
			},
		}
		tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main")
		if tc == nil || !tc.ForcePushBlocked || !tc.RequiredSignatures {
			t.Fatalf("expected controls from BOTH pages, got %+v", tc)
		}
		if !reflect.DeepEqual(tc.BypassActors, []string{"Integration:801323:always", "Team:42:always"}) {
			t.Errorf("bypass actors should union both pages' rulesets, got %v", tc.BypassActors)
		}
		if !tc.BypassActorsComplete {
			t.Error("expected complete (both pages read, both rulesets resolved)")
		}
	})

	t.Run("bypass actors de-duped across distinct rulesets", func(t *testing.T) {
		rules := &gh.BranchRules{
			NonFastForward:        []*gh.BranchRuleMetadata{{RulesetID: 5}},
			RequiredLinearHistory: []*gh.BranchRuleMetadata{{RulesetID: 6}},
		}
		rs := map[int64]*gh.RepositoryRuleset{
			5: {BypassActors: []*gh.BypassActor{srBypassActor("Integration", 801323, "always")}},
			6: {BypassActors: []*gh.BypassActor{srBypassActor("Integration", 801323, "always")}},
		}
		m := &mockReviewService{rules: rules, rulesets: rs}
		tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main")
		if tc == nil || !reflect.DeepEqual(tc.BypassActors, []string{"Integration:801323:always"}) {
			t.Errorf("bypass actors should de-dupe to one, got %v", tc.BypassActors)
		}
	})

	t.Run("no rules -> nil", func(t *testing.T) {
		m := &mockReviewService{rules: &gh.BranchRules{}}
		if tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main"); tc != nil {
			t.Errorf("expected nil for empty rules, got %+v", tc)
		}
	})

	t.Run("ListRulesForBranch error -> nil", func(t *testing.T) {
		m := &mockReviewService{rulesErr: errors.New("boom")}
		if tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", "main"); tc != nil {
			t.Errorf("expected nil on list error, got %+v", tc)
		}
	})

	t.Run("empty branch -> nil", func(t *testing.T) {
		m := &mockReviewService{rules: allRules}
		if tc, _ := fetchTechnicalControls(context.Background(), m, "liatrio", "autogov", ""); tc != nil {
			t.Errorf("expected nil for empty branch, got %+v", tc)
		}
	})
}

func TestNewSourceReview_TechnicalControls(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		rules: &gh.BranchRules{
			NonFastForward:     []*gh.BranchRuleMetadata{{RulesetID: 5}},
			RequiredSignatures: []*gh.BranchRuleMetadata{{RulesetID: 5}},
		},
		rulesets: map[int64]*gh.RepositoryRuleset{
			5: {BypassActors: []*gh.BypassActor{srBypassActor("Integration", 801323, "always")}},
		},
	}
	c := srBuild(t, m, srOpts())
	if c.TechnicalControls == nil {
		t.Fatal("expected TechnicalControls to be recorded")
	}
	if !c.TechnicalControls.ForcePushBlocked || !c.TechnicalControls.RequiredSignatures {
		t.Errorf("controls = %+v", c.TechnicalControls)
	}
	if !reflect.DeepEqual(c.TechnicalControls.BypassActors, []string{"Integration:801323:always"}) {
		t.Errorf("bypass actors = %v", c.TechnicalControls.BypassActors)
	}
	if !c.TechnicalControls.BypassActorsComplete {
		t.Error("expected BypassActorsComplete true (ruleset resolved)")
	}
	// no ruleset history fixtures -> continuity walk fails CLOSED: empty start,
	// complete=false, Method="none". The no-continuity (dormant) outcome.
	if c.ContinuityStartRevision != "" {
		t.Errorf("continuity start must be empty without provable history, got %q", c.ContinuityStartRevision)
	}
	if c.TechnicalControls.ContinuityComplete {
		t.Error("continuityComplete must be false without provable history")
	}
	if c.ContinuityEvidence == nil || c.ContinuityEvidence.Method != continuityMethodNone {
		t.Errorf("expected continuity evidence Method=none, got %+v", c.ContinuityEvidence)
	}
	srValidate(t, c) // schema must accept the new technicalControls fields (incl. required continuityComplete on v0.2)
}

func TestNewSourceReview_NoTechnicalControls(t *testing.T) {
	// regression: no ruleset rules -> TechnicalControls nil, review fields intact.
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if c.TechnicalControls != nil {
		t.Errorf("expected nil TechnicalControls, got %+v", c.TechnicalControls)
	}
	srValidate(t, c)
}

// --- continuity (SLSA Source L3) producer test matrix ------------------------

var continuityStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// cleanL3State builds a ruleset version STATE that enforces every L3-relevant
// control and targets `main` with a bypass set that is a SUBSET of the current
// (head) bypass set. updatedAt is the version's effective time.
func cleanL3State() *RulesetVersionState {
	include := []string{"refs/heads/main"}
	return &RulesetVersionState{
		Enforcement: string(gh.RulesetEnforcementActive),
		Conditions: &gh.RepositoryRulesetConditions{
			RefName: &gh.RepositoryRulesetRefConditionParameters{Include: include},
		},
		Rules: &gh.RepositoryRulesetRules{
			NonFastForward:        &gh.EmptyRuleParameters{},
			RequiredLinearHistory: &gh.EmptyRuleParameters{},
			RequiredStatusChecks: &gh.RequiredStatusChecksRuleParameters{
				RequiredStatusChecks: []*gh.RuleStatusCheck{{Context: "build"}},
			},
		},
		BypassActors: nil, // subset of {} current set -> narrow.
	}
}

// srVersion builds a history meta for version id at time t.
func srVersion(id int64, t time.Time) *RulesetVersion {
	return &RulesetVersion{VersionID: id, UpdatedAt: t.UTC(), Actor: RulesetActor{ID: 7, Type: "User"}}
}

// continuityCommitTime is the committer date of the R0 commit fixture: AFTER every
// fixture window start, so startCommitAtOrAfter accepts it as at-or-after the start.
var continuityCommitTime = continuityStart.Add(1000 * time.Hour)

// srR0Commit is the single R0 commit returned by ListCommits in continuity tests.
func srR0Commit() *gh.RepositoryCommit {
	return &gh.RepositoryCommit{
		SHA:    gh.Ptr("r0commit00000000000000000000000000000000"),
		Commit: &gh.Commit{Committer: &gh.CommitAuthor{Date: &gh.Timestamp{Time: continuityCommitTime}}},
	}
}

// createdAtOldest stamps the current-ruleset CreatedAt to the OLDEST version in
// history, modeling "the creation version is the oldest retained version" so a
// clean-and-no-break leg passes the retention-creation corroboration (no pruned
// pre-creation gap). It preserves any bypass actors already on rs.
func createdAtOldest(rs *gh.RepositoryRuleset, history []*RulesetVersion) *gh.RepositoryRuleset {
	if rs == nil {
		rs = &gh.RepositoryRuleset{}
	}
	if rs.CreatedAt != nil {
		return rs // caller set an explicit CreatedAt (e.g. to model a pruned gap).
	}
	var oldest time.Time
	for _, v := range history {
		if v == nil {
			continue
		}
		if oldest.IsZero() || v.UpdatedAt.Before(oldest) {
			oldest = v.UpdatedAt
		}
	}
	if !oldest.IsZero() {
		rs.CreatedAt = &gh.Timestamp{Time: oldest}
	}
	return rs
}

// continuityMock wires a single-ruleset (id=5) continuity fixture: history metas,
// per-version states, the current ruleset (for the narrow bound + CreatedAt), the
// branch rules (so fetchTechnicalControls records controls + the id), and the commit
// list (so the start time resolves to R0). The artifact is built with a clean
// review path.
func continuityMock(history []*RulesetVersion, states map[int64]*RulesetVersionState, current *gh.RepositoryRuleset) *mockReviewService {
	return &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		rules: &gh.BranchRules{
			NonFastForward:        []*gh.BranchRuleMetadata{{RulesetID: 5}},
			RequiredLinearHistory: []*gh.BranchRuleMetadata{{RulesetID: 5}},
			RequiredStatusChecks: []*gh.RequiredStatusChecksBranchRule{{
				BranchRuleMetadata: gh.BranchRuleMetadata{RulesetID: 5},
				Parameters: gh.RequiredStatusChecksRuleParameters{
					RequiredStatusChecks: []*gh.RuleStatusCheck{{Context: "build"}},
				},
			}},
		},
		rulesets: map[int64]*gh.RepositoryRuleset{5: createdAtOldest(current, history)},
		history:  map[int64][]*RulesetVersion{5: history},
		versions: map[int64]map[int64]*RulesetVersionState{5: states},
		commits:  []*gh.RepositoryCommit{srR0Commit()},
	}
}

func srBuildContinuity(t *testing.T, m *mockReviewService) *SourceReview {
	t.Helper()
	c := srBuild(t, m, srOpts())
	srValidate(t, c)
	return c
}

func TestContinuity_P1_CleanWindow(t *testing.T) {
	// P1: a single all-clean history -> start set + complete true, Method history.
	hist := []*RulesetVersion{srVersion(3, continuityStart.Add(48*time.Hour)), srVersion(2, continuityStart.Add(24*time.Hour)), srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{3: cleanL3State(), 2: cleanL3State(), 1: cleanL3State()}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if !c.TechnicalControls.ContinuityComplete {
		t.Fatal("P1: expected ContinuityComplete true")
	}
	if c.ContinuityStartRevision == "" {
		t.Error("P1: expected a non-empty start revision")
	}
	if c.ContinuityEvidence == nil || c.ContinuityEvidence.Method != continuityMethodHistory {
		t.Errorf("P1: Method = %+v, want ruleset-history", c.ContinuityEvidence)
	}
	if c.ContinuityEvidence.WeakenedAt != "" {
		t.Errorf("P1: WeakenedAt = %q, want empty (clean)", c.ContinuityEvidence.WeakenedAt)
	}
	// continuity holds since the OLDEST clean version (earliest in the run).
	if c.ContinuityEvidence.WindowStartAt != continuityStart.Format(time.RFC3339) {
		t.Errorf("P1: WindowStartAt = %q, want %q", c.ContinuityEvidence.WindowStartAt, continuityStart.Format(time.RFC3339))
	}
}

func TestContinuity_P2_DisabledVersion(t *testing.T) {
	// P2: a disabled (enforcement!=active) version at the HEAD breaks continuity now.
	disabled := cleanL3State()
	disabled.Enforcement = string(gh.RulesetEnforcementDisabled)
	hist := []*RulesetVersion{srVersion(2, continuityStart.Add(24*time.Hour)), srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{2: disabled, 1: cleanL3State()}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P2: expected fail-closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence.WeakenedAt == "" {
		t.Error("P2: expected WeakenedAt to record the disabled version")
	}
}

func TestContinuity_P3_EvaluateMode(t *testing.T) {
	// P3: an evaluate-mode head version is NOT active -> fail closed.
	eval := cleanL3State()
	eval.Enforcement = string(gh.RulesetEnforcementEvaluate)
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: eval}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P3: evaluate-mode must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
}

func TestContinuity_P4_BranchExcluded(t *testing.T) {
	// P4: a version that excludes the target branch is not protecting it -> fail.
	excluded := cleanL3State()
	excluded.Conditions.RefName.Include = []string{"~ALL"}
	excluded.Conditions.RefName.Exclude = []string{"refs/heads/main"}
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: excluded}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P4: branch-excluded must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
}

func TestContinuity_P5_WideBypass(t *testing.T) {
	// P5: a version with a bypass actor NOT in the current (narrow) set -> fail.
	wide := cleanL3State()
	wide.BypassActors = []*gh.BypassActor{srBypassActor("Team", 42, "always")}
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: wide}
	// current set has NO bypass actors, so Team:42 is wider than now -> weakened.
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P5: wide-bypass version must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
}

func TestContinuity_P6_HistoryForbidden(t *testing.T) {
	// P6: a 403 on history surfaces as UNREADABLE -> empty, Method none.
	m := continuityMock(nil, nil, &gh.RepositoryRuleset{})
	m.historyErr = map[int64]error{5: &gh.ErrorResponse{Response: &http.Response{StatusCode: 403}, Message: "forbidden"}}
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P6: 403 history must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence.Method != continuityMethodNone {
		t.Errorf("P6: Method = %q, want none", c.ContinuityEvidence.Method)
	}
	if c.ContinuityEvidence.HistoryComplete {
		t.Error("P6: HistoryComplete must be false on unreadable history")
	}
}

func TestContinuity_P7_TruncatedHistory(t *testing.T) {
	// P7: history that still advertises more pages at the cap -> HistoryComplete
	// false -> fail closed. We force this with a per-ruleset paginated history whose
	// pages exceed the page cap (each page advertises a NextPage).
	pages := make([][]*RulesetVersion, continuityMaxHistoryPages+1)
	for i := range pages {
		pages[i] = []*RulesetVersion{srVersion(int64(i+1), continuityStart.Add(time.Duration(i)*time.Hour))}
	}
	m := continuityMock(nil, map[int64]*RulesetVersionState{}, &gh.RepositoryRuleset{})
	m.historyPages = map[int64][][]*RulesetVersion{5: pages}
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P7: truncated history must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence.HistoryComplete {
		t.Error("P7: HistoryComplete must be false on truncation")
	}
}

func TestContinuity_P8_RetentionCapped(t *testing.T) {
	// P8: retention cap — the clean run reaches the OLDEST RETAINED version with NO
	// observed break, but the ruleset's CreatedAt is OLDER than that oldest retained
	// version. That means version(s) between creation and the oldest retained were
	// pruned/aged out and CANNOT be proven clean -> RetentionCapped, fail closed.
	// This is the honesty-critical case: only-clean retained versions must NOT be
	// read as "continuous since creation" when older versions were dropped.
	hist := []*RulesetVersion{srVersion(2, continuityStart.Add(24*time.Hour))}
	states := map[int64]*RulesetVersionState{2: cleanL3State()}
	current := &gh.RepositoryRuleset{
		// created BEFORE the oldest retained version -> a pruned pre-retention gap.
		CreatedAt: &gh.Timestamp{Time: continuityStart.Add(-240 * time.Hour)},
	}
	c := srBuildContinuity(t, continuityMock(hist, states, current))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P8: pruned pre-creation gap must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence == nil || !c.ContinuityEvidence.RetentionCapped {
		t.Errorf("P8: expected RetentionCapped, got %+v", c.ContinuityEvidence)
	}
}

func TestContinuity_P8b_CreationVersionRetained(t *testing.T) {
	// P8b: the corroborated case — the oldest retained version IS the creation version
	// (CreatedAt == oldest retained updatedAt), so there is no pruned gap and a clean
	// no-break leg establishes continuity.
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: cleanL3State()}
	current := &gh.RepositoryRuleset{CreatedAt: &gh.Timestamp{Time: continuityStart}}
	c := srBuildContinuity(t, continuityMock(hist, states, current))
	if !c.TechnicalControls.ContinuityComplete {
		t.Fatalf("P8b: creation version retained should establish continuity; ev=%+v", c.ContinuityEvidence)
	}
	if c.ContinuityEvidence.RetentionCapped {
		t.Error("P8b: must NOT be retention-capped when the creation version is retained")
	}
}

func TestContinuity_P9_CommitWalkNoAnchor(t *testing.T) {
	// P9: the commit list returns NO commit at-or-after the start time (the
	// time->commit mapping cannot anchor R0) -> fail closed.
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: cleanL3State()}
	m := continuityMock(hist, states, &gh.RepositoryRuleset{})
	m.commits = nil // no commit at-or-after start.
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P9: unanchored commit walk must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
}

func TestContinuity_P9b_CommitWalkTruncated(t *testing.T) {
	// P9b: the commit list keeps advertising more pages past the cap -> fail closed.
	pages := make([][]*gh.RepositoryCommit, continuityMaxCommitPages+1)
	for i := range pages {
		pages[i] = []*gh.RepositoryCommit{{SHA: gh.Ptr(fmt.Sprintf("c%039d", i))}}
	}
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: cleanL3State()}
	m := continuityMock(hist, states, &gh.RepositoryRuleset{})
	m.commits = nil
	m.commitsPages = pages
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P9b: truncated commit walk must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
}

func TestContinuity_P10_TwoRulesetsMaxStart(t *testing.T) {
	// P10: two rulesets clean since T1 and T2 -> continuity holds since max(T1,T2).
	t1 := continuityStart
	t2 := continuityStart.Add(72 * time.Hour) // the LATER per-leg start.
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		rules: &gh.BranchRules{
			NonFastForward:        []*gh.BranchRuleMetadata{{RulesetID: 5}},
			RequiredLinearHistory: []*gh.BranchRuleMetadata{{RulesetID: 6}},
			RequiredStatusChecks: []*gh.RequiredStatusChecksBranchRule{{
				BranchRuleMetadata: gh.BranchRuleMetadata{RulesetID: 5},
				Parameters: gh.RequiredStatusChecksRuleParameters{
					RequiredStatusChecks: []*gh.RuleStatusCheck{{Context: "build"}},
				},
			}},
		},
		rulesets: map[int64]*gh.RepositoryRuleset{
			5: {CreatedAt: &gh.Timestamp{Time: t1}},
			6: {CreatedAt: &gh.Timestamp{Time: t2}},
		},
		history: map[int64][]*RulesetVersion{
			5: {srVersion(1, t1)},
			6: {srVersion(1, t2)},
		},
		versions: map[int64]map[int64]*RulesetVersionState{
			5: {1: cleanL3State()},
			6: {1: cleanL3State()},
		},
		commits: []*gh.RepositoryCommit{srR0Commit()},
	}
	c := srBuildContinuity(t, m)
	if !c.TechnicalControls.ContinuityComplete {
		t.Fatal("P10: expected continuity across both legs")
	}
	if c.ContinuityEvidence.WindowStartAt != t2.Format(time.RFC3339) {
		t.Errorf("P10: WindowStartAt = %q, want max(T1,T2) = %q", c.ContinuityEvidence.WindowStartAt, t2.Format(time.RFC3339))
	}
	if len(c.ContinuityEvidence.RulesetIDs) != 2 {
		t.Errorf("P10: RulesetIDs = %v, want both legs", c.ContinuityEvidence.RulesetIDs)
	}
}

func TestContinuity_P11_OrgParentHistoryUnreadable(t *testing.T) {
	// P11: one (org/parent) ruleset's history is unreadable -> the whole walk fails
	// closed. The repo->org fallback is in the live service; from the walk's POV an
	// error on any leg's history is fatal.
	m := continuityMock([]*RulesetVersion{srVersion(1, continuityStart)},
		map[int64]*RulesetVersionState{1: cleanL3State()}, &gh.RepositoryRuleset{})
	// add a second backing ruleset (id 6) whose history 404s (org parent not found).
	m.rules.RequiredLinearHistory = []*gh.BranchRuleMetadata{{RulesetID: 6}}
	m.rulesets[6] = &gh.RepositoryRuleset{}
	m.historyErr = map[int64]error{6: &gh.ErrorResponse{Response: &http.Response{StatusCode: 404}, Message: "not found"}}
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P11: unreadable parent history must fail closed; complete=%v start=%q", c.TechnicalControls.ContinuityComplete, c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence.Method != continuityMethodNone {
		t.Errorf("P11: Method = %q, want none", c.ContinuityEvidence.Method)
	}
}

func TestContinuity_P12_DeleteRecreateFreshID(t *testing.T) {
	// P12: a delete+recreate yields a FRESH ruleset id with a short clean history;
	// the start is that recreate-era time only (continuity cannot reach before the
	// new id existed). The window start is the oldest retained CLEAN version of the
	// new id, which is the recreate era — not some earlier deleted-ruleset era.
	recreateEra := continuityStart.Add(240 * time.Hour)
	hist := []*RulesetVersion{srVersion(2, recreateEra.Add(time.Hour)), srVersion(1, recreateEra)}
	states := map[int64]*RulesetVersionState{2: cleanL3State(), 1: cleanL3State()}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if !c.TechnicalControls.ContinuityComplete {
		t.Fatal("P12: a fresh-id clean history should establish continuity from the recreate era")
	}
	if c.ContinuityEvidence.WindowStartAt != recreateEra.Format(time.RFC3339) {
		t.Errorf("P12: WindowStartAt = %q, want recreate era %q", c.ContinuityEvidence.WindowStartAt, recreateEra.Format(time.RFC3339))
	}
}

func TestContinuity_P13_DefaultBranchSelectorNonDefault(t *testing.T) {
	// P13: a version that targets ONLY "~DEFAULT_BRANCH" must NOT be credited when the
	// artifact's protected branch is NOT the repo default -> fail closed (over-claim
	// guard). The PR base ref here is "main" but the repo default is "trunk".
	st := cleanL3State()
	st.Conditions.RefName.Include = []string{"~DEFAULT_BRANCH"}
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: st}
	m := continuityMock(hist, states, &gh.RepositoryRuleset{})
	m.defaultBranch = "trunk" // != the artifact base branch "main"
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P13: ~DEFAULT_BRANCH on a non-default branch must fail closed; complete=%v", c.TechnicalControls.ContinuityComplete)
	}
}

func TestContinuity_P13b_DefaultBranchSelectorMatches(t *testing.T) {
	// P13b: the same "~DEFAULT_BRANCH"-only version DOES count when the artifact base
	// branch IS the repo default.
	st := cleanL3State()
	st.Conditions.RefName.Include = []string{"~DEFAULT_BRANCH"}
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: st}
	m := continuityMock(hist, states, &gh.RepositoryRuleset{})
	m.defaultBranch = "main" // == the artifact base branch
	c := srBuildContinuity(t, m)
	if !c.TechnicalControls.ContinuityComplete {
		t.Fatalf("P13b: ~DEFAULT_BRANCH on the default branch should count; ev=%+v", c.ContinuityEvidence)
	}
}

func TestContinuity_P14_GlobExcludeFailsClosed(t *testing.T) {
	// P14: an EXCLUDE with a glob that could match the branch must be treated as a
	// possible exclusion -> the version is not protecting the branch -> fail closed.
	st := cleanL3State()
	st.Conditions.RefName.Include = []string{"~ALL"}
	st.Conditions.RefName.Exclude = []string{"refs/heads/main*"} // glob could exclude main
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: st}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P14: a glob exclude that could match the branch must fail closed; complete=%v", c.TechnicalControls.ContinuityComplete)
	}
}

func TestContinuity_P15_VersionIDGapFailsClosed(t *testing.T) {
	// P15: a hole in the version_id sequence within the clean run means an
	// intermediate version was pruned and cannot be proven clean -> fail closed.
	// ids 3 and 1 are clean but id 2 is missing from the retained run.
	hist := []*RulesetVersion{srVersion(3, continuityStart.Add(48*time.Hour)), srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{3: cleanL3State(), 1: cleanL3State()}
	// CreatedAt == oldest so the creation-corroboration passes; the GAP is what must
	// trip the cap.
	current := &gh.RepositoryRuleset{CreatedAt: &gh.Timestamp{Time: continuityStart}}
	c := srBuildContinuity(t, continuityMock(hist, states, current))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P15: a version_id gap in the clean run must fail closed; complete=%v", c.TechnicalControls.ContinuityComplete)
	}
	if c.ContinuityEvidence == nil || !c.ContinuityEvidence.RetentionCapped {
		t.Errorf("P15: expected RetentionCapped on a version_id gap, got %+v", c.ContinuityEvidence)
	}
}

func TestContinuity_P16_NullVersionTimeFailsClosed(t *testing.T) {
	// P16: a clean version with a null effective time (zero updatedAt) cannot anchor
	// the window -> fail closed (even in a multi-version-looking history).
	hist := []*RulesetVersion{srVersion(1, time.Time{})} // zero UpdatedAt
	states := map[int64]*RulesetVersionState{1: cleanL3State()}
	c := srBuildContinuity(t, continuityMock(hist, states, &gh.RepositoryRuleset{}))
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P16: a null version time must fail closed; complete=%v", c.TechnicalControls.ContinuityComplete)
	}
}

func TestContinuity_P17_CommitDateBeforeStartFailsClosed(t *testing.T) {
	// P17: if the only commit ListCommits returns is BEFORE the window start, R0
	// cannot be anchored -> fail closed (the new min-by-date guard rejects it).
	hist := []*RulesetVersion{srVersion(1, continuityStart)}
	states := map[int64]*RulesetVersionState{1: cleanL3State()}
	m := continuityMock(hist, states, &gh.RepositoryRuleset{})
	m.commits = []*gh.RepositoryCommit{{
		SHA:    gh.Ptr("tooold00000000000000000000000000000000aa"),
		Commit: &gh.Commit{Committer: &gh.CommitAuthor{Date: &gh.Timestamp{Time: continuityStart.Add(-time.Hour)}}},
	}}
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete || c.ContinuityStartRevision != "" {
		t.Fatalf("P17: a pre-start commit must not anchor R0; complete=%v", c.TechnicalControls.ContinuityComplete)
	}
}

func TestContinuity_DormantByDefault_403(t *testing.T) {
	// DORMANT-by-default (producer half): a read-only token (history 403) yields
	// continuityComplete=false + empty start. This is the production reality until
	// the history scope is granted. The verifier half (these values keep the source
	// level dormant, NOT L3) is proven in pkg/source/review_test.go's
	// "continuityComplete=false + non-empty start -> not L3" + "empty continuity ->
	// not L3" cases, which key on exactly ContinuityComplete + ContinuityStartRevision.
	m := continuityMock(nil, nil, &gh.RepositoryRuleset{})
	m.historyErr = map[int64]error{5: &gh.ErrorResponse{Response: &http.Response{StatusCode: 403}, Message: "forbidden"}}
	c := srBuildContinuity(t, m)
	if c.TechnicalControls.ContinuityComplete {
		t.Error("dormant-by-default: continuityComplete must be false on a 403 history")
	}
	if c.ContinuityStartRevision != "" {
		t.Errorf("dormant-by-default: start must be empty, got %q", c.ContinuityStartRevision)
	}
	if c.ContinuityEvidence.Method != continuityMethodNone {
		t.Errorf("dormant-by-default: Method = %q, want none", c.ContinuityEvidence.Method)
	}
}

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

func TestNewSourceReview_MergedByPopulated(t *testing.T) {
	// the supplemental single-PR GET returns a merger -> mergedBy/mergedById are
	// recorded as evidence (login + rename-safe numeric id).
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		getPR:   &gh.PullRequest{MergedBy: srUser("merger", 138915, "User")},
	}
	c := srBuild(t, m, srOpts())
	if c.PullRequest == nil {
		t.Fatal("expected pullRequest to be populated")
	}
	if c.PullRequest.MergedBy != "merger" {
		t.Errorf("mergedBy = %q, want %q", c.PullRequest.MergedBy, "merger")
	}
	if c.PullRequest.MergedByID != 138915 {
		t.Errorf("mergedById = %d, want 138915", c.PullRequest.MergedByID)
	}
	srValidate(t, c) // schema must accept the new pullRequest.mergedBy/mergedById fields
}

func TestNewSourceReview_MergedByFetchErrorIsBestEffort(t *testing.T) {
	// the supplemental GET errors -> mergedBy/mergedById stay empty AND the rest of
	// the predicate is byte-for-byte the no-error baseline (no new fail-close). This
	// is fail-open evidence enrichment: an error must NOT flip ReviewToolingComplete.
	base := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	want := srBuild(t, base, srOpts())

	m := &mockReviewService{
		prs:      []*gh.PullRequest{srMergedPR()},
		reviews:  []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		getPRErr: errBoom,
	}
	c := srBuild(t, m, srOpts())

	if c.PullRequest == nil {
		t.Fatal("pullRequest should still be populated on a merged_by fetch error")
	}
	if c.PullRequest.MergedBy != "" || c.PullRequest.MergedByID != 0 {
		t.Errorf("mergedBy=%q mergedById=%d, want empty/0 on fetch error", c.PullRequest.MergedBy, c.PullRequest.MergedByID)
	}
	if !c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = false; a merged_by fetch error must NOT fail closed (best-effort)")
	}
	// the rest of the predicate must match the no-error baseline exactly.
	if c.Summary != want.Summary {
		t.Errorf("summary drift on fetch error: got %+v, want %+v", c.Summary, want.Summary)
	}
	if !reflect.DeepEqual(c.Approvers, want.Approvers) {
		t.Errorf("approvers drift on fetch error: got %+v, want %+v", c.Approvers, want.Approvers)
	}
	if !reflect.DeepEqual(c.PullRequest, want.PullRequest) {
		t.Errorf("pullRequest drift on fetch error: got %+v, want %+v", c.PullRequest, want.PullRequest)
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

func TestNewSourceReview_CodeownerReviewMetNull(t *testing.T) {
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if c.Summary.CodeownerReviewMet != nil {
		t.Errorf("codeownerReviewMet = %v, want nil (tri-state, REST-only)", *c.Summary.CodeownerReviewMet)
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
	// edge case: a well-reviewed PR whose merge_commit_sha does NOT match the
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

func TestNewSourceReview_NilAuthorFailsClosed(t *testing.T) {
	// edge case (M1): a nil PR author makes prAuthorID 0, which would silently
	// fail the self-approval exclusion (no real reviewer id is 0) — a solo author
	// could then clear min_approvals. Must fail closed instead.
	pr := srMergedPR()
	pr.User = nil
	m := &mockReviewService{
		prs:     []*gh.PullRequest{pr},
		reviews: []*gh.PullRequestReview{srReview(srUser("solo", 7, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, srOpts())
	if c.ReviewToolingComplete {
		t.Error("reviewToolingComplete = true; a nil PR author must fail closed (cannot exclude self-approval)")
	}
	if c.Summary.DistinctApprovers != 0 {
		t.Errorf("distinct = %d, want 0 (bailed before counting)", c.Summary.DistinctApprovers)
	}
}

func TestNewSourceReview_TrimsCommitSHA(t *testing.T) {
	// L2: a stray newline/space on --commit-sha must not cause a silent no-match.
	opts := srOpts()
	opts.CommitSHA = "  " + srSourceSHA + "\n"
	m := &mockReviewService{
		prs:     []*gh.PullRequest{srMergedPR()},
		reviews: []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
	}
	c := srBuild(t, m, opts)
	if !c.ReviewToolingComplete || c.PullRequest == nil {
		t.Errorf("whitespace commit-sha should still match: complete=%v pr=%v", c.ReviewToolingComplete, c.PullRequest)
	}
	if c.SourceRevision != srSourceSHA {
		t.Errorf("sourceRevision = %q, want trimmed %q", c.SourceRevision, srSourceSHA)
	}
}

func TestNewSourceReview_PaginatesBranchRules(t *testing.T) {
	// M3: requiredApprovals must reflect rules across ALL pages, not just page 1.
	page1 := []*gh.PullRequestBranchRule{{Parameters: gh.PullRequestRuleParameters{RequiredApprovingReviewCount: 1}}}
	page2 := []*gh.PullRequestBranchRule{{Parameters: gh.PullRequestRuleParameters{RequiredApprovingReviewCount: 4}}}
	m := &mockReviewService{
		prs:        []*gh.PullRequest{srMergedPR()},
		reviews:    []*gh.PullRequestReview{srReview(srUser("alice", 2, "User"), reviewStateApproved, srHeadSHA, srBaseTime.Add(time.Minute))},
		rulesPages: [][]*gh.PullRequestBranchRule{page1, page2},
	}
	c := srBuild(t, m, srOpts())
	if c.BranchProtection == nil || c.Summary.RequiredApprovals != 4 {
		t.Errorf("requiredApprovals = %v, want 4 (max across paginated rules)", c.Summary)
	}
}

// TestSourceReview_PredicateTypeConsistency locks the predicate type URI across
// the Go const, the embedded schema const, the verify-side registry, and the docs
// table. A drift in any one silently breaks gating, so it must fail the build.
// v0.2 is the only recognized version.
func TestSourceReview_PredicateTypeConsistency(t *testing.T) {
	const want = "https://autogov.dev/attestation/source-review/v0.2"

	if SourceReviewPredicateTypeURI != want {
		t.Errorf("SourceReviewPredicateTypeURI = %q, want %q", SourceReviewPredicateTypeURI, want)
	}
	if attestations.PredicateTypeAutogovSourceReview != want {
		t.Errorf("registry const = %q, want %q", attestations.PredicateTypeAutogovSourceReview, want)
	}
	info, ok := attestations.PredicateTypeRegistry[want]
	if !ok || info.ShortName != "AutoGov Source Review" {
		t.Errorf("registry entry for %q = %+v (ok=%v), want ShortName 'AutoGov Source Review'", want, info, ok)
	}

	var schema map[string]any
	if err := json.Unmarshal([]byte(getEmbeddedSchema("source-review-schema.json")), &schema); err != nil {
		t.Fatalf("parse embedded schema: %v", err)
	}
	props := schema["properties"].(map[string]any)
	pt := props["predicateType"].(map[string]any)
	if pt["enum"] != nil {
		t.Errorf("schema predicateType must be a const of %q (v0.2-only), got enum %v", want, pt["enum"])
	}
	if got, _ := pt["const"].(string); got != want {
		t.Errorf("schema predicateType const = %q, want %q", got, want)
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
