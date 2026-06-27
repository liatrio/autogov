package predicate

import (
	"net/http"
	"testing"

	gh "github.com/google/go-github/v88/github"
)

func TestAddPage(t *testing.T) {
	const base = "repos/o/r/rulesets/5/history"

	t.Run("nil opts -> bare url", func(t *testing.T) {
		if got := addPage(base, nil); got != base {
			t.Errorf("addPage(nil) = %q, want %q", got, base)
		}
	})

	t.Run("per_page carried even on page 0 (the per_page fix)", func(t *testing.T) {
		got := addPage(base, &gh.ListOptions{PerPage: 100})
		want := base + "?per_page=100"
		if got != want {
			t.Errorf("addPage = %q, want %q (per_page must be carried or the server defaults to 30)", got, want)
		}
	})

	t.Run("page + per_page", func(t *testing.T) {
		got := addPage(base, &gh.ListOptions{Page: 3, PerPage: 100})
		want := base + "?page=3&per_page=100"
		if got != want {
			t.Errorf("addPage = %q, want %q", got, want)
		}
	})

	t.Run("zero page and zero per_page -> bare url", func(t *testing.T) {
		if got := addPage(base, &gh.ListOptions{}); got != base {
			t.Errorf("addPage(empty opts) = %q, want %q", got, base)
		}
	})
}

func TestIsFirstPage(t *testing.T) {
	if !isFirstPage(nil) {
		t.Error("nil opts must be first page")
	}
	if !isFirstPage(&gh.ListOptions{Page: 0}) {
		t.Error("page 0 must be first page")
	}
	if !isFirstPage(&gh.ListOptions{Page: 1}) {
		t.Error("page 1 must be first page")
	}
	if isFirstPage(&gh.ListOptions{Page: 2}) {
		t.Error("page 2 must NOT be first page (org fallback must not fire on a later page)")
	}
}

func TestIsNotFound(t *testing.T) {
	if isNotFound(nil) {
		t.Error("nil response is not a 404")
	}
	if isNotFound(&gh.Response{Response: &http.Response{StatusCode: 403}}) {
		t.Error("403 must not be treated as 404 (no org fallback on a permission denial)")
	}
	if !isNotFound(&gh.Response{Response: &http.Response{StatusCode: 404}}) {
		t.Error("404 must be detected (triggers the org fallback)")
	}
}
