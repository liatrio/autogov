package boundary

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/liatrio/autogov"

func TestGoDependencyGraphsDoNotCrossCompanionBoundary(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("AutoGov does not import companion", func(t *testing.T) {
		dependencies := goListDependencies(t, repoRoot, ".", "./cmd/...", "./pkg/...")
		assertNoDependencyPrefix(t, dependencies, modulePath+"/agent-governance")
	})

	t.Run("companion does not import AutoGov", func(t *testing.T) {
		dependencies := goListDependencies(t, repoRoot, "./agent-governance/...")
		assertModuleDependenciesStayUnder(t, dependencies, modulePath+"/agent-governance")
	})
}

func goListDependencies(t *testing.T, repoRoot string, patterns ...string) []string {
	t.Helper()
	args := append([]string{"list", "-deps", "-test", "-f", "{{.ImportPath}}"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", patterns, err, output)
	}
	return strings.Fields(string(output))
}

func assertNoDependencyPrefix(t *testing.T, dependencies []string, forbidden string) {
	t.Helper()
	for _, dependency := range dependencies {
		if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
			t.Fatalf("dependency graph crosses extraction boundary through %s", dependency)
		}
	}
}

func assertModuleDependenciesStayUnder(t *testing.T, dependencies []string, allowed string) {
	t.Helper()
	for _, dependency := range dependencies {
		isThisModule := dependency == modulePath || strings.HasPrefix(dependency, modulePath+"/")
		isAllowed := dependency == allowed || strings.HasPrefix(dependency, allowed+"/")
		if isThisModule && !isAllowed {
			t.Fatalf("companion dependency graph imports AutoGov package %s", dependency)
		}
	}
}
