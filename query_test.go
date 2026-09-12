package main

import "testing"

func TestNormalizeTactic(t *testing.T) {
	got := normalizeTactic("Command-and-Control")
	want := "command and control"

	if got != want {
		t.Fatalf("normalizeTactic() = %q, want %q", got, want)
	}
}

func TestContainsTacticNormalized(t *testing.T) {
	values := []string{"command-and-control", "Initial Access"}

	if !containsTacticNormalized(values, "Command and Control") {
		t.Fatal("expected tactic match with normalized spacing")
	}

	if containsTacticNormalized(values, "Impact") {
		t.Fatal("did not expect unmatched tactic to return true")
	}
}

func TestSearchTechniquesPrioritizesNameMatches(t *testing.T) {
	techniques := []Technique{
		{ID: "T2000", Name: "Other", Description: "PowerShell appears here"},
		{ID: "T1000", Name: "PowerShell", Description: "Name match"},
	}

	results := searchTechniques(techniques, "powershell", false, 0)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].ID != "T1000" {
		t.Fatalf("first result ID = %q, want T1000", results[0].ID)
	}
}

func TestFindTechniqueByID(t *testing.T) {
	techniques := []Technique{{ID: "T1059", Name: "Command and Scripting Interpreter"}}

	technique, found := findTechniqueByID(techniques, "t1059")
	if !found {
		t.Fatal("expected technique to be found case-insensitively")
	}
	if technique.Name != "Command and Scripting Interpreter" {
		t.Fatalf("technique.Name = %q", technique.Name)
	}
}
