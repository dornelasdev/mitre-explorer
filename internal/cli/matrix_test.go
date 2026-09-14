package cli

import (
	"io"
	"reflect"
	"testing"

	"mitre-explorer/internal/attack"
)

func TestSetActiveMatrix(t *testing.T) {
	app := New(nil, io.Discard)
	if err := app.setActiveMatrix("mobile"); err != nil {
		t.Fatalf("setActiveMatrix(mobile) returned error: %v", err)
	}
	if app.activeMatrixName() != "mobile" {
		t.Fatalf("activeMatrixName() = %q, want mobile", app.activeMatrixName())
	}
	if app.matrix.CachePath != mobileMatrix.CachePath {
		t.Fatalf("cachePath = %q, want %q", app.matrix.CachePath, mobileMatrix.CachePath)
	}

	if err := app.setActiveMatrix("enterprise"); err != nil {
		t.Fatalf("setActiveMatrix(enterprise) returned error: %v", err)
	}
}

func TestSetActiveMatrixRejectsUnknown(t *testing.T) {
	app := New(nil, io.Discard)
	before := app.matrix
	if err := app.setActiveMatrix("unknown"); err == nil {
		t.Fatal("expected unsupported matrix error")
	}
	if !reflect.DeepEqual(app.matrix, before) {
		t.Fatal("invalid selection changed the matrix")
	}
}

func TestMatrixTacticQueries(t *testing.T) {
	for _, matrix := range []MatrixConfig{enterpriseMatrix, mobileMatrix, icsMatrix} {
		t.Run(matrix.Name, func(t *testing.T) {
			first, last := matrix.TacticOrder[0], matrix.TacticOrder[len(matrix.TacticOrder)-1]
			techniques := []attack.Technique{{Tactics: []string{last, first, "Unexpected tactic"}}}
			want := []string{first, last, "Unexpected tactic"}
			if got := attack.CollectUniqueTactics(techniques, matrix.TacticOrder); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s tactics = %v; want %v", matrix.Name, got, want)
			}
			known, unknown := attack.ValidateTactics(techniques, matrix.TacticOrder)
			if len(known) != 2 || !reflect.DeepEqual(unknown, []string{"Unexpected tactic"}) {
				t.Fatalf("%s known = %v, unknown = %v", matrix.Name, known, unknown)
			}
		})
	}
}
