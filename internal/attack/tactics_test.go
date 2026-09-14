package attack

import (
	"reflect"
	"testing"
)

func TestTacticQueriesUseExplicitOrder(t *testing.T) {
	techniques := []Technique{
		{Tactics: []string{"command-and-control", "initial_access", "Zulu", ""}},
		{Tactics: []string{"Initial Access", "alpha", "COMMAND AND CONTROL"}},
	}
	for _, tc := range []struct {
		order []string
		want  []string
	}{
		{[]string{"Initial Access", "Command and Control"}, []string{"Initial Access", "Command and Control", "alpha", "Zulu"}},
		{[]string{"Command and Control", "Initial Access"}, []string{"Command and Control", "Initial Access", "alpha", "Zulu"}},
	} {
		if got := CollectUniqueTactics(techniques, tc.order); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("tactics = %v; want %v", got, tc.want)
		}
	}
	known, unknown := ValidateTactics(techniques, []string{"Initial Access", "Command and Control"})
	if !reflect.DeepEqual(known, []string{"command-and-control", "initial_access"}) || !reflect.DeepEqual(unknown, []string{"alpha", "Zulu"}) {
		t.Fatalf("validation known = %v, unknown = %v", known, unknown)
	}
}
