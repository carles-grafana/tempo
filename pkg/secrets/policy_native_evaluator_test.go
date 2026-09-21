package secrets

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenericFiltersPreserveSpecificAndCustomFindings(t *testing.T) {
	policy, err := testPolicyCompiler.CompilePolicy(Policy{
		CustomRules: []CustomRule{{
			ID: "custom-generic", Regex: `(ghp_[A-Za-z0-9]{36})`,
		}},
	})
	require.NoError(t, err)
	const body = "r9Q2m7V4x1Z8c6B3n0H5j2L9p4T7w8Y1"
	ordinary := `api_key="ghp_` + body + body[:4] + `"`
	for _, probe := range []struct {
		name    string
		value   string
		generic bool
	}{
		{name: "additional-heuristic", value: ordinary, generic: true},
		{name: "secret-filter-isolation", value: `api_key="ghp_example` + body[:29] + `"`},
		{name: "line-filter-isolation", value: "--mount=type=secret, " + ordinary},
	} {
		t.Run(probe.name, func(t *testing.T) {
			want := Verdict{}
			if probe.generic {
				want.Matches = []Match{{RuleID: "generic-api-key"}}
			}
			want.Matches = append(want.Matches, Match{RuleID: "github-pat"}, Match{RuleID: "custom-generic"})
			require.Equal(t, want, fullScanPolicyVerdict(policy, probe.value), "unfiltered")
			require.Equal(t, want, policy.Detect(probe.value), "direct")
			batch := policy.NewBatchDetector()
			require.Equal(t, want, batch.Detect(probe.value), "batch miss")
			require.Equal(t, want, batch.Detect(probe.value), "batch hit")
		})
	}
}
