package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkDetectionWorkloads measures uncached public detection against the
// unfiltered semantic oracle on the same inputs. The oracle is not a historical
// release baseline. These synthetic workloads deliberately include slow paths;
// they are not a weighted model of production traffic.
func BenchmarkDetectionWorkloads(b *testing.B) {
	policy, err := testPolicyCompiler.CompilePolicy(evaluationCustomPolicy(maxPolicyCustomRules, `tenant_[A-Za-z0-9]{16,40}`))
	require.NoError(b, err)
	benchmarkDetectionWorkloads(b, fmt.Sprintf("custom-%d", maxPolicyCustomRules), policy)
}

func evaluationCustomPolicy(count int, expression string) Policy {
	rules := make([]CustomRule, count)
	for i := range rules {
		rules[i] = CustomRule{ID: fmt.Sprintf("evaluation-%02d", i), Regex: expression}
	}
	return Policy{CustomRules: rules}
}

var benchmarkCompiledPolicy *CompiledPolicy

// Tenant policy compilation reuses the immutable catalog. Shared-plan workloads
// deliberately repeat one expression; distinct workloads compile every rule.
// These synthetic workloads exercise optimization fallback and resource limits,
// not a weighted model of production traffic.
func BenchmarkDetectionCompilation(b *testing.B) {
	_, err := testPolicyCompiler.CompilePolicy(Policy{})
	require.NoError(b, err)
	// Each near-limit rule has 65,000 repeated rune instructions, a ten-byte
	// literal prefix and two terminal instructions: 1,040,192 across 16 rules,
	// below the 1<<20 policy cap. Its 660 source bytes also fit the 4096-byte cap.
	nearLimitRepeats := maxCustomPolicyInstructions / (maxPolicyCustomRules * 1000)
	cases := []struct {
		name       string
		count      int
		expression string
		distinct   bool
	}{
		{name: "warm-catalog"},
		{name: "custom-1", count: 1, expression: `tenant_[A-Za-z0-9]{16,40}`},
		{name: fmt.Sprintf("custom-shared-plan-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: `tenant_[A-Za-z0-9]{16,40}`},
		{name: fmt.Sprintf("dfa-fallback-shared-plan-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: `[ab]*a[ab]{12}!`},
		{name: fmt.Sprintf("nfa-fallback-shared-plan-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: strings.Repeat(`[ab]{1000}`, 5)},
		{name: fmt.Sprintf("custom-distinct-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: `[A-Za-z0-9]{16,40}`, distinct: true},
		{name: fmt.Sprintf("dfa-fallback-distinct-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: `[ab]*a[ab]{12}!`, distinct: true},
		{name: fmt.Sprintf("nfa-fallback-distinct-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: strings.Repeat(`[ab]{1000}`, 5), distinct: true},
		{name: fmt.Sprintf("near-policy-instruction-limit-distinct-%d", maxPolicyCustomRules), count: maxPolicyCustomRules, expression: strings.Repeat(`[ab]{1000}`, nearLimitRepeats), distinct: true},
	}
	for _, test := range cases {
		spec := evaluationCustomPolicy(test.count, test.expression)
		if test.distinct {
			for i := range spec.CustomRules {
				spec.CustomRules[i].Regex = fmt.Sprintf("tenant_%02d_%s", i, test.expression)
			}
		}
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				policy, err := testPolicyCompiler.CompilePolicy(spec)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkCompiledPolicy = policy
			}
		})
	}
}
