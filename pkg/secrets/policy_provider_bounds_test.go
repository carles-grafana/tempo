package secrets

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestPolicyProviderOversizedAllocationBound(t *testing.T) {
	for _, field := range []string{"custom-rules", "disabled-rules"} {
		t.Run(field, func(t *testing.T) {
			none := []string{}
			compiler, err := NewPolicyCompiler(&none)
			require.NoError(t, err)
			var input *Policy
			providers := make([]CompiledPolicyProvider, 8)
			for i := range providers {
				providers[i] = compiler.NewCompiledPolicyProvider(fmt.Sprint(i), func(string) (*Policy, bool) {
					return input, true
				}, log.NewNopLogger())
				_, ok := providers[i](context.Background())
				require.True(t, ok)
			}
			input = &Policy{}
			if field == "custom-rules" {
				input.CustomRules = make([]CustomRule, 1<<16)
			} else {
				input.DisabledRules = make([]string, 1<<16)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for _, provider := range providers {
				for range 3 {
					if _, ok := provider(context.Background()); !ok {
						t.Fatal("oversized policy lost its fallback")
					}
				}
			}
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(providers)
			runtime.KeepAlive(input)
			// Copying either input per provider exhausts this generous total
			// budget. Rejecting an inherited policy must not multiply its
			// payload by the number of tenants that read it.
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20))
		})
	}
}

func TestPolicyProviderOversizedPayloadNotRetained(t *testing.T) {
	none := []string{}
	compiler, err := NewPolicyCompiler(&none)
	require.NoError(t, err)
	var input *Policy
	provider := compiler.NewCompiledPolicyProvider("idle-tenant", func(string) (*Policy, bool) {
		return input, false
	}, log.NewNopLogger())
	_, ok := provider(context.Background())
	require.True(t, ok)
	// Drain both sync.Pool generations so discarded scratch from earlier
	// tests cannot mask retention of this payload in the full package suite.
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	input = &Policy{CustomRules: []CustomRule{
		{ID: "invalid ID", Regex: "SMALL"},
		{ID: "large", Regex: strings.Repeat("x", 32<<20)},
	}}
	_, ok = provider(context.Background())
	require.True(t, ok)
	// The earlier semantic error must not hide the later byte-limit violation.
	// Dropping the source must release the payload even if this provider is
	// never called again; rejection memory must not keep discarded data alive.
	input = nil
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(provider)
	require.Less(t, after.HeapAlloc, before.HeapAlloc+8<<20)
}

func TestPolicyProviderOversizedRejectionLifecycle(t *testing.T) {
	none := []string{}
	compiler, err := NewPolicyCompiler(&none)
	require.NoError(t, err)
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprintf("last-good-%t", initialized), func(t *testing.T) {
			source := &dynamicPolicySource{}
			provider, _ := newDynamicTestProvider(source)
			provider.compile = compiler.CompilePolicy
			if initialized {
				source.set(dynamicPolicy("DYNAMIC-OLD"), false)
				_, ok := provider.current(context.Background())
				require.True(t, ok)
			}
			oversized := []Policy{
				{CustomRules: make([]CustomRule, maxPolicyCustomRules+1)},
				{DisabledRules: make([]string, len(nativeRuleSpecs)+1)},
				{DisabledRules: []string{strings.Repeat("x", maxPolicyStringLength+1)}},
				{CustomRules: []CustomRule{{ID: strings.Repeat("x", maxPolicyStringLength+1), Regex: "DYNAMIC-NEW"}}},
				{CustomRules: []CustomRule{{ID: "new", Regex: strings.Repeat("x", maxCustomRegexLength+1)}}},
			}
			for i := range oversized {
				source.set(&oversized[i], true)
				for range 2 {
					compiled, ok := provider.current(context.Background())
					require.True(t, ok)
					require.Equal(t, initialized, compiled.Detect("DYNAMIC-OLD").Matched())
					require.False(t, compiled.Detect("DYNAMIC-NEW").Matched())
				}
			}
			require.Equal(t, 1.0, testutil.ToFloat64(provider.metrics.rejected), "one continuous oversized rejection episode")

			// Bounded but invalid inputs keep per-input rejection behavior.
			source.set(dynamicPolicy("("), false)
			_, ok := provider.current(context.Background())
			require.True(t, ok)
			source.set(dynamicPolicy("["), false)
			_, ok = provider.current(context.Background())
			require.True(t, ok)
			require.Equal(t, 3.0, testutil.ToFloat64(provider.metrics.rejected))

			// Correcting an input is never hidden by the oversized marker.
			source.set(dynamicPolicy("DYNAMIC-NEW"), false)
			recovered, ok := provider.current(context.Background())
			require.True(t, ok)
			require.True(t, recovered.Detect("DYNAMIC-NEW").Matched())
			require.False(t, recovered.Detect("DYNAMIC-OLD").Matched())
			source.set(&oversized[0], false)
			retained, ok := provider.current(context.Background())
			require.True(t, ok)
			require.True(t, retained.Detect("DYNAMIC-NEW").Matched())
			require.Equal(t, 4.0, testutil.ToFloat64(provider.metrics.rejected))
			source.set(nil, true)
			baseline, ok := provider.current(context.Background())
			require.True(t, ok)
			require.False(t, baseline.Detect("DYNAMIC-NEW").Matched())
			require.True(t, retained.Detect("DYNAMIC-NEW").Matched())
		})
	}
}
