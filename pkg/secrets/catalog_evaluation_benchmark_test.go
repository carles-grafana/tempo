package secrets

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func benchmarkDetectionWorkloads(b *testing.B, name string, policy *CompiledPolicy) {
	b.Helper()
	catalog := policy.catalog
	positive := findCatalogRuleWitness(b, catalog, 0)
	var curlPositive string
	for _, value := range nativeCatalogFixtures(b)["madkudu-api-basic-credential"].Positive {
		if strings.HasPrefix(value, "curl ") {
			curlPositive = value
			break
		}
	}
	require.NotEmpty(b, curlPositive)
	var overflow string
	for _, spec := range nativeRuleSpecs {
		nativeIndex, ok := catalog.byID[spec.ID]
		if ok && catalog.guided.has(nativeIndex) {
			overflow = strings.Repeat(effectiveKeywords(spec)[0]+" ", maxKeywordHits+32)
			break
		}
	}
	require.NotEmpty(b, overflow, "overflow workload needs a guided catalog rule")
	values := []struct{ name, value string }{
		{"url", "https://api.example.com/v1/orders/123456?region=us-east-1"},
		{"ascii-128KiB", strings.Repeat("~", 128<<10)},
		{"unicode-4KiB", strings.Repeat("~é~", 1024)},
		{"unicode-keywords-4KiB", strings.Repeat("api é token Σ ", 256)},
		{"invalid-utf8-4KiB", strings.Repeat("\xff~", 2048)},
		{"guided-hit-overflow", overflow},
		{"hex-near-misses-4KiB", strings.Repeat("0123456789abcdef0123456789abcdef012345678~", 100)},
		{"positive", positive},
		{"late-positive-128KiB", strings.Repeat("~", (128<<10)-len(positive)) + positive},
		{"contextual-curl", curlPositive},
		{"contextual-curl-start-128KiB", curlPositive + strings.Repeat("~", (128<<10)-len(curlPositive))},
		{"contextual-curl-late-128KiB", strings.Repeat("~", (128<<10)-len(curlPositive)) + curlPositive},
		{"custom-positive", "tenant_Ab12Cd34Ef56Gh78"},
	}
	for _, valueCase := range values {
		// Check the observed contract before measuring either path. Cache hits
		// and misses have separate existing BatchDetector/processor benchmarks.
		want := fullScanPolicyVerdict(policy, valueCase.value)
		require.Equal(b, want, policy.Detect(valueCase.value), valueCase.name)
		b.Run(name+"/"+valueCase.name+"/optimized", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(valueCase.value)))
			for range b.N {
				benchmarkVerdict = policy.Detect(valueCase.value)
			}
		})
		b.Run(name+"/"+valueCase.name+"/unfiltered", func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(valueCase.value)))
			for range b.N {
				benchmarkVerdict = fullScanPolicyVerdict(policy, valueCase.value)
			}
		})
	}
}

// BenchmarkNativeCatalogWorkloads measures uncached native detection against
// the same unfiltered semantic oracle and synthetic slow-path workloads.
func BenchmarkNativeCatalogWorkloads(b *testing.B) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(b)}
	benchmarkDetectionWorkloads(b, "catalog", policy)
}

// BenchmarkNativeCatalogCompile measures cold construction rather than the
// policy compiler's reuse of the immutable native catalog.
func BenchmarkNativeCatalogCompile(b *testing.B) {
	b.Run("cold-catalog", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			catalog, err := compileNativeCatalog()
			if err != nil {
				b.Fatal(err)
			}
			benchmarkCompiledCatalog = catalog
		}
	})
}

var benchmarkCompiledCatalog *compiledCatalog
