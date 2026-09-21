package secrets

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogRejectionFiltersAreSound(t *testing.T) {
	catalog := testNativeCatalog(t)
	contexts := []string{"", " ", "\n", `"`, "'", "=", "x", "_", "-", ".", "key ", "token=", "https://", strings.Repeat("a", 60)}

	for index, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			rule := &catalog.rules[index]
			if rule.filter == nil {
				return // A capped filter is bypassed; the fallback test covers those rules.
			}
			parsed := parseFilterRegexp(t, spec.Regex)
			re := regexp.MustCompile(spec.Regex)
			anchoredRE := regexp.MustCompile(`^(?:` + spec.Regex + `)`)
			rng := rand.New(rand.NewSource(catalogWitnessSeed(spec.ID)))
			probes := append([]string(nil), nativeCatalogFixtures(t)[spec.ID].Positive...)
			for range 200 {
				probes = append(probes, generateProbe(parsed, rng))
			}
			for iteration, probe := range probes {
				left := contexts[(iteration*2)%len(contexts)]
				right := contexts[(iteration*2+1)%len(contexts)]
				values := []string{
					probe,
					left + probe + right,
					probe + left + probe,
					probe[:len(probe)/2] + right + probe,
					probe + "\n" + left + probe + "\n",
					strings.ToUpper(probe),
				}
				for _, value := range values {
					if rule.fallbackFilter != nil && re.MatchString(value) {
						assert.True(t, rule.fallbackFilter.mayMatch(value), "fallback filter rejected a regex match")
					}
					if rule.plan.strategy == strategyAnchored {
						if anchoredRE.MatchString(value) {
							assert.True(t, rule.filter.mayMatchPrefix(value), "prefix filter rejected regex match %q", value)
						}
					} else if re.MatchString(value) {
						assert.True(t, rule.filter.mayMatch(value), "filter rejected regex match %q", value)
					}
				}
			}
		})
	}
}

func TestCatalogRejectionFilterBudgetAndFallback(t *testing.T) {
	catalog := testNativeCatalog(t)

	totalBytes, filtered := 0, 0
	for index := range catalog.rules {
		filter := catalog.rules[index].filter
		if fallback := catalog.rules[index].fallbackFilter; fallback != nil {
			assert.LessOrEqual(t, len(fallback.next), rejectionDFACap*fallback.classes)
			totalBytes += len(fallback.next)*2 + len(fallback.acceptAtEnd)
		}
		if filter == nil {
			witness := findCatalogRuleWitness(t, catalog, index)
			findings := assertCatalogRuleMatchesFullScan(t, catalog, index, witness)
			require.True(t, hasRuleFinding(findings, catalog.rules[index].id), "capped filters must conservatively fall back")
			continue
		}
		filtered++
		assert.LessOrEqual(t, len(filter.next), rejectionDFACap*filter.classes)
		totalBytes += len(filter.next)*2 + len(filter.acceptAtEnd)
	}
	t.Logf("%d primary rejection filters; primary and fallback tables use %d bytes", filtered, totalBytes)
	// Catalog growth may add independent tables. Bound average shared storage
	// per supported rule while the per-filter caps above enforce fallback.
	assert.Less(t, totalBytes, len(catalog.rules)*(16<<10))
}
