package secrets

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSingleKeywordGuidancePreservesCatalogEvaluation(t *testing.T) {
	// Retain every native rule, its global index, and the shared hit budget. The
	// added rules exercise single-byte starts, captures, context, and fold aliases
	// without depending on a provider's changing credential syntax.
	specs := append(
		slices.Clone(nativeRuleSpecs),
		catalogRuleSpec{
			ID: "single-guidance-capture", Regex: `\ba:([A-Z0-9]{4})\b`, Keywords: []string{"a"}, SecretGroup: 1, Entropy: 1.5,
			Validate: func(secret string) bool { return secret != "QW12" },
		},
		catalogRuleSpec{ID: "single-guidance-fold", Regex: `(?i)k:([a-z]{4})`, Keywords: []string{"k"}, SecretGroup: 1},
		catalogRuleSpec{ID: "single-guidance-window", Regex: `\b[0-9]{2}=s:([A-Z0-9]{4})\b`, Keywords: []string{"s"}, SecretGroup: 1},
		catalogRuleSpec{
			ID: "single-guidance-context", Regex: `\btoken:([A-Z0-9]{4})\b`, Keywords: []string{"token"}, SecretGroup: 1,
			ValidateContext: func(value string, start, end int, secret string) contextValidation {
				return contextValidation{accepted: strings.HasPrefix(value, "allow ") && value[start:end] == "token:"+secret}
			},
		},
	)
	catalog, err := compileCatalog(specs)
	require.NoError(t, err)
	for _, value := range []string{
		"allow a:AAAA a:QW12 a:AB12 token:CD34 12=s:EF56 k:abcd",
		"allow éa:AB12 πtoken:CD34 12=s:EF56 λk:abcd",
		"allow K:abcd token:CD34 ſ a:AB12",
		"allow \xffa:AB12 \xfetoken:CD34 k:abcd",
		"allow xa:AB12 xtoken:CD34 12=s:EF56",
		"deny a:AB12 token:CD34 k:abcd",
	} {
		assertKeywordGuidedMatchesFullScan(t, catalog, value)
		hits, _ := recordHits(t, catalog, value)
		require.False(t, hits.invalid, "single-byte rules must not disable catalog-wide guidance")
		require.True(t, hits.guides(catalog.byID["single-guidance-context"]))
	}

	// Singleton flooding must fall back for incomplete rules, without losing
	// complete pair-keyword positions or later accepted singleton matches.
	value := "allow token:CD34 " + strings.Repeat("a ", maxKeywordHits+32) + "a:AB12 k:abcd"
	hits, _ := recordHits(t, catalog, value)
	require.False(t, hits.invalid)
	require.False(t, hits.guides(catalog.byID["single-guidance-capture"]))
	require.True(t, hits.guides(catalog.byID["single-guidance-context"]))
	assertKeywordGuidedMatchesFullScan(t, catalog, value)
}
