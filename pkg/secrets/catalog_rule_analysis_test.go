package secrets

import (
	"regexp"
	"regexp/syntax"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExactLiteralAlternativesRequireRequestSeparators(t *testing.T) {
	parsed, err := syntax.Parse(auditedProviderRequestPattern2, syntax.Perl)
	require.NoError(t, err)
	reference := regexp.MustCompile(auditedProviderRequestPattern2)
	alternatives := requiredExactLiteralAlternatives(parsed)
	embedded := "界 curlish GETTING POSTED PUTATIVE PATCHWORK DELETED HEADER OPTIONSX"
	require.False(t, reference.MatchString(embedded))
	require.True(t, literalAlternativesPossible(embedded, requiredLiteralAlternatives(parsed), &keywordHits{nonASCII: true}))
	require.False(t, literalAlternativesPossible(embedded, alternatives, &keywordHits{nonASCII: true}))
	for _, method := range []string{"curl", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			for _, separator := range []string{" ", "\t\t"} {
				value := "\xff界 " + method + separator + "/public\nHeader: public"
				require.True(t, reference.MatchString(value))
				require.True(t, literalAlternativesPossible(value, alternatives, &keywordHits{nonASCII: true}))
			}
		})
	}
}

func TestExactLiteralAlternativesPreserveFullScanCatalogFindings(t *testing.T) {
	fixtures := nativeCatalogFixtures(t)
	for _, spec := range nativeRuleSpecs {
		switch spec.ID {
		case "duo-integration-secret-pair", "upstash-redis-rest-token", "snowflake-programmatic-access-token":
		default:
			continue
		}
		t.Run(spec.ID, func(t *testing.T) {
			parsed, err := syntax.Parse(spec.Regex, syntax.Perl)
			require.NoError(t, err)
			alternatives := requiredExactLiteralAlternatives(parsed)
			reference := regexp.MustCompile(spec.Regex)
			catalog, err := compileCatalog([]catalogRuleSpec{spec})
			require.NoError(t, err)
			// Assignment branches require exact markers; generic request
			// branches require a command/method followed by actual whitespace.
			clean := "K ſ public text"
			require.False(t, reference.MatchString(clean))
			require.False(t, literalAlternativesPossible(clean, alternatives, &keywordHits{asciiFoldAlias: true}))
			for group, values := range [][]string{fixtures[spec.ID].Positive, fixtures[spec.ID].Negative} {
				for _, witness := range values {
					for _, context := range []string{"", "K ſ", "\xff界"} {
						value := context + "\n" + witness + "\n" + context
						if reference.MatchString(value) {
							require.True(t, literalAlternativesPossible(value, alternatives, &keywordHits{asciiFoldAlias: true}))
						}
						// The nil-hit oracle bypasses every rejection gate and retains
						// the original capture and contextual-validation decisions.
						want := catalogFindings(catalog, value, false)
						if group == 0 {
							require.True(t, hasRuleFinding(want, spec.ID))
						}
						require.Equal(t, want, catalogFindings(catalog, value, true))
					}
				}
			}
		})
	}
}
