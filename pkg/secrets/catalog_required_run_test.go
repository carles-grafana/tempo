package secrets

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogRequiredRunsPreserveWitnesses(t *testing.T) {
	for _, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			parsed, err := syntax.Parse(spec.Regex, syntax.Perl)
			require.NoError(t, err)
			run := requiredASCIIRun(parsed)
			if run.width == 0 {
				return
			}
			for _, witness := range nativeCatalogFixtures(t)[spec.ID].Positive {
				if !run.allowsUnicode || isASCIIKeyword(witness) {
					require.True(t, run.exists(witness), "required run rejected independent positive")
				}
			}
			re := regexp.MustCompile(spec.Regex)
			rng := rand.New(rand.NewSource(catalogWitnessSeed(spec.ID)))
			for range 40 {
				probe := generateProbe(parsed, rng)
				for _, value := range []string{probe, "東京 " + probe + " \xff"} {
					if (!run.allowsUnicode || isASCIIKeyword(value)) && re.MatchString(value) {
						require.True(t, run.exists(value), "%q", value)
					}
				}
			}
		})
	}
}
