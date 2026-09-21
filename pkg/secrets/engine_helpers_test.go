package secrets

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic catalogs isolate algorithm contracts from changing provider inventories.
func compileTestCatalog(t testing.TB, specs ...catalogRuleSpec) *compiledCatalog {
	t.Helper()
	catalog, err := compileCatalog(specs)
	require.NoError(t, err)
	return catalog
}

// Isolated filter tests omit keyword hints so they exercise whole-value evaluation.
func compileTestRule(t testing.TB, spec catalogRuleSpec) compiledRule {
	t.Helper()
	compiler, err := newRuleCompiler(spec.Regex, regexp.Compile)
	require.NoError(t, err)
	rule, err := compiler.compile(spec, nil)
	require.NoError(t, err)
	return rule
}

// catalogFindings evaluates every catalog rule against value, either with keyword-guided
// evaluation or with the reference whole-value scan.
func catalogFindings(catalog *compiledCatalog, value string, guided bool) []Match {
	return selectedCatalogFindings(catalog, value, guided, catalog.all, allRuleMatches)
}

// Keep the complete matcher, global hit budget, and original rule indices even
// when checking one rule. Generated per-rule probes must not rescan every
// unrelated regexp quadratically as the catalog grows.
func selectedCatalogFindings(catalog *compiledCatalog, value string, guided bool, selected ruleSet, mode evaluationMode) []Match {
	if !guided {
		return evaluateRuleSet(catalog.rules, selected, value, nil, mode, nil)
	}
	var hits keywordHits
	defer hits.release()
	hits.reset(&catalog.guided, &catalog.boundary)
	var candidates ruleSet
	catalog.pairMatcher.matchHits(value, &candidates, &hits)
	hits.sort()
	candidates.merge(catalog.keywordless)
	return evaluateRuleSet(catalog.rules, candidates.intersect(selected), value, &hits, mode, nil)
}

func assertKeywordGuidedMatchesFullScan(t testing.TB, catalog *compiledCatalog, value string) []Match {
	reference := catalogFindings(catalog, value, false)
	guided := catalogFindings(catalog, value, true)
	if !assert.Equal(t, reference, guided, "value %q", value) {
		t.FailNow()
	}
	// Keep the raw multiplicity comparison above and independently check the
	// production consumer's ordered unique-ID projection, including existence mode.
	policy := CompiledPolicy{catalog: catalog}
	if !assert.Equal(t, uniqueFindingVerdict(reference), policy.Detect(value), "verdict for %q", value) {
		t.FailNow()
	}
	return reference
}

// generateASCII writes a random ASCII string that follows the structure of the expression.
// Zero-width assertions are ignored, so the result is a probe rather than a guaranteed match.
func generateASCII(builder *strings.Builder, re *syntax.Regexp, rng *rand.Rand) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= 0x80 {
				continue
			}
			value := byte(r)
			if re.Flags&syntax.FoldCase != 0 && rng.Intn(2) == 0 {
				switch {
				case value >= 'a' && value <= 'z':
					value -= 'a' - 'A'
				case value >= 'A' && value <= 'Z':
					value += 'a' - 'A'
				}
			}
			builder.WriteByte(value)
		}
	case syntax.OpCharClass:
		var members []byte
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1] && r < 0x80; r++ {
				members = append(members, byte(r))
			}
		}
		if len(members) == 0 {
			builder.WriteByte('x')
			return
		}
		builder.WriteByte(members[rng.Intn(len(members))])
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		builder.WriteByte(byte(' ' + rng.Intn(95)))
	case syntax.OpCapture:
		generateASCII(builder, re.Sub[0], rng)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			generateASCII(builder, sub, rng)
		}
	case syntax.OpAlternate:
		generateASCII(builder, re.Sub[rng.Intn(len(re.Sub))], rng)
	case syntax.OpQuest:
		if rng.Intn(2) == 0 {
			generateASCII(builder, re.Sub[0], rng)
		}
	case syntax.OpStar, syntax.OpPlus:
		count := rng.Intn(4)
		if re.Op == syntax.OpPlus {
			count++
		}
		for range count {
			generateASCII(builder, re.Sub[0], rng)
		}
	case syntax.OpRepeat:
		count := re.Min
		switch {
		case re.Max < 0:
			count += rng.Intn(4)
		case re.Max > re.Min && rng.Intn(8) == 0:
			count = re.Max
		case re.Max > re.Min:
			count += rng.Intn(min(re.Max-re.Min, 3) + 1)
		}
		for range count {
			generateASCII(builder, re.Sub[0], rng)
		}
	}
}

func generateProbe(re *syntax.Regexp, rng *rand.Rand) string {
	var builder strings.Builder
	generateASCII(&builder, re, rng)
	return builder.String()
}

// These cases are independent of regex witness generation and optimization plan
// fields. Expected IDs include every occurrence, in catalog order; the public
// contract is their ordered unique projection. Failure messages never print values.
func assertOptimizerHoldout(t testing.TB, policy *CompiledPolicy, value string, ids []string) {
	t.Helper()
	var want []Match
	for _, id := range ids {
		want = append(want, Match{RuleID: id})
	}
	require.Equal(t, want, catalogFindings(policy.catalog, value, false), "unfiltered finding sequence")
	require.Equal(t, want, catalogFindings(policy.catalog, value, true), "optimized finding sequence")
	verdict := uniqueFindingVerdict(want)
	require.Equal(t, verdict, policy.Detect(value), "direct verdict")
	batch := policy.NewBatchDetector()
	require.Equal(t, verdict, batch.Detect(value), "batch miss verdict")
	require.Equal(t, verdict, batch.Detect(value), "batch hit verdict")
}

func uniqueFindingVerdict(findings []Match) Verdict {
	var verdict Verdict
	seen := make(map[string]bool)
	for _, finding := range findings {
		if !seen[finding.RuleID] {
			seen[finding.RuleID] = true
			verdict.Matches = append(verdict.Matches, finding)
		}
	}
	return verdict
}

func fullScanPolicyVerdict(policy *CompiledPolicy, value string) Verdict {
	var findings []Match
	for i := range policy.catalog.rules {
		if !policy.disabled.has(uint16(i)) {
			findings = policy.catalog.rules[i].detect(value, findings)
		}
	}
	for i := range policy.custom.rules {
		findings = policy.custom.rules[i].detect(value, findings)
	}
	return uniqueFindingVerdict(findings)
}

type policyVerdictProbe struct {
	name    string
	value   string
	ruleIDs []string
}
