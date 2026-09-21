package secrets

import (
	"fmt"
	"math/rand"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogEvaluationPreservesFixtureContexts(t *testing.T) {
	catalog := testNativeCatalog(t)
	fixtures := nativeCatalogFixtures(t)
	for index, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			witness := findCatalogRuleWitness(t, catalog, index)
			for _, value := range []string{
				witness,
				" " + witness + "\n",
				"\x00" + witness + "\xff",
				witness + "\n" + witness,
				strings.Repeat("~", 8192) + witness,
				fixtures[spec.ID].Negative[0] + "\n" + witness,
			} {
				assertCatalogRuleMatchesFullScan(t, catalog, index, value)
			}
		})
	}
}

func catalogWitnessSeed(id string) int64 {
	const (
		offset = uint64(1469598103934665603)
		prime  = uint64(1099511628211)
	)
	hash := offset
	for i := range len(id) {
		hash = (hash ^ uint64(id[i])) * prime
	}
	return int64(hash)
}

func hasRuleFinding(findings []Match, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func findCatalogRuleWitness(t testing.TB, catalog *compiledCatalog, index int) string {
	t.Helper()
	fixture, ok := nativeCatalogFixtures(t)[catalog.rules[index].id]
	require.True(t, ok, "missing independent fixture for %q", catalog.rules[index].id)
	require.NotEmpty(t, fixture.Positive)
	return fixture.Positive[0]
}

func closestCatalogRuleNegative(t testing.TB, rule *compiledRule, witness string) string {
	t.Helper()
	for removed := 1; removed <= len(witness); removed++ {
		for _, candidate := range []string{witness[:len(witness)-removed], witness[removed:]} {
			if !hasRuleFinding(rule.detect(candidate, nil), rule.id) {
				return candidate
			}
		}
	}
	t.Fatalf("failed to derive negative witness for catalog rule %q", rule.id)
	return ""
}

func TestEveryCatalogRuleHasPositiveWitness(t *testing.T) {
	catalog := testNativeCatalog(t)
	require.Len(t, catalog.rules, len(nativeRuleSpecs))
	fixtures := nativeCatalogFixtures(t)

	for index, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			for fixtureIndex, witness := range fixtures[spec.ID].Positive {
				t.Run(fmt.Sprintf("positive-%d", fixtureIndex), func(t *testing.T) {
					findings := assertCatalogRuleMatchesFullScan(t, catalog, index, witness)
					require.True(t, hasRuleFinding(findings, spec.ID), "independent witness did not detect its catalog rule")
				})
			}
		})
	}
}

func TestCatalogRuleNearMissesMatchFullScan(t *testing.T) {
	catalog := testNativeCatalog(t)

	for index, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			t.Parallel()
			witness := findCatalogRuleWitness(t, catalog, index)
			nearMiss := closestCatalogRuleNegative(t, &catalog.rules[index], witness)
			require.False(t, hasRuleFinding(assertCatalogRuleMatchesFullScan(t, catalog, index, nearMiss), spec.ID))

			for _, value := range []string{
				nearMiss,
				"x" + nearMiss + "x",
				nearMiss + "\n" + nearMiss,
				"\x00" + nearMiss + "\xff",
				strings.ToUpper(nearMiss),
			} {
				assertCatalogRuleMatchesFullScan(t, catalog, index, value)
			}
		})
	}
}

func TestKeywordGuidedEvaluationMatchesFullScan(t *testing.T) {
	catalog := testNativeCatalog(t)
	rng := rand.New(rand.NewSource(1))
	contexts := []string{"", " ", "\n", "\"", "'", "=", "x", "_", "-", ".", "key ", "token=", "ey", "curl ", "api-", "s.", "\t", "ab_", "\\n", ";", "https://", strings.Repeat("a", 60)}
	pick := func() string { return contexts[rng.Intn(len(contexts))] }

	t.Run("rules", func(t *testing.T) {
		for index, spec := range nativeRuleSpecs {
			parsed, err := syntax.Parse(spec.Regex, syntax.Perl)
			require.NoError(t, err, spec.ID)
			values := []string{findCatalogRuleWitness(t, catalog, index)}
			for range 40 {
				probe := generateProbe(parsed, rng)
				values = append(
					values,
					probe,
					pick()+probe+pick(),
					probe+pick()+probe,
					probe[:len(probe)/2]+pick()+probe,
					probe+"\n"+pick()+probe+"\n",
					strings.ToUpper(probe),
				)
			}
			for _, keyword := range spec.Keywords {
				values = append(
					values,
					keyword,
					"x"+keyword+"x",
					" "+keyword+"=abc",
					strings.Repeat("y", 200)+keyword+strings.Repeat("z", 300),
					strings.ToUpper(keyword)+"\n"+keyword+keyword,
				)
			}
			const valueChunkSize = 32
			for start := 0; start < len(values); start += valueChunkSize {
				chunk := values[start:min(start+valueChunkSize, len(values))]
				t.Run(spec.ID, func(t *testing.T) {
					t.Parallel()
					for _, value := range chunk {
						assertCatalogRuleMatchesFullScan(t, catalog, index, value)
					}
				})
			}
		}
	})
}

func TestKeywordGuidedEvaluationEdgeCases(t *testing.T) {
	catalog := testNativeCatalog(t)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	aws := "AKIA" + "QWERTYUIOPASDFGH"
	generic := "secret_key = \"" + strings.Repeat("Zq9", 12) + "\""
	values := []string{
		jwt, "Bearer " + jwt, "x" + jwt, "key" + jwt, jwt + jwt, jwt + " " + jwt, "\n" + jwt + "\n",
		aws, "prefix " + aws + " suffix", aws + "\n" + aws, "AKIA" + aws, strings.Repeat("AKIA", 20),
		generic, strings.Repeat("x", 49) + generic, strings.Repeat("x", 50) + generic, strings.Repeat("x", 51) + generic,
		"passwd=" + strings.Repeat("Ab1", 8) + " " + generic, generic + "\n" + generic,
		"glsa_" + strings.Repeat("A1b2", 8) + "_0a1b2c3d", "xglsa_" + strings.Repeat("A1b2", 8) + "_0a1b2c3d",
		"hvs." + strings.Repeat("Zq9-", 24) + " s." + strings.Repeat("a1", 12) + " status.ok bytes.count",
		"ATATT3" + strings.Repeat("xY", 93) + " confluence=1 atlassian_token=" + strings.Repeat("ab12", 6),
		"the monkey took the key and they left: keyey eyey ey ey",
		strings.Repeat("ey", 100),
		// Windows whose keywords are ordinary text and that lack the rule's other factors.
		"is_public=true test_mode=false live_mode=false",
		strings.Repeat("is_public=true test_mode=false live_mode=false region=us-east-1 ", 14),
		"lob_api_key = test_" + strings.Repeat("a1b2c3d", 5) + " is_public=true",
		"LOB key: live_" + strings.Repeat("0f", 17) + "z live_pub_" + strings.Repeat("9c", 15) + "e",
		"nrii-" + strings.Repeat("aZ", 16) + " New_Relic insert key nrii-" + strings.Repeat("aZ", 16) + " sk-" + strings.Repeat("T3BlbkFJ", 4),
	}
	for _, value := range values {
		assertKeywordGuidedMatchesFullScan(t, catalog, value)
	}
}

func FuzzKeywordGuidedEvaluationMatchesFullScan(f *testing.F) {
	catalog := testNativeCatalog(f)
	seen := make(map[string]bool)
	addSeed := func(value string) {
		if !seen[value] {
			seen[value] = true
			f.Add(value)
		}
	}
	for _, seed := range []string{
		"clean",
		"AKIA" + "QWERTYUIOPASDFGH",
		"xoxb-" + "1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"api_key = \"" + strings.Repeat("Zq9", 12) + "\"",
		"glsa_" + strings.Repeat("A1b2", 8) + "_0a1b2c3d",
		"prefix Σ suffix",
	} {
		addSeed(seed)
	}
	// Keep mutations near every catalog expression, not only the handful of
	// common token formats above. Deterministic tests don't replace fuzz seeds:
	// only seeded or discovered inputs become starting points for new mutations.
	rng := rand.New(rand.NewSource(2))
	for index, spec := range nativeRuleSpecs {
		addSeed(findCatalogRuleWitness(f, catalog, index))
		parsed, err := syntax.Parse(spec.Regex, syntax.Perl)
		require.NoError(f, err, spec.ID)
		addSeed(" " + generateProbe(parsed, rng) + "\n")
		for _, keyword := range spec.Keywords {
			addSeed("x" + strings.ToUpper(keyword) + "=" + keyword)
		}
		for _, keyword := range effectiveKeywords(spec) {
			addSeed(keyword + "\n" + strings.ToUpper(keyword))
		}
	}
	f.Fuzz(func(t *testing.T, value string) {
		t.Parallel()
		assertKeywordGuidedMatchesFullScan(t, catalog, value)
	})
}

func BenchmarkDetectKeywordCollisions(b *testing.B) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(b)}
	sql := strings.Repeat("SELECT id, key, value FROM settings WHERE key = ? AND tenant = ? ORDER BY key; ", 13)
	cases := []struct {
		name   string
		policy *CompiledPolicy
		value  string
	}{
		{name: "clean-url", policy: policy, value: "https://api.example.com/v1/orders/123456?region=us-east-1"},
		{name: "sql-1k-key", policy: policy, value: sql},
		{name: "user-agent-curl", policy: policy, value: "curl/7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0 OpenSSL/1.1.1f zlib/1.2.11 " + strings.Repeat("token ", 40)},
		{name: "pod-name-api", policy: policy, value: "k8s.pod.name=checkout-api-7d9f68d4bb-x2klp k8s.namespace.name=production cloud.region=asia-east1"},
		{name: "json", policy: policy, value: `{"service.name":"checkout-api","auth.mode":"token","http.request.method":"POST","server.address":"api.example.com","secret_ref":"vault://kv/data/keys/checkout"}`},
		{name: "sql-1k", policy: policy, value: sql},
		{name: "catalog-match", policy: policy, value: findCatalogRuleWitness(b, policy.catalog, 0)},
		{name: "decimal-64", policy: policy, value: strings.Repeat("1234567890", 6) + "1234"},
		{name: "hex-2k", policy: policy, value: strings.Repeat("abc012345def6789", 128)},
		{name: "near-runs-2k", policy: policy, value: strings.Repeat("01234567890123~", 140)},
		{name: "repeated-token-prefix-64", policy: policy, value: strings.Repeat("ghp_~~~ ", 8)},
		{name: "repeated-token-prefix-2k", policy: policy, value: strings.Repeat("ghp_~~~ ", 256)},
		{name: "repeated-token-prefix-128k", policy: policy, value: strings.Repeat("ghp_~~~ ", 16384)},
		{name: "mixed-keyword-pressure", policy: policy, value: strings.Repeat("ghp_~~~ ", 256) + findCatalogRuleWitness(b, policy.catalog, 0)},
	}
	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.value)))
			for range b.N {
				benchmarkVerdict = test.policy.Detect(test.value)
			}
		})
	}
}

var benchmarkVerdict Verdict
