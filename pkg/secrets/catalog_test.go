package secrets

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests share the immutable native catalog without depending on policy construction.
var loadTestNativeCatalog = sync.OnceValues(func() (*compiledCatalog, error) {
	return compileCatalog(nativeRuleSpecs)
})

func testNativeCatalog(t testing.TB) *compiledCatalog {
	t.Helper()
	catalog, err := loadTestNativeCatalog()
	require.NoError(t, err)
	return catalog
}

func assertCatalogRuleMatchesFullScan(t testing.TB, catalog *compiledCatalog, index int, value string) []Match {
	t.Helper()
	var selected ruleSet
	selected.add(uint16(index))
	reference := selectedCatalogFindings(catalog, value, false, selected, allRuleMatches)
	guided := selectedCatalogFindings(catalog, value, true, selected, allRuleMatches)
	require.Equal(t, reference, guided, "per-rule multiplicity for %q", value)
	unique := selectedCatalogFindings(catalog, value, true, selected, uniqueRuleMatches)
	require.Equal(t, uniqueFindingVerdict(reference).Matches, unique, "per-rule existence projection for %q", value)
	return reference
}

type nativeCatalogFixture struct {
	ID         string                `json:"id"`
	Positive   []string              `json:"positive"`
	Negative   []string              `json:"negative"`
	Diagnostic []string              `json:"diagnostic,omitempty"`
	Evidence   nativeCatalogEvidence `json:"evidence"`
}

type nativeCatalogEvidence struct {
	Sources       []string `json:"sources"`
	Level         string   `json:"level"`
	Documented    []string `json:"documented"`
	Assumptions   []string `json:"assumptions"`
	FixtureMethod string   `json:"fixture_method"`
}

// The loaded map and its slices are shared read-only by tests, fuzzers and benchmarks.
var loadNativeCatalogFixtures = sync.OnceValues(func() (map[string]nativeCatalogFixture, error) {
	paths, err := filepath.Glob("testdata/catalog/*.json")
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no native catalog fixture shards")
	}
	known := make(map[string]bool, len(nativeRuleSpecs))
	for _, spec := range nativeRuleSpecs {
		if known[spec.ID] {
			return nil, fmt.Errorf("duplicate native catalog ID %q", spec.ID)
		}
		known[spec.ID] = true
	}
	fixtures := make(map[string]nativeCatalogFixture, len(known))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var shard []nativeCatalogFixture
		if err := json.Unmarshal(data, &shard); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		for _, fixture := range shard {
			if !known[fixture.ID] {
				return nil, fmt.Errorf("%s: unknown fixture ID %q", path, fixture.ID)
			}
			if _, exists := fixtures[fixture.ID]; exists {
				return nil, fmt.Errorf("%s: duplicate fixture ID %q", path, fixture.ID)
			}
			if len(fixture.Positive) == 0 || len(fixture.Negative) == 0 {
				return nil, fmt.Errorf("%s: %q requires positive and negative fixtures", path, fixture.ID)
			}
			evidence := fixture.Evidence
			if len(evidence.Sources) == 0 || len(evidence.Documented) == 0 ||
				evidence.Assumptions == nil || strings.TrimSpace(evidence.FixtureMethod) == "" {
				return nil, fmt.Errorf("%s: %q requires an explicit evidence record", path, fixture.ID)
			}
			switch evidence.Level {
			case "generator", "specification", "documented-prefix", "example-only":
			default:
				return nil, fmt.Errorf("%s: %q has an invalid evidence level", path, fixture.ID)
			}
			for _, reference := range evidence.Sources {
				source, err := url.Parse(reference)
				if err != nil || source.Scheme != "https" || source.Host == "" {
					return nil, fmt.Errorf("%s: %q has an invalid evidence source", path, fixture.ID)
				}
			}
			for _, statements := range [][]string{evidence.Documented, evidence.Assumptions} {
				for _, fact := range statements {
					if strings.TrimSpace(fact) == "" {
						return nil, fmt.Errorf("%s: %q has an empty evidence statement", path, fixture.ID)
					}
				}
			}
			fixtures[fixture.ID] = fixture
		}
	}
	for _, spec := range nativeRuleSpecs {
		if _, exists := fixtures[spec.ID]; !exists {
			return nil, fmt.Errorf("missing fixture for native catalog ID %q", spec.ID)
		}
	}
	return fixtures, nil
})

func nativeCatalogFixtures(t testing.TB) map[string]nativeCatalogFixture {
	t.Helper()
	fixtures, err := loadNativeCatalogFixtures()
	require.NoError(t, err)
	return fixtures
}

func TestNativeCatalogNegativeFixtures(t *testing.T) {
	catalog := testNativeCatalog(t)
	fixtures := nativeCatalogFixtures(t)
	for index, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			for i, value := range fixtures[spec.ID].Negative {
				t.Run(fmt.Sprintf("negative-%d", i), func(t *testing.T) {
					findings := assertCatalogRuleMatchesFullScan(t, catalog, index, value)
					require.False(t, hasRuleFinding(findings, spec.ID), "malformed or public fixture was detected")
				})
			}
		})
	}
}

func TestNativeCatalogRejectsPublicAndMalformedIndicators(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, test := range []struct{ name, value string }{
		{"build-digest", "8f3a12b6c9d047e5a1f2b3c4d5e60718293abcde"},
		{"aws-key-id", "AKIA" + "QWERTYUIOPASDFGH"},
		{"twilio-key-sid", "SK" + "0123456789abcdef0123456789abcdef"},
		{"oauth-client-id", "adobe_client_id=" + "0123456789abcdef0123456789abcdef"},
		{"publishable-key", "FLWPUBK_TEST-" + "0123456789abcdef0123456789abcdef-X"},
		{"bedrock-marker", "bedrock-api-key-" + "YmVkcm9jay5hbWF6b25hd3MuY29t"},
		{"slack-lookalike-host", "https://hooksXslackYcom/services/" + "T12345678/B12345678/Ab12Cd34Ef56Gh78Ij90Kl12"},
		{"key-armor-prose", "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("not-a-key!", 10) + "\nKEY-----"},
		{"encoded-jwt-marker", "ZXlKaGJHY2lPaU" + strings.Repeat("A", 80) + "=="},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, Verdict{}, policy.Detect(test.value))
			batch := policy.NewBatchDetector()
			require.Equal(t, Verdict{}, batch.Detect(test.value))
			require.Equal(t, Verdict{}, batch.Detect(test.value))
		})
	}
}

func TestNativeKeywordFoldingPreservesUnicodeRegexMatches(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, value := range []string{
		"AWS_SECRET_ACCESS_KEY=" + "Ab12Cd34Ef56Gh78Ij90" + "Kl12Mn34Op56Qr78St90",
		"aws_ſecret_acceſſ_key=" + "Ab12Cd34Ef56Gh78Ij90" + "Kl12Mn34Op56Qr78St90",
		"AWS_SECRET_ACCESS_KEY=" + "Ab12Cd34Ef56Gh78Ij90" + "Kl12Mn34Op56Qr78St90",
	} {
		want := fullScanPolicyVerdict(policy, value)
		require.Contains(t, want.Matches, Match{RuleID: "aws-secret-access-key"})
		require.Equal(t, want, policy.Detect(value))
		batch := policy.NewBatchDetector()
		require.Equal(t, want, batch.Detect(value))
	}
}

func TestNativeVaultScopeExcludesLegacyPrefixes(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	fixtures := nativeCatalogFixtures(t)
	for _, test := range []struct {
		id, modern, legacy string
	}{
		{"vault-service-token", "hvs.", "s."},
		{"vault-batch-token", "hvb.", "b."},
		{"vault-recovery-token", "hvr.", "r."},
	} {
		t.Run(test.id, func(t *testing.T) {
			value := fixtures[test.id].Positive[0]
			require.True(t, strings.Contains(value, test.modern), "fixture must represent a modern Vault token")
			legacy := strings.Replace(value, test.modern, test.legacy, 1)
			want := Verdict{Matches: []Match{{RuleID: test.id}}}
			require.Equal(t, want, policy.Detect(value))
			// Historic credentials are intentionally outside the native scope;
			// absence of this finding is not a claim that the token is invalid.
			require.False(t, hasRuleFinding(policy.Detect(legacy).Matches, test.id))
			batch := policy.NewBatchDetector()
			require.Equal(t, want, batch.Detect(value))
			require.False(t, hasRuleFinding(batch.Detect(legacy).Matches, test.id))
		})
	}
}

func TestCatalogContainsEveryValueRule(t *testing.T) {
	ids, err := CatalogRuleIDs()
	require.NoError(t, err)
	fixtures := nativeCatalogFixtures(t)
	expected := make([]string, 0, len(fixtures))
	for id := range fixtures {
		expected = append(expected, id)
	}
	slices.Sort(expected)
	assert.Equal(t, expected, ids)
}

func assertNativeFixtureDetection(t *testing.T, policy *CompiledPolicy) {
	t.Helper()
	fixtures := nativeCatalogFixtures(t)

	for _, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			batch := policy.NewBatchDetector()
			for index, value := range fixtures[spec.ID].Positive {
				t.Run(fmt.Sprintf("positive-%d", index), func(t *testing.T) {
					require.Contains(t, policy.Detect(value).Matches, Match{RuleID: spec.ID})
					require.Contains(t, batch.Detect(value).Matches, Match{RuleID: spec.ID})
					require.Contains(t, batch.Detect(value).Matches, Match{RuleID: spec.ID})
				})
			}
			for index, value := range fixtures[spec.ID].Negative {
				t.Run(fmt.Sprintf("negative-%d", index), func(t *testing.T) {
					require.False(t, hasRuleFinding(policy.Detect(value).Matches, spec.ID))
					require.False(t, hasRuleFinding(batch.Detect(value).Matches, spec.ID))
				})
			}
		})
	}
}

func TestNativeCatalogDetectsEveryFixture(t *testing.T) {
	assertNativeFixtureDetection(t, &CompiledPolicy{catalog: testNativeCatalog(t)})
}

func assertNativeCatalogBoundaryVerdict(t *testing.T, policy *CompiledPolicy, id, value string, accepted bool) {
	t.Helper()
	index := slices.IndexFunc(nativeRuleSpecs, func(spec catalogRuleSpec) bool { return spec.ID == id })
	require.NotEqual(t, -1, index)
	var want []Match
	if accepted {
		want = []Match{{RuleID: id}}
	}
	// Assert the full-scan multiplicity, not just agreement between two paths
	// that could both miss the candidate. The shared helper also checks the
	// keyword-guided and unique-rule projections.
	require.Equal(t, want, assertCatalogRuleMatchesFullScan(t, policy.catalog, index, value))
	require.Equal(t, accepted, hasRuleFinding(policy.Detect(value).Matches, id))
	batch := policy.NewBatchDetector()
	require.Equal(t, accepted, hasRuleFinding(batch.Detect(value).Matches, id))
}

func TestNativeCatalogFindsCandidateAfterRejectedNeighbor(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	const butter = "l2j0hyfwdubs9q7o5m3k1izgxevctar8p6n4l2j0"
	const mistral = "q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3"
	const robinhoodID = "rh-api-d8a41f9c-2e67-4b05-a19d-8c4e720f63b5"
	const robinhoodKey = "CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYY="
	const cloudsmith = "csa_21f12c72783f3636e03720cfa310f4rAW9SV"
	for _, test := range []struct {
		name, id, rejected, separator, supported string
	}{
		{
			"plain-assignment", "buttercms-write-token",
			"BUTTER_WRITE_TOKEN=" + strings.Repeat("x", 40), "\n",
			"BUTTER_WRITE_TOKEN=" + butter,
		},
		{
			"double-quoted-field", "mistral-api-key",
			`"MISTRAL_API_KEY":"` + strings.Repeat("x", 32) + `"`, "\n",
			`"MISTRAL_API_KEY":"` + mistral + `"`,
		},
		{
			"single-quoted-field", "mistral-api-key",
			`'MISTRAL_API_KEY':'` + strings.Repeat("x", 32) + `'`, ";",
			`'MISTRAL_API_KEY':'` + mistral + `'`,
		},
		{
			"entropy-rejected-assignment", "abuseipdb-api-key-assignment",
			`ABUSEIPDB_API_KEY="` + strings.Repeat("a", 80) + `"`, "\n",
			`ABUSEIPDB_API_KEY="af6bffd88236b7baa2f05c50d2640607cb64d77fe5a16b7ba1e0d456e46392d2ddc8f251ef9b95fb"`,
		},
		{
			"paired-id-first", "robinhood-crypto-credentials",
			"ROBINHOOD_API_KEY=" + robinhoodID + "; ROBINHOOD_PRIVATE_KEY=" + strings.Repeat("x", 43) + "=", "\n",
			"ROBINHOOD_API_KEY=" + robinhoodID + "; ROBINHOOD_PRIVATE_KEY=" + robinhoodKey,
		},
		{
			"paired-quoted-secret-first", "robinhood-crypto-credentials",
			`"ROBINHOOD_PRIVATE_KEY":"` + strings.Repeat("x", 43) + `="; "ROBINHOOD_API_KEY":"` + robinhoodID + `"`, "\n",
			`"ROBINHOOD_PRIVATE_KEY":"` + robinhoodKey + `"; "ROBINHOOD_API_KEY":"` + robinhoodID + `"`,
		},
		{
			"top-level-assignment-alternative", "knapsack-pro-test-suite-token",
			"KNAPSACK_PRO_TEST_SUITE_TOKEN=" + strings.Repeat("x", 32), "\n",
			`"KNAPSACK_PRO_TEST_SUITE_TOKEN_RSPEC":"9e71a6d4c2f0853b6a98d104efc57230"`,
		},
		{
			"non-word-option", "redhat-pyxis-api-token-option",
			"--pyxis-api-token=" + strings.Repeat("x", 32), "\n",
			"--pyxis-api-token=d72c39a6e85b04f19c63a02e75d918bf",
		},
		{
			"standalone-cloudsmith-alternative", "cloudsmith-api-key",
			`CLOUDSMITH_API_KEY="` + strings.Repeat("a", 40), "\n",
			cloudsmith,
		},
		{
			"quoted-curl", "qase-api-token-request",
			"curl 'https://api.qase.io/v1/user' --header 'Token: " + strings.Repeat("x", 40) + "'", "\n",
			"curl 'https://api.qase.io/v1/user' --header 'Token: HatCVo7Qj2LexGZsBUn6Pi1KdwFYrATm5Oh0JcvE'",
		},
		{
			"provider-url", "gyazo-access-token-url",
			"https://api.gyazo.com/api/images?access_token=" + strings.Repeat("x", 43), "\n",
			"https://api.gyazo.com/api/images?access_token=Q7m2Z9v4K1r8T6x3B5n0A2c7D9e4F1g8H6j3L5p0R2s",
		},
		{
			"non-word-token", "asaas-api-token",
			"$aact_prod_" + strings.Repeat("x", 32), " ",
			"$aact_prod_26SmXkqPr2fkx-o7yZzK3Es8rbALNtWikIkAlGeXNDm2ZFy33FTZ",
		},
		{
			"standalone-token", "midtrans-server-key",
			"Mid-server-" + strings.Repeat("x", 18), "\n",
			"Mid-server-WusSHfFCDsSexT0s2e",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertNativeCatalogBoundaryVerdict(t, policy, test.id, test.rejected, false)
			assertNativeCatalogBoundaryVerdict(t, policy, test.id, test.supported, true)
			// The rejected match consumes this one separator as its right
			// boundary; the following match must not need to consume it again.
			assertNativeCatalogBoundaryVerdict(t, policy, test.id, test.rejected+test.separator+test.supported, true)
		})
	}
}

func TestNativeCatalogPreservesLeftBoundaryScopes(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	const butter = "BUTTER_WRITE_TOKEN=l2j0hyfwdubs9q7o5m3k1izgxevctar8p6n4l2j0"
	const mistral = `"MISTRAL_API_KEY":"q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3"`
	const cloudsmith = "csa_21f12c72783f3636e03720cfa310f4rAW9SV"
	const gyazo = "https://api.gyazo.com/api/images?access_token=Q7m2Z9v4K1r8T6x3B5n0A2c7D9e4F1g8H6j3L5p0R2s"
	for _, test := range []struct {
		name, id, value string
		accepted        bool
	}{
		{"identifier-continuation", "buttercms-write-token", "prefix" + butter, false},
		{"digit-continuation", "buttercms-write-token", "7" + butter, false},
		{"underscore-continuation", "buttercms-write-token", "_" + butter, false},
		{"member-continuation", "buttercms-write-token", "." + butter, false},
		{"hyphen-continuation", "buttercms-write-token", "-" + butter, false},
		{"double-quoted-member", "mistral-api-key", "." + mistral, false},
		{"single-quoted-member", "mistral-api-key", `.'MISTRAL_API_KEY':'q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3'`, false},
		{"quoted-field-after-delimiter", "mistral-api-key", "{" + mistral + "}", true},
		{"paired-identifier-continuation", "robinhood-crypto-credentials", "_ROBINHOOD_API_KEY=rh-api-d8a41f9c-2e67-4b05-a19d-8c4e720f63b5; ROBINHOOD_PRIVATE_KEY=CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYY=", false},
		{"paired-quoted-member", "robinhood-crypto-credentials", `."ROBINHOOD_PRIVATE_KEY":"CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYY="; "ROBINHOOD_API_KEY":"rh-api-d8a41f9c-2e67-4b05-a19d-8c4e720f63b5"`, false},
		{"quoted-value-expression", "mistral-api-key", mistral + " + suffix", false},
		{"mismatched-value-quote", "mistral-api-key", `MISTRAL_API_KEY="q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3'`, false},
		{"standalone-prefix-member", "cloudsmith-api-key", "." + cloudsmith, false},
		{"standalone-prefix-delimiter", "cloudsmith-api-key", "(" + cloudsmith + ")", true},
		{"url-path-continuation", "gyazo-access-token-url", "/" + gyazo, false},
		{"url-scheme-continuation", "gyazo-access-token-url", ":" + gyazo, false},
		{"url-allowed-punctuation", "gyazo-access-token-url", "+" + gyazo, true},
		{"token-path-continuation", "asaas-api-token", "/$aact_prod_26SmXkqPr2fkx-o7yZzK3Es8rbALNtWikIkAlGeXNDm2ZFy33FTZ", false},
		{"token-plus-continuation", "midtrans-server-key", "+Mid-server-WusSHfFCDsSexT0s2e", false},
		{"option-identifier-continuation", "redhat-pyxis-api-token-option", "prefix--pyxis-api-token=d72c39a6e85b04f19c63a02e75d918bf", false},
		{"non-word-constructor", "powershell-plaintext-credential", `[Net.NetworkCredential]::new("operator", "R8!canvas slate")`, true},
		{"folded-unicode-word-start", "signalwire-api-token", "ſIGNALWIRE_API_TOKEN=HatCVo7Qj2LexGZsBUn6Pi1KdwFYrATm5Oh0JcvEXq9Sl4NgzI", true},
		{"folded-unicode-member", "signalwire-api-token", ".ſIGNALWIRE_API_TOKEN=HatCVo7Qj2LexGZsBUn6Pi1KdwFYrATm5Oh0JcvEXq9Sl4NgzI", false},
		{"unchanged-dropbox-prefix-scope", "dropbox-access-token", ".sl." + strings.Repeat("a", 130), true},
		{"unchanged-vercel-prefix-scope", "vercel-access-token", ".vci_" + strings.Repeat("a", 56), true},
		{"unchanged-facebook-secret-scope", "facebook-app-secret", ".FACEBOOK_APP_SECRET=Q7M2V9C4X6N8B3K5S1D0F2H4J6R8T9W3", true},
		{"facebook-access-token-member", "facebook-app-secret", `.FB_APP_ACCESS_TOKEN="123456789012345|Q7M2V9C4X6N8B3K5S1D0F2H4J6R8T9W3"`, false},
		{"unchanged-vonage-url-scope", "vonage-api-credentials", ".https://rest.nexmo.com/account/get-balance?api_key=q7m2v9c4&api_secret=q7m2v9c4x6n8b3k5", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertNativeCatalogBoundaryVerdict(t, policy, test.id, test.value, test.accepted)
		})
	}
}
