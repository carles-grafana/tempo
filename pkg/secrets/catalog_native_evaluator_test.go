package secrets

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func catalogMatcherKeywords() []matcherKeyword {
	keywords := make([]matcherKeyword, 0, len(nativeRuleSpecs)*2)
	for index, spec := range nativeRuleSpecs {
		if spec.Regex == "" {
			continue
		}
		for _, keyword := range effectiveKeywords(spec) {
			keywords = append(keywords, matcherKeyword{value: keyword, rule: uint16(index)})
		}
	}
	return keywords
}

func TestDerivedKeywordsAreRequiredByGeneratedMatches(t *testing.T) {
	for _, spec := range nativeRuleSpecs {
		t.Run(spec.ID, func(t *testing.T) {
			parsed, err := syntax.Parse(spec.Regex, syntax.Perl)
			require.NoError(t, err)

			configured := make([]string, 0, len(spec.Keywords))
			for _, keyword := range spec.Keywords {
				configured = append(configured, strings.ToLower(keyword))
			}
			keywords := effectiveKeywords(spec)
			if consumesKeyword(parsed, configured) || slices.Equal(keywords, spec.Keywords) {
				return
			}

			re, err := regexp.Compile(spec.Regex)
			require.NoError(t, err)
			rng := rand.New(rand.NewSource(catalogWitnessSeed(spec.ID)))
			matches := 0
			for range 40 {
				probe := generateProbe(parsed, rng)
				if !re.MatchString(probe) {
					continue
				}
				matches++
				assert.Truef(
					t,
					containsAnyKeyword(strings.ToLower(probe), keywords),
					"matching probe %q does not contain a derived keyword %q",
					probe,
					keywords,
				)
			}
			assert.NotZero(t, matches, "generated probes did not exercise the derived keyword")
		})
	}
}

func TestNativeCatalogMatcherMatchesReference(t *testing.T) {
	catalog := testNativeCatalog(t)
	reference, err := newKeywordMatcher(catalogMatcherKeywords())
	require.NoError(t, err)
	for index, spec := range nativeRuleSpecs {
		if spec.Regex == "" {
			continue
		}
		for _, keyword := range effectiveKeywords(spec) {
			var ahoCandidates, pairCandidates ruleSet
			value := strings.ToUpper(keyword)
			reference.match(value, &ahoCandidates)
			catalog.pairMatcher.match(value, &pairCandidates)
			assert.Truef(t, ahoCandidates.has(uint16(index)), "Aho-Corasick did not select rule %q keyword %q", spec.ID, keyword)
			assert.Equalf(t, ahoCandidates, pairCandidates, "pair matcher differed for rule %q keyword %q", spec.ID, keyword)
		}
	}
}

func TestGenericAPIKeyCandidateFilters(t *testing.T) {
	policy := &CompiledPolicy{catalog: compileTestCatalog(t, genericRuleSpecs...)}
	const body = "r9Q2m7V4x1Z8c6B3n0H5j2L9p4T7w8Y1"
	const assigned = `api_key="` + body + `"`
	for _, probe := range []struct {
		name  string
		value string
		valid bool
	}{
		{name: "unknown-assigned", value: assigned, valid: true},
		{name: "misleading-keyword-in-optional-prefix", value: "api" + strings.Repeat("z", 30) + assigned, valid: true},
		{name: "valid-candidate-beyond-filter-lookahead", value: `api_key="` + strings.Repeat(body, 16) + `"`, valid: true},
		{name: "lob-shaped-generic-only", value: `api_key="live_` + `7d42b1e960acf8352ed4a697bc0138fe592"`, valid: true},
		{name: "bare-candidate", value: body},
		{name: "low-entropy", value: `api_key="` + `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`},
		{name: "secret-identifier", value: `api_key="` + `QwErTyUiOpAsDfGhJkLzXcVbNm"`},
		{name: "match-identifier", value: `primary_key="` + body + `"`},
		{name: "secret-stopword", value: `api_key="` + body + `example"`},
		{name: "global-secret-regex", value: `api_key="true` + body + `"`},
		{name: "global-stopword", value: `api_key="` + `014df517-39d1-4453-b7b3-9930c563627c"`},
		{name: "distant-line-context", value: assigned + strings.Repeat(" ", 1024) + "--mount=type=secret,"},
		{name: "import-line-context", value: `import { publicName } from 'module'; ` + assigned},
		{name: "later-candidate", value: `primary_key="` + body + `" ` + assigned, valid: true},
		{name: "following-line-not-context", value: assigned + "\n--mount=type=secret,", valid: true},
		{name: "terminated-line-not-prefix", value: "--mount=type=secret,\n" + assigned + "\n", valid: true},
		{name: "unterminated-line-retains-prefix", value: "--mount=type=secret,\n" + assigned},
		{name: "multiline-final-line-truncation", value: "api_key=\n\"" + body + "\" --mount=type=secret,", valid: true},
		{name: "unrelated-unicode-around-ascii-match", value: "café " + assigned + " 東京", valid: true},
		{name: "folded-unicode-keyword", value: "ſecret=\"" + body + "\"", valid: true},
		{name: "folded-unicode-identifier-prefix", value: "K" + assigned, valid: true},
		{name: "filtered-line-followed-by-valid", value: strings.Repeat(assigned+" ", 8) + "--mount=type=secret,\n" + assigned + "\n", valid: true},
		{name: "multiline-rejection-does-not-hide-later-line", value: "api_key=\n\"" + body + "\" --mount=type=secret,\n" + assigned + "\n", valid: true},
		{name: "rejected-range-still-consumes-cross-line-match", value: assigned + " --mount=type=secret, api_key=\napi_key=" + body + "\n"},
		{name: "overflowed-keywords-find-final-candidate", value: strings.Repeat("API KEY ", 256) + assigned, valid: true},
		{name: "overflowed-unicode-keywords-find-final-candidate", value: strings.Repeat("café API KEY 東京 ", 256) + assigned, valid: true},
		{name: "overflowed-filtered-line-followed-by-valid", value: strings.Repeat(assigned+" ", 160) + "--mount=type=secret,\n" + assigned + "\n", valid: true},
		{name: "overflowed-rejected-range-consumes-cross-line-match", value: strings.Repeat(assigned+" ", 160) + "--mount=type=secret, api_key=\napi_key=" + body + "\n"},
		{name: "path-evidence-absent", value: `LICENSE = "` + assigned, valid: true},
		{name: "inline-directive-is-telemetry", value: assigned + " # gitleaks:allow", valid: true},
	} {
		t.Run(probe.name, func(t *testing.T) {
			var ids []string
			if probe.valid {
				ids = []string{"generic-api-key"}
			}
			assertOptimizerHoldout(t, policy, probe.value, ids)
		})
	}
}

func TestGenericExclusionFiltersPreserveRegexpSemantics(t *testing.T) {
	values := []string{
		"", "true", "true1", "1false2", "1null", "null1", "primary_key=value",
		"access_id=value", "secret_size=32", "keyfile", "MONKEY", "MoNkEy",
		"Keyfile", "ſecret_size", "İD", "\xffkeyfile", "ékeyfile東京",
		"A=\nB=", "A=\nB=\n", "A=\nB=x", "a=\nb=", "A=\nb=",
		"${TOKEN}", "{{ value }}", "$12", "/Users/test/path", "abc.123",
	}
	for _, fixture := range nativeCatalogFixtures(t) {
		values = append(values, fixture.Positive...)
		values = append(values, fixture.Negative...)
	}
	for _, test := range []struct{ name, pattern string }{
		{"secret", genericSecretFilterRegex},
		{"match", genericMatchFilterRegex},
		{"assertions-and-flags", `(?i:^key$)|(?-i:^TOKEN$)|secret\z`},
		{"dfa-limit-fallback", `[ab]*a[ab]{10}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			exact := regexp.MustCompile(test.pattern)
			filter := newGenericExclusionFilter(test.pattern)
			check := func(value string) {
				t.Helper()
				require.Equal(t, exact.MatchString(value), filter.MatchString(value), "exclusion acceptance")
			}
			for _, value := range values {
				check(value)
			}
			parsed, err := syntax.Parse(test.pattern, syntax.Perl)
			require.NoError(t, err)
			branches := []*syntax.Regexp{parsed}
			if parsed.Op == syntax.OpAlternate {
				branches = parsed.Sub
			}
			rng := rand.New(rand.NewSource(71))
			for _, branch := range branches {
				for range 8 {
					value := generateProbe(branch, rng)
					for _, context := range []string{"", "x", "\n", "K", "ſ", "\xff"} {
						check(context + value)
						check(value + context)
					}
				}
			}
		})
	}
}

func TestGenericStopwordsUseLowercaseNotSimpleFold(t *testing.T) {
	for _, probe := range []struct {
		name  string
		value string
	}{
		{name: "ascii-uppercase", value: "EXAMPLE"},
		{name: "long-s-not-ascii-s", value: "ſample"},
		{name: "kelvin-lowercases-to-ascii-k", value: "faKe"},
		{name: "dotted-i-lowercases-to-ascii-i", value: "gİthub"},
		{name: "combining-mark-breaks-substring", value: "sam\u0301ple"},
		{name: "invalid-utf8-keeps-following-match", value: "\xffexAMPle"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			// Independent pinned semantics, not the catalog's simple-fold oracle.
			lower := strings.ToLower(probe.value)
			want := false
			for _, word := range genericStopwords {
				if strings.Contains(lower, word) {
					want = true
					break
				}
			}
			require.Equal(t, want, containsGenericStopword(probe.value), "stopword acceptance")
		})
	}
}

func FuzzCatalogPairMatcherMatchesAhoCorasick(f *testing.F) {
	for _, seed := range []string{
		"clean",
		"AKIA" + "QWERTYUIOPASDFGH",
		"xoxb-" + "1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
		"prefix Key suffix",
		"prefix Σ suffix",
		string([]byte{0xff, 0xfe, 's', 'k'}),
	} {
		f.Add(seed)
	}
	catalog := testNativeCatalog(f)
	reference, err := newKeywordMatcher(catalogMatcherKeywords())
	if err != nil {
		f.Fatal(err)
	}
	for index, spec := range nativeRuleSpecs {
		f.Add(findCatalogRuleWitness(f, catalog, index))
		for _, keyword := range spec.Keywords {
			f.Add("prefix " + strings.ToUpper(keyword) + " suffix")
		}
	}
	f.Fuzz(func(t *testing.T, value string) {
		var ahoCandidates, pairCandidates ruleSet
		reference.match(value, &ahoCandidates)
		catalog.pairMatcher.match(value, &pairCandidates)
		assert.Equal(t, ahoCandidates, pairCandidates)
	})
}

var benchmarkCandidateRules ruleSet

func BenchmarkCatalogCandidateSelection(b *testing.B) {
	catalog := testNativeCatalog(b)
	reference, err := newKeywordMatcher(catalogMatcherKeywords())
	if err != nil {
		b.Fatal(err)
	}
	cases := []struct {
		name  string
		value string
	}{
		{name: "clean-url", value: "https://api.example.com/v1/orders/123456?region=us-east-1"},
		{name: "otel-json", value: `{"service.name":"checkout-api","deployment.environment":"production","http.request.method":"POST","server.address":"api.example.com"}`},
		{name: "kubernetes", value: "k8s.pod.name=checkout-api-7d9f68d4bb-x2klp k8s.namespace.name=production cloud.region=us-east-1"},
		{name: "natural-language", value: "payment authorization failed because the upstream gateway closed the connection before sending a response"},
		{name: "numeric", value: "status=200 duration_ms=17.384 content_length=65536 retry_count=0"},
		{name: "uuid-path", value: "/api/v1/accounts/550e8400-e29b-41d4-a716-446655440000/orders/8f14e45f-ea5e-4d2f-a8f3-c98bc0d81a42"},
		{name: "hex-base64", value: "4bf92f3577b34da6a3ce929d0e0e473600f067aa0ba902b7 SGVsbG8sIFdvcmxkIQ=="},
		{name: "long-clean", value: strings.Repeat("z", 1083)},
		{name: "long-mixed", value: strings.Repeat("Ab9_-zY/", 136)},
		{name: "catalog-match", value: findCatalogRuleWitness(b, catalog, 0)},
	}
	for _, test := range cases {
		b.Run(test.name, func(b *testing.B) {
			for _, strategy := range []struct {
				name  string
				match func(string, *ruleSet)
			}{
				{name: "aho-corasick", match: reference.match},
				{name: "rare-pair", match: catalog.pairMatcher.match},
			} {
				b.Run(strategy.name, func(b *testing.B) {
					var candidates ruleSet
					b.ReportAllocs()
					b.SetBytes(int64(len(test.value)))
					for range b.N {
						candidates = ruleSet{}
						strategy.match(test.value, &candidates)
					}
					benchmarkCandidateRules = candidates
				})
			}
		})
	}
}

func BenchmarkCatalogCandidateStorage(b *testing.B) {
	catalog := testNativeCatalog(b)
	reference, err := newKeywordMatcher(catalogMatcherKeywords())
	if err != nil {
		b.Fatal(err)
	}
	ahoBytes := unsafe.Sizeof(reference) + uintptr(cap(reference.states))*unsafe.Sizeof(matcherState{})
	for _, state := range reference.states {
		ahoBytes += uintptr(cap(state.outputs)) * unsafe.Sizeof(uint16(0))
	}
	ahoBytes += uintptr(cap(reference.unicodeKeywords)) * unsafe.Sizeof(unicodeKeyword{})

	pairBytes := unsafe.Sizeof(*catalog.pairMatcher) + unsafe.Sizeof(asciiFoldTable)
	if catalog.pairMatcher.entryByPair != nil {
		pairBytes += unsafe.Sizeof(*catalog.pairMatcher.entryByPair)
	}
	pairBytes += uintptr(cap(catalog.pairMatcher.compactPairs)) * unsafe.Sizeof(catalogPairEntry{})
	pairBytes += uintptr(cap(catalog.pairMatcher.singleCertificates)) * unsafe.Sizeof(catalogPairCertificate{})
	pairBytes += uintptr(cap(catalog.pairMatcher.collisionGroups)) * unsafe.Sizeof([]catalogPairCertificate{})
	pairBytes += uintptr(cap(catalog.pairMatcher.collisionGuards)) * unsafe.Sizeof(catalogCollisionGuard{})
	for _, group := range catalog.pairMatcher.collisionGroups {
		pairBytes += uintptr(cap(group)) * unsafe.Sizeof(catalogPairCertificate{})
	}
	pairBytes += uintptr(cap(catalog.pairMatcher.duplicateOutputs)) * unsafe.Sizeof(uint16(0))
	if catalog.pairMatcher.singleOutputs != nil {
		pairBytes += unsafe.Sizeof(*catalog.pairMatcher.singleOutputs)
		for _, outputs := range catalog.pairMatcher.singleOutputs {
			pairBytes += uintptr(cap(outputs)) * unsafe.Sizeof(uint16(0))
		}
	}
	pairBytes += uintptr(cap(catalog.pairMatcher.unicodeKeyword)) * unsafe.Sizeof(unicodeKeyword{})

	b.ReportMetric(float64(ahoBytes), "aho-bytes")
	b.ReportMetric(float64(pairBytes), "rare-pair-bytes")
	b.ReportMetric(float64(catalog.pairMatcher.singleCertificateCount), "singleton-pairs")
	b.ReportMetric(float64(len(catalog.pairMatcher.collisionGroups)), "collision-pairs")
	for range b.N {
		benchmarkCandidateRules[0] = uint64(ahoBytes + pairBytes)
	}
}
