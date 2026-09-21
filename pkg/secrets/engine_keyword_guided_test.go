package secrets

import (
	"crypto/sha256"
	"math"
	"math/rand"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeywordHitOrderingPreservesRuleAndPosition(t *testing.T) {
	rng := rand.New(rand.NewSource(29))
	for _, count := range []int{0, 1, 31, 32, maxKeywordHits} {
		var buffer keywordHitBuffer
		for i := range count {
			buffer[i] = keywordHit{
				rule:  uint16(rng.Intn(catalogRuleWords * 64)),
				start: uint32(rng.Intn(128)),
				end:   uint32(128 + rng.Intn(128)),
			}
		}
		want := append([]keywordHit(nil), buffer[:count]...)
		slices.SortFunc(want, compareKeywordHits)
		hits := keywordHits{buffer: &buffer, count: count}
		hits.sort()
		require.Equal(t, want, append([]keywordHit(nil), buffer[:count]...))
	}
}

func TestMinRuneWidth(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       int
	}{
		{
			name:       "repeated groups",
			expression: `\d{15,16}(\||%)[0-9a-z\-_]{27,40}`,
			want:       43,
		},
		{
			name:       "fixed character class",
			expression: `[a-fA-F0-9]{40}`,
			want:       40,
		},
		{
			name:       "optional prefix",
			expression: `(?:https?://)?hooks.slack.com/x`,
			want:       17,
		},
		{
			name:       "alternation",
			expression: `a|bcd`,
			want:       1,
		},
		{
			name:       "case-folded literal",
			expression: `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`,
			want:       175,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			re, err := syntax.Parse(test.expression, syntax.Perl)
			require.NoError(t, err)
			assert.Equal(t, test.want, minRuneWidth(re))
		})
	}
}

// recordHits runs candidate selection and records positions only for guided rules.
func recordHits(t *testing.T, catalog *compiledCatalog, value string) (*keywordHits, ruleSet) {
	hits := &keywordHits{}
	t.Cleanup(hits.release)
	hits.reset(&catalog.guided, &catalog.boundary)
	var candidates ruleSet
	catalog.pairMatcher.matchHits(value, &candidates, hits)
	hits.sort()
	return hits, candidates
}

func findingRuleIDs(findings []Match) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.RuleID)
	}
	return ids
}

func TestKeywordGuidedEmptyWindowPreservesUnicodeAlternatives(t *testing.T) {
	catalog, err := compileCatalog([]catalogRuleSpec{{
		ID: "alternative", Regex: `(?:Xtoken|é)`, Keywords: []string{"token"},
	}})
	require.NoError(t, err)
	policy := CompiledPolicy{catalog: catalog}
	batch := policy.NewBatchDetector()
	for _, probe := range []policyVerdictProbe{
		{"keyword-free-ascii", "safe", nil},
		{"unicode-alternative", "é", []string{"alternative"}},
		{"ascii-alternative", "Xtoken", []string{"alternative"}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			var want Verdict
			for _, id := range probe.ruleIDs {
				want.Matches = append(want.Matches, Match{RuleID: id})
			}
			require.Equal(t, want, policy.Detect(probe.value), "direct verdict")
			require.Equal(t, want, batch.Detect(probe.value), "batch miss verdict")
			require.Equal(t, want, batch.Detect(probe.value), "batch hit verdict")
		})
	}
}

func TestKeywordHitOffsetOverflowFallsBackPerRule(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("keyword offsets beyond uint32 cannot fit in int")
	}
	catalog, err := compileCatalog([]catalogRuleSpec{
		{ID: "boundary", Regex: `[kK]ey:[A-Z]{4}\b`, Keywords: []string{"key"}},
		{ID: "complete", Regex: `(?:A|B)tag:[A-Z]{4}\b`, Keywords: []string{"tag"}},
	})
	require.NoError(t, err)
	boundaryRule := catalog.byID["boundary"]
	completeRule := catalog.byID["complete"]
	require.False(t, catalog.boundary.has(boundaryRule), "test storage without indexing a synthetic wide position")
	require.True(t, catalog.guided.has(completeRule), "exercise an independent complete window")
	require.False(t, catalog.boundary.has(completeRule))

	value := strings.Repeat("~", 32) + " key:KEEP Atag:GOOD"
	tagStart := strings.Index(value, "tag")
	maxOffset := uint64(math.MaxUint32)
	for _, test := range []struct {
		name       string
		start, end uint64
	}{
		{"end-overflow", maxOffset - 1, maxOffset + 2},
		{"start-and-end-overflow", maxOffset + 2, maxOffset + 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits keywordHits
			t.Cleanup(hits.release)
			hits.reset(&catalog.guided, &catalog.boundary)
			hits.add(value, completeRule, tagStart, tagStart+len("tag"))
			// Inject positions rather than allocate a multi-GiB value. The window
			// rule needs no byte lookup to retain the largest representable end.
			hits.add(value, completeRule, int(maxOffset-3), int(maxOffset))
			hits.add(value, boundaryRule, int(test.start), int(test.end))
			hits.sort()

			// No usable key position was recorded. Finding the later match
			// requires fallback, not a truncated position in the unrelated prefix.
			want := Verdict{Matches: []Match{{RuleID: "boundary"}, {RuleID: "complete"}}}
			got := Verdict{Matches: evaluateRuleSet(catalog.rules, catalog.all, value, &hits, uniqueRuleMatches, nil)}
			require.Equal(t, want, got)
			require.True(t, hits.guides(completeRule), "representable positions remain complete")
			require.False(t, hits.guides(boundaryRule), "overflow requires fallback for this rule only")
		})
	}
}

func TestKeywordHitsOverflowIsPerRule(t *testing.T) {
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "flood", Regex: `\bkey:[A-Z]{4}\b`, Keywords: []string{"key"}},
		catalogRuleSpec{ID: "token", Regex: `\btoken:[A-Z]{4}\b`, Keywords: []string{"token"}},
	)
	floodRule := catalog.byID["flood"]
	tokenRule := catalog.byID["token"]
	flood := strings.Repeat("key ", maxKeywordHits+50)
	token := "token:ABCD"

	// The token arrives after the buffer filled: only overflowing rules lose positions.
	hits, _ := recordHits(t, catalog, flood+token)
	assert.Equal(t, maxKeywordHits, hits.count)
	assert.False(t, hits.invalid)
	assert.False(t, hits.guides(floodRule))
	assert.False(t, hits.guides(tokenRule))
	assert.Equal(t, []string{"token"}, findingRuleIDs(assertKeywordGuidedMatchesFullScan(t, catalog, flood+token)))

	// The token arrives first: its single occurrence is complete and stays guided.
	hits, _ = recordHits(t, catalog, token+" "+flood)
	assert.False(t, hits.guides(floodRule))
	assert.True(t, hits.guides(tokenRule))
	from, to := hits.rangeFor(tokenRule, 0)
	assert.Equal(t, 1, to-from)
	assert.Equal(t, []string{"token"}, findingRuleIDs(assertKeywordGuidedMatchesFullScan(t, catalog, token+" "+flood)))
}

func TestKeywordOverflowPreservesOrderedCaptures(t *testing.T) {
	type observation struct {
		start, end int
		capture    [sha256.Size]byte
	}
	for _, test := range []struct {
		name       string
		expression string
		keywords   []string
		flood      string
		value      string
	}{
		{
			name:       "anchored-later-accepted",
			expression: `\b(?i:tok):([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"tok"},
			flood:      "tok? ",
			value:      "tok:DROP tok:KEEP tok:KEEP",
		},
		{
			name:       "optional-prefix",
			expression: `[a-z]{0,3}(?i:tok):([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"tok"},
			flood:      "tok? ",
			value:      "abctok:DROP abctok:KEEP tok:KEEP",
		},
		{
			name:       "overlapping-keywords-and-rejected-match",
			expression: `(?i:tok(?:en)?):([A-Z]{4})(?:;tok:KEEP)?`,
			keywords:   []string{"tok", "token", "ok"},
			flood:      "tok? ",
			value:      "token:DROP;tok:KEEP tok:KEEP",
		},
		{
			name:       "anchored-real-eof",
			expression: `\b(?i:tok):([A-Z]{4})$`,
			keywords:   []string{"tok"},
			flood:      "tok? ",
			value:      "tok:KEEP!" + strings.Repeat("~", 40) + "tok:KEEP",
		},
		{
			name:       "anchored-sliced-later-match",
			expression: `\b(?i:tok):([A-Z]{1,4})$`,
			keywords:   []string{"tok"},
			flood:      "tok ",
			value:      "tok tok:KEEP",
		},
		{
			name:       "unicode-and-malformed-context",
			expression: `\bTOK:([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"TOK"},
			flood:      "TOK? ",
			value:      "\xffTOK:DROP界TOK:KEEP\xffTOK:KEEP",
		},
		{
			name:       "fold-alias-fallback",
			expression: `\b(?i:key|set):([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"key", "set"},
			flood:      "key? ",
			value:      "Key:DROP ſet:KEEP key:KEEP",
		},
		{
			name:       "windows-different-keyword-end-order",
			expression: `\b[A-Z]{1,3}=(?i:taglong|ag):([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"taglong", "ag"},
			flood:      "taglong? ",
			value:      "A=taglong:DROP~~B=ag:KEEP" + strings.Repeat("~", 70) + "C=taglong:KEEP",
		},
		{
			name:       "touching-windows",
			expression: `\b[A-Z]{1,2}=tag:([A-Z]{4})(?:$|[^A-Z])`,
			keywords:   []string{"tag"},
			flood:      "tag? ",
			// The two keyword starts are 23 bytes apart: with width 12,
			// the second window begins exactly at the first window's end.
			value: "A=tag:DROP" + strings.Repeat("~", 13) + "B=tag:KEEP",
		},
		{
			name:       "window-line-context",
			expression: `(?m)^[A-Z]{1,3}=(?i:tag|ag):([A-Z]{4})$`,
			keywords:   []string{"tag", "ag"},
			flood:      "tag?\n",
			value:      "\nA=tag:DROP\nB=ag:KEEP\n",
		},
		{
			name:       "window-real-eof",
			expression: `\b[A-Z]{1,3}=(?i:tag|ag):([A-Z]{4})$`,
			keywords:   []string{"tag", "ag"},
			flood:      "tag? ",
			value:      "A=tag:KEEP!" + strings.Repeat("~", 70) + "B=ag:KEEP",
		},
		{
			name:       "window-rune-edges",
			expression: `\b[A-Z]{1,3}=(?i:tag|ag):([A-Z]{4})[界é\x{fffd}]`,
			keywords:   []string{"tag", "ag"},
			flood:      "tag? ",
			value:      "A=tag:DROP界" + strings.Repeat("é", 37) + "\xffB=ag:KEEPé",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			oracle := regexp.MustCompile(test.expression)
			var seen []observation
			var originalValue string
			catalog := compileTestCatalog(
				t,
				catalogRuleSpec{ID: "existence", Regex: test.expression, Keywords: test.keywords, SecretGroup: 1},
				catalogRuleSpec{ID: "capture", Regex: test.expression, Keywords: test.keywords, SecretGroup: 1, Validate: func(secret string) bool {
					return secret == "KEEP"
				}},
				catalogRuleSpec{ID: "context", Regex: test.expression, Keywords: test.keywords, SecretGroup: 1, ValidateContext: func(original string, start, end int, secret string) contextValidation {
					require.True(t, original == originalValue, "context validator must receive the complete original value")
					seen = append(seen, observation{start, end, sha256.Sum256([]byte(secret))})
					return contextValidation{accepted: secret == "KEEP"}
				}},
			)
			for _, placement := range []string{"sparse", "prefix-overflow", "suffix-overflow"} {
				overflow := placement != "sparse"
				value := test.value
				switch placement {
				case "prefix-overflow":
					value = strings.Repeat(test.flood, maxKeywordHits+20) + value
				case "suffix-overflow":
					value += strings.Repeat(test.flood, maxKeywordHits+20)
				}
				originalValue = value
				hits, _ := recordHits(t, catalog, value)
				for index := range catalog.rules {
					require.Equal(t, overflow, hits.overflowed.has(uint16(index)), "probe overflow state")
				}
				indices := oracle.FindAllStringSubmatchIndex(value, -1)
				for _, mode := range []evaluationMode{allRuleMatches, uniqueRuleMatches} {
					var want []Match
					var wantSeen []observation
					for _, id := range []string{"existence", "capture", "context"} {
						for _, match := range indices {
							secret := value[match[2]:match[3]]
							if id == "context" {
								wantSeen = append(wantSeen, observation{match[0], match[1], sha256.Sum256([]byte(secret))})
							}
							if id == "existence" || secret == "KEEP" {
								want = append(want, Match{RuleID: id})
								if mode == uniqueRuleMatches {
									break
								}
							}
						}
					}
					seen = nil
					got := selectedCatalogFindings(catalog, value, true, catalog.all, mode)
					require.Equal(t, want, got, "ordered accepted matches; placement=%s mode=%d", placement, mode)
					require.Equal(t, wantSeen, seen, "original offsets and capture digests; placement=%s mode=%d", placement, mode)
				}
			}
		})
	}
}

func TestKeywordOverflowUnboundedContext(t *testing.T) {
	catalog := compileTestCatalog(t, catalogRuleSpec{
		ID:          "request",
		Regex:       `\bGET ([^\n]+)\n`,
		Keywords:    []string{"get"},
		SecretGroup: 1,
		ValidateContext: func(_ string, _, _ int, secret string) contextValidation {
			return contextValidation{accepted: secret == "KEEP"}
		},
	})
	policy := &CompiledPolicy{catalog: catalog}
	flood := strings.Repeat("GET x ", 1024)
	for _, probe := range []policyVerdictProbe{
		{"missing-newline", flood, nil},
		{"rejected-then-late-match", flood + "\nGET KEEP\n", []string{"request"}},
		{"match-before-overflow", "GET KEEP\n" + flood, []string{"request"}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			assertOptimizerHoldout(t, policy, probe.value, probe.ruleIDs)
		})
	}
}

func TestKeywordGuidedContextRejectionBoundary(t *testing.T) {
	for _, test := range []struct {
		name          string
		expression    string
		acceptedMatch string
	}{
		{name: "full", expression: `key:[A-Z]{4}\b`, acceptedMatch: "key:KEEP"},
		{name: "anchored", expression: `\bkey:[A-Z]{4}\b`, acceptedMatch: "key:KEEP"},
		{name: "window", expression: `\b[a-z]{2}=key:[A-Z]{4}\b`, acceptedMatch: "aa=key:KEEP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := compileTestCatalog(t, catalogRuleSpec{
				ID:       "boundary",
				Regex:    test.expression,
				Keywords: []string{"key"},
				ValidateContext: func(value string, start, _ int, _ string) contextValidation {
					boundary := strings.LastIndex(value, test.acceptedMatch)
					return contextValidation{accepted: start == boundary, rejectUntil: boundary}
				},
			})
			policy := &CompiledPolicy{catalog: catalog}
			for _, probe := range []policyVerdictProbe{
				{"recorded", "aa=key:DROP aa=key:KEEP", []string{"boundary"}},
				{"streamed", strings.Repeat("key? ", maxKeywordHits+20) + "aa=key:DROP aa=key:KEEP", []string{"boundary"}},
			} {
				t.Run(probe.name, func(t *testing.T) {
					assertOptimizerHoldout(t, policy, probe.value, probe.ruleIDs)
				})
			}
		})
	}
}

func TestFullScanKeywordsDoNotExhaustGuidedHits(t *testing.T) {
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "full", Regex: `full:[A-Z]{4}`, Keywords: []string{"full"}},
		catalogRuleSpec{ID: "guided", Regex: `\bkey:[A-Z]{4}\b`, Keywords: []string{"key"}},
	)
	value := "full:ABCD " + strings.Repeat("full:~~~ ", maxKeywordHits+20) + "key:EFGH"
	hits, candidates := recordHits(t, catalog, value)
	require.True(t, candidates.has(catalog.byID["full"]))
	require.True(t, hits.guides(catalog.byID["guided"]))
	require.Equal(t, []Match{{RuleID: "full"}, {RuleID: "guided"}},
		assertKeywordGuidedMatchesFullScan(t, catalog, value))
}

func TestKeywordHitsDropKeywordsGluedToWords(t *testing.T) {
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "boundary", Regex: `\bey:[A-Z]{4}\b`, Keywords: []string{"ey"}},
	)
	boundaryRule := catalog.byID["boundary"]

	// "ey" occurs six times but only three occurrences follow a non-word byte.
	value := "the monkey and they said: ey eyJ.ey key"
	hits, candidates := recordHits(t, catalog, value)
	assert.True(t, candidates.has(boundaryRule))
	assert.True(t, hits.guides(boundaryRule))
	from, to := hits.rangeFor(boundaryRule, 0)
	assert.Equal(t, 3, to-from)
	for i := from; i < to; i++ {
		assert.True(t, asciiWordBoundary(value, int(hits.buffer[i].start)))
	}
	assert.Empty(t, assertKeywordGuidedMatchesFullScan(t, catalog, value))

	// Every occurrence glued to a word character leaves the rule with a complete, empty range.
	hits, candidates = recordHits(t, catalog, "monkey turkey")
	assert.True(t, candidates.has(boundaryRule))
	assert.True(t, hits.guides(boundaryRule))
	from, to = hits.rangeFor(boundaryRule, 0)
	assert.Equal(t, from, to)
	assert.Empty(t, assertKeywordGuidedMatchesFullScan(t, catalog, "monkey turkey"))
}
