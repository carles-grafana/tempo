package secrets

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSingleKeywordMatcherPreservesOriginalPositions(t *testing.T) {
	keywords := []matcherKeyword{
		{value: "a", rule: 63},
		{value: "k", rule: 64},
		{value: "s", rule: 65},
		{value: "key", rule: 511},
		{value: "k", rule: 971},
		{value: "token", rule: 1023},
	}
	var enabled, boundary ruleSet
	for _, index := range []uint16{63, 64, 65, 511, 1023} {
		enabled.add(index)
	}
	boundary.add(63)

	probes := []struct {
		name     string
		value    string
		hits     []keywordHit
		nonASCII bool
		alias    bool
	}{
		{name: "empty"},
		{name: "one byte has no pair", value: "A", hits: []keywordHit{{rule: 63, start: 0, end: 1}}},
		{
			name:  "ASCII boundary and disabled duplicate output",
			value: "xa A K KEY TOKEN S",
			hits: []keywordHit{
				{rule: 63, start: 3, end: 4},
				{rule: 64, start: 5, end: 6},
				{rule: 64, start: 7, end: 8},
				{rule: 64, start: 13, end: 14},
				{rule: 65, start: 17, end: 18},
				{rule: 511, start: 7, end: 10},
				{rule: 1023, start: 11, end: 16},
			},
		},
		{
			name:  "ordinary Unicode uses original byte offsets",
			value: "éA πK TOKEN",
			hits: []keywordHit{
				{rule: 63, start: 2, end: 3},
				{rule: 64, start: 6, end: 7},
				{rule: 64, start: 10, end: 11},
				{rule: 1023, start: 8, end: 13},
			},
			nonASCII: true,
		},
		{
			name:  "invalid UTF8 retains original byte offsets",
			value: "\xffA\xfeK TOKEN",
			hits: []keywordHit{
				{rule: 63, start: 1, end: 2},
				{rule: 64, start: 3, end: 4},
				{rule: 64, start: 7, end: 8},
				{rule: 1023, start: 5, end: 10},
			},
			nonASCII: true,
		},
		{
			name:  "fold aliases select candidates without normalized positions",
			value: "Key ſ TOKEN K",
			hits: []keywordHit{
				{rule: 64, start: 11, end: 12},
				{rule: 64, start: 15, end: 16},
				{rule: 1023, start: 9, end: 14},
			},
			nonASCII: true,
			alias:    true,
		},
		{name: "high-bit aliases are not ASCII", value: "\xe1\xeb\xf3", nonASCII: true},
		{name: "Unicode keyword fold class", value: "σ Σ ς", nonASCII: true},
	}

	for _, unicodeInventory := range []bool{false, true} {
		inventory := keywords
		name := "ASCII inventory"
		if unicodeInventory {
			inventory = append(slices.Clone(keywords), matcherKeyword{value: "σ", rule: 512})
			name = "mixed Unicode inventory"
		}
		t.Run(name, func(t *testing.T) {
			reference, err := newKeywordMatcher(inventory)
			require.NoError(t, err)
			matcher, err := newCatalogPairMatcher(inventory)
			require.NoError(t, err)
			for _, probe := range probes {
				t.Run(probe.name, func(t *testing.T) {
					var expected, actual ruleSet
					var hits keywordHits
					defer hits.release()
					hits.reset(&enabled, &boundary)
					reference.match(probe.value, &expected)
					matcher.matchHits(probe.value, &actual, &hits)
					require.Equal(t, expected, actual)
					if unicodeInventory && probe.value != "" {
						require.True(t, hits.invalid, "Unicode normalization cannot supply original offsets")
						require.False(t, hits.guides(1023))
						return
					}
					require.False(t, hits.invalid)
					require.Equal(t, probe.nonASCII, hits.nonASCII)
					require.Equal(t, probe.alias, hits.asciiFoldAlias)
					hits.sort()
					var positions []keywordHit
					if hits.count != 0 {
						positions = append(positions, hits.buffer[:hits.count]...)
					}
					require.Equal(t, probe.hits, positions)
				})
			}
		})
	}
}
