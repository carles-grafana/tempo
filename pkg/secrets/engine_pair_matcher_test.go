package secrets

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogPairMatcherDuplicateOutputOffsetBoundary(t *testing.T) {
	keywords := make([]matcherKeyword, 0, 256*256+2)
	for i := range 256 {
		word := string([]byte{byte('a' + i/26), byte('a' + i%26)})
		for rule := range 256 {
			keywords = append(keywords, matcherKeyword{value: word, rule: uint16(rule)})
		}
	}
	// The final keyword follows 65,536 duplicate outputs but belongs to two
	// different rules, within both the rule-count and distinct-keyword caps.
	keywords = append(
		keywords,
		matcherKeyword{value: "zz", rule: 256},
		matcherKeyword{value: "zz", rule: 257},
	)
	matcher, err := newCatalogPairMatcher(keywords)
	require.NoError(t, err)

	var expected, actual ruleSet
	expected.add(256)
	expected.add(257)
	matcher.match("zz", &actual)
	require.Equal(t, expected, actual)
}

func TestCatalogPairMatcherLongKeywordAnchor(t *testing.T) {
	// The lexically preferred pair, "ab", starts immediately beyond uint16.
	keyword := strings.Repeat("z", 1<<16) + "ab"
	matcher, err := newCatalogPairMatcher([]matcherKeyword{{value: keyword, rule: 7}})
	require.NoError(t, err)

	var expected, actual ruleSet
	expected.add(7)
	matcher.match(keyword, &actual)
	require.Equal(t, expected, actual)
}
