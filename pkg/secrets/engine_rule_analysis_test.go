package secrets

import (
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDerivedKeywordFactorsPreserveUnicodeMatches(t *testing.T) {
	for _, test := range []struct {
		name, expression, value string
	}{
		{"mandatory folded literal", `(?i:secret)(?:token|é)`, "ſecreté"},
		{
			"common factor beyond enumeration limit",
			`(?i:token)[A-Z]{200}|é(?i:token)[0-9]{200}`,
			"étoKen" + strings.Repeat("1", 200),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := compileCatalog([]catalogRuleSpec{{
				ID: "derived-factor", Regex: test.expression, Keywords: []string{"unproven"},
			}})
			require.NoError(t, err)
			policy := CompiledPolicy{catalog: catalog}
			require.Equal(t, []Match{{RuleID: "derived-factor"}}, policy.Detect(test.value).Matches)
		})
	}
}

func TestExactLiteralAlternativesPreserveRegexpLanguage(t *testing.T) {
	for _, tc := range []struct {
		name, expression, value string
		matches, possible       bool
	}{
		{"missing mandatory marker", `(?i:access_key)[ \t]*=(AX[0-9]+)`, "K ſ access_key=public", false, false},
		{"exact marker case", `(?i:access_key)[ \t]*=(AX[0-9]+)`, "acceſſ_Key=ax123", false, false},
		{"aliases inside folded field", `(?i:access_key)[ \t]*=(AX[0-9]+)`, "acceſſ_Key=AX123", true, true},
		{"exact alternatives absent", `(?i:access_key)=(?:AX|BY)[0-9]+`, "K ſ access_key=public", false, false},
		{"second exact alternative", `(?i:access_key)=(?:AX|BY)[0-9]+`, "acceſſ_Key=BY123", true, true},
		{"request branch case", `(?i:access_key)=AX[0-9]+|GET[ \t]+[^\r\n]+`, "K ſ get /public", false, false},
		{"Unicode request branch", `(?i:access_key)=AX[0-9]+|GET[ \t]+[^\r\n]+`, "GET 界", true, true},
		{"unproved Unicode alternative", `(?i:access_key)=AX[0-9]+|éé`, "éé", true, true},
		{"unproved folded alternative", `(?i:access_key)=AX[0-9]+|(?i:secret)`, "ſecret", true, true},
		{"optional marker", `(?i:access_key)(?:AX)?`, "acceſſ_Key", true, true},
		{"mandatory repeated marker", `(?i:access_key)(?:AX){2,}`, "acceſſ_KeyAXAX", true, true},
		{"malformed context", `[^a]*(?i:access_key)=(AX[0-9]+)`, "\xffacceſſ_Key=AX123", true, true},
		{"bounded factor truncation", `(?i:access_key)=` + strings.Repeat("X", analysisMaxStringLength+1), "acceſſ_Key=" + strings.Repeat("X", analysisMaxStringLength+1), true, true},
		{"mandatory adjacent separator", `\bcurl[ \t]+[^\r\n]+`, "界 curlish", false, false},
		{"multiple separator copies", `\bcurl[ \t]+[^\r\n]+`, "界 curl \t public", true, true},
		{"adjacent factor exact case", `\bcurl[ \t]+[^\r\n]+`, "界 CURL public", false, false},
		{"assertion between adjacent atoms", `curl\b[ \t]+x`, "curl\tx", true, true},
		{"optional separator absent", `curl[ \t]?x`, "curlx", true, true},
		{"optional separator present", `curl[ \t]?x`, "curl x", true, true},
		{"unbounded gap stops adjacency", `curl[ \t]*x`, "curl \t x", true, true},
		{"variable repetition stops adjacency", `curl[ \t]{2,4}x`, "curl \t\tx", true, true},
		{"fixed repetition permits adjacency", `curl[ \t]{2}x`, "curl \tx", true, true},
		{"Unicode class member", `curl[ \t\x{2003}]+x`, "curl\u2003x", true, true},
		{"folded class member", `ab(?i:[k])+z`, "abKz", true, true},
		{"unknown adjacent alternative", `(?:curl|界)[ \t]+x`, "界 x", true, true},
		{"nullable adjacent alternative", `(?:curl|)[ \t]+x`, " x", true, true},
		{"prefix cross product cap", `curl[ab]{8}x`, "curlbbbbbbbbx", true, true},
		{"repeated prefix length cap", `(?:ab){40}x`, strings.Repeat("ab", 40) + "x", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := syntax.Parse(tc.expression, syntax.Perl)
			require.NoError(t, err)
			// The accepting language comes from the independent stdlib regexp,
			// not from the factor extractor's projection of the syntax tree.
			require.Equal(t, tc.matches, regexp.MustCompile(tc.expression).MatchString(tc.value))
			alternatives := requiredExactLiteralAlternatives(parsed)
			for _, hits := range []*keywordHits{nil, {asciiFoldAlias: true}, {invalid: true}} {
				require.Equal(t, tc.possible, literalAlternativesPossible(tc.value, alternatives, hits))
			}
		})
	}
}

func TestExactLiteralAlternativesDoNotReplaceASCIIFactors(t *testing.T) {
	parsed, err := syntax.Parse(`(?i:access_key)[ \t]*=(AX[0-9]+)`, syntax.Perl)
	require.NoError(t, err)
	// A shorter exact factor must not weaken the existing ASCII near-miss gate.
	value := "public AX123"
	require.False(t, literalAlternativesPossible(value, requiredLiteralAlternatives(parsed), &keywordHits{}))
}

func TestExactLiteralAlternativesFailOpenAtEnumerationLimit(t *testing.T) {
	branches := make([]*syntax.Regexp, analysisMaxStrings+1)
	for i := range branches {
		branches[i] = &syntax.Regexp{Op: syntax.OpLiteral, Rune: []rune("factor-" + strconv.Itoa(i) + "-end")}
	}
	parsed := &syntax.Regexp{Op: syntax.OpAlternate, Sub: branches}
	alternatives := requiredExactLiteralAlternatives(parsed)
	reference := regexp.MustCompile(parsed.String())
	for _, branch := range branches {
		value := string(branch.Rune)
		require.True(t, reference.MatchString(value))
		require.True(t, literalAlternativesPossible(value, alternatives, &keywordHits{asciiFoldAlias: true}))
	}
}
