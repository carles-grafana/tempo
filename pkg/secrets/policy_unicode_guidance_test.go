package secrets

import (
	"slices"
	"strings"
	"testing"
)

func TestKeywordGuidancePreservesMixedByteContexts(t *testing.T) {
	tests := []struct {
		name   string
		rule   CustomRule
		values []struct {
			name, value string
			matched     bool
		}
	}{
		{name: "word boundaries", rule: CustomRule{Regex: `\bTOK_[A-Z]{4}\b`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"multibyte neighbors", "界TOK_ABCDé", true},
			{"four-byte neighbors", "😀TOK_ABCD𐐀", true},
			{"invalid neighbors", "\xff\xc0TOK_ABCD\xaf\x80", true},
			{"ascii word before", "界xTOK_ABCDé", false},
			{"ascii word after", "界TOK_ABCDxé", false},
		}},
		{name: "line anchors", rule: CustomRule{Regex: `(?m)^TOK_[A-Z]{4}$`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"line after unicode", "界\nTOK_ABCD\né", true},
			{"not a line start", "界TOK_ABCD\n", false},
			{"not a line end", "\nTOK_ABCD界", false},
			{"unicode line separator is not LF", "\u2028TOK_ABCD\u2028", false},
		}},
		{name: "absolute anchors", rule: CustomRule{Regex: `\ATOK_[A-Z]{4}\z`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"exact input", "TOK_ABCD", true},
			{"unicode prefix", "界TOK_ABCD", false},
			{"unicode suffix", "TOK_ABCD界", false},
			{"invalid prefix", "\xffTOK_ABCD", false},
		}},
		{name: "nonword assertions", rule: CustomRule{Regex: `\BTOK_[A-Z]{4}\B`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"ascii word context", "界xTOK_ABCDyé", true},
			{"unicode is not ASCII word context", "界TOK_ABCDé", false},
		}},
		{name: "bounded window", rule: CustomRule{Regex: `[A-Z]{2}:TOK:[A-Z]{4}`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"multibyte window edges", "界AB:TOK:CDEF😀", true},
			{"invalid window edges", "\xffAB:TOK:CDEF\xc0", true},
			{"multibyte inside ASCII match", "AB:TOK:CD界F", false},
		}},
		{name: "optional prefix", rule: CustomRule{Regex: `[A-Z._]{0,4}TOK_[A-Z]{4}`}, values: []struct {
			name, value string
			matched     bool
		}{
			{"prefix after multibyte rune", "界AB._TOK_CDEFé", true},
			{"zero prefix after invalid byte", "\xffTOK_CDEF", true},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.rule.ID = "mixed-context-rule"
			policy, err := testPolicyCompiler.CompilePolicy(Policy{CustomRules: []CustomRule{test.rule}})
			if err != nil {
				t.Fatal("policy compilation failed")
			}
			batch := policy.NewBatchDetector()
			for _, probe := range test.values {
				var want Verdict
				if probe.matched {
					want.Matches = []Match{{RuleID: test.rule.ID}}
				}
				if !slices.Equal(want.Matches, fullScanPolicyVerdict(policy, probe.value).Matches) {
					t.Fatalf("probe %s: independent expectation disagrees with reference", probe.name)
				}
				if !slices.Equal(want.Matches, policy.Detect(probe.value).Matches) || !slices.Equal(want.Matches, batch.Detect(probe.value).Matches) || !slices.Equal(want.Matches, batch.Detect(probe.value).Matches) {
					t.Fatalf("probe %s: optimized verdict differs", probe.name)
				}
			}
		})
	}
}

func TestKeywordGuidancePreservesUnicodeConsumingRules(t *testing.T) {
	policy, err := testPolicyCompiler.CompilePolicy(Policy{CustomRules: []CustomRule{
		{ID: "folded", Regex: `FOLD:(?i:[a-z]{4})`},
		{ID: "folded-prefix", Regex: `(?i)KEL_[A-Z]{4}`},
		{ID: "wide", Regex: `WIDE:[^\n]{4}!`},
		{ID: "replacement", Regex: `BAD:\x{FFFD}{2}!`},
		{ID: "literal", Regex: `LIT:界{4}!`},
	}})
	if err != nil {
		t.Fatal("policy compilation failed")
	}
	for _, probe := range []struct{ name, value, id string }{
		{"folded ASCII aliases", "界FOLD:KſKſé", "folded"},
		{"folded prefix requires fallback", "界KEL_ABCDé", "folded-prefix"},
		{"four multibyte runes", "éWIDE:😀😀😀😀!界", "wide"},
		{"two invalid bytes", "界BAD:\xff\xfe!é", "replacement"},
		{"literal Unicode", "éLIT:界界界界!😀", "literal"},
		{"wrong folded alphabet", "FOLD:KſK界", ""},
		{"wrong rune count", "WIDE:😀😀😀!", ""},
		{"one replacement rune", "BAD:�!", ""},
	} {
		var want Verdict
		if probe.id != "" {
			want.Matches = []Match{{RuleID: probe.id}}
		}
		if !slices.Equal(want.Matches, fullScanPolicyVerdict(policy, probe.value).Matches) || !slices.Equal(want.Matches, policy.Detect(probe.value).Matches) {
			t.Fatalf("probe %s: Unicode-consuming rule changed", probe.name)
		}
	}
}

func TestKeywordGuidanceMixedInputOverflowAndReset(t *testing.T) {
	policy, err := testPolicyCompiler.CompilePolicy(Policy{CustomRules: []CustomRule{{ID: "overflow", Regex: `\bTOK_[A-Z]{4}\b`}}})
	if err != nil {
		t.Fatal("policy compilation failed")
	}
	batch := policy.NewBatchDetector()
	for index, value := range []string{
		"界" + strings.Repeat("TOK_? ", maxKeywordHits+1) + "TOK_ABCDé",
		"\xffTOK_ABCD " + strings.Repeat("TOK_? ", maxKeywordHits+1),
		"TOK_ABCD",
		"TOK_ABCD界",
		"TOK_ABC",
		"éTOK_ABC\xff",
	} {
		want := fullScanPolicyVerdict(policy, value)
		if !slices.Equal(want.Matches, policy.Detect(value).Matches) || !slices.Equal(want.Matches, batch.Detect(value).Matches) {
			t.Fatalf("probe %d: overflow or reused hit state changed the verdict", index)
		}
	}
}
