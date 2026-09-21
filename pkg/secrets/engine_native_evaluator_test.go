package secrets

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogSharedExpressionsPreserveRuleAcceptance(t *testing.T) {
	const expression = `token_([a-z]+):([a-z]+)`
	catalog, err := compileCatalog([]catalogRuleSpec{
		{ID: "left", Regex: expression, Keywords: []string{"token_"}, SecretGroup: 1, Validate: func(s string) bool { return s == "left" }},
		{ID: "right", Regex: expression, Keywords: []string{"token_"}, SecretGroup: 2, Validate: func(s string) bool { return s == "right" }},
	})
	require.NoError(t, err)
	for _, test := range []struct {
		value string
		want  []Match
	}{
		{"token_left:other", []Match{{RuleID: "left"}}},
		{"token_other:right", []Match{{RuleID: "right"}}},
		{"token_left:right", []Match{{RuleID: "left"}, {RuleID: "right"}}},
		{"token_other:other", nil},
	} {
		var hits keywordHits
		require.Equal(t, test.want, catalog.detect(test.value, &hits, nil))
	}
}

func TestCatalogSharedPlansPreserveKeywordSemantics(t *testing.T) {
	const expression = `(?i:tok_)([a-z]{1,8}):(secret|public)`
	catalog, err := compileCatalog([]catalogRuleSpec{
		{ID: "capture", Regex: expression, Keywords: []string{"tok_"}, SecretGroup: 1, Validate: func(s string) bool { return s == "good" }},
		{ID: "window", Regex: expression, Keywords: []string{"secret", "public"}, SecretGroup: 2, Validate: func(s string) bool { return s == "secret" }},
		{ID: "context", Regex: expression, Keywords: []string{"tok_"}, SecretGroup: 1, ValidateContext: func(value string, start, _ int, secret string) contextValidation {
			return contextValidation{accepted: secret == "good" && strings.HasSuffix(value[:start], "allow ")}
		}},
	})
	require.NoError(t, err)
	for _, test := range []struct {
		name  string
		value string
		want  []Match
	}{
		{"capture-only", "tok_good:public", []Match{{RuleID: "capture"}}},
		{"window-only", "tok_bad:secret", []Match{{RuleID: "window"}}},
		{"shared-acceptance", "allow tok_good:secret", []Match{{RuleID: "capture"}, {RuleID: "window"}, {RuleID: "context"}}},
		{"later-accepted", "tok_bad:public allow tok_good:secret", []Match{{RuleID: "capture"}, {RuleID: "window"}, {RuleID: "context"}}},
		{"unicode-fold", "allow toK_good:secret", []Match{{RuleID: "capture"}, {RuleID: "window"}, {RuleID: "context"}}},
		{"overflow", strings.Repeat("tok_ ", maxKeywordHits+20) + "allow tok_good:secret", []Match{{RuleID: "capture"}, {RuleID: "window"}, {RuleID: "context"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reference := assertKeywordGuidedMatchesFullScan(t, catalog, test.value)
			require.Equal(t, test.want, uniqueFindingVerdict(reference).Matches)
		})
	}
}

func TestAnchoredExecutionPreservesLeadingContext(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
		good       string
		bad        string
	}{
		{"suffix-only", `(?i:tok_)([A-Z]{4})\b`, "TOK_GOOD", "TOK_BADX"},
		{"internal-boundary", `(?i:tok)\b:([A-Z]{4})\b`, "TOK:GOOD", "TOK:BADX"},
		{"word-boundary", `\b(?i:tok_)([A-Z]{4})\b`, "TOK_GOOD", "TOK_BADX"},
		{"non-boundary", `\B(?i:tok_)([A-Z]{4})\b`, "TOK_GOOD", "TOK_BADX"},
		{"optional-boundary", `(?:\b)?(?i:tok_)([A-Z]{4})\b`, "TOK_GOOD", "TOK_BADX"},
		{"alternate-boundary", `(?:\b|\B)(?i:tok_)([A-Z]{4})\b`, "TOK_GOOD", "TOK_BADX"},
		{"line-anchor", `(?m)^(?i:tok_)([A-Z]{4})$`, "TOK_GOOD", "TOK_BADX"},
		{"text-anchor", `\A(?i:tok_)([A-Z]{4})\z`, "TOK_GOOD", "TOK_BADX"},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := compileCatalog([]catalogRuleSpec{
				{ID: "existence", Regex: test.expression, Keywords: []string{"tok"}},
				{ID: "capture", Regex: test.expression, Keywords: []string{"tok"}, SecretGroup: 1, Validate: func(s string) bool { return s == "GOOD" }},
				{ID: "context", Regex: test.expression, Keywords: []string{"tok"}, SecretGroup: 1, ValidateContext: func(value string, start, end int, secret string) contextValidation {
					return contextValidation{accepted: secret == "GOOD" && value[start:end] == test.good && !strings.HasPrefix(value, "deny")}
				}},
			})
			require.NoError(t, err)
			for _, value := range []string{
				test.good,
				"x" + test.good,
				"\n" + test.good,
				"界" + test.good,
				"\xff" + test.good,
				test.bad + " " + test.good,
				test.good + "\n" + test.good,
				"deny " + test.good,
				strings.Repeat("tok ", maxKeywordHits+20) + test.good,
			} {
				assertKeywordGuidedMatchesFullScan(t, catalog, value)
			}
		})
	}
}

func TestLiteralRunMatcherPreservesRegexpCaptures(t *testing.T) {
	for _, test := range []struct {
		name       string
		expression string
	}{
		{"delimiter", `\b(TOK_[A-Z]{2,4})(?:$|[^A-Z_])`},
		{"word-boundary", `\b(TOK_[A-Z]{2,4})\b`},
		{"end-of-text", `\b(TOK_[A-Z]{2,4})$`},
		{"no-tail", `\b(TOK_[A-Z]{2,4})`},
		{"unbounded", `\b(TOK_[A-Z]+)(?:$|[^A-Z_])`},
		{"fixed-width", `\b(TOK_[A-Z]{4})(?:$|[^A-Z_])`},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := syntax.Parse(test.expression, syntax.Perl)
			require.NoError(t, err)
			matcher := newLiteralRunMatcher(parsed)
			require.NotNil(t, matcher)
			reference := regexp.MustCompile(test.expression)
			catalog, err := compileCatalog([]catalogRuleSpec{
				{ID: "existence", Regex: test.expression, Keywords: []string{"TOK_"}},
				{ID: "capture", Regex: test.expression, Keywords: []string{"TOK_"}, SecretGroup: 1, Validate: func(s string) bool { return s == "TOK_AB" }},
				{ID: "context", Regex: test.expression, Keywords: []string{"TOK_"}, SecretGroup: 1, ValidateContext: func(value string, start, end int, secret string) contextValidation {
					return contextValidation{accepted: secret == "TOK_AB" && strings.HasSuffix(value[:start], "allow ") && strings.HasPrefix(value[start:end], secret)}
				}},
			})
			require.NoError(t, err)
			for _, value := range []string{
				"TOK_A",
				"TOK_AB",
				"TOK_ABCD",
				"TOK_ABCDE",
				"xTOK_AB",
				"界TOK_AB界TOK_CD",
				"\xffTOK_AB\xffTOK_CD",
				"TOK_AB\nTOK_CD",
				"TOK_CD allow TOK_AB",
				"TOK_AB,TOK_CD,TOK_EF",
			} {
				var actual [][]int
				for scan := 0; scan < len(value); {
					offset := strings.Index(value[scan:], matcher.prefix)
					if offset < 0 {
						break
					}
					start := scan + offset
					end, captureEnd, matched := matcher.match(value, start)
					if matched {
						actual = append(actual, []int{start, end, start, captureEnd})
						scan = end
					} else {
						scan = start + 1
					}
				}
				require.Equal(t, reference.FindAllStringSubmatchIndex(value, -1), actual)
				assertKeywordGuidedMatchesFullScan(t, catalog, value)
			}
			assertKeywordGuidedMatchesFullScan(t, catalog, strings.Repeat("TOK_ ", maxKeywordHits+20)+"allow TOK_AB")
		})
	}
}

func TestLiteralRunFallbackPreservesBacktracking(t *testing.T) {
	for _, expression := range []string{
		`\b(TOK_[A-Z]{2,4})(?:$|[A-Z])`,
		`\b(TOK_[A-Z]{2,4}?)`,
		`\b(TOK_[A-Z-]{2,4})\b`,
		`\b((?i:TOK_)[A-Z]{2,4})(?:$|[^A-Z_])`,
	} {
		catalog, err := compileCatalog([]catalogRuleSpec{
			{ID: "capture", Regex: expression, Keywords: []string{"TOK_"}, SecretGroup: 1, Validate: func(s string) bool { return s == "TOK_AB" || s == "TOK_AB-" }},
		})
		require.NoError(t, err)
		for _, value := range []string{"TOK_ABC", "TOK_AB--", "TOK_AB--X", "TOK_ABC", "TOK_BAD TOK_ABC"} {
			assertKeywordGuidedMatchesFullScan(t, catalog, value)
		}
	}
}

func TestCatalogPairMatcherSingleAndUnicodeKeywords(t *testing.T) {
	keywords := []matcherKeyword{
		{value: "a", rule: 0},
		{value: "bc", rule: 1},
		{value: "σ", rule: 2},
	}
	reference, err := newKeywordMatcher(keywords)
	require.NoError(t, err)
	pair, err := newCatalogPairMatcher(keywords)
	require.NoError(t, err)

	for _, value := range []string{"", "A", "xxBCxx", "éA", "Σ", "prefix σ suffix", string([]byte{0xff, 'A'})} {
		var expected, actual ruleSet
		reference.match(value, &expected)
		pair.match(value, &actual)
		assert.Equal(t, expected, actual, value)
	}
}

func TestCatalogPairMatcherDuplicateKeywordOutputs(t *testing.T) {
	keywords := []matcherKeyword{
		{value: "token", rule: 0},
		{value: "token", rule: 1},
		{value: "token", rule: 1},
		{value: "other", rule: 2},
	}
	reference, err := newKeywordMatcher(keywords)
	require.NoError(t, err)
	pair, err := newCatalogPairMatcher(keywords)
	require.NoError(t, err)

	for _, value := range []string{"no match", "prefix TOKEN suffix", "token and other"} {
		var expected, actual ruleSet
		reference.match(value, &expected)
		pair.match(value, &actual)
		assert.Equal(t, expected, actual, value)
	}
}

func TestCatalogPairMatcherLargeCollisionInventory(t *testing.T) {
	var keywords []matcherKeyword
	for i := range 160 {
		word := string([]byte{byte('a' + i/26), byte('a' + i%26)})
		keywords = append(
			keywords,
			matcherKeyword{value: word, rule: uint16(i)},
			matcherKeyword{value: word, rule: uint16(i + 256)},
		)
	}
	reference, err := newKeywordMatcher(keywords)
	require.NoError(t, err)
	pair, err := newCatalogPairMatcher(keywords)
	require.NoError(t, err)
	var values []string
	for i := range 160 {
		word := string([]byte{byte('a' + i/26), byte('a' + i%26)})
		values = append(values, word, strings.ToUpper(word))
	}
	values = append(values, "fK", "aſ", "no-match", "\xfffk")
	for _, value := range values {
		var expected, actual ruleSet
		reference.match(value, &expected)
		pair.match(value, &actual)
		require.Equal(t, expected, actual, "large inventory candidate selection")
	}
}

func TestCatalogPairMatcherRejectsAliasedNonASCII(t *testing.T) {
	keywords := []matcherKeyword{{value: "bc", rule: 0}}
	reference, err := newKeywordMatcher(keywords)
	require.NoError(t, err)
	pair, err := newCatalogPairMatcher(keywords)
	require.NoError(t, err)

	for _, value := range []string{
		string([]byte{0xe2, 0xe3}),
		string([]byte{0xff, 'B', 'C', 0xfe}),
		"πBCλ",
	} {
		var expected, actual ruleSet
		reference.match(value, &expected)
		pair.match(value, &actual)
		assert.Equal(t, expected, actual, value)
	}
}

func TestCatalogPairMatcherLookupBoundary(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
	}{
		{name: "compact", count: 16},
		{name: "dense", count: 17},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Length order opposes pair order, so direct certificate indices
			// cannot double as sorted lookup positions. A duplicate output also
			// moves its pair behind the direct certificates.
			keywords := make([]matcherKeyword, 0, test.count+1)
			for i := range test.count {
				word := strings.Repeat(string(rune('z'-i)), i+2)
				keywords = append(keywords, matcherKeyword{value: word, rule: uint16(i)})
			}
			keywords = append(keywords, matcherKeyword{value: keywords[0].value, rule: uint16(test.count)})
			reference, err := newKeywordMatcher(keywords)
			require.NoError(t, err)
			matcher, err := newCatalogPairMatcher(keywords)
			require.NoError(t, err)

			for _, keyword := range keywords[:test.count] {
				for _, value := range []string{
					keyword.value,
					"prefix " + strings.ToUpper(keyword.value) + " suffix",
					"\xff" + keyword.value + "\xfe",
					keyword.value[:len(keyword.value)-1] + "\x80",
					strings.ReplaceAll(strings.ReplaceAll(keyword.value, "k", "K"), "s", "ſ"),
				} {
					var expected, actual ruleSet
					reference.match(value, &expected)
					matcher.match(value, &actual)
					require.Equal(t, expected, actual, "candidate selection across compact lookup boundary")
				}
			}
		})
	}
}

func TestNativeEvaluatorUsesCaptureGroups(t *testing.T) {
	tests := []struct {
		name  string
		spec  catalogRuleSpec
		value string
	}{
		{
			name:  "first nonempty capture",
			spec:  catalogRuleSpec{ID: "capture", Regex: `key=(?:([A-Z]+)|([0-9]+))`},
			value: "key=1234",
		},
		{
			name:  "explicit capture",
			spec:  catalogRuleSpec{ID: "capture", Regex: `key=([A-Z]+):([0-9]+)`, SecretGroup: 2},
			value: "key=ABCD:1234",
		},
		{
			name:  "gitleaks allow annotation is telemetry",
			spec:  catalogRuleSpec{ID: "annotated", Regex: `secret`},
			value: "secret gitleaks:allow",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := compileTestRule(t, test.spec)
			assert.Equal(t, []Match{{RuleID: test.spec.ID}}, rule.detect(test.value, nil))
		})
	}
}

func TestNativeEvaluatorValidatesCapturedCandidates(t *testing.T) {
	for _, test := range []struct {
		name    string
		entropy float64
	}{
		{name: "zero-entropy"},
		{name: "with-entropy", entropy: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			validate := func(secret string) bool { return secret == "key:GOOD" }
			catalog := compileTestCatalog(
				t,
				catalogRuleSpec{ID: "full", Regex: `(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, Entropy: test.entropy, Validate: validate},
				catalogRuleSpec{ID: "anchored", Regex: `\b(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, Entropy: test.entropy, Validate: validate},
				catalogRuleSpec{ID: "window", Regex: `\b[a-z]{2}=(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, Entropy: test.entropy, Validate: validate},
			)
			policy := &CompiledPolicy{catalog: catalog}
			batch := policy.NewBatchDetector()
			for _, probe := range []struct {
				value string
				valid bool
			}{
				{value: "aa=key:BAD"},
				{value: "aa=key:GOODX"},
				{value: "aa=key:GOOD", valid: true},
				{value: "aa=key:BAD aa=key:GOOD", valid: true},
				{value: "aa=key:GOOD aa=key:BAD", valid: true},
				{value: "aa=key:GOOD aa=key:GOOD", valid: true},
				{value: "\xff aa=key:BAD aa=key:GOOD", valid: true},
				{value: strings.Repeat("key ", maxKeywordHits+20) + "aa=key:BAD"},
				{value: strings.Repeat("key ", maxKeywordHits+20) + "aa=key:BAD aa=key:GOOD", valid: true},
			} {
				var want Verdict
				if probe.valid {
					want.Matches = []Match{{RuleID: "full"}, {RuleID: "anchored"}, {RuleID: "window"}}
				}
				findings := assertKeywordGuidedMatchesFullScan(t, catalog, probe.value)
				require.Equal(t, want, uniqueFindingVerdict(findings), "unfiltered capture validation")
				require.Equal(t, want, policy.Detect(probe.value), "direct")
				require.Equal(t, want, batch.Detect(probe.value), "batch miss")
				require.Equal(t, want, batch.Detect(probe.value), "batch hit")
			}
		})
	}
}

func TestNativeEvaluatorPreservesNewlineCaptures(t *testing.T) {
	for _, test := range []struct {
		name        string
		expression  string
		secretGroup int
		secret      string
	}{
		{name: "explicit-capture", expression: `\nKEY=([A-Z]{4})\n`, secretGroup: 1, secret: "GOOD"},
		{name: "first-nonempty-capture", expression: `\nKEY=()([A-Z]{4})\n`, secret: "GOOD"},
		{name: "explicit-empty-capture", expression: `\nKEY=()([A-Z]{4})\n`, secretGroup: 1},
		{name: "unmatched-capture", expression: `\nKEY=(?:([0-9]{4})|([A-Z]{4}))\n`, secretGroup: 1},
		{name: "captured-newline", expression: `\nKEY=(GOOD\n)`, secretGroup: 1, secret: "GOOD\n"},
		{name: "no-captures", expression: `\nKEY=GOOD\n`, secret: "KEY=GOOD"},
		{name: "empty-captures-fallback", expression: `\nKEY=()GOOD\n`, secret: "KEY=GOOD"},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := compileTestCatalog(t, catalogRuleSpec{
				ID:          "capture",
				Regex:       test.expression,
				Keywords:    []string{"key"},
				SecretGroup: test.secretGroup,
				Validate:    func(secret string) bool { return secret == test.secret },
			})
			assertOptimizerHoldout(t, &CompiledPolicy{catalog: catalog}, "\nKEY=GOOD\n", []string{"capture"})
		})
	}
}

func TestNativeEvaluatorNewlineCaptureEntropy(t *testing.T) {
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "below-threshold", Regex: `\nKEY=([A-Z]{4})\n`, Keywords: []string{"key"}, SecretGroup: 1, Entropy: 1.4},
		catalogRuleSpec{ID: "at-threshold", Regex: `\nKEY=([A-Z]{4})\n`, Keywords: []string{"key"}, SecretGroup: 1, Entropy: 1.5},
	)
	// GOOD has entropy 1.5; including KEY= would incorrectly raise it.
	assertOptimizerHoldout(t, &CompiledPolicy{catalog: catalog}, "\nKEY=GOOD\n", []string{"below-threshold"})
}

func TestNativeEvaluatorEntropyThresholdIsStrict(t *testing.T) {
	entropy := shannonEntropy("aabb")
	atThreshold := compileTestRule(t, catalogRuleSpec{ID: "entropy", Regex: `(aabb)`, Entropy: entropy})
	assert.Empty(t, atThreshold.detect("aabb", nil))

	belowThreshold := compileTestRule(t, catalogRuleSpec{ID: "entropy", Regex: `(aabb)`, Entropy: entropy - 0.001})
	assert.Len(t, belowThreshold.detect("aabb", nil), 1)
}

func TestNativeEvaluatorEntropyPreservesUnicodeSemantics(t *testing.T) {
	below := compileTestRule(t, catalogRuleSpec{ID: "entropy", Regex: `(éa)`, Entropy: 1.1})
	assert.Empty(t, below.detect("éa", nil))

	above := compileTestRule(t, catalogRuleSpec{ID: "entropy", Regex: `(éa)`, Entropy: 1})
	assert.Len(t, above.detect("éa", nil), 1)
}

func TestNativeEvaluatorCaptureAndEntropyVerdicts(t *testing.T) {
	for _, test := range []struct {
		name   string
		rules  []catalogRuleSpec
		probes []policyVerdictProbe
	}{
		{
			name: "capture-selection-and-strict-entropy",
			rules: []catalogRuleSpec{
				{ID: "z-zero", Regex: `C:(?:([a-z]{4})|([A-Z0-9]{4}))`},
				{ID: "a-default", Regex: `C:(?:([a-z]{4})|([A-Z0-9]{4}))`, Entropy: 1},
				{ID: "second-group", Regex: `C:(?:([a-z]{4})|([A-Z0-9]{4}))`, Entropy: 1, SecretGroup: 2},
				{ID: "first-group", Regex: `C:(?:([a-z]{4})|([A-Z0-9]{4}))`, Entropy: 1, SecretGroup: 1},
				{ID: "below-threshold", Regex: `C:(?:([a-z]{4})|([A-Z0-9]{4}))`, Entropy: 0.999},
			},
			probes: []policyVerdictProbe{
				{"rejected", "C:aaaa", []string{"z-zero"}},
				{"at-threshold", "C:aabb", []string{"z-zero", "below-threshold"}},
				{"first-group", "C:abcd", []string{"z-zero", "a-default", "first-group", "below-threshold"}},
				{"second-group", "C:AB12", []string{"z-zero", "a-default", "second-group", "below-threshold"}},
				{"rejected-then-accepted", "C:aabb C:AB12", []string{"z-zero", "a-default", "second-group", "below-threshold"}},
				{"order-and-dedup", strings.Repeat("C:AB12 C:abcd ", 8), []string{"z-zero", "a-default", "second-group", "first-group", "below-threshold"}},
			},
		},
		{
			name: "empty-and-nested-captures",
			rules: []catalogRuleSpec{
				{ID: "first-nonempty", Regex: `P:()(ab)(cd)`, Entropy: 1.5},
				{ID: "explicit-group", Regex: `P:()(ab)(cd)`, Entropy: 0.5, SecretGroup: 3},
				{ID: "outer-group", Regex: `N:((aa)(bc))`, Entropy: 1.25},
				{ID: "inner-group", Regex: `N:((aa)(bc))`, Entropy: 0.1, SecretGroup: 2},
				{ID: "empty-falls-back", Regex: `E:()`, Entropy: 0.5},
				{ID: "explicit-empty", Regex: `E:()`, Entropy: 0.5, SecretGroup: 1},
				{ID: "empty-entropy", Regex: `()`, Entropy: 0.5},
			},
			probes: []policyVerdictProbe{
				{"first-nonempty-not-full-match", "P:abcd", []string{"explicit-group"}},
				{"outer-before-inner", "N:aabc", []string{"outer-group"}},
				{"default-empty-versus-selected-empty", "E:", []string{"empty-falls-back"}},
				{"absent", "P:ab", nil},
				{"empty", "", nil},
			},
		},
		{
			name: "alternation-and-greediness",
			rules: []catalogRuleSpec{
				{ID: "short-first", Regex: `A:(a|abcd)`, Entropy: 0.5, SecretGroup: 1},
				{ID: "long-first", Regex: `A:(abcd|a)`, Entropy: 0.5, SecretGroup: 1},
				{ID: "lazy", Regex: `Q:([a-d]+?)`, Entropy: 0.5, SecretGroup: 1},
				{ID: "greedy", Regex: `Q:([a-d]+)`, Entropy: 0.5, SecretGroup: 1},
			},
			probes: []policyVerdictProbe{
				{"alternative-priority", "A:abcd", []string{"long-first"}},
				{"later-alternative-match", "A:aaaa A:abcd", []string{"long-first"}},
				{"short-only", "A:a", nil},
				{"greedy-capture", "Q:abcd", []string{"greedy"}},
				{"low-entropy-greedy-capture", "Q:aaaa", nil},
			},
		},
		{
			name: "unicode-capture-context",
			rules: []catalogRuleSpec{
				{ID: "capture", Regex: `CAP:([A-Z0-9]{8})(?:[^A-Z0-9]|$)`, SecretGroup: 1, Entropy: 2},
			},
			probes: []policyVerdictProbe{
				{"rejected-first-then-accepted", "界CAP:AAAAAAAAéCAP:AB12CD34😀", []string{"capture"}},
				{"accepted-capture-excludes-context", "界CAP:AB12CD34é", []string{"capture"}},
				{"context-must-not-raise-capture-entropy", "界CAP:AAAAAAAAé", nil},
			},
		},
		{
			name: "same-regex-distinct-acceptance",
			rules: []catalogRuleSpec{
				{ID: "same-a", Regex: `(MEM:([A-Z0-9]{8}))`, SecretGroup: 2},
				{ID: "same-b", Regex: `(MEM:([A-Z0-9]{8}))`, SecretGroup: 2},
				{ID: "body", Regex: `(MEM:([A-Z0-9]{8}))`, SecretGroup: 2, Entropy: 1},
				{ID: "whole", Regex: `(MEM:([A-Z0-9]{8}))`, SecretGroup: 1, Entropy: 1},
			},
			probes: []policyVerdictProbe{
				{"low-entropy-body", "界MEM:AAAAAAAAé", []string{"same-a", "same-b", "whole"}},
				{"diverse-body", "界MEM:AB12CD34é", []string{"same-a", "same-b", "body", "whole"}},
				{"short-body", "MEM:AB12CD3", nil},
			},
		},
		{
			name: "long-values-and-late-matches",
			rules: []catalogRuleSpec{
				{ID: "late-entropy", Regex: `LATE:([A-Z0-9]{8})`, Entropy: 2.5, SecretGroup: 1},
				{ID: "late-zero", Regex: `LATE:([A-Z0-9]{8})`},
			},
			probes: []policyVerdictProbe{
				{"long-clean", strings.Repeat("~", 131072), nil},
				{"late-match", strings.Repeat("~", 131072) + "LATE:AB12CD34", []string{"late-entropy", "late-zero"}},
				{"rejected-first-late-match", "LATE:AAAAAAAA" + strings.Repeat("~", 131072) + "LATE:AB12CD34", []string{"late-entropy", "late-zero"}},
				{"late-near-miss", strings.Repeat("~", 131072) + "LATE:AB12CD3", nil},
				{"invalid-before-late-match", "\xff" + strings.Repeat("~", 4096) + "LATE:AB12CD34", []string{"late-entropy", "late-zero"}},
				{"keyword-overflow-rejected-then-two-accepted", strings.Repeat("LATE:AAAAAAAA ", maxKeywordHits+1) + "LATE:AB12CD34 LATE:EF56GH78", []string{"late-entropy", "late-zero"}},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := compileCatalog(test.rules)
			require.NoError(t, err)
			policy := &CompiledPolicy{catalog: catalog}
			batch := policy.NewBatchDetector()
			for _, probe := range test.probes {
				t.Run(probe.name, func(t *testing.T) {
					var want Verdict
					for _, id := range probe.ruleIDs {
						want.Matches = append(want.Matches, Match{RuleID: id})
					}
					require.Equal(t, want, fullScanPolicyVerdict(policy, probe.value), "oracle")
					require.Equal(t, want, policy.Detect(probe.value), "direct")
					require.Equal(t, want, batch.Detect(probe.value), "batch miss")
					require.Equal(t, want, batch.Detect(probe.value), "batch hit")
				})
			}
		})
	}
}

func TestNativeEvaluatorValidatesOriginalContext(t *testing.T) {
	validate := func(value string, _, _ int, secret string) contextValidation {
		return contextValidation{accepted: secret == "key:GOOD" && !strings.Contains(value, "deny")}
	}
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "full", Regex: `(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, ValidateContext: validate},
		catalogRuleSpec{ID: "anchored", Regex: `\b(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, ValidateContext: validate},
		catalogRuleSpec{ID: "window", Regex: `\b[a-z]{2}=(key:[A-Z]{3,4})(?:$|[^A-Za-z0-9])`, Keywords: []string{"key"}, SecretGroup: 1, ValidateContext: validate},
	)
	policy := &CompiledPolicy{catalog: catalog}
	for _, probe := range []struct {
		name  string
		value string
		valid bool
	}{
		{name: "accepted", value: "aa=key:GOOD", valid: true},
		{name: "capture-rejected", value: "aa=key:BAD"},
		{name: "distant-context", value: "aa=key:GOOD" + strings.Repeat(" ", 1024) + "deny"},
		{name: "later-accepted", value: "aa=key:BAD aa=key:GOOD", valid: true},
		{name: "overflow-context", value: strings.Repeat("key ", maxKeywordHits+20) + "aa=key:GOOD deny"},
		{name: "unicode-context", value: "Key aa=key:GOOD deny"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			var ids []string
			if probe.valid {
				ids = []string{"full", "anchored", "window"}
			}
			assertOptimizerHoldout(t, policy, probe.value, ids)
		})
	}
}

func TestNativeEvaluatorContextRejectionAtEOF(t *testing.T) {
	for _, test := range []struct {
		name             string
		expression       string
		value            string
		firstRejectUntil int
		matched          bool
	}{
		{name: "first-rejection", expression: `a|$`, value: "aX", firstRejectUntil: 2, matched: true},
		{name: "later-rejection", expression: `a|b|$`, value: "abX", firstRejectUntil: 1, matched: true},
		{name: "abutting-empty-match-stays-suppressed", expression: `a|$`, value: "a", firstRejectUntil: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := compileTestCatalog(t, catalogRuleSpec{
				ID:    "eof",
				Regex: test.expression,
				ValidateContext: func(value string, start, _ int, _ string) contextValidation {
					if start == len(value) {
						return contextValidation{accepted: true}
					}
					if start == 0 {
						return contextValidation{rejectUntil: test.firstRejectUntil}
					}
					return contextValidation{rejectUntil: len(value)}
				},
			})
			var ids []string
			if test.matched {
				ids = []string{"eof"}
			}
			assertOptimizerHoldout(t, &CompiledPolicy{catalog: catalog}, test.value, ids)
		})
	}
}

func TestNativeEvaluatorCallbackFreeKeywordOverflow(t *testing.T) {
	for _, test := range []struct {
		name     string
		spec     catalogRuleSpec
		rejected string
		accepted string
	}{
		{
			name: "context-regexp",
			spec: catalogRuleSpec{
				ID:          "request",
				Regex:       `\bGET ([^\n]+)\n`,
				Keywords:    []string{"get"},
				SecretGroup: 1,
			},
			rejected: "~" + strings.Repeat("GET x ", maxKeywordHits*2),
			accepted: "~" + strings.Repeat("GET x ", maxKeywordHits*2) + "\n",
		},
		{
			name: "literal-run",
			spec: catalogRuleSpec{
				ID:          "token",
				Regex:       `\b(TOK_[A-Z _]+)$`,
				Keywords:    []string{"tok_"},
				SecretGroup: 1,
			},
			rejected: strings.Repeat("TOK_X ", maxKeywordHits*2) + "!",
			accepted: strings.Repeat("TOK_X ", maxKeywordHits*2),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &CompiledPolicy{catalog: compileTestCatalog(t, test.spec)}
			assertOptimizerHoldout(t, policy, test.rejected, nil)
			assertOptimizerHoldout(t, policy, test.accepted, []string{test.spec.ID})
		})
	}
}

func TestNativeEvaluatorEarlyVerdictAllocationGrowth(t *testing.T) {
	for _, test := range []struct {
		name   string
		spec   catalogRuleSpec
		prefix string
		token  string
	}{
		{
			name: "context-window",
			spec: catalogRuleSpec{
				ID:          "context",
				Regex:       `[a-z]{2}=key:([A-Z]{4})`,
				Keywords:    []string{"key"},
				SecretGroup: 1,
				ValidateContext: func(_ string, _, _ int, secret string) contextValidation {
					return contextValidation{accepted: secret == "KEEP"}
				},
			},
			token: "aa=key:KEEP ",
		},
		{
			name: "rejected-first-full-scan",
			spec: catalogRuleSpec{
				ID:          "capture",
				Regex:       `key:([A-Z]{4})`,
				Keywords:    []string{"key"},
				SecretGroup: 1,
				Validate:    func(secret string) bool { return secret == "KEEP" },
			},
			prefix: "key:DROP ",
			token:  "key:KEEP ",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := &CompiledPolicy{catalog: compileTestCatalog(t, test.spec)}
			small := test.prefix + strings.Repeat(test.token, 512)
			large := test.prefix + strings.Repeat(test.token, 8192)
			want := Verdict{Matches: []Match{{RuleID: test.spec.ID}}}
			batch := policy.NewBatchDetector()
			for _, value := range []string{small, large} {
				require.Equal(t, want, fullScanPolicyVerdict(policy, value), "oracle")
				require.Equal(t, want, policy.Detect(value), "direct")
				require.Equal(t, want, batch.Detect(value), "batch miss")
				require.Equal(t, want, batch.Detect(value), "batch hit")
			}
			assertOptimizerHoldout(t, policy, strings.ReplaceAll(small, "KEEP", "DROP"), nil)

			allocations := func(value string) float64 {
				// Direct detection has no value cache. Construction and oracle scans
				// stay outside the measurement; AllocsPerRun warms runtime pools.
				return testing.AllocsPerRun(20, func() {
					got := policy.Detect(value)
					if len(got.Matches) != 1 || got.Matches[0].RuleID != test.spec.ID {
						t.Fatalf("unexpected direct verdict: %+v", got)
					}
				})
			}
			smallAllocs := allocations(small)
			largeAllocs := allocations(large)
			// Allow fixed overhead and regexp execution-strategy differences,
			// but not allocation growth with the 16x larger unused match tail.
			require.LessOrEqual(t, largeAllocs, 2*smallAllocs+16,
				"early accepted verdict allocated with unused trailing matches: small=%g large=%g", smallAllocs, largeAllocs)
		})
	}
}
