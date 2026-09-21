package secrets

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestKeywordCandidatesRetainUnicodeBranches(t *testing.T) {
	for _, test := range []struct {
		name, expression, keyword, value string
		matches                          bool
	}{
		{"Unicode alternative", `(?:token|é)`, "token", "é", true},
		{"Unicode class", `t[oé]k`, "tok", "ték", true},
		{"folded Unicode alternative", `(?i:token|é)`, "token", "É", true},
		{"class with fold aliases and other Unicode", `(?i:to[ké]en)`, "token", "toéen", true},
		{"derived common suffix", `(?:token|é)credential`, "token", "écredential", true},
		{"exact keyword rejects fold alias", `token`, "token", "toKen", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := compileCatalog([]catalogRuleSpec{{
				ID: "unicode-candidate", Regex: test.expression, Keywords: []string{test.keyword},
			}})
			if err != nil {
				t.Fatal(err)
			}
			policy := CompiledPolicy{catalog: catalog}
			batch := policy.NewBatchDetector()
			var want []Match
			if test.matches {
				want = []Match{{RuleID: "unicode-candidate"}}
			}
			if !slices.Equal(want, policy.Detect(test.value).Matches) ||
				!slices.Equal(want, batch.Detect(test.value).Matches) {
				t.Fatal("public finding differs from the independently expected verdict")
			}
		})
	}
}

func TestUnicodeKeywordPlansPreserveIndependentCaptureOracle(t *testing.T) {
	tests := []struct {
		name, expression string
		keywords         []string
		values           []string
	}{
		{
			name:       "Unicode alternative and folded keyword starts",
			expression: `(?i:(token|é|secret))`,
			keywords:   []string{"token", "secret"},
			values:     []string{"é ſecret toKen token", "\xffÉ ſecret", "token é secret"},
		},
		{
			name:       "alternative request starts",
			expression: `(?i:\b(?:GET|POST)) ([^\n]{1,8})(?:\n|$)`,
			keywords:   []string{"get", "post"},
			values: []string{
				"GET deny\nPOST 界😀\n",
				"界GET deny\npost \xff\xfe\n",
				"éPOſT Kſ\n",
				"GET too-long-body\n界POST valid\n",
				"界" + strings.Repeat("GET? ", maxKeywordHits+1) + "\nPOST deny\nGET valid\n",
				"GET deny\n" + strings.Repeat("POST? ", maxKeywordHits+1) + "\nPOST 界\n",
			},
		},
		{
			name:       "exact alternative starts with fold aliases in tail",
			expression: `\b(?:GET|PUT) ((?i:[a-z]){4})(?:\n|$)`,
			keywords:   []string{"get", "put"},
			values:     []string{"界GET KſKſ\nPUT deny\n", "\xffPUT deny\nGET pass\n"},
		},
		{
			name:       "Unicode branch retains its earlier match start",
			expression: `((?:GET|界GET)[^\n]{4})`,
			keywords:   []string{"get"},
			values:     []string{"界GETabcd GETefgh", "\xff界GET😀😀😀😀", "GETabcd界GETefgh"},
		},
		{
			name:       "nullable Unicode prefix",
			expression: `((?:界)?GET[^\n]{4})`,
			keywords:   []string{"get"},
			values:     []string{"界GETabcd GETefgh", "\xffGET😀😀😀😀"},
		},
		{
			name:       "bounded Unicode windows",
			expression: `(?:\A|[^A-Z])((?:GET|POST)[^\n]{4})(?:\n|\z)`,
			keywords:   []string{"get", "post"},
			values: []string{
				strings.Repeat("界", 40) + "GET😀😀😀😀\n" + strings.Repeat("é", 40),
				"\xffGETabcd\n界POSTefgh\n",
				strings.Repeat("é", 30) + "界GETabcdX" + strings.Repeat("界", 40),
				"GETabcd\n" + strings.Repeat("POST? ", maxKeywordHits+1) + "界GET😀😀😀😀\n",
			},
		},
		{
			name:       "replacement rune windows preserve malformed bytes",
			expression: `(?:\x{FFFD}|!)(GET[^\n]{2})(?:\n|\z)`,
			keywords:   []string{"get"},
			values: []string{
				strings.Repeat("é", 20) + "\xffGET😀界\n" + strings.Repeat("界", 20),
				strings.Repeat("😀", 20) + "!GET\xfe\x80\n",
				"界GETab\n", "\xef\xbf\xbdGETab\n",
			},
		},
		{
			name:       "nullable ASCII prefix with Unicode body",
			expression: `[A-Z._]{0,4}(GET[^\n]{4})`,
			keywords:   []string{"get"},
			values:     []string{"界AB._GET😀😀😀😀", "GETabcdGETefgh"},
		},
		{
			name:       "overlapping alternative keywords",
			expression: `\b((?:ABA|BAB)[^\n]{1,4})`,
			keywords:   []string{"aba", "bab"},
			values:     []string{"界ABABABA😀 BABAB\n", "ABABABABAB", "\xffBAB😀ABA界"},
		},
		{
			name:       "line and absolute assertions",
			expression: `(?m)^(GET|POST)[^\n]{1,4}$`,
			keywords:   []string{"get", "post"},
			values:     []string{"界GETabcd\nPOST😀😀😀😀\n", "GETabcdX\nPOST界\n", "\xff\nGET😀😀😀😀"},
		},
	}
	type observation struct {
		start, end int
		secret     string
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oracle := regexp.MustCompile(test.expression)
			var value string
			var observed []observation
			catalog, err := compileCatalog([]catalogRuleSpec{{
				ID: "unicode-oracle", Regex: test.expression, Keywords: test.keywords, SecretGroup: 1,
				ValidateContext: func(original string, start, end int, secret string) contextValidation {
					if original != value {
						t.Fatal("context validator received a sliced value")
					}
					observed = append(observed, observation{start, end, secret})
					return contextValidation{accepted: secret != "deny"}
				},
			}})
			if err != nil {
				t.Fatal("catalog compilation failed")
			}
			policy := CompiledPolicy{catalog: catalog}
			batch := policy.NewBatchDetector()
			for probe, input := range test.values {
				value = input
				var wantObservations []observation
				var want []Match
				for _, indices := range oracle.FindAllStringSubmatchIndex(value, -1) {
					secret := value[indices[2]:indices[3]]
					wantObservations = append(wantObservations, observation{indices[0], indices[1], secret})
					if secret != "deny" {
						want = append(want, Match{RuleID: "unicode-oracle"})
					}
				}
				observed = nil
				got := catalogFindings(catalog, value, true)
				if !slices.Equal(want, got) || !slices.Equal(wantObservations, observed) {
					t.Fatalf("probe %d: complete matches or capture byte offsets differ from standard regexp", probe)
				}
				if len(want) > 1 {
					want = want[:1]
				}
				if !slices.Equal(want, policy.Detect(value).Matches) || !slices.Equal(want, batch.Detect(value).Matches) {
					t.Fatalf("probe %d: public first-accepted finding differs from standard regexp", probe)
				}
			}
		})
	}
}

func TestContextExecutionPreservesExistenceAndCaptureAcceptance(t *testing.T) {
	for _, expression := range []string{
		`\b(?:GET|POST) ([^\n]{1,8})(?:\n|$)`,
		`(?m)^(?:GET|POST) ([^\n]{1,8})$`,
		`\A(?:GET|POST) ([^\n]{1,8})\z`,
	} {
		for _, entropy := range []float64{0, 1} {
			catalog, err := compileCatalog([]catalogRuleSpec{{
				ID: "context-execution", Regex: expression, SecretGroup: 1, Entropy: entropy,
				Keywords: []string{"get", "post"},
			}})
			if err != nil {
				t.Fatal("policy compilation failed")
			}
			policy := CompiledPolicy{catalog: catalog}
			oracle := regexp.MustCompile(expression)
			for probe, value := range []string{
				"GET aaaaaaaa\nPOST abcd1234\n",
				"GET too-long-body\nPOST abcd1234\n",
				"界GET abcd1234\n",
				"GET aaaaaaaa\n",
				"GET abcd1234",
				strings.Repeat("GET? ", maxKeywordHits+1) + "\nPOST abcd1234\n",
			} {
				var want []Match
				for _, indices := range oracle.FindAllStringSubmatchIndex(value, -1) {
					if entropy == 0 || shannonEntropy(value[indices[2]:indices[3]]) > entropy {
						want = []Match{{RuleID: "context-execution"}}
						break
					}
				}
				if !slices.Equal(want, policy.Detect(value).Matches) {
					t.Fatalf("probe %d: context execution differs from standard regexp", probe)
				}
			}
		}
	}
}
