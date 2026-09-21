package secrets

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkEngineContextKeywordOverflow(b *testing.B) {
	catalog := compileTestCatalog(b, catalogRuleSpec{
		ID:          "request",
		Regex:       `\bGET ([^\n]+)\n`,
		Keywords:    []string{"get"},
		SecretGroup: 1,
		ValidateContext: func(_ string, _, _ int, _ string) contextValidation {
			return contextValidation{accepted: true}
		},
	})
	policy := &CompiledPolicy{catalog: catalog}
	for _, starts := range []int{512, 2048, 8192} {
		b.Run(fmt.Sprintf("starts-%d", starts), func(b *testing.B) {
			value := strings.Repeat("GET x ", starts)
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if policy.Detect(value).Matched() {
					b.Fatal("matched a request without its required newline")
				}
			}
		})
	}
}

func BenchmarkEngineCallbackFreeKeywordOverflow(b *testing.B) {
	for _, test := range []struct {
		name   string
		spec   catalogRuleSpec
		prefix string
		token  string
		suffix string
	}{
		{
			name: "context-regexp",
			spec: catalogRuleSpec{
				ID:          "request",
				Regex:       `\bGET ([^\n]+)\n`,
				Keywords:    []string{"get"},
				SecretGroup: 1,
			},
			prefix: "~",
			token:  "GET x ",
		},
		{
			name: "literal-run",
			spec: catalogRuleSpec{
				ID:          "token",
				Regex:       `\b(TOK_[A-Z _]+)$`,
				Keywords:    []string{"tok_"},
				SecretGroup: 1,
			},
			token:  "TOK_X ",
			suffix: "!",
		},
	} {
		b.Run(test.name, func(b *testing.B) {
			policy := &CompiledPolicy{catalog: compileTestCatalog(b, test.spec)}
			for _, starts := range []int{512, 2048, 8192} {
				b.Run(fmt.Sprintf("starts-%d", starts), func(b *testing.B) {
					value := test.prefix + strings.Repeat(test.token, starts) + test.suffix
					b.SetBytes(int64(len(value)))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if policy.Detect(value).Matched() {
							b.Fatal("matched an invalid value")
						}
					}
				})
			}
		})
	}
}

func BenchmarkEngineEarlyVerdictAllocations(b *testing.B) {
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
		b.Run(test.name, func(b *testing.B) {
			policy := &CompiledPolicy{catalog: compileTestCatalog(b, test.spec)}
			for _, matches := range []int{512, 2048, 8192} {
				b.Run(fmt.Sprintf("accepted-%d", matches), func(b *testing.B) {
					value := test.prefix + strings.Repeat(test.token, matches)
					b.SetBytes(int64(len(value)))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						got := policy.Detect(value)
						if len(got.Matches) != 1 || got.Matches[0].RuleID != test.spec.ID {
							b.Fatalf("unexpected direct verdict: %+v", got)
						}
					}
				})
			}
		})
	}
}

func BenchmarkEngineSharedKeywordRules(b *testing.B) {
	for _, count := range []int{16, 64, 256} {
		b.Run(fmt.Sprintf("rules-%d", count), func(b *testing.B) {
			specs := make([]catalogRuleSpec, count)
			for i := range specs {
				specs[i] = catalogRuleSpec{
					ID:       fmt.Sprintf("rule-%03d", i),
					Regex:    `\bkey:[A-Z]{4}\b`,
					Keywords: []string{"key"},
				}
			}
			catalog := compileTestCatalog(b, specs...)
			policy := &CompiledPolicy{catalog: catalog}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if got := len(policy.Detect("key:ABCD").Matches); got != count {
					b.Fatalf("matched %d rules, want %d", got, count)
				}
			}
		})
	}
}
