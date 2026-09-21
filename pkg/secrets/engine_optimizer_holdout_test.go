package secrets

import (
	"fmt"
	"strings"
	"testing"
)

func TestOptimizerHoldoutStrictRunBoundaries(t *testing.T) {
	// The same credential appears in anchored, bounded-context and unbounded-
	// context expressions. Tests deliberately do not prescribe their chosen plans.
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "z-anchored", Regex: `\bHLD:([A-Za-z0-9]{16})!`, Keywords: []string{"hld:"}, SecretGroup: 1},
		catalogRuleSpec{ID: "a-bounded", Regex: `[A-Z]{2}/HLD:([A-Za-z0-9]{16})!`, Keywords: []string{"hld:"}, SecretGroup: 1},
		catalogRuleSpec{ID: "m-unbounded", Regex: `[A-Z]+/HLD:([A-Za-z0-9]{16})!`, Keywords: []string{"hld:"}, SecretGroup: 1},
	)
	policy := &CompiledPolicy{catalog: catalog}
	const body = "A1b2C3d4E5f6G7h8"
	const credential = "AB/HLD:" + body + "!"
	one := []string{"z-anchored", "a-bounded", "m-unbounded"}
	cases := []struct {
		name  string
		value string
		ids   []string
	}{
		{"one-short", "AB/HLD:" + body[:15] + "!", nil},
		{"exact", credential, one},
		{"one-long", "AB/HLD:" + body + "9!", nil},
		{"punctuation-splits-run", "AB/HLD:" + body[:8] + "." + body[8:] + "!", nil},
		{"two-byte-rune-splits-run", "AB/HLD:" + body[:8] + "é" + body[8:] + "!", nil},
		{"four-byte-rune-replaces-byte", "AB/HLD:" + body[:7] + "\U00010400" + body[8:] + "!", nil},
		{"invalid-byte-splits-run", "AB/HLD:" + body[:8] + "\xff" + body[8:] + "!", nil},
		{"strict-class-rejects-kelvin", "AB/HLD:" + body[:15] + "K!", nil},
		{"strict-class-rejects-long-s", "AB/HLD:" + body[:15] + "ſ!", nil},
		{"unrelated-long-run-does-not-match", strings.Repeat("x", 64) + " AB/HLD:" + body[:15] + "!", nil},
		{"unicode-around-exact-run", "界é/" + credential + "/λ中", one},
		{"invalid-utf8-around-exact-run", "\xff\xc0\xaf/" + credential + "/\xed\xa0\x80", one},
		{"rejected-first-valid-later", "AB/HLD:" + body[:15] + "! " + credential, one},
		{"adjacent-valid-occurrences", credential + credential, []string{"z-anchored", "z-anchored", "a-bounded", "a-bounded", "m-unbounded", "m-unbounded"}},
		{"keyword-flood-then-exact", strings.Repeat("HLD:? ", 300) + credential, one},
		{"unicode-keyword-flood-then-exact", strings.Repeat("HLD:é ", 250) + credential, one},
	}
	// Place the mandatory body across common byte/chunk boundaries, including
	// values just below 2 KiB. These offsets are not read from implementation constants.
	for _, boundary := range []int{32, 64, 128, 256, 512, 1024} {
		cases = append(cases, struct {
			name  string
			value string
			ids   []string
		}{fmt.Sprintf("body-crosses-%d", boundary), strings.Repeat("~", boundary-9) + credential, one})
	}
	cases = append(cases, struct {
		name  string
		value string
		ids   []string
	}{"exact-at-2047-bytes", strings.Repeat("~", 2047-len(credential)) + credential, one})
	// Measurement sizes must never become a runtime truncation boundary.
	cases = append(cases, struct {
		name  string
		value string
		ids   []string
	}{"valid-after-128KiB", strings.Repeat("~", 128<<10) + credential, one})
	for _, probe := range cases {
		t.Run(probe.name, func(t *testing.T) {
			assertOptimizerHoldout(t, policy, probe.value, probe.ids)
		})
	}
}

func TestOptimizerHoldoutAlternationOptionalAndUnicode(t *testing.T) {
	catalog := compileTestCatalog(
		t,
		catalogRuleSpec{ID: "branch", Regex: `\b(?:long_[A-Za-z0-9]{24}|ok_[0-9]{2})!`, Keywords: []string{"long_"}},
		catalogRuleSpec{ID: "optional", Regex: `\b(?:pad_[A-Z]{24};)?done_[0-9]{2}!`, Keywords: []string{"pad_"}},
		catalogRuleSpec{ID: "repeat", Regex: `\b(?:pad_[A-Z]{24};){0,2}stop_[0-9]{2}!`, Keywords: []string{"pad_"}},
		catalogRuleSpec{ID: "folded-class", Regex: `\bfold_((?i:[a-z]{8}))!`, Keywords: []string{"fold_"}, SecretGroup: 1},
		catalogRuleSpec{ID: "mixed-scope", Regex: `\bscope_(?i:[ks]{8})[A-Z0-9]{12}!`, Keywords: []string{"scope_"}},
		catalogRuleSpec{ID: "replacement-rune", Regex: `\bbad_\x{FFFD}[A-F0-9]{12}!`, Keywords: []string{"bad_"}},
		catalogRuleSpec{ID: "punctuated-run", Regex: `\bpunct_([A-Za-z0-9_/-]{16})!`, Keywords: []string{"punct_"}, SecretGroup: 1},
		catalogRuleSpec{ID: "entropy", Regex: `\bentropy_([A-Za-z0-9]{16})!`, Keywords: []string{"entropy_"}, SecretGroup: 1, Entropy: 2.5},
	)
	policy := &CompiledPolicy{catalog: catalog}
	const pad = "pad_ABCDEFGHIJKLMNOPQRSTUVWX;"
	const high = "entropy_A1b2C3d4E5f6G7h8!"
	const low = "entropy_aaaaaaaaaaaaaaaa!"
	for _, probe := range []struct {
		name  string
		value string
		ids   []string
	}{
		{"short-alternate-without-long-run", "ok_42!", []string{"branch"}},
		{"long-alternate-exact", "long_Ab12Cd34Ef56Gh78Ij90Kl12!", []string{"branch"}},
		{"short-alternate-after-failed-long", "long_Ab12! ok_42!", []string{"branch"}},
		{"short-alternate-after-unicode", "界/ok_42!", []string{"branch"}},
		{"both-alternates-in-one-value", "ok_42! long_Ab12Cd34Ef56Gh78Ij90Kl12!", []string{"branch", "branch"}},
		{"optional-long-run-absent", "done_42!", []string{"optional"}},
		{"optional-long-run-present", pad + "done_42!", []string{"optional"}},
		{"optional-long-run-separated-by-unicode", "é" + pad + "done_42!", []string{"optional"}},
		{"zero-optional-repeats", "stop_42!", []string{"repeat"}},
		{"two-optional-repeats", pad + pad + "stop_42!", []string{"repeat"}},
		{"folded-ascii-exact", "fold_kSkSkSkS!", []string{"folded-class"}},
		{"kelvin-class-aliases", "fold_KKKKKKKK!", []string{"folded-class"}},
		{"long-s-class-aliases", "fold_ſſſſſſſſ!", []string{"folded-class"}},
		{"mixed-class-aliases", "fold_kKsſKKSſ!", []string{"folded-class"}},
		{"alias-byte-length-is-not-rune-length", "fold_KſKſKſK!", nil},
		{"folded-class-does-not-accept-arbitrary-unicode", "fold_KſKſKſKé!", nil},
		{"folded-class-invalid-byte", "fold_kSkS\xffSkS!", nil},
		{"strict-run-after-unicode-folds", "scope_KſKſKſKſAB12CD34EF56!", []string{"mixed-scope"}},
		{"strict-run-after-folds-one-short", "scope_KſKſKſKſAB12CD34EF5!", nil},
		{"strict-scope-must-not-fold", "scope_KſKſKſKſAB12CD34EF5ſ!", nil},
		{"invalid-utf8-matches-replacement-rune", "bad_\xffAB12CD34EF56!", []string{"replacement-rune"}},
		{"literal-replacement-rune", "bad_�AB12CD34EF56!", []string{"replacement-rune"}},
		{"two-invalid-bytes-are-two-runes", "bad_\xc0\xafAB12CD34EF56!", nil},
		{"punctuation-is-part-of-required-class", "punct_A1_b2/C3-d4_E5/f!", []string{"punctuated-run"}},
		{"punctuation-class-rejects-dot", "punct_A1_b2.C3-d4_E5/f!", nil},
		{"punctuation-class-rejects-multibyte", "punct_A1_b2éC3-d4_E5/f!", nil},
		{"low-entropy-only", low, nil},
		{"rejected-entropy-candidate-then-valid", low + " " + high, []string{"entropy"}},
		{"rejected-between-valid-candidates", high + " " + low + " " + high, []string{"entropy", "entropy"}},
		{"keyword-flood-then-short-branch", strings.Repeat("long_? ", 270) + "ok_42!", []string{"branch"}},
		{"catalog-order-not-position-or-name", high + " fold_KſKſKſKſ! ok_42! " + high, []string{"branch", "folded-class", "entropy", "entropy"}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			assertOptimizerHoldout(t, policy, probe.value, probe.ids)
		})
	}
}

func TestOptimizerHoldoutResumedVerdictContext(t *testing.T) {
	for _, test := range []struct {
		name, expression, value, secret string
		start, end                      int
		matched                         bool
	}{
		{"word-boundary", `(a|\bb)`, "ab", "b", 1, 2, false},
		{"non-boundary", `(a|\Bb)`, "ab", "b", 1, 2, true},
		{"text-anchor", `(a|\Ab)`, "ab", "b", 1, 2, false},
		{"line-anchor", `(?m)(a|^b)`, "a\nb", "b", 2, 3, true},
		{"unicode-context", `(é|\bb)`, "éb", "b", 2, 3, true},
		{"invalid-utf8-context", `(\x{FFFD}|\bb)`, "\xffb", "b", 1, 2, true},
		{"nonoverlapping-captures", `(aa|ab)`, "aab", "ab", 1, 3, false},
		{"nullable-unicode", `(\B|$)`, "é", "", 2, 2, true},
		{"resumed-newline-capture", `(?m)^(?:DROP|KEY=([A-Z]{4}))\n`, "DROP\nKEY=KEEP\n", "KEEP", 5, 14, true},
		{"window-original-offsets", `[a-z]{2}=key:([A-Z]{4})`, strings.Repeat("~", 64) + "aa=key:DROP bb=key:KEEP ", "KEEP", 76, 87, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := compileTestCatalog(t, catalogRuleSpec{
				ID: "context", Regex: test.expression, SecretGroup: 1,
				ValidateContext: func(value string, start, end int, secret string) contextValidation {
					return contextValidation{accepted: value == test.value &&
						start == test.start && end == test.end && secret == test.secret}
				},
			})
			var ids []string
			if test.matched {
				ids = []string{"context"}
			}
			assertOptimizerHoldout(t, &CompiledPolicy{catalog: catalog}, test.value, ids)
		})
	}
}
