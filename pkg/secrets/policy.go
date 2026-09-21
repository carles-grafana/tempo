package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
)

const (
	maxPolicyCustomRules  = 16
	maxPolicyStringLength = 512
	maxCustomRegexLength  = 4096
)

type FeatureConfig struct {
	DetectionEnabled bool      `yaml:"detection_enabled,omitempty" json:"detection_enabled,omitempty"`
	EnabledRules     *[]string `yaml:"enabled_rules,omitempty" json:"enabled_rules,omitempty"`
}

// MarshalJSON preserves an explicitly empty Go-created selection as [] rather
// than null, which would enable the full catalog when the config is reloaded.
func (c FeatureConfig) MarshalJSON() ([]byte, error) {
	type plainFeatureConfig FeatureConfig
	if c.EnabledRules != nil && *c.EnabledRules == nil {
		empty := []string{}
		c.EnabledRules = &empty
	}
	return json.Marshal(plainFeatureConfig(c))
}

// Validate checks operator configuration even when detection is disabled.
func (c FeatureConfig) Validate() error {
	_, err := validateNativeSelection(c.EnabledRules)
	return err
}

// Policy excludes selected native rules and adds tenant-owned value rules.
// The process selection bounds native coverage. Attribute names are never input.
type Policy struct {
	DisabledRules []string     `yaml:"disabled_rules,omitempty" json:"disabled_rules,omitempty"`
	CustomRules   []CustomRule `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

type CustomRule struct {
	ID    string `yaml:"id" json:"id"`
	Regex string `yaml:"regex" json:"regex"`
}

func (c *PolicyCompiler) compilePolicy(policy Policy) (*CompiledPolicy, error) {
	if err := validatePolicyBounds(policy); err != nil {
		return nil, err
	}
	for i, rule := range policy.CustomRules {
		if !validCustomRuleID(rule.ID) {
			return nil, fmt.Errorf("custom secrets rule %d ID contains unsupported characters", i+1)
		}
	}
	var excluded ruleSet
	for i, id := range policy.DisabledRules {
		index, supported := supportedNativeRuleIndex(id)
		if !supported {
			return nil, fmt.Errorf("disabled secrets rule %d is not supported", i+1)
		}
		if excluded.has(index) {
			return nil, fmt.Errorf("disabled secrets rule %d is duplicated", i+1)
		}
		excluded.add(index)
	}
	catalog, err := c.catalog()
	if err != nil {
		return nil, errors.New("secret catalog compilation failed")
	}
	var disabled ruleSet
	disabledCount := 0
	for _, id := range policy.DisabledRules {
		if index, active := catalog.byID[id]; active {
			disabled.add(index)
			disabledCount++
		}
	}
	custom, err := compileCustomRules(policy.CustomRules)
	if err != nil {
		return nil, err
	}
	minWidth := int(^uint(0) >> 1)
	for i := range catalog.rules {
		if !disabled.has(uint16(i)) {
			minWidth = min(minWidth, catalog.rules[i].plan.minWidth)
		}
	}
	for i := range custom.rules {
		minWidth = min(minWidth, custom.rules[i].plan.minWidth)
	}
	return &CompiledPolicy{
		catalog:       catalog,
		disabled:      disabled,
		disabledCount: disabledCount,
		custom:        custom,
		minWidth:      minWidth,
	}, nil
}

func validatePolicyBounds(policy Policy) error {
	if len(policy.DisabledRules) > len(nativeRuleSpecs) {
		return errors.New("secrets policy has too many disabled rules")
	}
	if len(policy.CustomRules) > maxPolicyCustomRules {
		return errors.New("secrets policy has too many custom rules")
	}
	for i, id := range policy.DisabledRules {
		if len(id) > maxPolicyStringLength {
			return fmt.Errorf("disabled secrets rule %d is not supported", i+1)
		}
	}
	for i, rule := range policy.CustomRules {
		if len(rule.ID) > maxPolicyStringLength {
			return fmt.Errorf("custom secrets rule %d ID exceeds the byte limit", i+1)
		}
		if len(rule.Regex) > maxCustomRegexLength {
			return fmt.Errorf("custom secrets rule %d regex exceeds the byte limit", i+1)
		}
	}
	return nil
}

func validCustomRuleID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func compileCustomRules(custom []CustomRule) (compiledRuleSet, error) {
	var set compiledRuleSet
	if len(custom) == 0 {
		return set, nil
	}
	seen := make(map[string]struct{}, len(custom))
	instructions := 0
	// Complete the bounded parse/accounting pass before compiling any rule. A
	// small source expression can otherwise expand into a large exact program.
	for i, rule := range custom {
		if rule.ID == "" || rule.Regex == "" {
			return set, fmt.Errorf("custom secrets rule %d requires id and regex", i+1)
		}
		if _, exists := supportedNativeRuleIndex(rule.ID); exists {
			return set, fmt.Errorf("custom secrets rule %d conflicts with the production catalog", i+1)
		}
		if _, exists := seen[rule.ID]; exists {
			return set, fmt.Errorf("custom secrets rule %d has a duplicate ID", i+1)
		}
		seen[rule.ID] = struct{}{}
		parsed, err := syntax.Parse(rule.Regex, syntax.Perl)
		if err != nil {
			return set, fmt.Errorf("custom secrets rule %d has an invalid regex", i+1)
		}
		// Every program also has the fail and match instructions.
		instructions = addRegexpInstructions(instructions, addRegexpInstructions(regexpInstructionEstimate(parsed), 2))
		if instructions > maxCustomPolicyInstructions {
			return set, errors.New("custom secrets policy exceeds the regex instruction limit")
		}
	}
	// Identical execution plans may share immutable regexes and filters while
	// each configured rule keeps its own ID and matcher output. This cache is
	// compilation-local: it retains neither policies nor historical revisions.
	type compiledPlan struct {
		index    int
		keywords []string
	}
	var plans map[string]compiledPlan
	if len(custom) > 1 {
		plans = make(map[string]compiledPlan, len(custom))
	}
	set.rules = make([]compiledRule, len(custom))
	var matcherKeywords []matcherKeyword
	for i, rule := range custom {
		if previous, ok := plans[rule.Regex]; ok {
			set.rules[i] = set.rules[previous.index]
			set.rules[i].id = rule.ID
			matcherKeywords = set.addRuleKeywords(uint16(i), previous.keywords, matcherKeywords)
			continue
		}
		spec := catalogRuleSpec{ID: rule.ID, Regex: rule.Regex}
		keywords := effectiveKeywords(spec)
		compiled, err := compileRuleSpec(spec, keywords)
		if err != nil {
			// regexp errors include the expression. Neither those errors nor
			// tenant-authored IDs are safe to return to logs or callers.
			return compiledRuleSet{}, fmt.Errorf("custom secrets rule %d could not be compiled", i+1)
		}
		set.rules[i] = compiled
		matcherKeywords = set.addRuleKeywords(uint16(i), keywords, matcherKeywords)
		if plans != nil {
			plans[rule.Regex] = compiledPlan{i, keywords}
		}
	}
	var err error
	set.pairMatcher, err = newCatalogPairMatcher(matcherKeywords)
	if err != nil {
		return compiledRuleSet{}, errors.New("custom secrets policy matcher could not be compiled")
	}
	return set, nil
}

func isBaselinePolicy(policy Policy) bool {
	return len(policy.CustomRules) == 0 && len(policy.DisabledRules) == 0
}

// Bound expanded exact regexp programs before regexp.Compile or Simplify.
// Optimization caps may fall back, but this policy-wide resource cap rejects.
const maxCustomPolicyInstructions = 1 << 20

// regexpInstructionEstimate bounds the expanded Thompson program without
// simplifying counted repetitions. Captures add two instructions, optional
// copies and loops add branches, and nullable stars may require two branches.
// Saturation keeps nested arithmetic safe and preserves rejection at the cap.
func regexpInstructionEstimate(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return max(1, len(re.Rune))
	case syntax.OpCapture:
		return addRegexpInstructions(regexpInstructionEstimate(re.Sub[0]), 2)
	case syntax.OpStar:
		return addRegexpInstructions(regexpInstructionEstimate(re.Sub[0]), 2)
	case syntax.OpPlus, syntax.OpQuest:
		return addRegexpInstructions(regexpInstructionEstimate(re.Sub[0]), 1)
	case syntax.OpRepeat:
		if re.Max == 0 {
			return 1
		}
		body := regexpInstructionEstimate(re.Sub[0])
		if re.Max < 0 {
			if re.Min == 0 {
				return addRegexpInstructions(body, 2)
			}
			return addRegexpInstructions(multiplyRegexpInstructions(body, re.Min), 1)
		}
		return addRegexpInstructions(multiplyRegexpInstructions(body, re.Max), re.Max-re.Min)
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		if re.Op == syntax.OpAlternate {
			total = max(0, len(re.Sub)-1)
		}
		for _, sub := range re.Sub {
			total = addRegexpInstructions(total, regexpInstructionEstimate(sub))
		}
		return max(1, total)
	default:
		// Empty matches, assertions, no-match, and rune classes each need
		// at most one instruction.
		return 1
	}
}

func addRegexpInstructions(left, right int) int {
	if left > maxCustomPolicyInstructions || right > maxCustomPolicyInstructions-left {
		return maxCustomPolicyInstructions + 1
	}
	return left + right
}

func multiplyRegexpInstructions(instructions, copies int) int {
	if copies == 0 {
		return 0
	}
	if instructions > maxCustomPolicyInstructions/copies {
		return maxCustomPolicyInstructions + 1
	}
	return instructions * copies
}

func compileRuleSpec(spec catalogRuleSpec, keywords []string) (compiledRule, error) {
	compiler, err := newRuleCompiler(spec.Regex, regexp.Compile)
	if err != nil {
		return compiledRule{}, err
	}
	return compiler.compile(spec, keywords)
}
