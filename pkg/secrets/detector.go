package secrets

type Match struct {
	RuleID string
}

type Verdict struct {
	Matches []Match
}

func (v Verdict) Matched() bool {
	return len(v.Matches) > 0
}

type CompiledPolicy struct {
	catalog       *compiledCatalog
	disabled      ruleSet
	disabledCount int
	custom        compiledRuleSet
	minWidth      int // lower bound in runes across enabled native and custom rules
}

const batchDetectorValueCacheEntries = 32

type batchDetectorValueCacheEntry struct {
	value   string
	matches []Match
	hash    uint32
	valid   bool
}

type BatchDetector struct {
	policy     *CompiledPolicy
	valueCache [batchDetectorValueCacheEntries]batchDetectorValueCacheEntry
	hits       keywordHits
	hitBuffer  keywordHitBuffer
}

func (p *CompiledPolicy) NewBatchDetector() BatchDetector {
	return BatchDetector{policy: p}
}

func (d *BatchDetector) Detect(value string) Verdict {
	// Every rune consumes at least one byte. This bound includes tenant rules,
	// and becomes zero for nullable rules, so it is safe before cache lookup.
	if len(value) < d.policy.minWidth {
		return Verdict{}
	}
	return d.detect(value)
}

func (d *BatchDetector) detect(value string) Verdict {
	// Re-pointing on every call keeps copies of the detector self-contained.
	d.hits.buffer = &d.hitBuffer
	hash := batchDetectorValueHash(value)
	entry := &d.valueCache[hash&(batchDetectorValueCacheEntries-1)]
	if entry.valid && entry.hash == hash && entry.value == value {
		return Verdict{Matches: append([]Match(nil), entry.matches...)}
	}
	entry.value = value
	entry.matches = d.policy.detectMatches(value, &d.hits)
	entry.hash = hash
	entry.valid = true
	return Verdict{Matches: append([]Match(nil), entry.matches...)}
}

func batchDetectorValueHash(value string) uint32 {
	hash := uint32(len(value)) * 16777619
	if len(value) == 0 {
		return hash
	}
	hash = (hash ^ uint32(value[0])) * 16777619
	hash = (hash ^ uint32(value[len(value)/2])) * 16777619
	return (hash ^ uint32(value[len(value)-1])) * 16777619
}

func (p *CompiledPolicy) Detect(value string) Verdict {
	if len(value) < p.minWidth {
		return Verdict{}
	}
	return p.detect(value)
}

func (p *CompiledPolicy) detect(value string) Verdict {
	var hits keywordHits
	matches := p.detectMatches(value, &hits)
	hits.release()
	return Verdict{Matches: matches}
}

func (p *CompiledPolicy) detectMatches(value string, hits *keywordHits) []Match {
	var matches []Match
	if p.disabledCount == 0 {
		matches = p.catalog.detect(value, hits, nil)
	} else if p.disabledCount < len(p.catalog.rules) {
		matches = p.catalog.detectExcluding(value, hits, &p.disabled, nil)
	}
	return p.custom.detect(value, hits, matches)
}
