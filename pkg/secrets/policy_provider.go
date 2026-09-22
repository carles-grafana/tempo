package secrets

import (
	"context"
	"slices"
	"sync/atomic"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type CompiledPolicyProvider func(context.Context) (policy *CompiledPolicy, ok bool)

const policyMetricsNamespace = "tempo"

var (
	policyCompilationSlots = make(chan struct{}, 2)
	policyUpdates          = newPolicyUpdateMetrics(prometheus.DefaultRegisterer)
)

type policyUpdateMetrics struct {
	applied    prometheus.Counter
	rejected   prometheus.Counter
	superseded prometheus.Counter
	canceled   prometheus.Counter
	duration   prometheus.Histogram
	active     prometheus.Gauge
}

func newPolicyUpdateMetrics(registerer prometheus.Registerer) *policyUpdateMetrics {
	factory := promauto.With(registerer)
	updates := factory.NewCounterVec(prometheus.CounterOpts{
		Namespace: policyMetricsNamespace,
		Name:      "secret_detection_policy_updates_total",
		Help:      "Secret detection policy update outcomes across all tenants.",
	}, []string{"outcome"})
	return &policyUpdateMetrics{
		applied:    updates.WithLabelValues("applied"),
		rejected:   updates.WithLabelValues("rejected"),
		superseded: updates.WithLabelValues("superseded"),
		canceled:   updates.WithLabelValues("canceled"),
		duration: factory.NewHistogram(prometheus.HistogramOpts{
			Namespace: policyMetricsNamespace,
			Name:      "secret_detection_policy_compilation_duration_seconds",
			Help:      "Time spent compiling secret detection policies, excluding admission waits.",
			Buckets:   prometheus.DefBuckets,
		}),
		active: factory.NewGauge(prometheus.GaugeOpts{
			Namespace: policyMetricsNamespace,
			Name:      "secret_detection_policy_compilations_active",
			Help:      "Secret detection policy compilations currently running across all tenants.",
		}),
	}
}

// Oversized inputs share a fixed rejection state. Never retain their payload,
// hash it, or compare it: even identifying a rejected revision must be bounded.
type policyInput struct {
	policy    Policy
	oversized bool
}

func (input policyInput) equal(other policyInput) bool {
	return input.oversized == other.oversized && policiesEqual(input.policy, other.policy)
}

// Entries are immutable after publication, including both policy rule slices.
// A rejected lastInput is remembered without changing the accepted policy.
type compiledPolicyEntry struct {
	compiled  *CompiledPolicy
	lastInput policyInput
	accepted  Policy
}

type compiledPolicyProvider struct {
	tenant    string
	policy    func(string) (*Policy, bool)
	logger    log.Logger
	updating  chan struct{}
	entry     atomic.Pointer[compiledPolicyEntry]
	compile   func(Policy) (*CompiledPolicy, error)
	admission chan struct{}
	metrics   *policyUpdateMetrics
}

// NewCompiledPolicyProvider refreshes the tenant's policy on each call. The
// callback resolves override precedence; its bool denotes inheritance and is
// ignored. Its returned policy and slices must remain stable during provider
// calls; backing storage may be reused between completed calls.
// Consecutive oversized inputs are coalesced into one rejection episode until
// an in-bounds input is observed, without retaining the oversized payload.
// The returned bool is false only when no compiled fallback is available.
func (c *PolicyCompiler) NewCompiledPolicyProvider(tenant string, policy func(string) (*Policy, bool), logger log.Logger) CompiledPolicyProvider {
	provider := &compiledPolicyProvider{
		tenant:    tenant,
		policy:    policy,
		logger:    logger,
		updating:  make(chan struct{}, 1),
		compile:   c.compileAdmitted,
		admission: policyCompilationSlots,
		metrics:   policyUpdates,
	}
	return provider.current
}

func (p *compiledPolicyProvider) current(ctx context.Context) (*CompiledPolicy, bool) {
	// Only the caller holding this gate may build or publish. Waiting callers
	// do not enqueue policy snapshots: they read the effective override afresh.
	select {
	case p.updating <- struct{}{}:
		defer func() { <-p.updating }()
	case <-ctx.Done():
		return p.canceled()
	}

	for {
		if ctx.Err() != nil {
			return p.canceled()
		}
		input := p.effectivePolicy()
		previous := p.entry.Load()
		if previous != nil {
			if input.equal(previous.lastInput) {
				return p.snapshot()
			}
			if !input.oversized && previous.compiled != nil && policiesEqual(input.policy, previous.accepted) {
				entry := *previous
				entry.lastInput = policyInput{policy: previous.accepted}
				p.entry.Store(&entry)
				return p.snapshot()
			}
		}

		select {
		case p.admission <- struct{}{}:
		case <-ctx.Done():
			return p.canceled()
		}
		if ctx.Err() != nil {
			<-p.admission
			return p.canceled()
		}
		// Admission can wait behind other tenants. Do not compile an override
		// that was removed or replaced while waiting for a process-wide slot.
		if !input.equal(p.effectivePolicy()) {
			<-p.admission
			p.metrics.superseded.Inc()
			continue
		}

		var compiled *CompiledPolicy
		rejected := input.oversized
		if !rejected {
			input.policy = clonePolicy(input.policy)
			var err error
			compiled, err = p.metrics.compile(p.compile, input.policy)
			rejected = err != nil
		}
		// regexp.Compile is not interruptible. Keep its slot until it returns,
		// then discard canceled or stale work rather than publishing it.
		if ctx.Err() != nil {
			<-p.admission
			return p.canceled()
		}
		if !input.equal(p.effectivePolicy()) {
			<-p.admission
			p.metrics.superseded.Inc()
			continue
		}
		if rejected && (previous == nil || previous.compiled == nil) {
			// Invalid initial overrides fail open to this compiler's selected
			// baseline, under the same admission bound as custom policies.
			compiled, _ = p.metrics.compile(p.compile, Policy{})
		}
		<-p.admission

		if ctx.Err() != nil {
			return p.canceled()
		}
		if !input.equal(p.effectivePolicy()) {
			p.metrics.superseded.Inc()
			continue
		}

		entry := &compiledPolicyEntry{lastInput: input}
		if previous != nil {
			entry.compiled = previous.compiled
			entry.accepted = previous.accepted
		}
		if rejected {
			if entry.compiled == nil && compiled != nil {
				entry.compiled = compiled
			}
		} else {
			entry.compiled = compiled
			entry.accepted = input.policy
		}
		// Publication linearizes here. The per-provider gate prevents any
		// older caller from replacing this snapshot with its completed build.
		p.entry.Store(entry)
		if rejected {
			p.metrics.rejected.Inc()
			// Never log compiler errors: they can contain tenant-authored IDs,
			// expressions, or credentials. Rejections are not coverage gaps.
			level.Error(p.logger).Log("msg", "secrets policy rejected; retaining last-known-good or native policy")
		} else {
			p.metrics.applied.Inc()
		}
		return p.snapshot()
	}
}

func (p *compiledPolicyProvider) effectivePolicy() policyInput {
	// Overrides already resolve overlay, tenant, wildcard and default
	// precedence. Inheritance metadata does not change the effective rules.
	input, _ := p.policy(p.tenant)
	if input == nil {
		return policyInput{}
	}
	if input.rejected {
		return policyInput{policy: RejectedPolicy()}
	}
	if validatePolicyBounds(*input) != nil {
		return policyInput{oversized: true}
	}
	return policyInput{policy: *input}
}

func (m *policyUpdateMetrics) compile(compile func(Policy) (*CompiledPolicy, error), input Policy) (*CompiledPolicy, error) {
	m.active.Inc()
	started := time.Now()
	defer func() {
		m.duration.Observe(time.Since(started).Seconds())
		m.active.Dec()
	}()
	return compile(input)
}

func (p *compiledPolicyProvider) canceled() (*CompiledPolicy, bool) {
	p.metrics.canceled.Inc()
	return p.snapshot()
}

func (p *compiledPolicyProvider) snapshot() (*CompiledPolicy, bool) {
	entry := p.entry.Load()
	if entry == nil {
		return nil, false
	}
	return entry.compiled, entry.compiled != nil
}

func clonePolicy(policy Policy) Policy {
	policy.DisabledRules = append([]string(nil), policy.DisabledRules...)
	policy.CustomRules = append([]CustomRule(nil), policy.CustomRules...)
	return policy
}

func policiesEqual(left, right Policy) bool {
	return left.rejected == right.rejected && slices.Equal(left.DisabledRules, right.DisabledRules) &&
		slices.Equal(left.CustomRules, right.CustomRules)
}
