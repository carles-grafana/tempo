package secretdetection

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	gklog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/grafana/tempo/modules/generator/processor"
	"github.com/grafana/tempo/modules/generator/registry"
	"github.com/grafana/tempo/pkg/ingest"
	"github.com/grafana/tempo/pkg/secrets"
	"github.com/grafana/tempo/pkg/tempopb"
	common_v1 "github.com/grafana/tempo/pkg/tempopb/common/v1"
	resource_v1 "github.com/grafana/tempo/pkg/tempopb/resource/v1"
	trace_v1 "github.com/grafana/tempo/pkg/tempopb/trace/v1"
	"github.com/grafana/tempo/pkg/util/test"
)

// capturingLogger records all log calls for assertion.
type capturingLogger struct {
	mu      sync.Mutex
	entries []map[string]string
}

func (l *capturingLogger) Log(keyvals ...interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := make(map[string]string)
	for i := 0; i+1 < len(keyvals); i += 2 {
		key, _ := keyvals[i].(string)
		val := fmt.Sprintf("%v", keyvals[i+1])
		entry[key] = val
	}
	l.entries = append(l.entries, entry)
	return nil
}

func (l *capturingLogger) Entries() []map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]map[string]string, len(l.entries))
	copy(cp, l.entries)
	return cp
}

type capturingObserver struct {
	value float64
}

func (o *capturingObserver) Observe(value float64) {
	o.value = value
}

func newTestProcessor(t *testing.T) *Processor {
	t.Helper()
	cfg := Config{}
	cfg.RegisterFlagsAndApplyDefaults("", nil)
	p, err := New(cfg, "test-tenant", gklog.NewNopLogger(), nil)
	require.NoError(t, err)
	p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	return p
}

func newTestProcessorWithLogger(t *testing.T, logger *capturingLogger) *Processor {
	t.Helper()
	p, err := New(Config{}, "test-tenant", level.Warn(logger), nil)
	require.NoError(t, err)
	p.logFinding = logger.Log
	p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	return p
}

// Test secrets are built via concatenation so no complete token literal appears
// in source — this avoids triggering GitHub push protection.
func fakeSlackToken() string { return "xoxb-" + "1234567890-1234567890123-abcdefghijklmnopqrstuvwx" }
func fakeStripeKey() string  { return "sk_live_" + "1234567890abcdefghijklmnop" }

func TestName(t *testing.T) {
	p := newTestProcessor(t)
	assert.Equal(t, processor.SecretDetectionName, p.Name())
}

func TestDetectsSlackBotToken(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Attributes: []*common_v1.KeyValue{
									test.MakeAttribute("slack.token", fakeSlackToken()),
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))
	assert.Greater(t, count, 0.0, "expected secret detection for Slack bot token")
}

func TestDetectsStripeKey(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Attributes: []*common_v1.KeyValue{
									test.MakeAttribute("payment.key", fakeStripeKey()),
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))
	assert.Greater(t, count, 0.0, "expected secret detection for Stripe key")
}

func TestNoSecretNoDetection(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Attributes: []*common_v1.KeyValue{
									test.MakeAttribute("http.method", "GET"),
									test.MakeAttribute("http.url", "https://example.com/api/users"),
									test.MakeAttribute("service.name", "my-service"),
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))
	assert.Equal(t, 0.0, count, "expected no secret detections for clean attributes")
}

func TestDetectsSecretInResourceAttributes(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{
					Attributes: []*common_v1.KeyValue{
						test.MakeAttribute("deployment.token", fakeSlackToken()),
					},
				},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeResource))
	assert.Greater(t, count, 0.0, "expected secret detection in resource attributes")
}

func TestDetectsSecretInEventAttributes(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Events: []*trace_v1.Span_Event{
									{
										Attributes: []*common_v1.KeyValue{
											test.MakeAttribute("error.detail", fakeStripeKey()),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeEvent))
	assert.Greater(t, count, 0.0, "expected secret detection in event attributes")
}

func TestDetectsSecretInLinkAttributes(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Links: []*trace_v1.Span_Link{
									{
										Attributes: []*common_v1.KeyValue{
											test.MakeAttribute("link.token", fakeSlackToken()),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeLink))
	assert.Greater(t, count, 0.0, "expected secret detection in link attributes")
}

func TestSkipsEmptyAndNilValues(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	p := newTestProcessor(t)

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
								SpanId:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
								Attributes: []*common_v1.KeyValue{
									test.MakeAttribute("empty", ""),
									{Key: "nil_value", Value: nil},
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	count := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))
	assert.Equal(t, 0.0, count, "expected no detections for empty/nil values")
}

func TestLogOutputContainsExpectedFields(t *testing.T) {
	metricSecretDetectionsTotal.Reset()
	logger := &capturingLogger{}
	p := newTestProcessorWithLogger(t, logger)
	p.now = func() time.Time { return time.Unix(100, 0) }

	traceID := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xee, 0xff}
	spanID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	req := &tempopb.PushSpansRequest{
		Batches: []*trace_v1.ResourceSpans{
			{
				Resource: &resource_v1.Resource{},
				ScopeSpans: []*trace_v1.ScopeSpans{
					{
						Spans: []*trace_v1.Span{
							{
								TraceId: traceID,
								SpanId:  spanID,
								Attributes: []*common_v1.KeyValue{
									test.MakeAttribute("slack.token", fakeSlackToken()),
								},
							},
						},
					},
				},
			},
		},
	}

	p.PushSpans(context.Background(), req)

	assert.Equal(t, []map[string]string{{
		"msg":        "secret detected in trace field",
		"tenant":     "test-tenant",
		"traceID":    "aabbccdd11223344556677889900eeff",
		"spanID":     "0102030405060708",
		"field_kind": string(secrets.FieldKindSpanAttribute),
		"rule":       "slack-bot-token",
		"ts":         "1970-01-01T00:01:40Z",
	}}, logger.Entries())
}

func TestDetectionScansBeyondFormerPerTraceCeilings(t *testing.T) {
	assertFindingAfter := func(t *testing.T, attributes []*common_v1.KeyValue) {
		t.Helper()
		logger := &capturingLogger{}
		p := newTestProcessorWithLogger(t, logger)
		request := &tempopb.PushSpansRequest{Batches: []*trace_v1.ResourceSpans{{
			Resource: &resource_v1.Resource{},
			ScopeSpans: []*trace_v1.ScopeSpans{{Spans: []*trace_v1.Span{{
				TraceId:    []byte{1},
				SpanId:     []byte{1},
				Attributes: attributes,
			}}}},
		}}}

		p.PushSpans(context.Background(), request)

		found := false
		for _, entry := range logger.Entries() {
			found = found || entry["msg"] == "secret detected in trace field" &&
				entry["traceID"] == "01" &&
				entry["rule"] == "slack-bot-token"
		}
		assert.True(t, found)
	}

	t.Run("fields", func(t *testing.T) {
		const formerMaxFieldsPerTrace = 10_000
		attributes := make([]*common_v1.KeyValue, formerMaxFieldsPerTrace+1)
		for index := range formerMaxFieldsPerTrace {
			attributes[index] = test.MakeAttribute("field", "safe")
		}
		attributes[formerMaxFieldsPerTrace] = test.MakeAttribute("slack.token", fakeSlackToken())
		assertFindingAfter(t, attributes)
	})

	t.Run("bytes", func(t *testing.T) {
		const formerMaxBytesPerTrace = 1 << 20
		attributes := []*common_v1.KeyValue{
			test.MakeAttribute("large.field", strings.Repeat("x", formerMaxBytesPerTrace)),
			test.MakeAttribute("slack.token", fakeSlackToken()),
		}
		assertFindingAfter(t, attributes)
	})
}

func TestFindingLogLimitIsIsolatedPerTrace(t *testing.T) {
	logger := &capturingLogger{}
	p := newTestProcessorWithLogger(t, logger)

	firstAttributes := make([]*common_v1.KeyValue, maxFindingLogsPerTrace+1)
	for index := range firstAttributes {
		firstAttributes[index] = test.MakeAttribute(fmt.Sprintf("field.%d", index), fakeSlackToken())
	}
	spans := []*trace_v1.Span{{TraceId: []byte{1}, SpanId: []byte{1}, Attributes: firstAttributes}}
	for traceID := byte(2); traceID <= 10; traceID++ {
		spans = append(spans, &trace_v1.Span{
			TraceId: []byte{traceID}, SpanId: []byte{traceID},
			Attributes: []*common_v1.KeyValue{test.MakeAttribute("slack.token", fakeSlackToken())},
		})
	}
	// Revisit the capped trace after enough other traces to grow state storage.
	spans = append(spans, &trace_v1.Span{
		TraceId: []byte{1}, SpanId: []byte{11},
		Attributes: []*common_v1.KeyValue{test.MakeAttribute("slack.token", fakeSlackToken())},
	})
	request := &tempopb.PushSpansRequest{Batches: []*trace_v1.ResourceSpans{{
		ScopeSpans: []*trace_v1.ScopeSpans{{Spans: spans}},
	}}}

	p.PushSpans(context.Background(), request)

	findingsByTrace := map[string]int{}
	gaps := 0
	for _, entry := range logger.Entries() {
		if entry["rule"] != "" {
			findingsByTrace[entry["traceID"]]++
		}
		if entry["reason"] == "finding_log_limit_exceeded" {
			assert.Equal(t, "01", entry["traceID"])
			gaps++
		}
	}
	assert.Equal(t, maxFindingLogsPerTrace, findingsByTrace["01"])
	for traceID := 2; traceID <= 10; traceID++ {
		assert.Equal(t, 1, findingsByTrace[fmt.Sprintf("%02x", traceID)])
	}
	assert.Equal(t, 1, gaps)
}

func newConfiguredProcessor(t *testing.T, policy secrets.Policy, logger *capturingLogger) *Processor {
	t.Helper()
	compiler, err := secrets.NewPolicyCompiler(nil)
	require.NoError(t, err)
	compiled, err := compiler.CompilePolicy(context.Background(), policy)
	require.NoError(t, err)
	p, err := New(Config{CompiledPolicy: compiled}, "test-tenant", level.Warn(logger), nil)
	require.NoError(t, err)
	p.logFinding = logger.Log
	p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	return p
}

func spanAttrReq(attrs ...[2]string) *tempopb.PushSpansRequest {
	kvs := make([]*common_v1.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		kvs = append(kvs, test.MakeAttribute(a[0], a[1]))
	}
	return &tempopb.PushSpansRequest{Batches: []*trace_v1.ResourceSpans{{
		Resource: &resource_v1.Resource{},
		ScopeSpans: []*trace_v1.ScopeSpans{{Spans: []*trace_v1.Span{{
			TraceId:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			SpanId:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
			Attributes: kvs,
		}}}},
	}}}
}

func ruleSet(entries []map[string]string) map[string]bool {
	m := map[string]bool{}
	for _, e := range entries {
		if r, ok := e["rule"]; ok {
			m[r] = true
		}
	}
	return m
}

func TestProcessorFallbackRespectsNativeSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		ids  []string
		want map[string]bool
	}{
		{"selected", []string{"stripe-access-token"}, map[string]bool{"stripe-access-token": true}},
		{"empty", []string{}, map[string]bool{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiler, err := secrets.NewPolicyCompiler(&tc.ids)
			require.NoError(t, err)
			logger := &capturingLogger{}
			p, err := New(Config{PolicyCompiler: compiler}, "test-tenant", logger, nil)
			require.NoError(t, err)
			p.logFinding = logger.Log
			p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
			p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
			p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
			p.PushSpans(context.Background(), spanAttrReq(
				[2]string{"first", fakeSlackToken()},
				[2]string{"second", "sk_test_" + "0123456789abcdefghijklmn"},
			))
			require.Equal(t, tc.want, ruleSet(logger.Entries()))
		})
	}
}

func TestCustomRuleExtendsProductionCatalog(t *testing.T) {
	logger := &capturingLogger{}
	p := newConfiguredProcessor(t, secrets.Policy{
		CustomRules: []secrets.CustomRule{{ID: "acme-key", Regex: `ACME-[A-Z0-9]{10}`}},
	}, logger)
	p.PushSpans(context.Background(), spanAttrReq([2]string{"auth", "ACME-AB12CD34EF"}, [2]string{"slack", fakeSlackToken()}))
	rules := ruleSet(logger.Entries())
	assert.True(t, rules["acme-key"])
	assert.True(t, rules["slack-bot-token"])
}

func TestAttributeNamesAreNotDetectionInput(t *testing.T) {
	logger := &capturingLogger{}
	p := newConfiguredProcessor(t, secrets.Policy{}, logger)
	p.PushSpans(context.Background(), spanAttrReq([2]string{fakeSlackToken(), "safe"}))
	assert.Empty(t, logger.Entries())
}

func TestFindingLogOmitsSecretAttributeNamesAndValues(t *testing.T) {
	logger := &capturingLogger{}
	p := newConfiguredProcessor(t, secrets.Policy{}, logger)
	secret := fakeSlackToken()
	p.PushSpans(context.Background(), spanAttrReq([2]string{secret, secret}))

	entries := logger.Entries()
	require.Len(t, entries, 1)
	assert.Equal(t, string(secrets.FieldKindSpanAttribute), entries[0]["field_kind"])
	assert.NotContains(t, entries[0], "attr_key")
	for _, value := range entries[0] {
		assert.NotContains(t, value, secret)
	}
}

func TestFindingLogLimitReportsDegradedCoverage(t *testing.T) {
	const tenant = "finding-log-limit-tenant"
	logger := &capturingLogger{}
	p, err := New(Config{}, tenant, logger, nil)
	require.NoError(t, err)
	p.logFinding = logger.Log
	p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.now = func() time.Time { return time.Unix(100, 0) }

	attrs := make([][2]string, maxFindingLogsPerTrace+1)
	for i := range attrs {
		attrs[i] = [2]string{fmt.Sprintf("field.%d", i), fakeSlackToken()}
	}
	p.PushSpans(context.Background(), spanAttrReq(attrs...))

	entries := logger.Entries()
	require.Len(t, entries, maxFindingLogsPerTrace+1)
	assert.Equal(t, map[string]string{
		"msg":        "secret detection coverage gap",
		"tenant":     tenant,
		"traceID":    "0102030405060708090a0b0c0d0e0f10",
		"field_kind": string(secrets.FieldKindSpanAttribute),
		"reason":     "finding_log_limit_exceeded",
		"ts":         "1970-01-01T00:01:40Z",
	}, entries[len(entries)-1])
}

func TestFindingLogRateLimitReportsDegradedCoverage(t *testing.T) {
	logger := &capturingLogger{}
	p := newTestProcessorWithLogger(t, logger)
	p.findingLogLimiter = rate.NewLimiter(0, 0)
	p.now = func() time.Time { return time.Unix(100, 0) }

	p.PushSpans(context.Background(), spanAttrReq([2]string{"authorization", fakeSlackToken()}))

	assert.Equal(t, []map[string]string{{
		"msg":        "secret detection coverage gap",
		"tenant":     "test-tenant",
		"traceID":    "0102030405060708090a0b0c0d0e0f10",
		"field_kind": string(secrets.FieldKindSpanAttribute),
		"reason":     "finding_log_rate_limit_exceeded",
		"ts":         "1970-01-01T00:01:40Z",
	}}, logger.Entries())
}

func TestFindingLogProcessLimitIsSharedAcrossProcessors(t *testing.T) {
	// These tests are serial: isolate the process budget before construction,
	// leaving each constructor-selected limiter untouched.
	oldFinding, oldCoverage := sharedFindingLogLimiter, sharedCoverageLogLimiter
	sharedFindingLogLimiter = rate.NewLimiter(0, 1)
	sharedCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	t.Cleanup(func() {
		sharedFindingLogLimiter, sharedCoverageLogLimiter = oldFinding, oldCoverage
	})

	firstLogger := &capturingLogger{}
	first, err := New(Config{}, "first-tenant", firstLogger, nil)
	require.NoError(t, err)
	secondLogger := &capturingLogger{}
	second, err := New(Config{}, "second-tenant", secondLogger, nil)
	require.NoError(t, err)

	first.PushSpans(context.Background(), spanAttrReq([2]string{"authorization", fakeSlackToken()}))
	second.PushSpans(context.Background(), spanAttrReq([2]string{"authorization", fakeSlackToken()}))

	require.Len(t, firstLogger.Entries(), 1)
	assert.Equal(t, "slack-bot-token", firstLogger.Entries()[0]["rule"])
	require.Len(t, secondLogger.Entries(), 1)
	assert.Empty(t, secondLogger.Entries()[0]["rule"])
	assert.Equal(t, "finding_log_rate_limit_exceeded", secondLogger.Entries()[0]["reason"])
}

func TestCoverageLogProcessLimitIsSharedAcrossProcessors(t *testing.T) {
	oldFinding, oldCoverage := sharedFindingLogLimiter, sharedCoverageLogLimiter
	sharedFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	sharedCoverageLogLimiter = rate.NewLimiter(0, 1)
	t.Cleanup(func() {
		sharedFindingLogLimiter, sharedCoverageLogLimiter = oldFinding, oldCoverage
	})

	firstLogger := &capturingLogger{}
	first, err := New(Config{}, "first-tenant", firstLogger, nil)
	require.NoError(t, err)
	secondLogger := &capturingLogger{}
	second, err := New(Config{}, "second-tenant", secondLogger, nil)
	require.NoError(t, err)

	first.findingLogLimiter = rate.NewLimiter(0, 0)
	second.findingLogLimiter = rate.NewLimiter(0, 0)
	detectionsBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))
	first.PushSpans(context.Background(), spanAttrReq([2]string{"authorization", fakeSlackToken()}))
	second.PushSpans(context.Background(), spanAttrReq([2]string{"authorization", fakeSlackToken()}))

	require.Len(t, firstLogger.Entries(), 1)
	assert.Equal(t, "finding_log_rate_limit_exceeded", firstLogger.Entries()[0]["reason"])
	assert.Empty(t, secondLogger.Entries())
	assert.Equal(t, detectionsBefore+2, testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan)))
}

func TestTenantMetricsCountRuleFieldMatchesAndBatches(t *testing.T) {
	testRegistry := registry.NewTestRegistry()
	tenantMetrics := NewTenantMetrics(testRegistry, "sampler-ingest")
	compiler, err := secrets.NewPolicyCompiler(&[]string{})
	require.NoError(t, err)
	compiled, err := compiler.CompilePolicy(context.Background(), secrets.Policy{CustomRules: []secrets.CustomRule{
		{ID: "first-rule", Regex: `CUSTOMER-[0-9]+`},
		{ID: "second-rule", Regex: `CUSTOMER-[0-9]+`},
	}})
	require.NoError(t, err)
	p, err := New(Config{CompiledPolicy: compiled, SourceStream: "sampler-ingest"}, "test-tenant", gklog.NewNopLogger(), tenantMetrics)
	require.NoError(t, err)
	p.findingLogLimiter = rate.NewLimiter(0, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	detectionsBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeResource))
	pushesBefore := testutil.ToFloat64(metricSecretDetectionPushesTotal.WithLabelValues("sampler-ingest"))

	// Repeated occurrences and fan-out to two traces do not multiply rule-field matches.
	p.PushSpans(context.Background(), &tempopb.PushSpansRequest{Batches: []*trace_v1.ResourceSpans{{
		Resource: &resource_v1.Resource{Attributes: []*common_v1.KeyValue{
			test.MakeAttribute("authorization", "CUSTOMER-1 CUSTOMER-2"),
		}},
		ScopeSpans: []*trace_v1.ScopeSpans{{Spans: []*trace_v1.Span{
			{TraceId: []byte{1}},
			{TraceId: []byte{2}},
		}}},
	}}})
	p.PushSpans(context.Background(), &tempopb.PushSpansRequest{})

	sourceLabels := labels.FromStrings("source_stream", "sampler-ingest")
	detectionLabels := labels.FromStrings("attribute_scope", scopeResource, "source_stream", "sampler-ingest")
	assert.Equal(t, 2.0, testRegistry.Query(tenantMetricPushes, sourceLabels))
	assert.Equal(t, 2.0, testRegistry.Query(tenantMetricDetections, detectionLabels))
	assert.Equal(t, pushesBefore+2, testutil.ToFloat64(metricSecretDetectionPushesTotal.WithLabelValues("sampler-ingest")))
	assert.Equal(t, detectionsBefore+2, testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeResource)))
}

func TestFindingLogErrorsProduceBoundedSafeDiagnostics(t *testing.T) {
	logger := &capturingLogger{}
	p := newTestProcessorWithLogger(t, logger)
	p.coverageLogLimiter = rate.NewLimiter(0, 1)
	p.now = func() time.Time { return time.Unix(100, 0) }
	failures := 0
	p.logFinding = func(keyvals ...interface{}) error {
		if keyvals[1] == "secret detected in trace field" {
			failures++
			return fmt.Errorf("cannot write %s", fakeSlackToken())
		}
		return logger.Log(keyvals...)
	}

	p.PushSpans(context.Background(), spanAttrReq(
		[2]string{"authorization", fakeSlackToken()},
		[2]string{"authorization", fakeSlackToken()},
		[2]string{"authorization", fakeSlackToken()},
	))

	assert.Equal(t, 3, failures)
	assert.Equal(t, []map[string]string{{
		"msg":        "secret detection coverage gap",
		"tenant":     "test-tenant",
		"traceID":    "0102030405060708090a0b0c0d0e0f10",
		"field_kind": string(secrets.FieldKindSpanAttribute),
		"reason":     "finding_log_error",
		"ts":         "1970-01-01T00:01:40Z",
	}}, logger.Entries())
}

func TestPushSpansObservesCompletedScanDuration(t *testing.T) {
	p := newTestProcessor(t)
	started := time.Unix(100, 0)
	times := []time.Time{started, started.Add(2 * time.Second)}
	p.now = func() time.Time {
		now := times[0]
		times = times[1:]
		return now
	}
	duration := &capturingObserver{}
	p.duration = duration

	p.PushSpans(context.Background(), &tempopb.PushSpansRequest{})

	assert.Equal(t, 2.0, duration.value)
}

func TestOTLPSpanFieldsWithoutTraceIDDoNotImplicateSibling(t *testing.T) {
	compiler, err := secrets.NewPolicyCompiler(&[]string{})
	require.NoError(t, err)
	compiled, err := compiler.CompilePolicy(context.Background(), secrets.Policy{CustomRules: []secrets.CustomRule{
		{ID: "owned-rule", Regex: `OWNED-[0-9]+`},
		{ID: "shared-rule", Regex: `SHARED-[0-9]+`},
	}})
	require.NoError(t, err)
	logger := &capturingLogger{}
	p, err := New(Config{CompiledPolicy: compiled}, "otlp-tenant", logger, nil)
	require.NoError(t, err)
	p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processFindingLogLimiter = rate.NewLimiter(rate.Inf, 0)

	const owned = "OWNED-123"
	const cleanTraceID = "0102030405060708090a0b0c0d0e0f10"
	request := decodeOTLPRequest(t, []*trace_v1.ResourceSpans{{
		SchemaUrl: "SHARED-123",
		ScopeSpans: []*trace_v1.ScopeSpans{{
			Scope: &common_v1.InstrumentationScope{Name: "SHARED-123"},
			Spans: []*trace_v1.Span{
				{
					// Both IDs are absent in this raw OTLP span.
					Name: owned, TraceState: owned,
					Status:     &trace_v1.Status{Message: owned},
					Attributes: []*common_v1.KeyValue{test.MakeAttribute("span", owned)},
					Events: []*trace_v1.Span_Event{{
						Name: owned, Attributes: []*common_v1.KeyValue{test.MakeAttribute("event", owned)},
					}},
					Links: []*trace_v1.Span_Link{{
						TraceId: []byte{42}, TraceState: owned,
						Attributes: []*common_v1.KeyValue{test.MakeAttribute("link", owned)},
					}},
				},
				{TraceId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Name: "clean"},
			},
		}},
	}})

	p.PushSpans(context.Background(), request)

	ownedFindings, sharedFindings := 0, 0
	for _, entry := range logger.Entries() {
		switch entry["rule"] {
		case "owned-rule":
			ownedFindings++
			assert.Empty(t, entry["traceID"], "a missing owner ID must stay unattributed")
			assert.Empty(t, entry["spanID"])
		case "shared-rule":
			sharedFindings++
			assert.Equal(t, cleanTraceID, entry["traceID"], "shared metadata still belongs to descendant traces")
			assert.Empty(t, entry["spanID"])
		default:
			t.Fatalf("unexpected reporting entry: %v", entry)
		}
	}
	assert.Equal(t, 8, ownedFindings)
	assert.Equal(t, 2, sharedFindings)
}

func TestOTLPSharedFieldReportingStopsAfterRateLimit(t *testing.T) {
	const (
		fieldCount = 4096
		traceCount = 1024
		logBudget  = 3
	)
	compiler, err := secrets.NewPolicyCompiler(&[]string{})
	require.NoError(t, err)
	compiled, err := compiler.CompilePolicy(context.Background(), secrets.Policy{CustomRules: []secrets.CustomRule{
		{ID: "first-rule", Regex: `CUSTOMER-[0-9]+`},
		{ID: "second-rule", Regex: `CUSTOMER-[0-9]+`},
		{ID: "after-rule", Regex: `AFTER-[0-9]+`},
	}})
	require.NoError(t, err)
	logger := &capturingLogger{}
	testRegistry := registry.NewTestRegistry()
	p, err := New(Config{CompiledPolicy: compiled}, "otlp-tenant", logger, NewTenantMetrics(testRegistry, "otlp"))
	require.NoError(t, err)
	p.findingLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processFindingLogLimiter = rate.NewLimiter(0, logBudget)
	p.coverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	p.processCoverageLogLimiter = rate.NewLimiter(rate.Inf, 0)
	resourceBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeResource))
	scopeBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeScope))
	spanBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan))

	p.PushSpans(context.Background(), sharedOTLPRequest(t, fieldCount, traceCount))

	findings, gaps := 0, 0
	for _, entry := range logger.Entries() {
		if entry["rule"] != "" {
			findings++
		} else {
			gaps++
			assert.Equal(t, "finding_log_rate_limit_exceeded", entry["reason"])
			assert.Equal(t, string(secrets.FieldKindResourceAttribute), entry["field_kind"])
			assert.Len(t, entry["traceID"], 32)
		}
	}
	assert.Equal(t, logBudget, findings)
	assert.Equal(t, 1, gaps, "one representative gap bounds diagnostics, not one per suppressed trace")
	assert.Equal(t, resourceBefore+2*fieldCount, testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeResource)))
	assert.Equal(t, scopeBefore+2*fieldCount, testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeScope)))
	assert.Equal(t, spanBefore+1, testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeSpan)))
	assert.Equal(t, float64(2*fieldCount), testRegistry.Query(tenantMetricDetections, labels.FromStrings("attribute_scope", scopeResource, "source_stream", "otlp")))
	assert.Equal(t, float64(2*fieldCount), testRegistry.Query(tenantMetricDetections, labels.FromStrings("attribute_scope", scopeScope, "source_stream", "otlp")))
	assert.Equal(t, 1.0, testRegistry.Query(tenantMetricDetections, labels.FromStrings("attribute_scope", scopeSpan, "source_stream", "otlp")))
}

func TestOTLPSharedFindingLimitLeavesOtherScopesReportable(t *testing.T) {
	logger := &capturingLogger{}
	p := newConfiguredProcessor(t, secrets.Policy{CustomRules: []secrets.CustomRule{
		{ID: "shared-rule", Regex: `CUSTOMER-[0-9]+`},
	}}, logger)
	values := make([]*common_v1.AnyValue, maxFindingLogsPerTrace+100)
	for i := range values {
		values[i] = &common_v1.AnyValue{Value: &common_v1.AnyValue_StringValue{StringValue: "CUSTOMER-123"}}
	}
	request := decodeOTLPRequest(t, []*trace_v1.ResourceSpans{{ScopeSpans: []*trace_v1.ScopeSpans{
		{
			Scope: &common_v1.InstrumentationScope{Attributes: []*common_v1.KeyValue{{
				Key: "values", Value: &common_v1.AnyValue{Value: &common_v1.AnyValue_ArrayValue{
					ArrayValue: &common_v1.ArrayValue{Values: values},
				}},
			}}},
			Spans: []*trace_v1.Span{{TraceId: []byte{1}}},
		},
		{
			Scope: &common_v1.InstrumentationScope{Attributes: []*common_v1.KeyValue{test.MakeAttribute("value", "CUSTOMER-123")}},
			Spans: []*trace_v1.Span{{TraceId: []byte{2}}},
		},
	}}})
	detectionsBefore := testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeScope))

	p.PushSpans(context.Background(), request)

	findings := map[string]int{}
	gaps := 0
	for _, entry := range logger.Entries() {
		if entry["rule"] == "shared-rule" {
			findings[entry["traceID"]]++
		}
		if entry["reason"] == "finding_log_limit_exceeded" {
			gaps++
			assert.Equal(t, "01", entry["traceID"])
		}
	}
	assert.Equal(t, map[string]int{"01": maxFindingLogsPerTrace, "02": 1}, findings)
	assert.Equal(t, 1, gaps)
	assert.Equal(t, detectionsBefore+float64(len(values)+1), testutil.ToFloat64(metricSecretDetectionsTotal.WithLabelValues(scopeScope)))
}

func decodeOTLPRequest(t testing.TB, resources []*trace_v1.ResourceSpans) *tempopb.PushSpansRequest {
	t.Helper()
	trace := tempopb.Trace{ResourceSpans: resources}
	data, err := trace.Marshal()
	require.NoError(t, err)
	requests, err := ingest.NewOTLPDecoder().Decode(data)
	require.NoError(t, err)
	for request, err := range requests {
		require.NoError(t, err)
		return request
	}
	t.Fatal("OTLP decoder did not yield a request")
	return nil
}

func sharedOTLPRequest(t testing.TB, fieldCount, traceCount int) *tempopb.PushSpansRequest {
	t.Helper()
	values := make([]*common_v1.AnyValue, fieldCount)
	for i := range values {
		values[i] = &common_v1.AnyValue{Value: &common_v1.AnyValue_StringValue{StringValue: "CUSTOMER-123"}}
	}
	attribute := &common_v1.KeyValue{
		Key: "values", Value: &common_v1.AnyValue{Value: &common_v1.AnyValue_ArrayValue{
			ArrayValue: &common_v1.ArrayValue{Values: values},
		}},
	}
	spans := make([]*trace_v1.Span, traceCount)
	for i := range spans {
		traceID := make([]byte, 16)
		traceID[12], traceID[13], traceID[14], traceID[15] = byte((i+1)>>24), byte((i+1)>>16), byte((i+1)>>8), byte(i+1)
		spans[i] = &trace_v1.Span{TraceId: traceID}
	}
	spans[len(spans)-1].Attributes = []*common_v1.KeyValue{test.MakeAttribute("after", "AFTER-123")}
	return decodeOTLPRequest(t, []*trace_v1.ResourceSpans{{
		Resource: &resource_v1.Resource{Attributes: []*common_v1.KeyValue{attribute}},
		ScopeSpans: []*trace_v1.ScopeSpans{{
			Scope: &common_v1.InstrumentationScope{Attributes: []*common_v1.KeyValue{attribute}},
			Spans: spans,
		}},
	}})
}
