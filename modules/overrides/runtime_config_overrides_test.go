package overrides

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kitlog "github.com/go-kit/log"
	"github.com/grafana/dskit/services"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v2"

	"github.com/grafana/tempo/pkg/secrets"
	"github.com/grafana/tempo/pkg/sharedconfig"
	tempolog "github.com/grafana/tempo/pkg/util/log"
	"github.com/grafana/tempo/tempodb/backend"
)

func TestMigrationPolicyDecodeErrorsAreValueSafe(t *testing.T) {
	const private = "synthetic-private-policy-marker"
	for _, policy := range []string{
		"custom_rules: " + private,
		"custom_rules:\n- id: safe-rule\n  regex: " + private + "\n  description: " + private,
		"custom_rules:\n- id: safe-rule\n  regex: " + private + "\n  entropy: 1.5",
		"custom_rules:\n- id: safe-rule\n  regex: (" + private + ")\n  secret_group: 1",
		"custom_rules:\n- id: safe-rule\n  regex: *" + private,
		private + ": true",
	} {
		data := "overrides:\n  tenant:\n    metrics_generator:\n      processor:\n        secret_detection:\n          " + strings.ReplaceAll(policy, "\n", "\n          ") + "\n"
		parsed, err := UnmarshalPerTenantOverrides([]byte(data))
		require.True(t, err != nil, "invalid migration input must be rejected")
		require.True(t, parsed == nil, "invalid migration input must not return limits")
		require.False(t, strings.Contains(err.Error(), private), "migration decode error disclosed private policy")
	}
}

func TestRuntimeOrdinaryDecodeDiagnostics(t *testing.T) {
	data := []byte("overrides:\n  tenant:\n    ingestion:\n      max_traces_per_user: bad-limit\n")
	_, err := loadPerTenantOverrides(nil, ConfigTypeNew, false, false)(bytes.NewReader(data))
	var typeError *yaml.TypeError
	require.ErrorAs(t, err, &typeError)
	require.Contains(t, err.Error(), "bad-limit")
	_, err = UnmarshalPerTenantOverrides(data)
	require.ErrorAs(t, err, &typeError)
	require.Contains(t, err.Error(), "bad-limit")
}

func TestRuntimePolicyIsolationPreservesOrdinaryStrictness(t *testing.T) {
	const private = "synthetic-private-policy-marker"
	for _, legacy := range []bool{false, true} {
		for _, ordinary := range []string{
			"unknown_override: true",
			"ingestion:\n  max_traces_per_user: bad-limit",
		} {
			data := runtimePolicyTestYAML(t, legacy, map[string]any{
				"bad": map[string]any{private: true},
			}, "invalid")
			data += "  ordinary:\n    " + strings.ReplaceAll(ordinary, "\n", "\n    ") + "\n"
			limits, err := loadPerTenantOverrides(nil, ConfigTypeNew, false, true)(strings.NewReader(data))
			require.Error(t, err)
			require.Nil(t, limits)
			require.NotContains(t, err.Error(), private)
		}
	}
}

func TestRuntimeDuplicateConfigCannotHidePolicy(t *testing.T) {
	const private = "synthetic-private-policy-marker"
	data := []byte("overrides:\n  tenant:\n    metrics_generator:\n      processor:\n        secret_detection:\n          custom_rules: " + private + "\noverrides: {}\n")
	_, err := loadPerTenantOverrides(nil, ConfigTypeNew, false, false)(bytes.NewReader(data))
	require.Error(t, err)
	require.NotContains(t, err.Error(), private)
	_, err = UnmarshalPerTenantOverrides(data)
	require.Error(t, err)
	require.NotContains(t, err.Error(), private)
}

type runtimeLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *runtimeLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *runtimeLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func writeRuntimeOverridesFile(t *testing.T, path, data string) {
	t.Helper()
	var output bytes.Buffer
	if strings.HasSuffix(path, ".gz") {
		writer := gzip.NewWriter(&output)
		_, err := writer.Write([]byte(data))
		require.NoError(t, err)
		require.NoError(t, writer.Close())
	} else {
		output.WriteString(data)
	}
	temporary := path + ".tmp"
	require.NoError(t, os.WriteFile(temporary, output.Bytes(), 0o600))
	require.NoError(t, os.Rename(temporary, path))
}

func reloadRuntimeOverridesFile(t *testing.T, manager *runtimeConfigOverridesManager, path, data string) {
	t.Helper()
	updates := manager.runtimeConfigMgr.CreateListenerChannel(1)
	defer manager.runtimeConfigMgr.CloseListenerChannel(updates)
	writeRuntimeOverridesFile(t, path, data)
	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime manager did not publish the updated overrides")
	}
}

func TestRuntimeRawYAMLPrivacy(t *testing.T) {
	const private = "synthetic-private-policy-marker"
	for _, suffix := range []string{".yaml", ".yaml.gz"} {
		for _, stage := range []string{"startup", "reload"} {
			for _, invalid := range []struct {
				name string
				data string
			}{
				{"unknown alias", "custom_rules:\n- regex: *" + private},
				{"duplicate private key", private + ": one\n" + private + ": two"},
				{"invalid map key", "custom_rules:\n  ? [" + private + "]\n  : value"},
			} {
				t.Run(suffix+"/"+stage+"/"+invalid.name, func(t *testing.T) {
					var logs runtimeLogBuffer
					originalLogger := tempolog.Logger
					tempolog.Logger = kitlog.NewLogfmtLogger(&logs)
					t.Cleanup(func() { tempolog.Logger = originalLogger })

					path := filepath.Join(t.TempDir(), "overrides"+suffix)
					badConfig := "overrides:\n  tenant:\n    metrics_generator:\n      processor:\n        secret_detection:\n          " +
						strings.ReplaceAll(invalid.data, "\n", "\n          ") + "\n"
					initial := badConfig
					if stage == "reload" {
						initial = "overrides:\n  tenant:\n    forwarders: [before]\n"
					}
					writeRuntimeOverridesFile(t, path, initial)
					service, err := newRuntimeConfigOverrides(Config{
						ConfigType:              ConfigTypeNew,
						PerTenantOverrideConfig: path,
						PerTenantOverridePeriod: model.Duration(10 * time.Millisecond),
					}, nil, prometheus.NewRegistry())
					require.NoError(t, err)
					manager := service.(*runtimeConfigOverridesManager)
					err = services.StartAndAwaitRunning(context.Background(), service)
					if stage == "startup" {
						require.Error(t, err)
						require.NotContains(t, err.Error(), private)
						require.NotContains(t, service.FailureCase().Error(), private)
						cause := manager.runtimeConfigMgr.FailureCase()
						require.Error(t, cause)
						require.Contains(t, cause.Error(), "configuration")
						require.NotContains(t, cause.Error(), private)
					} else {
						require.NoError(t, err)
						t.Cleanup(func() {
							require.NoError(t, services.StopAndAwaitTerminated(context.Background(), service))
						})
						writeRuntimeOverridesFile(t, path, badConfig)
						require.Eventually(t, func() bool {
							return strings.Contains(logs.String(), "failed to load config")
						}, 5*time.Second, time.Millisecond)
						require.Equal(t, []string{"before"}, service.Forwarders("tenant"))
						require.Equal(t, services.Running, service.State())
						reloadRuntimeOverridesFile(t, manager, path, "overrides:\n  tenant:\n    forwarders: [after]\n")
						require.Equal(t, []string{"after"}, service.Forwarders("tenant"))
					}
					require.NotContains(t, logs.String(), private)
				})
			}
		}
	}
}

func runtimePolicyTestYAML(t *testing.T, legacy bool, policies map[string]any, revision string) string {
	t.Helper()
	tenants := make(map[string]map[string]any, len(policies))
	for tenant, policy := range policies {
		limits := map[string]any{"forwarders": []string{revision}}
		if policy != nil {
			if legacy {
				limits["metrics_generator_processor_secret_detection"] = policy
			} else {
				limits["metrics_generator"] = map[string]any{
					"processor": map[string]any{"secret_detection": policy},
				}
			}
		}
		tenants[tenant] = limits
	}
	data, err := yaml.Marshal(map[string]any{"overrides": tenants})
	require.NoError(t, err)
	return string(data)
}

func TestRuntimePolicySchemaIsolation(t *testing.T) {
	const private = "synthetic-private-policy-marker"
	const native = "sk_test_" + "0123456789abcdefghijklmn"
	const unselected = "xoxb-" + "1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
	makePolicy := func(id string) *secrets.Policy {
		return &secrets.Policy{
			DisabledRules: []string{"stripe-access-token"},
			CustomRules:   []secrets.CustomRule{{ID: id, Regex: "CUSTOM-" + id}},
		}
	}
	for _, legacy := range []bool{false, true} {
		for _, invalid := range []struct {
			name   string
			policy any
		}{
			{"unknown field", map[string]any{private: true}},
			{"wrong policy shape", []string{private}},
			{"wrong rule type", map[string]any{"custom_rules": private}},
		} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, invalid.name), func(t *testing.T) {
				var logs runtimeLogBuffer
				originalLogger := tempolog.Logger
				tempolog.Logger = kitlog.NewLogfmtLogger(&logs)
				t.Cleanup(func() { tempolog.Logger = originalLogger })

				path := filepath.Join(t.TempDir(), "overrides.yaml")
				policies := map[string]any{
					"bad":     invalid.policy,
					"healthy": makePolicy("healthy-first"),
					"*":       makePolicy("wildcard"),
					"sparse":  nil,
				}
				writeRuntimeOverridesFile(t, path, runtimePolicyTestYAML(t, legacy, policies, "initial"))
				typ := ConfigTypeNew
				if legacy {
					typ = ConfigTypeLegacy
				}
				service, err := newRuntimeConfigOverrides(Config{
					ConfigType:              typ,
					EnableLegacyOverrides:   legacy,
					Defaults:                Overrides{MetricsGenerator: MetricsGeneratorOverrides{Processor: ProcessorOverrides{SecretDetection: makePolicy("default")}}},
					PerTenantOverrideConfig: path,
					PerTenantOverridePeriod: model.Duration(10 * time.Millisecond),
				}, nil, prometheus.NewRegistry())
				require.NoError(t, err)
				require.NoError(t, services.StartAndAwaitRunning(context.Background(), service))
				t.Cleanup(func() { require.NoError(t, services.StopAndAwaitTerminated(context.Background(), service)) })
				manager := service.(*runtimeConfigOverridesManager)
				compiler, err := secrets.NewPolicyCompiler(&[]string{"stripe-access-token"})
				require.NoError(t, err)
				bad := compiler.NewCompiledPolicyProvider("bad", service.SecretsPolicy, kitlog.NewNopLogger())
				healthy := compiler.NewCompiledPolicyProvider("healthy", service.SecretsPolicy, kitlog.NewNopLogger())
				missing := compiler.NewCompiledPolicyProvider("missing", service.SecretsPolicy, kitlog.NewNopLogger())
				sparse := compiler.NewCompiledPolicyProvider("sparse", service.SecretsPolicy, kitlog.NewNopLogger())
				probe := strings.Join([]string{
					native, unselected, "CUSTOM-default", "CUSTOM-wildcard", "CUSTOM-bad-accepted", "CUSTOM-bad-unseen",
					"CUSTOM-healthy-first", "CUSTOM-healthy-updated", "CUSTOM-healthy-recovered",
				}, "\n")
				assertVerdict := func(provider secrets.CompiledPolicyProvider, id string) {
					t.Helper()
					compiled, ok := provider(context.Background())
					require.True(t, ok)
					require.Equal(t, []secrets.Match{{RuleID: id}}, compiled.Detect(probe).Matches)
				}
				reload := func(revision string) {
					t.Helper()
					reloadRuntimeOverridesFile(t, manager, path, runtimePolicyTestYAML(t, legacy, policies, revision))
					require.Equal(t, []string{revision}, service.Forwarders("healthy"))
				}

				// Bad startup policy must not suppress healthy tenants or inherit a
				// default that disables the process-selected native fallback.
				assertVerdict(bad, "stripe-access-token")
				assertVerdict(healthy, "healthy-first")
				assertVerdict(missing, "wildcard")
				assertVerdict(sparse, "default")

				policies["bad"] = makePolicy("bad-accepted")
				policies["healthy"] = makePolicy("healthy-updated")
				reload("accepted")
				assertVerdict(bad, "bad-accepted")
				assertVerdict(healthy, "healthy-updated")

				// Publishing a decoded policy is not compilation. Skip observing
				// this revision, then reject its replacement at schema decode.
				policies["bad"] = makePolicy("bad-unseen")
				reload("unobserved")
				policies["bad"] = invalid.policy
				policies["healthy"] = makePolicy("healthy-recovered")
				reload("schema-rejected")
				assertVerdict(bad, "bad-accepted")
				assertVerdict(healthy, "healthy-recovered")

				policies["bad"] = &secrets.Policy{CustomRules: []secrets.CustomRule{{ID: "invalid-regex", Regex: "("}}}
				reload("compile-rejected")
				assertVerdict(bad, "bad-accepted")
				policies["bad"] = invalid.policy
				reload("schema-after-compile-rejection")
				assertVerdict(bad, "bad-accepted")

				// Removing just the policy restores the default (not wildcard).
				policies["bad"] = nil
				reload("policy-removed")
				assertVerdict(bad, "default")
				policies["bad"] = invalid.policy
				reload("schema-after-default")
				assertVerdict(bad, "default")
				fresh := compiler.NewCompiledPolicyProvider("bad", service.SecretsPolicy, kitlog.NewNopLogger())
				assertVerdict(fresh, "stripe-access-token")

				// Removing the tenant restores wildcard precedence; removing the
				// wildcard policy then restores the default.
				delete(policies, "bad")
				reload("tenant-removed")
				assertVerdict(bad, "wildcard")
				policies["*"] = nil
				reload("wildcard-policy-removed")
				assertVerdict(bad, "default")
				assertVerdict(missing, "default")

				// An unrelated invalid override still rejects the complete reload;
				// policy isolation must not weaken ordinary configuration validation.
				policies["bad"] = invalid.policy
				data := runtimePolicyTestYAML(t, legacy, policies, "ordinary-invalid")
				data += "  ordinary:\n    unknown_override: true\n"
				writeRuntimeOverridesFile(t, path, data)
				require.Eventually(t, func() bool {
					return strings.Contains(logs.String(), "failed to load config")
				}, 5*time.Second, time.Millisecond)
				require.Equal(t, []string{"wildcard-policy-removed"}, service.Forwarders("healthy"))
				assertVerdict(bad, "default")
				require.NotContains(t, logs.String(), private)
				require.Contains(t, logs.String(), "secrets policy schema rejected")
			})
		}
	}
}

func TestRuntimePolicyIsolationPreservesExpandedValues(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, value := range []struct {
			input     string
			canonical string
		}{
			{"YES", "true"},
			{"001", "1"},
			{"on", "true"},
			{"010", "8"},
		} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, value.input), func(t *testing.T) {
				t.Setenv("RUNTIME_POLICY_PATTERN", value.input)
				path := filepath.Join(t.TempDir(), "overrides.yaml")
				data := runtimePolicyTestYAML(t, legacy, map[string]any{
					"bad": map[string]any{"unsupported_policy_field": true},
					"healthy": &secrets.Policy{CustomRules: []secrets.CustomRule{{
						ID: "expanded", Regex: "${RUNTIME_POLICY_PATTERN}",
					}}},
				}, "initial")
				if legacy {
					data += "  ordinary:\n    metrics_generator_remote_write_headers:\n      X-Private: ${RUNTIME_POLICY_PATTERN}\n"
				} else {
					data += "  ordinary:\n    metrics_generator:\n      remote_write_headers:\n        X-Private: ${RUNTIME_POLICY_PATTERN}\n"
				}
				writeRuntimeOverridesFile(t, path, data)
				typ := ConfigTypeNew
				if legacy {
					typ = ConfigTypeLegacy
				}
				service, err := newRuntimeConfigOverrides(Config{
					ConfigType:              typ,
					EnableLegacyOverrides:   legacy,
					ExpandEnv:               true,
					PerTenantOverrideConfig: path,
					PerTenantOverridePeriod: model.Duration(time.Hour),
				}, nil, prometheus.NewRegistry())
				require.NoError(t, err)
				require.NoError(t, services.StartAndAwaitRunning(context.Background(), service))
				t.Cleanup(func() { require.NoError(t, services.StopAndAwaitTerminated(context.Background(), service)) })
				compiler, err := secrets.NewPolicyCompiler(&[]string{})
				require.NoError(t, err)
				provider := compiler.NewCompiledPolicyProvider("healthy", service.SecretsPolicy, kitlog.NewNopLogger())
				compiled, ok := provider(context.Background())
				require.True(t, ok)
				require.Equal(t, []secrets.Match{{RuleID: "expanded"}}, compiled.Detect(value.input).Matches)
				require.Empty(t, compiled.Detect(value.canonical).Matches)
				require.Equal(t, map[string]string{"X-Private": value.input}, service.MetricsGeneratorRemoteWriteHeaders("ordinary"))
			})
		}
	}
}

func TestRuntimePolicyIsolationPreservesAliases(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			body := "    metrics_generator:\n      processor:\n        secret_detection:\n          custom_rules:\n          - id: anchored\n            regex: &pattern YES\n      remote_write_headers:\n        X-Private: *pattern\n"
			if legacy {
				body = "    metrics_generator_processor_secret_detection:\n      custom_rules:\n      - id: anchored\n        regex: &pattern YES\n    metrics_generator_remote_write_headers:\n      X-Private: *pattern\n"
			}
			data := "overrides:\n  template: &template\n" + body + "  tenant:\n    <<: *template\n"
			data += strings.TrimPrefix(runtimePolicyTestYAML(t, legacy, map[string]any{
				"bad": map[string]any{"unsupported_policy_field": true},
			}, "initial"), "overrides:\n")
			result, err := loadPerTenantOverrides(nil, ConfigTypeNew, false, legacy)(strings.NewReader(data))
			require.NoError(t, err)
			limits := result.(*perTenantOverrides)
			compiler, err := secrets.NewPolicyCompiler(&[]string{})
			require.NoError(t, err)
			for _, tenant := range []string{"template", "tenant"} {
				provider := compiler.NewCompiledPolicyProvider(tenant, func(id string) (*secrets.Policy, bool) {
					return limits.TenantLimits[id].MetricsGenerator.Processor.SecretDetection, false
				}, kitlog.NewNopLogger())
				compiled, ok := provider(context.Background())
				require.True(t, ok)
				require.Equal(t, []secrets.Match{{RuleID: "anchored"}}, compiled.Detect("YES").Matches)
				require.Empty(t, compiled.Detect("true").Matches)
				require.Equal(t, map[string]string{"X-Private": "YES"}, limits.TenantLimits[tenant].MetricsGenerator.RemoteWriteHeaders.toStringStringMap())
			}
		})
	}
}

func TestRuntimeRejectedPolicySkipsRecursiveAliases(t *testing.T) {
	const anchor = "private-policy-anchor"
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			data := runtimePolicyTestYAML(t, legacy, map[string]any{
				"healthy": &secrets.Policy{CustomRules: []secrets.CustomRule{{ID: "healthy", Regex: "HEALTHY"}}},
			}, "initial")
			if legacy {
				data += "  bad:\n    metrics_generator_processor_secret_detection: &" + anchor + "\n      custom_rules:\n      - id: rejected\n        regex: *" + anchor + "\n"
			} else {
				data += "  bad:\n    metrics_generator:\n      processor:\n        secret_detection: &" + anchor + "\n          custom_rules:\n          - id: rejected\n            regex: *" + anchor + "\n"
			}
			loader := loadPerTenantOverrides(nil, ConfigTypeNew, false, legacy)
			result, err := loader(strings.NewReader(data))
			require.NoError(t, err)
			limits := result.(*perTenantOverrides)
			compiler, err := secrets.NewPolicyCompiler(&[]string{"stripe-access-token"})
			require.NoError(t, err)
			source := func(id string) (*secrets.Policy, bool) {
				return limits.TenantLimits[id].MetricsGenerator.Processor.SecretDetection, false
			}
			bad := compiler.NewCompiledPolicyProvider("bad", source, kitlog.NewNopLogger())
			compiled, ok := bad(context.Background())
			require.True(t, ok)
			require.Equal(t, []secrets.Match{{RuleID: "stripe-access-token"}}, compiled.Detect("sk_test_"+"0123456789abcdefghijklmn").Matches)
			healthy := compiler.NewCompiledPolicyProvider("healthy", source, kitlog.NewNopLogger())
			compiled, ok = healthy(context.Background())
			require.True(t, ok)
			require.Equal(t, []secrets.Match{{RuleID: "healthy"}}, compiled.Detect("HEALTHY").Matches)

			// Referencing the same recursive payload from an ordinary override
			// is not a policy-only error and must reject the complete config.
			_, err = loader(strings.NewReader(data + "  ordinary:\n    forwarders: *" + anchor + "\n"))
			require.Error(t, err)
			require.NotContains(t, err.Error(), anchor)
		})
	}
}

func TestRuntimeConfigOverrides_loadPerTenantOverrides(t *testing.T) {
	validator := &mockValidator{}

	loader := loadPerTenantOverrides(validator, ConfigTypeNew, false, false)

	perTenantOverrides := perTenantOverrides{
		TenantLimits: map[string]*Overrides{
			"foo": {Ingestion: IngestionOverrides{TenantShardSize: 6}},
			"bar": {Ingestion: IngestionOverrides{TenantShardSize: 1}},
			"bzz": {Ingestion: IngestionOverrides{TenantShardSize: 3}},
		},
	}
	overridesBytes, err := yaml.Marshal(&perTenantOverrides)
	assert.NoError(t, err)

	// load overrides - validator should pass
	_, err = loader(bytes.NewReader(overridesBytes))
	assert.NoError(t, err)

	// load overrides - validator should reject bar
	validator.f = func(overrides *Overrides) error {
		if overrides.Ingestion.TenantShardSize == 1 {
			return errors.New("no")
		}
		return nil
	}

	_, err = loader(bytes.NewReader(overridesBytes))
	assert.ErrorContains(t, err, "validating overrides for bar failed: no")
}

func TestRuntimeConfigOverrides(t *testing.T) {
	tests := []struct {
		name                        string
		defaultLimits               Overrides
		perTenantOverrides          *perTenantOverrides
		expectedMaxLocalTraces      map[string]int
		expectedMaxGlobalTraces     map[string]int
		expectedMaxBytesPerTrace    map[string]int
		expectedIngestionRateSpans  map[string]int
		expectedIngestionBurstSpans map[string]int
		expectedMaxSearchDuration   map[string]int
	}{
		{
			name: "limits only",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{
					MaxGlobalTracesPerUser: 1,
					MaxLocalTracesPerUser:  2,
					BurstSizeBytes:         4,
					RateLimitBytes:         5,
				},
				Global: GlobalOverrides{
					MaxBytesPerTrace: 3,
				},
			},
			expectedMaxGlobalTraces:     map[string]int{"user1": 1, "user2": 1},
			expectedMaxLocalTraces:      map[string]int{"user1": 2, "user2": 2},
			expectedMaxBytesPerTrace:    map[string]int{"user1": 3, "user2": 3},
			expectedIngestionBurstSpans: map[string]int{"user1": 4, "user2": 4},
			expectedIngestionRateSpans:  map[string]int{"user1": 5, "user2": 5},
			expectedMaxSearchDuration:   map[string]int{"user1": 0, "user2": 0},
		},
		{
			name: "basic Overrides",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{
					MaxGlobalTracesPerUser: 1,
					MaxLocalTracesPerUser:  2,
					BurstSizeBytes:         4,
					RateLimitBytes:         5,
				},
				Global: GlobalOverrides{
					MaxBytesPerTrace: 3,
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						Ingestion: IngestionOverrides{
							MaxGlobalTracesPerUser: 6,
							MaxLocalTracesPerUser:  7,
							BurstSizeBytes:         9,
							RateLimitBytes:         10,
						},
						Global: GlobalOverrides{
							MaxBytesPerTrace: 8,
						},
						Read: ReadOverrides{
							MaxSearchDuration: model.Duration(11 * time.Second),
						},
					},
				},
			},
			expectedMaxGlobalTraces:     map[string]int{"user1": 6, "user2": 1},
			expectedMaxLocalTraces:      map[string]int{"user1": 7, "user2": 2},
			expectedMaxBytesPerTrace:    map[string]int{"user1": 8, "user2": 3},
			expectedIngestionBurstSpans: map[string]int{"user1": 9, "user2": 4},
			expectedIngestionRateSpans:  map[string]int{"user1": 10, "user2": 5},
			expectedMaxSearchDuration:   map[string]int{"user1": int(11 * time.Second), "user2": 0},
		},
		{
			name: "wildcard override",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{
					MaxGlobalTracesPerUser: 1,
					MaxLocalTracesPerUser:  2,
					BurstSizeBytes:         4,
					RateLimitBytes:         5,
				},
				Global: GlobalOverrides{
					MaxBytesPerTrace: 3,
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						Ingestion: IngestionOverrides{
							MaxGlobalTracesPerUser: 6,
							MaxLocalTracesPerUser:  7,
							BurstSizeBytes:         9,
							RateLimitBytes:         10,
						},
						Global: GlobalOverrides{
							MaxBytesPerTrace: 8,
						},
					},
					"*": {
						Ingestion: IngestionOverrides{
							MaxGlobalTracesPerUser: 11,
							MaxLocalTracesPerUser:  12,
							BurstSizeBytes:         14,
							RateLimitBytes:         15,
						},
						Global: GlobalOverrides{
							MaxBytesPerTrace: 13,
						},
						Read: ReadOverrides{
							MaxSearchDuration: model.Duration(16 * time.Second),
						},
						CostAttribution: CostAttributionOverrides{Dimensions: map[string]string{"foo": "bar"}},
					},
				},
			},
			expectedMaxGlobalTraces:     map[string]int{"user1": 6, "user2": 11},
			expectedMaxLocalTraces:      map[string]int{"user1": 7, "user2": 12},
			expectedMaxBytesPerTrace:    map[string]int{"user1": 8, "user2": 13},
			expectedIngestionBurstSpans: map[string]int{"user1": 9, "user2": 14},
			expectedIngestionRateSpans:  map[string]int{"user1": 10, "user2": 15},
			expectedMaxSearchDuration:   map[string]int{"user1": 0, "user2": int(16 * time.Second)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tt.defaultLimits, toYamlBytes(t, tt.perTenantOverrides))
			defer cleanup()

			for user, expectedVal := range tt.expectedMaxLocalTraces {
				assert.Equal(t, expectedVal, overrides.MaxLocalTracesPerUser(user))
			}

			for user, expectedVal := range tt.expectedMaxGlobalTraces {
				assert.Equal(t, expectedVal, overrides.MaxGlobalTracesPerUser(user))
			}

			for user, expectedVal := range tt.expectedIngestionBurstSpans {
				assert.Equal(t, expectedVal, overrides.IngestionBurstSizeBytes(user))
			}

			for user, expectedVal := range tt.expectedIngestionRateSpans {
				assert.Equal(t, float64(expectedVal), overrides.IngestionRateLimitBytes(user))
			}

			for user, expectedVal := range tt.expectedMaxSearchDuration {
				assert.Equal(t, time.Duration(expectedVal), overrides.MaxSearchDuration(user))
			}
		})

		t.Run(fmt.Sprintf("%s (legacy)", tt.name), func(t *testing.T) {
			cfg := Config{
				Defaults:              tt.defaultLimits,
				EnableLegacyOverrides: true, // need to enable it to test
			}

			if tt.perTenantOverrides != nil {
				overridesFile := filepath.Join(t.TempDir(), "Overrides.yaml")

				legacyOverrides := &perTenantLegacyOverrides{}
				legacyOverrides.TenantLimits = make(map[string]*LegacyOverrides)
				for tenantID, limits := range tt.perTenantOverrides.TenantLimits {
					legacyLimits := limits.toLegacy()
					legacyOverrides.TenantLimits[tenantID] = &legacyLimits
				}
				buff, err := yaml.Marshal(legacyOverrides)
				require.NoError(t, err)

				err = os.WriteFile(overridesFile, buff, 0o700)
				require.NoError(t, err)

				cfg.PerTenantOverrideConfig = overridesFile
				cfg.PerTenantOverridePeriod = model.Duration(time.Hour)
			}

			prometheus.DefaultRegisterer = prometheus.NewRegistry() // have to overwrite the registry or test panics with multiple metric reg
			overrides, err := newRuntimeConfigOverrides(cfg, &mockValidator{}, prometheus.DefaultRegisterer)
			require.NoError(t, err)
			err = services.StartAndAwaitRunning(context.TODO(), overrides)
			require.NoError(t, err)

			for user, expectedVal := range tt.expectedMaxLocalTraces {
				assert.Equal(t, expectedVal, overrides.MaxLocalTracesPerUser(user))
			}

			for user, expectedVal := range tt.expectedMaxGlobalTraces {
				assert.Equal(t, expectedVal, overrides.MaxGlobalTracesPerUser(user))
			}

			for user, expectedVal := range tt.expectedIngestionBurstSpans {
				assert.Equal(t, expectedVal, overrides.IngestionBurstSizeBytes(user))
			}

			for user, expectedVal := range tt.expectedIngestionRateSpans {
				assert.Equal(t, float64(expectedVal), overrides.IngestionRateLimitBytes(user))
			}

			for user, expectedVal := range tt.expectedMaxSearchDuration {
				assert.Equal(t, time.Duration(expectedVal), overrides.MaxSearchDuration(user))
			}

			err = services.StopAndAwaitTerminated(context.TODO(), overrides)
			require.NoError(t, err)
		})
	}
}

func TestMetricsGeneratorOverrides(t *testing.T) {
	tests := []struct {
		name                                 string
		defaultLimits                        Overrides
		perTenantOverrides                   *perTenantOverrides
		expectedEnableTargetInfo             map[string]bool
		expectedDimensionMappings            map[string][]sharedconfig.DimensionMappings
		expectedTargetInfoExcludedDimensions map[string][]string
		expectedEnableInstanceLabel          map[string]bool
	}{
		{
			name: "limits only",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					Processor: ProcessorOverrides{
						SpanMetrics: SpanMetricsOverrides{
							EnableTargetInfo: boolPtr(true),
							DimensionMappings: []sharedconfig.DimensionMappings{
								{
									Name:        "test-name",
									SourceLabel: []string{"service.name"},
									Join:        "/",
								},
							},
							EnableInstanceLabel: boolPtr(false),
						},
					},
				},
			},
			expectedEnableTargetInfo: map[string]bool{"user1": true, "user2": true},
			expectedDimensionMappings: map[string][]sharedconfig.DimensionMappings{
				"user1": {
					{
						Name:        "test-name",
						SourceLabel: []string{"service.name"},
						Join:        "/",
					},
				},
				"user2": {
					{
						Name:        "test-name",
						SourceLabel: []string{"service.name"},
						Join:        "/",
					},
				},
			},
			expectedEnableInstanceLabel: map[string]bool{"user1": false, "user2": false},
		},
		{
			name:          "basic Overrides",
			defaultLimits: Overrides{},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							Processor: ProcessorOverrides{
								SpanMetrics: SpanMetricsOverrides{
									EnableTargetInfo: boolPtr(true),
									DimensionMappings: []sharedconfig.DimensionMappings{
										{
											Name:        "test-name",
											SourceLabel: []string{"service.name"},
											Join:        "/",
										},
									},
									EnableInstanceLabel: boolPtr(false),
								},
							},
						},
					},
				},
			},
			expectedEnableTargetInfo: map[string]bool{"user1": true, "user2": false},
			expectedDimensionMappings: map[string][]sharedconfig.DimensionMappings{
				"user1": {
					{
						Name:        "test-name",
						SourceLabel: []string{"service.name"},
						Join:        "/",
					},
				},
				"user2": nil,
			},
			expectedEnableInstanceLabel: map[string]bool{"user1": false, "user2": true},
		},
		{
			name: "wildcard override",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					Processor: ProcessorOverrides{
						SpanMetrics: SpanMetricsOverrides{
							EnableTargetInfo: boolPtr(false),
							DimensionMappings: []sharedconfig.DimensionMappings{
								{
									Name:        "test-name",
									SourceLabel: []string{"service.name"},
									Join:        "/",
								},
							},
						},
					},
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							Processor: ProcessorOverrides{
								SpanMetrics: SpanMetricsOverrides{
									EnableTargetInfo: boolPtr(true),
									DimensionMappings: []sharedconfig.DimensionMappings{
										{
											Name:        "another-name",
											SourceLabel: []string{"service.namespace"},
											Join:        "/",
										},
									},
									TargetInfoExcludedDimensions: []string{"some-label"},
								},
							},
						},
					},
					"*": {
						MetricsGenerator: MetricsGeneratorOverrides{
							Processor: ProcessorOverrides{
								SpanMetrics: SpanMetricsOverrides{
									EnableTargetInfo: boolPtr(false),
									DimensionMappings: []sharedconfig.DimensionMappings{
										{
											Name:        "id-name",
											SourceLabel: []string{"service.instance.id"},
											Join:        "/",
										},
										{
											Name:        "job",
											SourceLabel: []string{"service.namespace", "service.name"},
											Join:        "/",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedEnableTargetInfo: map[string]bool{"user1": true, "user2": false},
			expectedDimensionMappings: map[string][]sharedconfig.DimensionMappings{
				"user1": {
					{
						Name:        "another-name",
						SourceLabel: []string{"service.namespace"},
						Join:        "/",
					},
				},
				"user2": {
					{
						Name:        "id-name",
						SourceLabel: []string{"service.instance.id"},
						Join:        "/",
					},
					{
						Name:        "job",
						SourceLabel: []string{"service.namespace", "service.name"},
						Join:        "/",
					},
				},
			},
			expectedTargetInfoExcludedDimensions: map[string][]string{
				"user1": {"some-label"},
			},
			expectedEnableInstanceLabel: map[string]bool{"user1": true, "user2": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tt.defaultLimits, toYamlBytes(t, tt.perTenantOverrides))
			defer cleanup()

			for user, expectedVal := range tt.expectedEnableTargetInfo {
				enableTargetInfoValue, _ := overrides.MetricsGeneratorProcessorSpanMetricsEnableTargetInfo(user)
				assert.Equal(t, expectedVal, enableTargetInfoValue)
			}

			for user, expectedVal := range tt.expectedDimensionMappings {
				assert.Equal(t, expectedVal, overrides.MetricsGeneratorProcessorSpanMetricsDimensionMappings(user))
			}

			for user, expectedVal := range tt.expectedTargetInfoExcludedDimensions {
				assert.Equal(t, expectedVal, overrides.MetricsGeneratorProcessorSpanMetricsTargetInfoExcludedDimensions(user))
			}

			for user, expectedVal := range tt.expectedEnableInstanceLabel {
				EnableInstanceLabelValue, _ := overrides.MetricsGeneratorProcessorSpanMetricsEnableInstanceLabel(user)
				assert.Equal(t, expectedVal, EnableInstanceLabelValue)
			}

			err := services.StopAndAwaitTerminated(context.TODO(), overrides)
			require.NoError(t, err)
		})
	}
}

func TestTempoDBOverrides(t *testing.T) {
	tests := []struct {
		name                     string
		defaultLimits            Overrides
		perTenantOverrides       string
		expectedDedicatedColumns map[string]backend.DedicatedColumns
	}{
		{
			name: "limits",
			defaultLimits: Overrides{
				Storage: StorageOverrides{
					DedicatedColumns: backend.DedicatedColumns{
						{Scope: "resource", Name: "namespace", Type: "string"},
					},
				},
			},
			expectedDedicatedColumns: map[string]backend.DedicatedColumns{
				"user1": {{Scope: "resource", Name: "namespace", Type: "string"}},
				"user2": {{Scope: "resource", Name: "namespace", Type: "string"}},
			},
		},
		{
			name: "basic overrides",
			defaultLimits: Overrides{
				Storage: StorageOverrides{
					DedicatedColumns: backend.DedicatedColumns{
						{Scope: "resource", Name: "namespace", Type: "string"},
					},
				},
			},
			perTenantOverrides: `
overrides:
  user2:
    storage:
      parquet_dedicated_columns:
        - scope: "span"
          name: "http.status"
          type: "int"
`,
			expectedDedicatedColumns: map[string]backend.DedicatedColumns{
				"user1": {{Scope: "resource", Name: "namespace", Type: "string"}},
				"user2": {{Scope: "span", Name: "http.status", Type: "int"}},
			},
		},
		{
			name: "empty dedicated columns override global cfg",
			defaultLimits: Overrides{
				Storage: StorageOverrides{
					DedicatedColumns: backend.DedicatedColumns{
						{Scope: "resource", Name: "namespace", Type: "string"},
					},
				},
			},
			perTenantOverrides: `
overrides:
  user1:
  user2:
    storage:
      parquet_dedicated_columns: []
`,
			expectedDedicatedColumns: map[string]backend.DedicatedColumns{
				"user1": {{Scope: "resource", Name: "namespace", Type: "string"}},
				"user2": {},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tc.defaultLimits, []byte(tc.perTenantOverrides))
			defer cleanup()

			for user, expected := range tc.expectedDedicatedColumns {
				assert.Equal(t, expected, overrides.DedicatedColumns(user))
			}
		})
	}
}

func TestRemoteWriteHeaders(t *testing.T) {
	cfg := Config{
		Defaults: Overrides{
			MetricsGenerator: MetricsGeneratorOverrides{
				RemoteWriteHeaders: map[string]config.Secret{
					"Authorization": "Bearer secret-token",
				},
			},
		},
	}

	overrides, err := newRuntimeConfigOverrides(cfg, &mockValidator{}, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NoError(t, services.StartAndAwaitRunning(context.TODO(), overrides))

	buff := bytes.NewBuffer(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, overrides.WriteStatusRuntimeConfig(buff, req))

	// Verify the YAML output can be unmarshalled back
	var runtimeConfig struct {
		Defaults           Overrides          `yaml:"defaults"`
		PerTenantOverrides perTenantOverrides `yaml:",inline"`
	}
	require.NoError(t, yaml.UnmarshalStrict(buff.Bytes(), &runtimeConfig))

	assert.Equal(t, "<secret>", string(runtimeConfig.Defaults.MetricsGenerator.RemoteWriteHeaders["Authorization"]))

	fmt.Println(buff.String())
}

func TestExpandEnvOverrides(t *testing.T) {
	const envVar = "TOKEN"
	cfg := Config{
		Defaults: Overrides{
			MetricsGenerator: MetricsGeneratorOverrides{
				RemoteWriteHeaders: map[string]config.Secret{
					"Authorization": "Bearer token",
				},
			},
		},
		ExpandEnv: true,
	}
	// Set the ORG_ID env var
	require.NoError(t, os.Setenv(envVar, "super-secret-token"))
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv(envVar))
	})

	perTenantOverrides := fmt.Sprintf(`
overrides:
  user1:
    metrics_generator:
      remote_write_headers:
        Authorization: Bearer ${%s}
`, envVar)

	overridesFile := filepath.Join(t.TempDir(), "Overrides.yaml")

	require.NoError(t, os.WriteFile(overridesFile, []byte(perTenantOverrides), 0o700))

	cfg.PerTenantOverrideConfig = overridesFile
	cfg.PerTenantOverridePeriod = model.Duration(time.Hour)

	overrides, err := newRuntimeConfigOverrides(cfg, &mockValidator{}, prometheus.NewRegistry())
	require.NoError(t, err)
	require.NoError(t, services.StartAndAwaitRunning(context.TODO(), overrides))

	expectedRemoteWriteHeaders := map[string]map[string]string{
		"user1": {"Authorization": "Bearer super-secret-token"},
		"user2": {"Authorization": "Bearer token"},
	}
	for user, expected := range expectedRemoteWriteHeaders {
		assert.Equal(t, expected, overrides.MetricsGeneratorRemoteWriteHeaders(user))
	}

	require.NoError(t, services.StopAndAwaitTerminated(context.Background(), overrides))
}

func TestNativeHistogramOverrides(t *testing.T) {
	tests := []struct {
		name                            string
		defaultLimits                   Overrides
		perTenantOverrides              *perTenantOverrides
		nativeHistogramBucketFactor     float64
		nativeHistogramMaxBucketNumber  uint32
		nativeHistogramMinResetDuration time.Duration
	}{
		{
			name: "defaults only",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					NativeHistogramBucketFactor:     1.5,
					NativeHistogramMaxBucketNumber:  20,
					NativeHistogramMinResetDuration: 5 * time.Minute,
				},
			},
			nativeHistogramBucketFactor:     1.5,
			nativeHistogramMaxBucketNumber:  20,
			nativeHistogramMinResetDuration: 5 * time.Minute,
		},
		{
			name: "defaults only",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					NativeHistogramBucketFactor:     1.5,
					NativeHistogramMaxBucketNumber:  20,
					NativeHistogramMinResetDuration: 5 * time.Minute,
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							NativeHistogramBucketFactor:     2.0,
							NativeHistogramMaxBucketNumber:  30,
							NativeHistogramMinResetDuration: 10 * time.Minute,
						},
					},
				},
			},
			nativeHistogramBucketFactor:     2.0,
			nativeHistogramMaxBucketNumber:  30,
			nativeHistogramMinResetDuration: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tt.defaultLimits, toYamlBytes(t, tt.perTenantOverrides))
			defer cleanup()

			assert.Equal(t, tt.nativeHistogramBucketFactor, overrides.MetricsGeneratorNativeHistogramBucketFactor("user1"))
			assert.Equal(t, tt.nativeHistogramMaxBucketNumber, overrides.MetricsGeneratorNativeHistogramMaxBucketNumber("user1"))
			assert.Equal(t, tt.nativeHistogramMinResetDuration, overrides.MetricsGeneratorNativeHistogramMinResetDuration("user1"))

			err := services.StopAndAwaitTerminated(context.TODO(), overrides)
			require.NoError(t, err)
		})
	}
}

func TestIngestionRetryInfoEnabled(t *testing.T) {
	tests := []struct {
		name               string
		defaultLimits      Overrides
		perTenantOverrides *perTenantOverrides
		expected           bool
	}{
		{
			name: "no tenant override: cluster default wins",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{RetryInfoEnabled: new(true)},
			},
			expected: true,
		},
		{
			name: "tenant override explicitly disables it",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{RetryInfoEnabled: new(true)},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {Ingestion: IngestionOverrides{RetryInfoEnabled: new(false)}},
				},
			},
			expected: false,
		},
		{
			name: "tenant override exists but doesn't mention retry info: falls back to cluster default",
			defaultLimits: Overrides{
				Ingestion: IngestionOverrides{RetryInfoEnabled: new(true)},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {Ingestion: IngestionOverrides{RateLimitBytes: 600_000_000}},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A nil perTenantOverrides marshals to a literal "null" document; writing that as
			// the runtime overrides file makes the loader decode a nil *perTenantOverrides and
			// panic. Pass a nil []byte instead so no runtime overrides file is created at all.
			var perTenantBytes []byte
			if tt.perTenantOverrides != nil {
				perTenantBytes = toYamlBytes(t, tt.perTenantOverrides)
			}
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tt.defaultLimits, perTenantBytes)
			defer cleanup()

			assert.Equal(t, tt.expected, overrides.IngestionRetryInfoEnabled("user1"))

			err := services.StopAndAwaitTerminated(context.TODO(), overrides)
			require.NoError(t, err)
		})
	}
}

func TestMetricsGeneratorMaxCardinalityPerLabel(t *testing.T) {
	tests := []struct {
		name               string
		defaultLimits      Overrides
		perTenantOverrides *perTenantOverrides
		expected           map[string]uint64
	}{
		{
			name: "default enabled, no tenant override",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					MaxCardinalityPerLabel: 100,
				},
			},
			expected: map[string]uint64{"user1": 100, "user2": 100},
		},
		{
			name:          "default disabled, tenant enables",
			defaultLimits: Overrides{},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							MaxCardinalityPerLabel: 50,
						},
					},
				},
			},
			expected: map[string]uint64{"user1": 50, "user2": 0},
		},
		{
			name: "default enabled, tenant disables with 0",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					MaxCardinalityPerLabel: 100,
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							MaxCardinalityPerLabel: 0,
						},
					},
				},
			},
			expected: map[string]uint64{"user1": 0, "user2": 100},
		},
		{
			name: "default enabled, tenant overrides with higher value",
			defaultLimits: Overrides{
				MetricsGenerator: MetricsGeneratorOverrides{
					MaxCardinalityPerLabel: 100,
				},
			},
			perTenantOverrides: &perTenantOverrides{
				TenantLimits: map[string]*Overrides{
					"user1": {
						MetricsGenerator: MetricsGeneratorOverrides{
							MaxCardinalityPerLabel: 500,
						},
					},
				},
			},
			expected: map[string]uint64{"user1": 500, "user2": 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			overrides, cleanup := createAndInitializeRuntimeOverridesManager(t, tt.defaultLimits, toYamlBytes(t, tt.perTenantOverrides))
			defer cleanup()

			for user, expected := range tt.expected {
				require.Equal(t, expected, overrides.MetricsGeneratorMaxCardinalityPerLabel(user), "user: %s", user)
			}
		})
	}
}

func TestSecretsPolicyFallsBackToDefault(t *testing.T) {
	defaultPolicy := &secrets.Policy{CustomRules: []secrets.CustomRule{{ID: "default", Regex: `DEFAULT-[0-9]+`}}}
	tenantPolicy := &secrets.Policy{CustomRules: []secrets.CustomRule{{ID: "tenant", Regex: `TENANT-[0-9]+`}}}
	perTenant := &perTenantOverrides{
		TenantLimits: map[string]*Overrides{
			"sparse": {
				Ingestion: IngestionOverrides{TenantShardSize: 2},
			},
			"explicit": {
				MetricsGenerator: MetricsGeneratorOverrides{Processor: ProcessorOverrides{SecretDetection: tenantPolicy}},
			},
		},
	}

	overrides, cleanup := createAndInitializeRuntimeOverridesManager(
		t,
		Overrides{MetricsGenerator: MetricsGeneratorOverrides{Processor: ProcessorOverrides{SecretDetection: defaultPolicy}}},
		toYamlBytes(t, perTenant),
	)
	defer cleanup()

	policy, inherited := overrides.SecretsPolicy("sparse")
	assert.Equal(t, defaultPolicy, policy)
	assert.True(t, inherited)
	policy, inherited = overrides.SecretsPolicy("missing")
	assert.Equal(t, defaultPolicy, policy)
	assert.True(t, inherited)
	policy, inherited = overrides.SecretsPolicy("explicit")
	assert.Equal(t, tenantPolicy, policy)
	assert.False(t, inherited)
	assert.Zero(t, testing.AllocsPerRun(100, func() {
		_, _ = overrides.SecretsPolicy("explicit")
	}))
}

func createAndInitializeRuntimeOverridesManager(t *testing.T, defaultLimits Overrides, perTenantOverrides []byte) (Service, func()) {
	cfg := Config{
		Defaults: defaultLimits,
	}

	if perTenantOverrides != nil {
		overridesFile := filepath.Join(t.TempDir(), "Overrides.yaml")

		err := os.WriteFile(overridesFile, perTenantOverrides, 0o700)
		require.NoError(t, err)

		cfg.PerTenantOverrideConfig = overridesFile
		cfg.PerTenantOverridePeriod = model.Duration(time.Hour)
	}

	prometheus.DefaultRegisterer = prometheus.NewRegistry() // have to overwrite the registry or test panics with multiple metric reg
	overrides, err := newRuntimeConfigOverrides(cfg, &mockValidator{}, prometheus.DefaultRegisterer)
	require.NoError(t, err)

	err = services.StartAndAwaitRunning(context.TODO(), overrides)
	require.NoError(t, err)

	return overrides, func() {
		err := services.StopAndAwaitTerminated(context.TODO(), overrides)
		require.NoError(t, err)
	}
}

func toYamlBytes(t *testing.T, perTenantOverrides *perTenantOverrides) []byte {
	buff, err := yaml.Marshal(perTenantOverrides)
	require.NoError(t, err)
	return buff
}

type mockValidator struct {
	f func(*Overrides) error
}

func (m mockValidator) Validate(config *Overrides) (warnings []error, err error) {
	if m.f != nil {
		return nil, m.f(config)
	}
	return nil, nil
}
