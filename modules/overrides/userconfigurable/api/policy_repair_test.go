package api

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/tempo/modules/overrides"
	"github.com/grafana/tempo/modules/overrides/userconfigurable/client"
	"github.com/grafana/tempo/pkg/secrets"
	"github.com/grafana/tempo/tempodb/backend"
	"github.com/grafana/tempo/tempodb/backend/gcs"
)

// versionedPolicyBackend implements the object operations used by the real GCS
// client. Unlike the local backend, generation checks and writes/deletes are
// atomic, so using a missing or stale repair token cannot overwrite an update.
type versionedPolicyBackend struct {
	mu         sync.Mutex
	generation int64
	objects    map[string]versionedPolicyObject
}

type versionedPolicyObject struct {
	body       []byte
	generation int64
}

func (b *versionedPolicyBackend) store(name string, body []byte) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.generation++
	b.objects[name] = versionedPolicyObject{bytes.Clone(body), b.generation}
	return fmt.Sprint(b.generation)
}

func (b *versionedPolicyBackend) load(name string) versionedPolicyObject {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.objects[name]
}

func (b *versionedPolicyBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/b/policies" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"policies","versioning":{"enabled":true}}`)
		return
	}
	var name string
	var body []byte
	if r.Method == http.MethodPost {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || params["boundary"] == "" {
			http.Error(w, "expected multipart upload", http.StatusBadRequest)
			return
		}
		parts := multipart.NewReader(r.Body, params["boundary"])
		metadata, err := parts.NextPart()
		if err != nil {
			http.Error(w, "missing upload metadata", http.StatusBadRequest)
			return
		}
		var object struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(metadata).Decode(&object); err != nil {
			http.Error(w, "invalid upload metadata", http.StatusBadRequest)
			return
		}
		name = object.Name
		data, err := parts.NextPart()
		if err != nil {
			http.Error(w, "missing upload data", http.StatusBadRequest)
			return
		}
		body, err = io.ReadAll(data)
		if err != nil {
			http.Error(w, "invalid upload data", http.StatusBadRequest)
			return
		}
	} else {
		_, name, _ = strings.Cut(r.URL.Path, "/o/")
	}
	if name == "" {
		http.Error(w, "unknown object route", http.StatusNotFound)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	object, exists := b.objects[name]
	if r.Method != http.MethodGet {
		current := "0"
		if exists {
			current = fmt.Sprint(object.generation)
		}
		if r.URL.Query().Get("ifGenerationMatch") != current {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"error":{"code":412,"message":"generation does not match"}}`)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-Goog-Generation", fmt.Sprint(object.generation))
		w.Header().Set("Content-Length", fmt.Sprint(len(object.body)))
		_, _ = w.Write(object.body)
	case http.MethodPost:
		b.generation++
		b.objects[name] = versionedPolicyObject{body, b.generation}
		var checksum [4]byte
		binary.BigEndian.PutUint32(checksum[:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name": name, "generation": fmt.Sprint(b.generation), "size": fmt.Sprint(len(body)),
			"crc32c": base64.StdEncoding.EncodeToString(checksum[:]),
		})
	case http.MethodDelete:
		delete(b.objects, name)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestUserConfigOverridesAPIRepairsRejectedPolicyConditionally(t *testing.T) {
	const tenant = "tenant"
	const objectName = "overrides/tenant/overrides.json"
	const private = "private-unsupported-policy-content"
	invalid := []byte(`{"forwarders":["preserved"],"metrics_generator":{"processor":{"secret_detection":{"optional_rules":["` + private + `"]}}}}`)
	disk := &versionedPolicyBackend{objects: make(map[string]versionedPolicyObject)}
	server := httptest.NewServer(disk)
	t.Cleanup(server.Close)
	storeCfg := &client.Config{Backend: backend.GCS, ConfirmVersioning: true, GCS: &gcs.Config{
		BucketName: "policies", Endpoint: server.URL, Insecure: true,
	}}
	// Existing documents may be replaced despite runtime conflicts. A new
	// document must still be protected by the ordinary runtime conflict check.
	runtimeOverrides, err := overrides.NewOverrides(overrides.Config{Defaults: overrides.Overrides{
		MetricsGenerator: overrides.MetricsGeneratorOverrides{CollectionInterval: 15 * time.Second},
	}}, nil, prometheus.NewRegistry())
	require.NoError(t, err)
	a, err := New(&overrides.UserConfigurableOverridesAPIConfig{CheckForConflictingRuntimeOverrides: true}, storeCfg, runtimeOverrides, &mockValidator{})
	require.NoError(t, err)
	t.Cleanup(a.client.Shutdown)
	var logs bytes.Buffer
	a.logger = log.NewLogfmtLogger(&logs)

	get := func(scope string) *httptest.ResponseRecorder {
		request := prepareRequest(tenant, http.MethodGet, nil)
		request.URL.RawQuery = "scope=" + scope
		response := httptest.NewRecorder()
		a.GetHandler(response, request)
		return response
	}
	replacement := []byte(`{"forwarders":["replacement"],"metrics_generator":{"processor":{"secret_detection":{"disabled_rules":["generic-api-key"],"custom_rules":[{"id":"repaired-rule","regex":"REPAIRED"}]}}}}`)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			version := disk.store(objectName, invalid)
			for _, scope := range []string{queryParamScopeAPI, queryParamScopeMerged} {
				response := get(scope)
				require.Equal(t, http.StatusInternalServerError, response.Code)
				require.Equal(t, version, response.Header().Get(headerEtag))
				require.NotContains(t, response.Body.String(), private)
			}
			patch := httptest.NewRecorder()
			a.PatchHandler(patch, prepareRequest(tenant, http.MethodPatch, []byte(`{"forwarders":["patched"]}`)))
			require.Equal(t, http.StatusInternalServerError, patch.Code)
			require.Equal(t, version, patch.Header().Get(headerEtag))
			require.Equal(t, invalid, disk.load(objectName).body, "PATCH cannot reconstruct an unsupported policy")

			handler := a.PostHandler
			if method == http.MethodDelete {
				handler = a.DeleteHandler
			}
			missingToken := prepareRequest(tenant, method, replacement)
			missingToken.Header.Del(headerIfMatch)
			missingResponse := httptest.NewRecorder()
			handler(missingResponse, missingToken)
			require.Equal(t, http.StatusPreconditionRequired, missingResponse.Code)
			require.Equal(t, invalid, disk.load(objectName).body)

			// Another writer changes the object after the error GET. The old
			// version must not be usable for either repair or deletion.
			newer := bytes.Replace(invalid, []byte("preserved"), []byte("concurrent-update"), 1)
			currentVersion := disk.store(objectName, newer)
			stale := prepareRequest(tenant, method, replacement)
			stale.Header.Set(headerIfMatch, version)
			staleResponse := httptest.NewRecorder()
			handler(staleResponse, stale)
			require.GreaterOrEqual(t, staleResponse.Code, 400)
			require.Equal(t, newer, disk.load(objectName).body, "stale repair must not lose the concurrent update")
			require.Equal(t, currentVersion, get(queryParamScopeAPI).Header().Get(headerEtag))

			repair := prepareRequest(tenant, method, replacement)
			repair.Header.Set(headerIfMatch, currentVersion)
			repaired := httptest.NewRecorder()
			handler(repaired, repair)
			require.Equal(t, http.StatusOK, repaired.Code, repaired.Body.String())
			readback := get(queryParamScopeAPI)
			if method == http.MethodDelete {
				require.Equal(t, http.StatusNotFound, readback.Code)
				return
			}
			require.Equal(t, http.StatusOK, readback.Code)
			require.NotEqual(t, currentVersion, readback.Header().Get(headerEtag))
			require.Equal(t, repaired.Header().Get(headerEtag), readback.Header().Get(headerEtag))
			var limits client.Limits
			require.NoError(t, json.Unmarshal(readback.Body.Bytes(), &limits))
			require.Equal(t, &[]string{"replacement"}, limits.Forwarders)
			require.Equal(t, &secrets.Policy{DisabledRules: []string{"generic-api-key"}, CustomRules: []secrets.CustomRule{{ID: "repaired-rule", Regex: "REPAIRED"}}}, limits.MetricsGenerator.Processor.SecretDetection)
		})
	}

	version := disk.store(objectName, invalid)
	unauthorized := httptest.NewRecorder()
	a.GetHandler(unauthorized, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusBadRequest, unauthorized.Code)
	require.Empty(t, unauthorized.Header().Get(headerEtag))
	other := httptest.NewRecorder()
	a.GetHandler(other, prepareRequest("other-tenant", http.MethodGet, nil))
	require.Equal(t, http.StatusNotFound, other.Code)
	require.Empty(t, other.Header().Get(headerEtag))
	conflict := httptest.NewRecorder()
	a.PostHandler(conflict, prepareRequest("other-tenant", http.MethodPost, replacement))
	require.Equal(t, http.StatusBadRequest, conflict.Code)
	require.Equal(t, version, get(queryParamScopeAPI).Header().Get(headerEtag))
	require.NotContains(t, logs.String(), private)
}
