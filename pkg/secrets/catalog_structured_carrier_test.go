package secrets

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeUpstashStructuredTokenFraming(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	// These synthetic values exercise the declared structural subset, not
	// provider issuance or whether a credential works against a live endpoint.
	const token = "AYNgASAACxwtPk9gcYKTpLXG1Aj5ChssPU5fcIGSo7TF1uf4CRorPE1eb4CRog=="
	const host = "https://cobalt-reef-482.upstash.io"
	const opaque = "k7P2mN9qR5sT8vW3xY6zA1bC4dE0fG8h"
	const tokenName = "UPSTASH_REDIS_REST_TOKEN"
	const hostName = "UPSTASH_REDIS_REST_URL"
	const ruleID = "upstash-redis-rest-token"
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{"bare-token-first", tokenName + "=" + token + "; " + hostName + "=" + host, true},
		{"bare-host-first", hostName + "=" + host + "\n" + tokenName + "=" + token, true},
		{"double-quoted-token-first", tokenName + "=\"" + token + "\"; " + hostName + "=\"" + host + "\"", true},
		{"double-quoted-host-first", hostName + "=\"" + host + "\"\n" + tokenName + "=\"" + token + "\"", true},
		{"single-quoted-token-first", tokenName + "='" + token + "'; " + hostName + "='" + host + "'", true},
		{"single-quoted-host-first", hostName + "='" + host + "'\n" + tokenName + "='" + token + "'", true},
		{"json-token-first", "{\"" + tokenName + "\": \"" + token + "\", \"" + hostName + "\": \"" + host + "\"}", true},
		{"json-host-first", "{\"" + hostName + "\": \"" + host + "\", \"" + tokenName + "\": \"" + token + "\"}", true},
		{"opaque-alternative", tokenName + "=" + opaque + "; " + hostName + "=" + host, true},
		{"curl-bearer", "curl " + host + "/ping -H 'Authorization: Bearer " + token + "'", true},
		{"http-bearer", "GET " + host + "/ping HTTP/1.1\r\nHost: cobalt-reef-482.upstash.io\r\nAuthorization: Bearer " + token + "\r\n\r\n", true},
		{"curl-matching-host", "curl " + host + "/ping -H 'Authorization: Bearer " + token + "' -H 'Host: cobalt-reef-482.upstash.io'", true},
		{"curl-mismatched-host", "curl " + host + "/ping -H 'Authorization: Bearer " + token + "' -H 'Host: other.upstash.io'", false},
		{"curl-duplicate-host", "curl " + host + "/ping -H 'Authorization: Bearer " + token + "' -H 'Host: cobalt-reef-482.upstash.io' -H 'Host: cobalt-reef-482.upstash.io'", false},
		{"http-mismatched-host", "GET " + host + "/ping HTTP/1.1\r\nHost: other.upstash.io\r\nAuthorization: Bearer " + token + "\r\n\r\n", false},
		{"http-duplicate-host", "GET " + host + "/ping HTTP/1.1\r\nHost: cobalt-reef-482.upstash.io\r\nHost: cobalt-reef-482.upstash.io\r\nAuthorization: Bearer " + token + "\r\n\r\n", false},
		{"bare-continuation", hostName + "=" + host + "\n" + tokenName + "=" + token + "suffix", false},
		{"quoted-continuation", hostName + "=\"" + host + "\"\n" + tokenName + "=\"" + token + "\" + suffix", false},
		{"missing-padding", hostName + "=" + host + "\n" + tokenName + "=" + token[:len(token)-1], false},
		{"noncanonical-padding-bits", hostName + "=" + host + "\n" + tokenName + "=" + token[:len(token)-3] + "h==", false},
		{"mismatched-value-quote", hostName + "=\"" + host + "\"\n" + tokenName + "=\"" + token + "'", false},
		{"opaque-prefix-continuation", hostName + "=" + host + "\n" + tokenName + "=" + opaque + ".suffix", false},
		{"host-continuation", tokenName + "=" + token + "; " + hostName + "=" + host + ".evil.invalid", false},
		{"http-malformed-token-continuation", "GET " + host + "/ping HTTP/1.1\r\nAuthorization: Bearer " + token + "suffix\r\n\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, hasRuleFinding(policy.Detect(test.value).Matches, ruleID))
			batch := policy.NewBatchDetector()
			require.Equal(t, test.want, hasRuleFinding(batch.Detect(test.value).Matches, ruleID))
		})
	}
}
