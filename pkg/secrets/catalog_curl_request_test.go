package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func assertNativeCurlVerdict(t *testing.T, policy *CompiledPolicy, value, ruleID string, accepted bool) {
	t.Helper()
	require.Equal(t, accepted, hasRuleFinding(policy.Detect(value).Matches, ruleID), "direct verdict")
	batch := policy.NewBatchDetector()
	require.Equal(t, accepted, hasRuleFinding(batch.Detect(value).Matches, ruleID), "batch verdict")
}

func TestNativeCurlUserQuoting(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, test := range []struct {
		name, operand string
		accepted      bool
	}{
		{"double-quoted-ordinary-backslash", `"alice:p\assword"`, true},
		{"equivalent-single-quoted-backslash", `'alice:p\assword'`, true},
		{"unquoted-escape-produces-placeholder", `alice:p\assword`, false},
		{"literal-placeholder", `"alice:password"`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertNativeCurlVerdict(t, policy, "curl --user "+test.operand+" https://example.com", "curl-user-credential", test.accepted)
		})
	}
}

func TestNativeCurlDataURLEncode(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, provider := range []struct {
		name, ruleID, endpoint, field, encodedField, key string
	}{
		{"shared", "canny-api-request", "https://canny.io/api/v1/boards/list", "apiKey", "api%4Bey", "931ca72f-bd08-451a-ae26-8013d57fc942"},
		{"independent-six", "postageapp-api-key-request", "https://api.postageapp.com/v.1.0/send_message.json", "api_key", "api%5Fkey", "G7mK2pR9vB4xT8cL6nQ3zA5sD1fH0jW2"},
	} {
		t.Run(provider.name, func(t *testing.T) {
			for _, test := range []struct {
				name, options string
				accepted      bool
			}{
				{"genuine-operand", "--data-urlencode '" + provider.field + "=" + provider.key + "'", true},
				{"encoded-name", "--data-urlencode '" + provider.encodedField + "=" + provider.key + "'", true},
				{"embedded-field-is-content", "--data-urlencode 'note=public&" + provider.field + "=" + provider.key + "'", false},
				{"raw-data-still-splits-fields", "--data 'note=public&" + provider.field + "=" + provider.key + "'", true},
				{"literal-percent-is-not-decoded", fmt.Sprintf("--data-urlencode '%s=%%%02X%s'", provider.field, provider.key[0], provider.key[1:]), false},
				{"leading-equals-is-content", "--data-urlencode '=" + provider.field + "=" + provider.key + "'", false},
				{"file-operand", "--data-urlencode '@credentials'", false},
				{"named-file-operand", "--data-urlencode '" + provider.field + "@credentials'", false},
			} {
				t.Run(test.name, func(t *testing.T) {
					assertNativeCurlVerdict(t, policy, "curl "+provider.endpoint+" "+test.options, provider.ruleID, test.accepted)
				})
			}
		})
	}

	const endpoint = "curl https://canny.io/api/v1/boards/list "
	const credential = "apiKey=931ca72f-bd08-451a-ae26-8013d57fc942"
	for _, test := range []struct {
		name, options string
		accepted      bool
	}{
		{"separate-genuine-operand", "--data-urlencode 'note=public&apiKey=not-a-key' --data-urlencode '" + credential + "'", true},
		{"content-only-with-literal-punctuation", "--data-urlencode 'public&+%' --data-urlencode '" + credential + "'", true},
		{"named-content-with-literal-punctuation", "--data-urlencode 'note=public&+%' --data-urlencode '" + credential + "'", true},
		{"file-before-genuine-operand", "--data-urlencode '@credentials' --data '" + credential + "'", false},
		{"named-file-after-genuine-operand", "--data '" + credential + "' --data-urlencode 'note@credentials'", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertNativeCurlVerdict(t, policy, endpoint+test.options, "canny-api-request", test.accepted)
		})
	}

	// The '+' in this literal base64-shaped secret must not become a form space.
	secret := strings.Repeat("Ab3+/", 17) + "Q=="
	assertNativeCurlVerdict(t, policy, "curl https://api.sirv.com/v2/token --data-urlencode 'clientSecret="+secret+"'", "sirv-client-secret-request", true)
}

func TestNativeCurlHostAuthority(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, provider := range []struct {
		name, ruleID, endpoint, host, authentication string
	}{
		{"shared-header", "newsapi-api-key-request", "https://newsapi.org/v2/everything", "newsapi.org", "-H 'X-Api-Key: 0123456789abcdef0123456789abcdef'"},
		{"independent-six-header", "qase-api-token-request", "https://api.qase.io/v1/user", "api.qase.io", "-H 'Token: HatCVo7Qj2LexGZsBUn6Pi1KdwFYrATm5Oh0JcvE'"},
		{"independent-eight-header", "tyntec-api-key-request", "https://api.tyntec.com/api", "api.tyntec.com", "-H 'apikey: hyP6nEVctK1izQ7oFWduL2jAR8pGXevM'"},
	} {
		t.Run(provider.name, func(t *testing.T) {
			for _, test := range []struct {
				name, before, after string
				accepted            bool
			}{
				{"no-override", "", "", true},
				{"matching-override", "-H 'Host: " + provider.host + "' ", "", true},
				{"mixed-case-matching-override", "", " -H 'hOsT: " + strings.ToUpper(provider.host) + "'", true},
				{"conflict-before-authentication", "-H 'Host: public.example' ", "", false},
				{"conflict-after-authentication", "", " -H 'Host: public.example'", false},
				{"duplicate-matching-overrides", "-H 'Host: " + provider.host + "' ", " -H 'host: " + provider.host + "'", false},
				{"removed-host", "", " -H 'Host:'", false},
			} {
				t.Run(test.name, func(t *testing.T) {
					command := "curl " + provider.endpoint + " " + test.before + provider.authentication + test.after
					assertNativeCurlVerdict(t, policy, command, provider.ruleID, test.accepted)
				})
			}
		})
	}
}

func TestNativeCurlHostAuthorityCredentialRoles(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	for _, test := range []struct {
		name, ruleID, command string
	}{
		{"shared-body", "meaningcloud-license-key", "curl https://api.meaningcloud.com/lang-4.0/identification -d 'key=q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3'"},
		{"shared-basic-user", "onfleet-api-key-curl", "curl https://onfleet.com/api/v2/organization --user 'q7m2v9c4x6n8b3k5s1d0f2h4j6r8t9w3:'"},
		{"independent-six-body", "postageapp-api-key-request", "curl https://api.postageapp.com/v.1.0/send_message.json --data '{\"api_key\":\"G7mK2pR9vB4xT8cL6nQ3zA5sD1fH0jW2\"}'"},
		{"independent-six-basic-user", "signable-api-key-request", "curl https://api.signable.co.uk/v1/templates --user 'G7mK2pR9vB4xT8cL6nQ3zA5sD1fH0jW2:'"},
		{"independent-eight-form", "typetalk-client-secret", "curl https://typetalk.com/oauth2/access_token -d 'client_secret=hyP6nEVctK1izQ7oFWduL2jAR8pGXevM3kBS9qHYfwN4lCTarIZgxO5mDUbsJ0hy'"},
		{"independent-eight-json", "zipbooks-login-credentials", "curl https://api.zipbooks.com/v2/auth/login -d '{\"email\":\"person@example.org\",\"password\":\"Synthetic-7!pass\"}'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertNativeCurlVerdict(t, policy, test.command, test.ruleID, true)
			assertNativeCurlVerdict(t, policy, test.command+" -H 'Host: public.example'", test.ruleID, false)
		})
	}
}

func TestNativeHTTPHostAuthority(t *testing.T) {
	policy := &CompiledPolicy{catalog: testNativeCatalog(t)}
	const auth = "X-Api-Key: 0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name, target, headers string
		accepted              bool
	}{
		{"absolute-target-without-host", "https://newsapi.org/v2/everything", auth, true},
		{"absolute-mixed-case-host", "https://newsapi.org/v2/everything", auth + "\r\nhOsT: NEWSAPI.ORG", true},
		{"absolute-conflicting-host", "https://newsapi.org/v2/everything", "Host: public.example\r\n" + auth, false},
		{"duplicate-host", "https://newsapi.org/v2/everything", "Host: newsapi.org\r\n" + auth + "\r\nHost: newsapi.org", false},
		{"empty-host-before-valid-host", "https://newsapi.org/v2/everything", "Host:\r\nHost: newsapi.org\r\n" + auth, false},
		{"origin-form-matching-host", "/v2/everything", "Host: newsapi.org\r\n" + auth, true},
		{"origin-form-missing-host", "/v2/everything", auth, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := "GET " + test.target + " HTTP/1.1\r\n" + test.headers
			assertNativeCurlVerdict(t, policy, request, "newsapi-api-key-request", test.accepted)
		})
	}
}
