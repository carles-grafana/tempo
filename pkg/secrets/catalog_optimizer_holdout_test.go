package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	holdoutGitHubPAT      = "github-pat"
	holdoutGitHubApp      = "github-app-token"
	holdoutPyPI           = "pypi-upload-token"
	holdoutConfluent      = "confluent-secret-key"
	holdoutAge            = "age-secret-key"
	holdoutJWT            = "jwt"
	holdoutPrivateKey     = "private-key"
	holdoutBedrock        = "aws-amazon-bedrock-api-key-short-lived"
	holdoutGrafana        = "grafana-service-account-token"
	holdoutGitLabRoutable = "gitlab-pat-routable"
)

func TestOptimizerHoldoutStructuralCredentials(t *testing.T) {
	catalog := testNativeCatalog(t)
	policy := &CompiledPolicy{catalog: catalog}
	fixtures := nativeCatalogFixtures(t)
	// Fixed indices select independently serialized fixtures, not regex-generated
	// witnesses: checksums, routing frames, JSON, DER, JWT and macaroon framing.
	for _, selected := range []struct {
		id       string
		positive int
		negative int
	}{
		{holdoutGrafana, 0, 0},
		{holdoutConfluent, 0, 0},
		{holdoutGitLabRoutable, 0, 4},
		{holdoutAge, 0, 1},
		{holdoutJWT, 0, 6},
		{holdoutGitHubApp, 2, 1},
		{holdoutPyPI, 3, 5},
		{holdoutPrivateKey, 1, 0},
		{holdoutBedrock, 0, 4},
	} {
		t.Run(selected.id, func(t *testing.T) {
			fixture := fixtures[selected.id]
			positive := fixture.Positive[selected.positive]
			negative := fixture.Negative[selected.negative]
			t.Run("malformed", func(t *testing.T) {
				assertOptimizerHoldout(t, policy, negative, nil)
			})
			t.Run("valid-surrounded-by-unicode", func(t *testing.T) {
				assertOptimizerHoldout(t, policy, "界\n"+positive+"\né", []string{selected.id})
			})
			t.Run("rejected-first-then-two-valid", func(t *testing.T) {
				value := "\xff\n" + negative + "\n" + positive + "\n" + positive
				assertOptimizerHoldout(t, policy, value, []string{selected.id, selected.id})
			})
		})
	}
}

type optimizerHoldoutWorkload struct {
	name  string
	value string
	ids   []string
}

// Fill only complete UTF-8 motifs and use ASCII spaces for the remainder. Input
// sizes are exact bytes without accidentally turning the Unicode cases invalid.
func optimizerHoldoutFill(motif string, size int) string {
	return strings.Repeat(motif, size/len(motif)) + strings.Repeat(" ", size%len(motif))
}

func optimizerHoldoutWorkloads(t testing.TB) []optimizerHoldoutWorkload {
	t.Helper()
	fixtures := nativeCatalogFixtures(t)
	var cases []optimizerHoldoutWorkload
	addNoise := func(name, motif string, sizes ...int) {
		for _, size := range sizes {
			cases = append(cases, optimizerHoldoutWorkload{
				name: name + fmt.Sprintf("/%dB", size), value: optimizerHoldoutFill(motif, size),
			})
		}
	}
	addNoise("alternating-ascii-unicode", "r7é.p2界/", 8, 24, 64, 192, 768, 1536, 32768)
	addNoise("near-complete-github-starts", "ghp_"+strings.Repeat("Ab7d", 8)+"Ab7! ", 48, 128, 384, 1024, 2048, 131072)
	addNoise("multiple-provider-prefixes", "ghp_! glsa_! pypi-! xoxb-! Bearer ! glpat-! ", 96, 256, 512, 1792, 32768)
	addNoise("non-ascii-only", "éλ", 16, 32, 128, 512, 1984, 131072)
	addNoise("invalid-utf8-and-false-starts", "\xffghp_?\xc0\xafglsa_?\xed\xa0\x80pypi-? ", 1024)

	// Positive placement and provider choice vary together deliberately, rather
	// than multiplying every family by every size and offset.
	for _, placement := range []struct {
		id       string
		fixture  int
		size     int
		position string
	}{
		{holdoutGitHubPAT, 0, 64, "early"},
		{holdoutGrafana, 0, 192, "middle"},
		{holdoutPyPI, 0, 256, "end"},
		{holdoutJWT, 0, 384, "early"},
		{holdoutConfluent, 0, 768, "middle"},
		{holdoutGitLabRoutable, 0, 1024, "end"},
		{holdoutAge, 0, 1536, "early"},
		{holdoutGitHubApp, 2, 2048, "middle"},
		{holdoutPyPI, 3, 1920, "end"},
		{holdoutPrivateKey, 1, 32768, "end"},
		{holdoutBedrock, 0, 131072, "middle"},
	} {
		positive := fixtures[placement.id].Positive[placement.fixture]
		space := placement.size - len(positive) - 2
		require.GreaterOrEqual(t, space, 0, "fixture exceeds held-out workload size")
		offset := 0
		switch placement.position {
		case "middle":
			offset = space / 2
		case "end":
			offset = space
		}
		const request = "GET /v2/items?id=42; peer=ab7d; region=eu-west-1; status=204\n"
		value := optimizerHoldoutFill(request, offset) + "\n" + positive + "\n" + optimizerHoldoutFill(request, space-offset)
		cases = append(cases, optimizerHoldoutWorkload{
			name:  fmt.Sprintf("positive-%s-%s/%dB", placement.position, placement.id, placement.size),
			value: value, ids: []string{placement.id},
		})
	}

	// Encounter order differs from catalog order and the repeated GitHub token
	// must produce two full findings but only one public rule ID.
	multiple := strings.Join([]string{
		fixtures[holdoutPyPI].Positive[0],
		fixtures[holdoutGitHubPAT].Positive[0],
		fixtures[holdoutGrafana].Positive[0],
		fixtures[holdoutConfluent].Positive[0],
		fixtures[holdoutGitHubPAT].Positive[0],
	}, "\n")
	for _, size := range []int{512, 1536} {
		cases = append(cases, optimizerHoldoutWorkload{
			name:  fmt.Sprintf("several-valid-credentials/%dB", size),
			value: multiple + "\n" + optimizerHoldoutFill("status=204 peer=é; ", size-len(multiple)-1),
			ids:   []string{holdoutConfluent, holdoutGitHubPAT, holdoutGitHubPAT, holdoutGrafana, holdoutPyPI},
		})
	}
	flood := strings.Repeat("ghp_? ", 300) + fixtures[holdoutGitHubPAT].Positive[0]
	cases = append(cases, optimizerHoldoutWorkload{
		name: "keyword-flood-then-short-valid/1920B", value: flood + "\n" + strings.Repeat(" ", 1920-len(flood)-1), ids: []string{holdoutGitHubPAT},
	})
	return cases
}

func TestOptimizerHoldoutWorkloads(t *testing.T) {
	catalog := testNativeCatalog(t)
	policy := &CompiledPolicy{catalog: catalog}
	for _, workload := range optimizerHoldoutWorkloads(t) {
		t.Run(workload.name, func(t *testing.T) {
			t.Parallel()
			assertOptimizerHoldout(t, policy, workload.value, workload.ids)
		})
	}
}

// BenchmarkOptimizerHoldoutWorkloads measures uncached full-catalog detection and
// the unfiltered oracle over held-out shapes, not the default production workload.
// Compilation and fixture setup are outside each timed workload.
func BenchmarkOptimizerHoldoutWorkloads(b *testing.B) {
	catalog := testNativeCatalog(b)
	policy := &CompiledPolicy{catalog: catalog}
	for _, workload := range optimizerHoldoutWorkloads(b) {
		b.Run(workload.name, func(b *testing.B) {
			assertOptimizerHoldout(b, policy, workload.value, workload.ids)
			b.Run("optimized", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(workload.value)))
				for range b.N {
					benchmarkVerdict = policy.Detect(workload.value)
				}
			})
			b.Run("unfiltered", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(workload.value)))
				for range b.N {
					benchmarkVerdict = fullScanPolicyVerdict(policy, workload.value)
				}
			})
		})
	}
}
