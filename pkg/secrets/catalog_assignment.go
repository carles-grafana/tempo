package secrets

import "strings"

// catalogLeftBoundary checks the byte before a candidate without consuming it.
// Keeping separators outside the match lets a rejected candidate's right
// boundary also introduce the next candidate. The punctuation is the original
// rule's exclusion set beyond ASCII letters, digits and underscore.
func catalogLeftBoundary(value string, start int, punctuation string) bool {
	return start == 0 || !isASCIIWordByte(value[start-1]) && !strings.ContainsRune(punctuation, rune(value[start-1]))
}

func withCatalogLeftBoundary(punctuation string, next func(string, int, int, string) contextValidation) func(string, int, int, string) contextValidation {
	return func(value string, start, end int, secret string) contextValidation {
		if !catalogLeftBoundary(value, start, punctuation) {
			return contextValidation{}
		}
		if next == nil {
			return contextValidation{accepted: true}
		}
		return next(value, start, end, secret)
	}
}

// validateAuditedAssignmentContext rejects expression continuations when an
// opaque credential is captured from an assignment or header. It does not
// reinterpret standalone prefixed credentials or complete parsed carriers.
func validateAuditedAssignmentContext(value string, matchStart, matchEnd int, secret string) contextValidation {
	relative := strings.LastIndex(value[matchStart:matchEnd], secret)
	if relative < 0 || secret == "" {
		return contextValidation{}
	}
	start := matchStart + relative
	end := start + len(secret)
	if !strings.ContainsAny(value[matchStart:start], "=:") {
		return contextValidation{accepted: true}
	}
	// Some source-specific validators capture the complete quoted literal.
	quotedCapture := len(secret) >= 2 && (secret[0] == '\'' || secret[0] == '"') && secret[len(secret)-1] == secret[0]
	if !quotedCapture && start > matchStart && (value[start-1] == '\'' || value[start-1] == '"') {
		if end >= len(value) || value[end] != value[start-1] {
			return contextValidation{}
		}
		end++
		quotedCapture = true
	}
	for end < len(value) && (value[end] == ' ' || value[end] == '\t') {
		end++
	}
	if end < len(value) && (strings.ContainsRune("([{.$+-*/%?:=!<>|&\\", rune(value[end])) ||
		quotedCapture && strings.ContainsRune("'\"`", rune(value[end]))) {
		return contextValidation{}
	}
	return contextValidation{accepted: true}
}

// withAuditedAssignmentContext preserves a rule's existing structural checks.
func withAuditedAssignmentContext(next func(string, int, int, string) contextValidation) func(string, int, int, string) contextValidation {
	return func(value string, start, end int, secret string) contextValidation {
		if result := validateAuditedAssignmentContext(value, start, end, secret); !result.accepted {
			return result
		}
		return next(value, start, end, secret)
	}
}
