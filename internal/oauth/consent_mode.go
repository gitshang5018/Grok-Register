package oauth

import "strings"

func normalizeConsentMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "browser":
		return "browser"
	case "http":
		return "http"
	case "auto":
		return "auto"
	default:
		return "auto"
	}
}

func shouldTryHTTPConsent(mode string) bool {
	switch normalizeConsentMode(mode) {
	case "http", "auto":
		return true
	default:
		return false
	}
}

func shouldAllowBrowserConsent(mode string) bool {
	switch normalizeConsentMode(mode) {
	case "browser", "auto":
		return true
	default:
		return false
	}
}

// serverActionIndicatesBrowserFallback reports business errors that mean
// further SA body variants will not yield a code.
func serverActionIndicatesBrowserFallback(actionResult string) bool {
	s := strings.ToLower(actionResult)
	if strings.Contains(s, "no redirect received from authorization server") {
		return true
	}
	if strings.Contains(s, `"error":"access denied"`) || strings.Contains(s, `"error": "access denied"`) {
		return true
	}
	// plain Access denied in structured SA result
	if strings.Contains(s, "access denied") && strings.Contains(s, "success") && strings.Contains(s, "false") {
		return true
	}
	return false
}
