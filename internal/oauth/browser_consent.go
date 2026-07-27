package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type consentScriptResult struct {
	OK          bool   `json:"ok"`
	Code        string `json:"code"`
	State       string `json:"state"`
	CallbackURL string `json:"callback_url"`
	Error       string `json:"error"`
}

func parseConsentScriptOutput(stdout string) (consentScriptResult, error) {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var last string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") {
			last = line
			break
		}
	}
	if last == "" {
		return consentScriptResult{}, fmt.Errorf("pkce_browser_consent_no_json")
	}
	var res consentScriptResult
	if err := json.Unmarshal([]byte(last), &res); err != nil {
		return consentScriptResult{}, fmt.Errorf("pkce_browser_consent_bad_json: %w", err)
	}
	if !res.OK {
		msg := res.Error
		if msg == "" {
			msg = "ok=false"
		}
		return res, fmt.Errorf("pkce_browser_consent: %s", msg)
	}
	if strings.TrimSpace(res.Code) == "" && res.CallbackURL == "" {
		return res, fmt.Errorf("pkce_browser_consent_no_code")
	}
	if res.CallbackURL == "" && res.Code != "" {
		res.CallbackURL = fmt.Sprintf("%s?code=%s&state=%s", RedirectURI, res.Code, res.State)
	}
	return res, nil
}

func findConsentScript() string {
	if p := strings.TrimSpace(os.Getenv("GROK_OAUTH_CONSENT_SCRIPT")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if abs, e := filepath.Abs(p); e == nil {
				return abs
			}
			return p
		}
	}
	var candidates []string
	// Same share dir as Turnstile mint (common when only GROK_TURNSTILE_SCRIPT is set).
	if ts := strings.TrimSpace(os.Getenv("GROK_TURNSTILE_SCRIPT")); ts != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(ts), "oauth_consent.py"))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "oauth_consent.py"),
			filepath.Join(dir, "oauth_consent.py"),
			filepath.Join(dir, "..", "scripts", "oauth_consent.py"),
			filepath.Join(dir, "..", "Grok-Register", "scripts", "oauth_consent.py"),
			filepath.Join(dir, "..", "share", "grok-reg", "oauth_consent.py"),
			filepath.Join(dir, "..", "local", "share", "grok-reg", "oauth_consent.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "scripts", "oauth_consent.py"),
			filepath.Join(wd, "Grok-Register", "scripts", "oauth_consent.py"),
		)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".local", "share", "grok-reg", "oauth_consent.py"),
			filepath.Join(home, "Grok-Register", "scripts", "oauth_consent.py"),
		)
	}
	// Default install.sh SHARE_DIR / INSTALL_DIR layouts
	candidates = append(candidates,
		"/usr/local/share/grok-reg/oauth_consent.py",
		"/opt/Grok-Register/scripts/oauth_consent.py",
		"/opt/Grok-Reg/scripts/oauth_consent.py",
	)
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if abs, e := filepath.Abs(p); e == nil {
				return abs
			}
			return p
		}
	}
	return ""
}

func findConsentPython() string {
	var names []string
	if p := strings.TrimSpace(os.Getenv("GROK_PYTHON")); p != "" {
		names = append(names, p)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		names = append(names, filepath.Join(home, ".local", "share", "cloakbrowser-venv", "bin", "python"))
	}
	names = append(names,
		"/opt/cloakbrowser-venv/bin/python",
		"python3",
		"python",
	)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		if strings.ContainsAny(name, `/\`) {
			if st, err := os.Stat(name); err == nil && !st.IsDir() {
				return name
			}
		}
	}
	return ""
}

// ConfigureConsent sets PKCE consent strategy. Safe to call once after NewClient.
func (c *Client) ConfigureConsent(mode string, timeoutSec, concurrency int) {
	if c == nil {
		return
	}
	c.consentMode = normalizeConsentMode(mode)
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	c.consentTimeout = time.Duration(timeoutSec) * time.Second
	if concurrency <= 0 {
		concurrency = 1
	}
	c.consentConcurrency = concurrency
}

func (c *Client) getConsentMode() string {
	if c == nil {
		return "auto"
	}
	return normalizeConsentMode(c.consentMode)
}

func (c *Client) acquireConsentSlot(ctx context.Context) error {
	c.consentMu.Lock()
	if c.consentSem == nil {
		n := c.consentConcurrency
		if n <= 0 {
			n = 1
		}
		c.consentSem = make(chan struct{}, n)
	}
	sem := c.consentSem
	c.consentMu.Unlock()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) releaseConsentSlot() {
	c.consentMu.Lock()
	sem := c.consentSem
	c.consentMu.Unlock()
	if sem != nil {
		select {
		case <-sem:
		default:
		}
	}
}

// browserConsent runs scripts/oauth_consent.py and returns a callback Location.
func (c *Client) browserConsent(ctx context.Context, consentURL, cookie, wantState string) (string, error) {
	if c != nil && c.consentRunner != nil {
		to := c.consentTimeout
		if to <= 0 {
			to = 60 * time.Second
		}
		return c.consentRunner(ctx, consentURL, cookie, to)
	}
	if err := c.acquireConsentSlot(ctx); err != nil {
		return "", err
	}
	defer c.releaseConsentSlot()

	script := findConsentScript()
	if script == "" {
		return "", fmt.Errorf("pkce_browser_consent_no_script: set GROK_OAUTH_CONSENT_SCRIPT or keep scripts/oauth_consent.py")
	}
	py := findConsentPython()
	if py == "" {
		return "", fmt.Errorf("pkce_browser_consent_no_python: set GROK_PYTHON or install python3")
	}
	to := c.consentTimeout
	if to <= 0 {
		to = 60 * time.Second
	}
	// Parent budget slightly above script timeout so the script can print JSON
	// before CommandContext sends kill (VPS often needs the extra headroom).
	parentTO := to + 20*time.Second
	ctx, cancel := context.WithTimeout(ctx, parentTO)
	defer cancel()

	mode := "offscreen"
	if m := strings.TrimSpace(os.Getenv("OAUTH_CONSENT_BROWSER_MODE")); m != "" {
		mode = m
	} else if m := strings.TrimSpace(os.Getenv("TURNSTILE_MODE")); m != "" {
		mode = m
	}

	args := []string{
		script,
		"--consent-url", consentURL,
		"--cookie", cookie,
		"--timeout", fmt.Sprintf("%.0f", to.Seconds()),
		"--expected-state", wantState,
		"--mode", mode,
	}
	if c != nil && strings.TrimSpace(c.proxy) != "" {
		args = append(args, "--proxy", strings.TrimSpace(c.proxy))
	}
	if chrome := strings.TrimSpace(os.Getenv("CHROME_PATH")); chrome != "" {
		args = append(args, "--chrome", chrome)
	}

	bin, binArgs := maybeXvfbConsent(py, args, mode)
	cmd := exec.CommandContext(ctx, bin, binArgs...)
	cmd.Env = os.Environ()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	c.logDiag("pkce_browser_consent start bin=%s script=%s mode=%s timeout=%s parent=%s", bin, script, mode, to, parentTO)
	err := cmd.Run()
	out, errText := stdout.String(), strings.TrimSpace(stderr.String())
	if err != nil {
		c.logDiag("pkce_browser_consent fail err=%v stderr=%q stdout=%q", err, trimDiag(errText, 300), trimDiag(out, 200))
		if ctx.Err() != nil {
			return "", fmt.Errorf("pkce_browser_consent_timeout")
		}
		if res, perr := parseConsentScriptOutput(out); perr == nil && !res.OK {
			return "", fmt.Errorf("pkce_browser_consent: %s", res.Error)
		}
		// signal: killed on VPS is often OOM or missing xvfb → headless Chrome hang/kill
		msg := fmt.Sprintf("pkce_browser_consent: %v (%s)", err, trimDiag(errText, 200))
		if strings.Contains(err.Error(), "killed") || strings.Contains(errText, "no DISPLAY") {
			msg += "; VPS tip: apt install -y xvfb && ensure xvfb-run is on PATH (headed offscreen under virtual display)"
		}
		return "", fmt.Errorf("%s", msg)
	}
	res, err := parseConsentScriptOutput(out)
	if err != nil {
		c.logDiag("pkce_browser_consent parse fail stderr=%q", trimDiag(errText, 300))
		return "", err
	}
	loc := res.CallbackURL
	if loc == "" {
		loc = fmt.Sprintf("%s?code=%s&state=%s", RedirectURI, res.Code, res.State)
	}
	c.logDiag("pkce_browser_consent ok callback=%q", trimLoc(loc))
	return loc, nil
}

func trimDiag(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// maybeXvfbConsent wraps python with xvfb-run when offscreen is requested and
// there is no DISPLAY — same approach as Turnstile on headless VPS.
func maybeXvfbConsent(python string, args []string, mode string) (string, []string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "auto" {
		mode = "offscreen"
	}
	if mode == "headless" {
		return python, args
	}
	if strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return python, args
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("GROK_OAUTH_NO_XVFB")))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(os.Getenv("GROK_TURNSTILE_NO_XVFB")))
	}
	if v == "1" || v == "true" || v == "yes" {
		return python, args
	}
	xvfb, err := exec.LookPath("xvfb-run")
	if err != nil {
		return python, args
	}
	out := []string{"-a", python}
	out = append(out, args...)
	return xvfb, out
}
