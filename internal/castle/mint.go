package castle

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/grok-free-register/grok-reg/internal/clearance"
)

const (
	DefaultPK  = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
	DefaultURL = "https://accounts.x.ai/sign-up?redirect=grok-com"
)

// Minter creates Castle request tokens for signup (browser SDK).
type Minter interface {
	Mint(ctx context.Context, pk string) (string, error)
	Name() string
}

// Optional closer.
type Closer interface {
	Close()
}

// Options for New().
type Options struct {
	Enabled bool
	// PK override; empty = scrape default / DefaultPK
	PK    string
	Proxy string
	Clear *clearance.Manager
	// Mode: offscreen | headless | auto (mirrors turnstile)
	Mode string
	// Timeout per mint
	Timeout time.Duration
}

// PlaywrightBridge shells out to scripts/castle_mint.py.
type PlaywrightBridge struct {
	ScriptPath string
	Python     string
	Proxy      string
	Clear      *clearance.Manager
	Timeout    time.Duration
	Mode       string
	DefaultPK  string

	mu sync.Mutex
}

func NewPlaywrightBridge(opt Options) *PlaywrightBridge {
	to := opt.Timeout
	if to <= 0 {
		to = 70 * time.Second
	}
	mode := strings.ToLower(strings.TrimSpace(opt.Mode))
	if mode == "" || mode == "auto" {
		mode = "offscreen"
	}
	pk := strings.TrimSpace(opt.PK)
	if pk == "" {
		pk = DefaultPK
	}
	return &PlaywrightBridge{
		ScriptPath: findMintScript(),
		Python:     findPython(),
		Proxy:      opt.Proxy,
		Clear:      opt.Clear,
		Timeout:    to,
		Mode:       mode,
		DefaultPK:  pk,
	}
}

func (p *PlaywrightBridge) Name() string { return "castle-browser" }

func (p *PlaywrightBridge) Close() {}

func (p *PlaywrightBridge) Available() bool {
	return p != nil && p.ScriptPath != "" && p.Python != ""
}

func (p *PlaywrightBridge) Mint(ctx context.Context, pk string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ScriptPath == "" {
		return "", fmt.Errorf("castle_mint.py not found; keep scripts/ next to binary or set GROK_CASTLE_SCRIPT")
	}
	if p.Python == "" {
		return "", fmt.Errorf("python not found for Castle mint")
	}
	pk = strings.TrimSpace(pk)
	if pk == "" {
		pk = p.DefaultPK
	}
	if pk == "" {
		pk = DefaultPK
	}
	to := p.Timeout
	if to <= 0 {
		to = 70 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	args := []string{
		p.ScriptPath,
		"--pk", pk,
		"--url", DefaultURL,
		"--timeout", fmt.Sprintf("%.0f", to.Seconds()),
	}
	if p.Proxy != "" {
		args = append(args, "--proxy", p.Proxy)
	}
	if injectClearance() && p.Clear != nil {
		if h := p.Clear.CookieHeader(); h != "" {
			args = append(args, "--cookie", h)
		}
		if ua := p.Clear.UserAgent(); ua != "" {
			args = append(args, "--ua", ua)
		}
	}
	if chrome := strings.TrimSpace(os.Getenv("CHROME_PATH")); chrome != "" {
		args = append(args, "--chrome", chrome)
	}
	mode := strings.ToLower(strings.TrimSpace(p.Mode))
	if mode == "" || mode == "auto" {
		mode = "offscreen"
	}
	args = append(args, "--mode", mode)

	bin, binArgs := maybeXvfb(p.Python, args, mode)
	cmd := exec.CommandContext(ctx, bin, binArgs...)
	cmd.Env = os.Environ()
	setProcessGroup(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("castle mint start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		killProcessGroup(cmd)
		return "", fmt.Errorf("castle mint: %v", ctx.Err())
	case err := <-done:
		out := strings.TrimSpace(stdout.String())
		errText := strings.TrimSpace(stderr.String())
		if err != nil {
			killProcessGroup(cmd)
			if errText == "" {
				errText = err.Error()
			}
			return "", fmt.Errorf("castle mint: %s", truncate(errText, 300))
		}
		if len(out) <= 20 {
			return "", fmt.Errorf("castle mint: empty token %s", truncate(errText, 200))
		}
		if i := strings.IndexByte(out, '\n'); i >= 0 {
			out = strings.TrimSpace(out[:i])
		}
		return out, nil
	}
}

// Disabled never mints (empty token path — will mark accounts).
type Disabled struct{}

func (Disabled) Name() string { return "castle-disabled" }
func (Disabled) Mint(context.Context, string) (string, error) {
	return "", nil
}

// New returns a minter. When disabled, returns Disabled (empty tokens).
func New(opt Options) Minter {
	if !opt.Enabled {
		return Disabled{}
	}
	pw := NewPlaywrightBridge(opt)
	if !pw.Available() {
		// Still return bridge so Mint surfaces a clear error instead of silent empty.
		return pw
	}
	return pw
}

// DetectedPython / DetectedScript for startup logs.
func DetectedPython() string { return findPython() }
func DetectedScript() string { return findMintScript() }

func maybeXvfb(python string, args []string, mode string) (string, []string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" || mode == "auto" {
		mode = "offscreen"
	}
	if mode == "headless" {
		return python, args
	}
	if runtime.GOOS == "windows" {
		return python, args
	}
	if strings.TrimSpace(os.Getenv("DISPLAY")) != "" || strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) != "" {
		return python, args
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("GROK_CASTLE_NO_XVFB")))
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

func injectClearance() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("GROK_CASTLE_INJECT_CLEARANCE")))
	if v == "" {
		v = strings.TrimSpace(strings.ToLower(os.Getenv("GROK_TURNSTILE_INJECT_CLEARANCE")))
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func findPython() string {
	for _, name := range []string{
		os.Getenv("GROK_PYTHON"),
		"/opt/cloakbrowser-venv/bin/python",
		"/opt/Grok-Reg/.venv/bin/python",
		"python3",
		"python",
	} {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		if strings.Contains(name, string(os.PathSeparator)) || strings.Contains(name, "/") {
			if st, err := os.Stat(name); err == nil && !st.IsDir() {
				return name
			}
		}
	}
	// Windows venv next to cwd
	if wd, err := os.Getwd(); err == nil {
		for _, rel := range []string{
			filepath.Join(wd, ".venv", "Scripts", "python.exe"),
			filepath.Join(wd, ".venv", "bin", "python"),
		} {
			if st, err := os.Stat(rel); err == nil && !st.IsDir() {
				return rel
			}
		}
	}
	return ""
}

func findMintScript() string {
	if p := strings.TrimSpace(os.Getenv("GROK_CASTLE_SCRIPT")); p != "" {
		if fileExists(p) {
			return p
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "castle_mint.py"),
			filepath.Join(dir, "castle_mint.py"),
			filepath.Join(dir, "..", "scripts", "castle_mint.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "scripts", "castle_mint.py"),
		)
	}
	candidates = append(candidates,
		"/opt/Grok-Register/scripts/castle_mint.py",
		"/opt/Grok-Reg/scripts/castle_mint.py",
	)
	for _, c := range candidates {
		if fileExists(c) {
			abs, err := filepath.Abs(c)
			if err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
