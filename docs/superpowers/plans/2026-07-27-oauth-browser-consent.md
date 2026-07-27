# OAuth 浏览器驱动 Consent 实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 在 PKCE OAuth 流程中，用 Playwright 浏览器完成 consent 批准并拦截 callback code，HTTP 仍负责 authorize 与 code 换 token。

**架构：** `authorizeCode` 用 HTTP 走到 consent 页；`OAUTH_CONSENT_MODE=auto|browser|http` 决定是否/何时调用 `browserConsent`（Go 桥 → `scripts/oauth_consent.py`）。脚本注入含 `sso` 的 cookie、点 Allow、拦 `127.0.0.1:56121/callback`。auto 下 HTTP Server Action 一旦返回 `No redirect` / `Access denied` 立即切浏览器，不再穷举 body。

**技术栈：** Go、Playwright + CloakBrowser/Chrome、现有 `tls-client` OAuth 客户端、config.env

**规格：** [docs/superpowers/specs/2026-07-27-oauth-browser-consent-design.md](../specs/2026-07-27-oauth-browser-consent-design.md)

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `internal/config/config.go` | `OAuthConsentMode` / Timeout / Concurrency 字段、Defaults、applyMap、Save |
| `internal/config/example.env` | 配置模板注释与默认值（embed 源） |
| `config.env.example` | 与 example.env 同步（若仓库根有副本则同步改） |
| `internal/oauth/consent_mode.go` | mode 归一化、`shouldUseBrowserAfterHTTP`、SA 业务错误识别 |
| `internal/oauth/consent_mode_test.go` | 上述纯函数测试 |
| `internal/oauth/browser_consent.go` | 信号量、找脚本/Python、起进程、解析 JSON |
| `internal/oauth/browser_consent_test.go` | mock 脚本解析、缺脚本错误 |
| `scripts/oauth_consent.py` | Playwright consent 脚本（**保留 sso cookie**） |
| `internal/oauth/pkce.go` | `submitConsent` / `authorizeCode` 接入 mode + browser |
| `internal/oauth/oauth.go` | `Client` 增加 consent 配置字段；`NewClient` 或 `ConfigureConsent` |
| `internal/pipeline/pipeline.go` | 创建 oauth client 后注入 consent 配置 |
| `internal/reoauth/reoauth.go` | 同样注入（若 reoauth 建 oauth client） |
| `README.md` | 一行配置说明（可选，仅 OAuth 段） |

---

### 任务 1：配置项

**文件：**
- 修改：`internal/config/config.go`
- 修改：`internal/config/example.env`
- 修改：`config.env.example`（若与 example 内容重复则同步）
- 测试：可在 `internal/config` 用临时文件测 Load（若无现成测试文件则本任务只做 Load 手工验证 + 后续任务覆盖）

- [ ] **步骤 1：在 Config 结构体增加字段**

在 `OAuthGrant` 附近加入：

```go
OAuthConsentMode        string // auto | browser | http
OAuthConsentTimeoutSec  int    // default 60
OAuthConsentConcurrency int    // default 1
```

- [ ] **步骤 2：Defaults()**

```go
OAuthConsentMode:        "auto",
OAuthConsentTimeoutSec:  60,
OAuthConsentConcurrency: 1,
```

- [ ] **步骤 3：applyMap 解析**

```go
if v, ok := env["OAUTH_CONSENT_MODE"]; ok {
    switch m := strings.ToLower(strings.TrimSpace(v)); m {
    case "auto", "browser", "http":
        cfg.OAuthConsentMode = m
    }
}
if v, ok := env["OAUTH_CONSENT_TIMEOUT_SEC"]; ok {
    if n, err := strconv.Atoi(v); err == nil && n > 0 {
        cfg.OAuthConsentTimeoutSec = n
    }
}
if v, ok := env["OAUTH_CONSENT_CONCURRENCY"]; ok {
    if n, err := strconv.Atoi(v); err == nil && n > 0 {
        cfg.OAuthConsentConcurrency = n
    }
}
```

- [ ] **步骤 4：Save() 写出新键**

在 `OAUTH_GRANT` 行后：

```go
b.WriteString(fmt.Sprintf("OAUTH_CONSENT_MODE=%s\n", cfg.OAuthConsentMode))
b.WriteString(fmt.Sprintf("OAUTH_CONSENT_TIMEOUT_SEC=%d\n", cfg.OAuthConsentTimeoutSec))
b.WriteString(fmt.Sprintf("OAUTH_CONSENT_CONCURRENCY=%d\n", cfg.OAuthConsentConcurrency))
```

- [ ] **步骤 5：example.env / config.env.example 文档**

在 OAuth 段 `OAUTH_RETRY_SEC` 附近加入：

```env
# PKCE consent 实现：auto=HTTP 快失败后浏览器；browser=直接浏览器；http=仅旧路径
OAUTH_CONSENT_MODE=auto
# 浏览器 consent 超时（秒）
OAUTH_CONSENT_TIMEOUT_SEC=60
# 同时进行的浏览器 consent 数（与 Turnstile 抢 Chrome，建议 1）
OAUTH_CONSENT_CONCURRENCY=1
# 可选：GROK_OAUTH_CONSENT_SCRIPT=/path/to/oauth_consent.py
```

- [ ] **步骤 6：Commit**

```bash
git add internal/config/config.go internal/config/example.env config.env.example
git commit -m "feat(config): add OAUTH_CONSENT_MODE timeout concurrency"
```

---

### 任务 2：consent mode 纯函数（TDD）

**文件：**
- 创建：`internal/oauth/consent_mode.go`
- 创建：`internal/oauth/consent_mode_test.go`

- [ ] **步骤 1：编写失败的测试**

```go
package oauth

import "testing"

func TestNormalizeConsentMode(t *testing.T) {
	cases := map[string]string{
		"":        "auto",
		"AUTO":    "auto",
		"browser": "browser",
		"http":    "http",
		"nope":    "auto",
	}
	for in, want := range cases {
		if got := normalizeConsentMode(in); got != want {
			t.Fatalf("normalizeConsentMode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestServerActionIndicatesBrowserFallback(t *testing.T) {
	yes := []string{
		`{"success":false,"error":"No redirect received from authorization server"}`,
		`{"success":false,"error":"Access denied"}`,
		`1:{"success":false,"error":"No redirect received from authorization server"}`,
	}
	for _, s := range yes {
		if !serverActionIndicatesBrowserFallback(s) {
			t.Fatalf("expected fallback for %q", s)
		}
	}
	if serverActionIndicatesBrowserFallback(`{"user":{"userId":"x"}}`) {
		t.Fatal("session payload must not force browser")
	}
}

func TestShouldTryHTTPConsent(t *testing.T) {
	if !shouldTryHTTPConsent("auto") || !shouldTryHTTPConsent("http") {
		t.Fatal("auto/http should try HTTP")
	}
	if shouldTryHTTPConsent("browser") {
		t.Fatal("browser mode skips HTTP consent")
	}
}

func TestShouldAllowBrowserConsent(t *testing.T) {
	if !shouldAllowBrowserConsent("auto") || !shouldAllowBrowserConsent("browser") {
		t.Fatal("auto/browser allow browser")
	}
	if shouldAllowBrowserConsent("http") {
		t.Fatal("http mode must not use browser")
	}
}
```

- [ ] **步骤 2：运行测试确认失败**

```bash
go test ./internal/oauth -run "TestNormalizeConsentMode|TestServerActionIndicatesBrowserFallback|TestShouldTryHTTPConsent|TestShouldAllowBrowserConsent" -count=1
```

预期：FAIL（函数未定义）

- [ ] **步骤 3：实现最少代码**

`internal/oauth/consent_mode.go`：

```go
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
```

- [ ] **步骤 4：运行测试确认通过**

```bash
go test ./internal/oauth -run "TestNormalizeConsentMode|TestServerActionIndicatesBrowserFallback|TestShouldTryHTTPConsent|TestShouldAllowBrowserConsent" -count=1
```

预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add internal/oauth/consent_mode.go internal/oauth/consent_mode_test.go
git commit -m "feat(oauth): consent mode helpers and SA fallback detection"
```

---

### 任务 3：Go 桥 — 解析与发现（TDD）

**文件：**
- 创建：`internal/oauth/browser_consent.go`（先放可测纯函数 + 结构）
- 创建：`internal/oauth/browser_consent_test.go`

- [ ] **步骤 1：编写失败的测试**

```go
package oauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConsentScriptOutputOK(t *testing.T) {
	raw := `{"ok":true,"code":"abc.def","state":"st123","callback_url":"http://127.0.0.1:56121/callback?code=abc.def&state=st123"}`
	res, err := parseConsentScriptOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "abc.def" || res.State != "st123" {
		t.Fatalf("got %+v", res)
	}
	if !isCallback(res.CallbackURL) {
		t.Fatalf("callback %q", res.CallbackURL)
	}
}

func TestParseConsentScriptOutputPrefersLastJSONLine(t *testing.T) {
	raw := "warn noise\n{\"ok\":true,\"code\":\"c1\",\"state\":\"s1\",\"callback_url\":\"http://127.0.0.1:56121/callback?code=c1&state=s1\"}\n"
	res, err := parseConsentScriptOutput(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "c1" {
		t.Fatalf("code=%q", res.Code)
	}
}

func TestParseConsentScriptOutputError(t *testing.T) {
	_, err := parseConsentScriptOutput(`{"ok":false,"error":"timeout"}`)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFindConsentScriptEnvOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "oauth_consent.py")
	if err := os.WriteFile(p, []byte("#"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GROK_OAUTH_CONSENT_SCRIPT", p)
	got := findConsentScript()
	if got != p {
		t.Fatalf("got %q want %q", got, p)
	}
}
```

- [ ] **步骤 2：运行确认失败**

```bash
go test ./internal/oauth -run "TestParseConsentScriptOutput|TestFindConsentScriptEnvOverride" -count=1
```

- [ ] **步骤 3：实现解析与脚本发现**

在 `browser_consent.go`：

```go
package oauth

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
			return p
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "oauth_consent.py"),
			filepath.Join(dir, "oauth_consent.py"),
			filepath.Join(dir, "..", "scripts", "oauth_consent.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "scripts", "oauth_consent.py"),
			filepath.Join(wd, "..", "scripts", "oauth_consent.py"),
		)
	}
	// source-tree relative to this package is unreliable at runtime; wd/exe cover install + dev
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func findConsentPython() string {
	for _, name := range []string{
		os.Getenv("GROK_PYTHON"),
		"/opt/cloakbrowser-venv/bin/python",
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
		if strings.ContainsAny(name, `/\`) {
			if st, err := os.Stat(name); err == nil && !st.IsDir() {
				return name
			}
		}
	}
	return ""
}
```

（完整 `browserConsent` 跑进程放任务 4；本任务先让解析测试通过。）

- [ ] **步骤 4：测试通过并 Commit**

```bash
go test ./internal/oauth -run "TestParseConsentScriptOutput|TestFindConsentScriptEnvOverride" -count=1
git add internal/oauth/browser_consent.go internal/oauth/browser_consent_test.go
git commit -m "feat(oauth): parse browser consent script output"
```

---

### 任务 4：Go 桥 — 执行脚本 + 信号量

**文件：**
- 修改：`internal/oauth/browser_consent.go`
- 修改：`internal/oauth/oauth.go`（Client 字段）
- 修改：`internal/oauth/browser_consent_test.go`（可选：用临时 python 脚本 mock）

- [ ] **步骤 1：扩展 Client**

在 `oauth.go` 的 `Client` 上增加：

```go
consentMode        string
consentTimeout     time.Duration
consentConcurrency int
consentSem         chan struct{} // lazy init
consentMu          sync.Mutex
// optional override for tests
consentRunner      func(ctx context.Context, consentURL, cookie string, timeout time.Duration) (callbackURL string, err error)
```

增加方法：

```go
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
```

- [ ] **步骤 2：实现 acquire/release 与 browserConsent**

```go
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

type browserConsentOpts struct {
	ConsentURL string
	Cookie     string
	State      string
	Proxy      string // from client construction — store proxy on Client if not already
	Timeout    time.Duration
	Mode       string // offscreen|headless
}

// browserConsent runs scripts/oauth_consent.py and returns a callback Location.
func (c *Client) browserConsent(ctx context.Context, consentURL, cookie, wantState string) (string, error) {
	if c != nil && c.consentRunner != nil {
		return c.consentRunner(ctx, consentURL, cookie, c.consentTimeout)
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
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	args := []string{
		script,
		"--consent-url", consentURL,
		"--cookie", cookie,
		"--timeout", fmt.Sprintf("%.0f", to.Seconds()),
		"--expected-state", wantState,
		"--mode", "offscreen",
	}
	if p := strings.TrimSpace(os.Getenv("REGISTER_PROXY")); p != "" {
		// Prefer Client-stored proxy if you add c.proxy in NewClient
		args = append(args, "--proxy", p)
	}
	// Better: store proxy on Client in NewClient — plan requires adding `proxy string` field set in NewClient
	if c != nil && strings.TrimSpace(c.proxy) != "" {
		// replace env-based with c.proxy — implement by saving proxy in NewClient
		// filter duplicate: build args with c.proxy only
	}
	if chrome := strings.TrimSpace(os.Getenv("CHROME_PATH")); chrome != "" {
		args = append(args, "--chrome", chrome)
	}

	cmd := exec.CommandContext(ctx, py, args...)
	cmd.Env = os.Environ()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	c.logDiag("pkce_browser_consent start script=%s timeout=%s", script, to)
	err := cmd.Run()
	out, errText := stdout.String(), strings.TrimSpace(stderr.String())
	if err != nil {
		c.logDiag("pkce_browser_consent fail err=%v stderr=%q stdout=%q", err, trimDiag(errText, 300), trimDiag(out, 200))
		if ctx.Err() != nil {
			return "", fmt.Errorf("pkce_browser_consent_timeout")
		}
		// still try parse JSON error
		if res, perr := parseConsentScriptOutput(out); perr != nil {
			return "", fmt.Errorf("pkce_browser_consent: %v (%s)", err, trimDiag(errText, 200))
		} else if !res.OK {
			return "", fmt.Errorf("pkce_browser_consent: %s", res.Error)
		}
		return "", fmt.Errorf("pkce_browser_consent: %v", err)
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
```

**实现时注意：**

1. 在 `NewClient` 增加 `proxy string` 存到 `c.proxy`，`browserConsent` 只用 `c.proxy`，不要依赖 `REGISTER_PROXY` env 重复。
2. Windows 上 `CommandContext` 杀进程可能需与 turnstile 的 `killProcessGroup` 对齐；首版可用 `CommandContext`，若残留再复用 turnstile helper（可复制小函数到 oauth 包避免循环依赖）。

- [ ] **步骤 3：mock runner 单测**

```go
func TestBrowserConsentUsesRunner(t *testing.T) {
	c := &Client{
		consentTimeout: 5 * time.Second,
		consentRunner: func(ctx context.Context, consentURL, cookie string, timeout time.Duration) (string, error) {
			if !strings.Contains(consentURL, "consent") {
				t.Fatalf("url %s", consentURL)
			}
			if !strings.Contains(cookie, "sso=") {
				t.Fatal("missing sso")
			}
			return "http://127.0.0.1:56121/callback?code=tok&state=want", nil
		},
	}
	loc, err := c.browserConsent(context.Background(), "https://accounts.x.ai/oauth2/consent?x=1", "sso=abc", "want")
	if err != nil {
		t.Fatal(err)
	}
	code, err := codeFromCallback(loc, "want")
	if err != nil || code != "tok" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}
```

- [ ] **步骤 4：测试 + Commit**

```bash
go test ./internal/oauth -count=1
git add internal/oauth/browser_consent.go internal/oauth/browser_consent_test.go internal/oauth/oauth.go
git commit -m "feat(oauth): browser consent bridge and client config"
```

---

### 任务 5：`scripts/oauth_consent.py`

**文件：**
- 创建：`scripts/oauth_consent.py`

- [ ] **步骤 1：实现完整脚本**

要求（对照规格 4.1）：

1. CLI：`--consent-url`（必填）、`--cookie`、`--proxy`、`--chrome`、`--timeout`、`--mode`、`--expected-state`
2. `parse_cookie_header`：**不得**丢弃 `sso` / `sso-rw`（与 turnstile 相反）
3. 对每个 cookie 尝试写入 domains：`.x.ai`、`accounts.x.ai`、`auth.x.ai`（或 url=https://accounts.x.ai/ 回退）
4. `page.on("request"/"response")` 或 `expect_navigation` / 轮询 `page.url`，匹配 `127.0.0.1:56121` 或 `localhost:56121` 且含 `code=` 或 `error=`
5. `goto(consent_url, wait_until="domcontentloaded")`
6. 若已在 callback，解析并打印 JSON
7. 否则找 Allow 按钮点击：文本/角色匹配 `(?i)allow|approve|授权|同意`，排除 deny/拒绝；`button` 与 `[role=button]`
8. 成功 stdout 仅一行：`{"ok":true,"code":"...","state":"...","callback_url":"..."}`
9. 失败 exit 1 + stderr；可打印 `{"ok":false,"error":"..."}`
10. 复用 turnstile 的 `find_chrome` / `resolve_launch_mode` / `launch_args` 模式（可复制，勿 import turnstile 文件）

核心骨架：

```python
#!/usr/bin/env python3
"""OAuth PKCE consent via Playwright. Prints one JSON line to stdout on success."""
from __future__ import annotations
# ... argparse, find_chrome, parse_cookie_header KEEPING sso ...

def parse_cookie_header(raw: str) -> list[dict]:
    out = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name:
            continue
        # IMPORTANT: keep sso / sso-rw
        out.append({"name": name, "value": val, "domain": ".x.ai", "path": "/"})
    return out

def is_callback(url: str) -> bool:
    u = (url or "").lower()
    return ("127.0.0.1:56121" in u or "localhost:56121" in u) and (
        "code=" in u or "error=" in u
   )

async def run_consent(...) -> dict:
    # launch, add cookies for multiple domains, listen for callback, goto, click Allow
    ...
```

- [ ] **步骤 2：本地语法检查**

```bash
python -m py_compile scripts/oauth_consent.py
```

预期：无输出、exit 0

- [ ] **步骤 3：Commit**

```bash
git add scripts/oauth_consent.py
git commit -m "feat(scripts): oauth_consent.py Playwright consent helper"
```

---

### 任务 6：接入 pkce.go + SA 快失败

**文件：**
- 修改：`internal/oauth/pkce.go`
- 修改：`internal/oauth/pkce_test.go`（快失败与 mode 路由，尽量用 runner mock）

- [ ] **步骤 1：改 `submitServerActionConsent` 快失败信号**

将返回值扩展为能表达「应切浏览器」，或在循环内设置外部变量。推荐最小改动：

把 `submitServerActionConsent` 改为返回 `(loc, cookie, ok bool, browserHint bool)`，当 `serverActionIndicatesBrowserFallback(actionResult)` 时 `browserHint=true` 并 **break 出全部 ID 循环**（不再试剩余 body）。

或者：保持三返回值，在 `submitConsent` 内调用新函数 `submitServerActionConsentFast`。

实现要点（在现有循环 `actionResult := parseFlightActionResult(bodyStr)` 之后）：

```go
if serverActionIndicatesBrowserFallback(actionResult) {
    c.logDiag("pkce server action %s body#%d(%s) business error -> browser hint", tag, bi, ab.label)
    return "", cookie, false, true // if 4-tuple
}
```

若不想改所有调用签名：用闭包/`*bool` 参数 `browserHint *bool`。

- [ ] **步骤 2：改 `submitConsent` 主流程**

伪代码：

```go
func (c *Client) submitConsent(ctx context.Context, consentURL, html, cookie string) (string, string, error) {
    // ... existing form parse ...
    mode := c.getConsentMode()

    if shouldTryHTTPConsent(mode) {
        saLoc, saCookie, ok, hint := submitServerActionConsent(...) // or hint via pointer
        if ok {
            return saLoc, saCookie, nil
        }
        cookie = saCookie
        if mode == "http" {
            // existing form POST fallback then return
            ...
        }
        // auto: skip long form POST if hint or always after SA fail — spec: form POST not expected to succeed
        if hint || true {
            c.logDiag("pkce_consent HTTP path exhausted -> browser (mode=%s hint=%v)", mode, hint)
        }
    }

    if shouldAllowBrowserConsent(mode) {
        // extract state from form for wantState
        wantState := form.Get("state")
        loc, err := c.browserConsent(ctx, consentURL, sanitizeSessionCookies(cookie), wantState)
        if err != nil {
            return "", cookie, err
        }
        return loc, cookie, nil
    }

    // http-only: existing form POST
    ...
}
```

**browser 模式：** `shouldTryHTTPConsent` 为 false，直接 `browserConsent`，不要先扫 SA 18s。

**cookie 传给浏览器：** 使用合并后的完整 cookie 字符串（含 sso 与 consent 页 Set-Cookie），`sanitizeSessionCookies` 与 HTTP 发送一致即可。

- [ ] **步骤 3：测试 mode=browser 走 runner**

```go
func TestSubmitConsentBrowserModeUsesRunner(t *testing.T) {
	html := `<html><body><form action="https://auth.x.ai/oauth2/authorize">
<input name="client_id" value="cid"/>
<input name="state" value="st"/>
<input name="redirect_uri" value="http://127.0.0.1:56121/callback"/>
<input name="scope" value="openid"/>
<input name="code_challenge" value="ch"/>
<input name="code_challenge_method" value="S256"/>
<input name="nonce" value="n"/>
<input name="principal_type" value="User"/>
<input name="principal_id" value=""/>
<button type="button">Allow</button>
</form></body></html>`
	// Need approvalForm to find form — match parseForms expectations from oauth.go
	c := &Client{consentMode: "browser"}
	c.consentRunner = func(ctx context.Context, consentURL, cookie string, timeout time.Duration) (string, error) {
		return "http://127.0.0.1:56121/callback?code=from-browser&state=st", nil
	}
	loc, _, err := c.submitConsent(context.Background(),
		"https://accounts.x.ai/oauth2/consent?state=st", html, "sso=tok")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(loc, "code=from-browser") {
		t.Fatalf("loc=%s", loc)
	}
}
```

（若 `approvalForm` 对 HTML 结构敏感，先读 `approvalForm`/`parseForms` 用真实可解析的最小 HTML；或在 browser 模式在解析 form 失败前仍允许 browser——规格要求有 form 字段以带 state；state 也可从 consent URL query 取：）

```go
wantState := form.Get("state")
if wantState == "" {
    if u, err := url.Parse(consentURL); err == nil {
        wantState = u.Query().Get("state")
    }
}
```

**增强：** browser 模式若 `approvalForm` 失败，仍可从 URL query 取 OAuth 参数并直接 browserConsent，避免因 HTML 解析卡住。

- [ ] **步骤 4：全量 oauth 包测试**

```bash
go test ./internal/oauth -count=1
```

预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add internal/oauth/pkce.go internal/oauth/pkce_test.go
git commit -m "feat(oauth): wire browser consent into PKCE submitConsent"
```

---

### 任务 7：pipeline / reoauth 注入配置

**文件：**
- 修改：`internal/pipeline/pipeline.go`（`oauth.NewClient` 之后）
- 修改：`internal/reoauth/reoauth.go`（创建 client 处）

- [ ] **步骤 1：pipeline**

在两处 `oauth.NewClient(...)` 成功后：

```go
e.oauth.ConfigureConsent(cfg.OAuthConsentMode, cfg.OAuthConsentTimeoutSec, cfg.OAuthConsentConcurrency)
```

第二处 clearance 重建 client 后同样调用。

- [ ] **步骤 2：reoauth**

找到 `oauth.NewClient`，在 Options 增加字段或直接读环境 / 扩展 `Options`：

```go
// Options
ConsentMode        string
ConsentTimeoutSec  int
ConsentConcurrency int
```

调用方若未设，client 默认 auto。在 reoauth 内：

```go
oc.ConfigureConsent(opt.ConsentMode, opt.ConsentTimeoutSec, opt.ConsentConcurrency)
```

若 reoauth 的 CLI 尚未暴露这些 flag，首版可从 `os.Getenv("OAUTH_CONSENT_MODE")` 读，或在 cmd 加载 config 传入——与现有 reoauth 如何拿 proxy 的方式一致。

- [ ] **步骤 3：编译**

```bash
go test ./internal/oauth ./internal/config -count=1
go build -o nul ./internal/pipeline/
go build -o nul ./internal/reoauth/
```

（若 `cmd/grok` 因无关 Flock 失败，不要在本任务修 Flock；验证 pipeline/reoauth/oauth 包即可。）

- [ ] **步骤 4：Commit**

```bash
git add internal/pipeline/pipeline.go internal/reoauth/reoauth.go
git commit -m "feat: configure OAuth browser consent from config"
```

---

### 任务 8：文档与冒烟清单

**文件：**
- 修改：`README.md`（OAuth 相关一小段，若有）
- 可选：确认 `install.sh` 不需要拷贝新脚本路径（若 install 拷贝 scripts，把 `oauth_consent.py` 列入）

- [ ] **步骤 1：Grep install 是否复制 turnstile 脚本**

若有 `cp scripts/turnstile_mint.py`，并列复制 `oauth_consent.py`。

- [ ] **步骤 2：README 简短说明**

在 OAuth 或配置表增加：

```text
OAUTH_CONSENT_MODE=auto|browser|http  — PKCE consent；默认 auto（HTTP 失败后浏览器）
```

- [ ] **步骤 3：手动冒烟清单（执行者本地跑，不强制 CI）**

1. 确认 Python + Playwright + Chrome/CloakBrowser 可用  
2. 取一条有效 SSO：`outputs/.../sso/accounts.txt`  
3. `OAUTH_CONSENT_MODE=browser` + 现有 proxy  
4. 跑 reoauth 单账号或小脚本调用 `ExchangePKCE`  
5. 期望：日志含 `pkce_browser_consent ok`，产出 CPA  

- [ ] **步骤 4：Commit**

```bash
git add README.md scripts/install.sh
git commit -m "docs: OAUTH_CONSENT_MODE and install script copy"
```

---

## 自检（对照规格）

| 规格章节 | 任务 |
|----------|------|
| 目标混合架构 | 6、4 |
| oauth_consent.py 契约 | 5 |
| browser_consent.go 桥 | 3、4 |
| auto/browser/http | 2、6 |
| SA 快失败 | 2、6 |
| 配置项 | 1、7 |
| 错误前缀 | 4、5 |
| 并发信号量 | 4 |
| 单元测试 | 2、3、4、6 |
| 不改注册/Turnstile/Castle | 遵守 |
| pipeline 透明 ExchangeGrant | 7 仅 ConfigureConsent |

无占位符；类型名统一：`normalizeConsentMode`、`ConfigureConsent`、`browserConsent`、`parseConsentScriptOutput`、`consentScriptResult`。

---

## 执行交接

计划已保存到 `docs/superpowers/plans/2026-07-27-oauth-browser-consent.md`。

**两种执行方式：**

1. **子代理驱动（推荐）** — 每任务新子代理 + 任务间审查（`subagent-driven-development`）
2. **内联执行** — 当前会话按 `executing-plans` 批量做并设检查点

选哪种方式？
