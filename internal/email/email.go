package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grok-free-register/grok-reg/internal/config"
)

var bannedDomains = map[string]struct{}{
	"duckmail.sbs":     {},
	"web-library.net":  {},
	"mail.tm":          {},
	"mail.gw":          {},
	"baldur.edu.kg":    {},
}

var codeRe = []*regexp.Regexp{
	// 1. Highest priority: code/verification context + any separator (non-greedy) + 6-char code
	//    e.g. "Your verification code is TFIHSY" or "code: 0BJOQ4"
	regexp.MustCompile(`(?i)(?:code|verification|verify|grok|confirm|confirmation).{0,60}?\b([A-Z0-9]{3}-?[A-Z0-9]{3})\b`),
	// 2. HTML tag enclosed code
	regexp.MustCompile(`>([A-Z0-9]{3}-[A-Z0-9]{3})<`),
	regexp.MustCompile(`>([A-Z0-9]{6})<`),
	// 3. Exact 3-3 format with dash
	regexp.MustCompile(`\b([A-Z0-9]{3}-[A-Z0-9]{3})\b`),
	// 4. Exact 6-digit number
	regexp.MustCompile(`\b([0-9]{6})\b`),
	// 5. Standalone 6-char uppercase alphanumeric (fallback for TFIHSY/UJVOQO/0BJOQ4 etc.)
	regexp.MustCompile(`\b([A-Z0-9]{6})\b`),
}

type Handle struct {
	Kind     string // lol | mt | custom | testmail
	Email    string
	Password string
	Token    string
	Base     string // mail.tm base
	// testmail.app
	Tag       string
	Timestamp int64 // ms — only accept mails after Create()
}

type Provider struct {
	cfg Config
	mu  sync.Mutex
	// lol rate limit
	lolNextOK time.Time
}

type Config struct {
	Mode          config.EmailMode
	Domain        string
	API           string
	Password      string
	LOLRetries    int
	LOLIntervalMS int
	// testmail.app
	TestmailAPIKey    string
	TestmailNamespace string
	TestmailDomain    string
	HTTPClient        *http.Client
}

func New(cfg Config) *Provider {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.LOLRetries <= 0 {
		cfg.LOLRetries = 8
	}
	if cfg.LOLIntervalMS <= 0 {
		cfg.LOLIntervalMS = 400
	}
	return &Provider{cfg: cfg}
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (p *Provider) Create() (Handle, error) {
	password := randStr(15)
	switch p.cfg.Mode {
	case config.EmailCustom, config.EmailCFTemp:
		return p.cfTempCreate(password)
	case config.EmailTestmail:
		h, err := p.testmailCreate()
		if err != nil {
			return Handle{}, err
		}
		h.Password = password
		return h, nil
	default:
		// tempmail.lol then mail.tm family
		var last error
		for i := 0; i < p.cfg.LOLRetries; i++ {
			h, err := p.lolCreate()
			if err == nil {
				h.Password = password
				return h, nil
			}
			last = err
			time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
		}
		for _, base := range []string{"https://api.mail.tm", "https://api.mail.gw", "https://api.duckmail.sbs"} {
			h, err := p.mailtmCreate(base, password)
			if err == nil {
				return h, nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("所有临时邮箱 provider 均不可用")
		}
		return Handle{}, last
	}
}

// testmailCreate builds {namespace}.{tag}@{domain} — tags need no pre-registration.
// Docs: https://testmail.app/docs  JSON API livequery + tag filter.
func (p *Provider) testmailCreate() (Handle, error) {
	key := strings.TrimSpace(p.cfg.TestmailAPIKey)
	ns := strings.TrimSpace(p.cfg.TestmailNamespace)
	if key == "" || ns == "" {
		return Handle{}, fmt.Errorf("testmail: set TESTMAIL_API_KEY and TESTMAIL_NAMESPACE")
	}
	dom := strings.TrimSpace(p.cfg.TestmailDomain)
	if dom == "" {
		dom = "inbox.testmail.app"
	}
	tag := "g" + randStr(12)
	email := fmt.Sprintf("%s.%s@%s", ns, tag, dom)
	return Handle{
		Kind:      "testmail",
		Email:     email,
		Tag:       tag,
		Timestamp: time.Now().UnixMilli(),
	}, nil
}

func (p *Provider) lolCreate() (Handle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if now.Before(p.lolNextOK) {
		time.Sleep(time.Until(p.lolNextOK))
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.tempmail.lol/v2/inbox/create", nil)
	if err != nil {
		return Handle{}, err
	}
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return Handle{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var data map[string]any
	_ = json.Unmarshal(body, &data)
	if resp.StatusCode == 429 || strings.Contains(strings.ToLower(string(body)), "rate limit") {
		cool := 5 * time.Second
		p.lolNextOK = time.Now().Add(cool)
		return Handle{}, fmt.Errorf("lol rate limited status=%d", resp.StatusCode)
	}
	addr, _ := data["address"].(string)
	tok, _ := data["token"].(string)
	if addr == "" || tok == "" {
		p.lolNextOK = time.Now().Add(800 * time.Millisecond)
		return Handle{}, fmt.Errorf("lol create failed status=%d body=%s", resp.StatusCode, truncate(string(body), 80))
	}
	if domainBanned(addr) {
		p.lolNextOK = time.Now().Add(time.Duration(p.cfg.LOLIntervalMS) * time.Millisecond)
		return Handle{}, fmt.Errorf("lol domain banned: %s", domainOf(addr))
	}
	p.lolNextOK = time.Now().Add(time.Duration(p.cfg.LOLIntervalMS) * time.Millisecond)
	return Handle{Kind: "lol", Email: addr, Token: tok}, nil
}

func (p *Provider) mailtmCreate(base, password string) (Handle, error) {
	resp, err := p.cfg.HTTPClient.Get(base + "/domains")
	if err != nil {
		return Handle{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return Handle{}, err
	}
	members, _ := doc["hydra:member"].([]any)
	var doms []string
	for _, m := range members {
		mm, _ := m.(map[string]any)
		if mm == nil {
			continue
		}
		d, _ := mm["domain"].(string)
		if d == "" || domainBanned(d) {
			continue
		}
		active, _ := mm["isActive"].(bool)
		priv, _ := mm["isPrivate"].(bool)
		if mm["isActive"] != nil && !active {
			continue
		}
		if priv {
			continue
		}
		doms = append(doms, d)
	}
	if len(doms) == 0 {
		return Handle{}, fmt.Errorf("no domain from %s", base)
	}
	rand.Shuffle(len(doms), func(i, j int) { doms[i], doms[j] = doms[j], doms[i] })
	var last error
	for _, dom := range doms {
		if len(doms) > 6 {
			// try at most 6
		}
		email := fmt.Sprintf("oc%s@%s", randStr(10), dom)
		payload := map[string]string{"address": email, "password": password}
		raw, _ := json.Marshal(payload)
		r, err := p.cfg.HTTPClient.Post(base+"/accounts", "application/json", strings.NewReader(string(raw)))
		if err != nil {
			last = err
			continue
		}
		_ = r.Body.Close()
		r2, err := p.cfg.HTTPClient.Post(base+"/token", "application/json", strings.NewReader(string(raw)))
		if err != nil {
			last = err
			continue
		}
		tb, _ := io.ReadAll(io.LimitReader(r2.Body, 1<<20))
		_ = r2.Body.Close()
		var tokDoc map[string]any
		_ = json.Unmarshal(tb, &tokDoc)
		tok, _ := tokDoc["token"].(string)
		if tok == "" {
			last = fmt.Errorf("no token")
			continue
		}
		return Handle{Kind: "mt", Email: email, Password: password, Token: tok, Base: base}, nil
	}
	if last == nil {
		last = fmt.Errorf("mailtm create failed")
	}
	return Handle{}, last
}

func (p *Provider) PollCode(h Handle, maxWait time.Duration) (string, error) {
	deadline := time.Now().Add(maxWait)
	var lastText string
	for time.Now().Before(deadline) {
		text, err := p.fetch(h)
		if err == nil && text != "" {
			if code := extractCode(text); code != "" {
				return code, nil
			}
			lastText = text
		} else if err != nil {
			lastText = err.Error()
		}
		time.Sleep(2 * time.Second)
	}
	if lastText != "" {
		return "", fmt.Errorf("验证码超时 [%s]", lastText)
	}
	return "", fmt.Errorf("验证码超时")
}

func (p *Provider) fetch(h Handle) (string, error) {
	switch h.Kind {
	case "custom":
		apiBase := strings.TrimRight(p.cfg.API, "/")
		urlsToTry := []string{
			apiBase + "/api/mails?limit=20&offset=0",
			apiBase + "/api/mails?mail=" + url.QueryEscape(h.Email),
			apiBase + "/admin/mails?mail=" + url.QueryEscape(h.Email),
			apiBase + "/api/mail?address=" + url.QueryEscape(h.Email),
			apiBase + "/check/" + url.PathEscape(h.Email),
		}
		if strings.Contains(apiBase, "/admin/mails") || strings.Contains(apiBase, "/api/mails") || strings.Contains(apiBase, "/api/messages") {
			urlsToTry = []string{apiBase}
		}

		var lastDiag string
		var hadSuccess200 bool
		for _, u := range urlsToTry {
			uReq := u
			if p.cfg.Password != "" {
				sep := "?"
				if strings.Contains(uReq, "?") {
					sep = "&"
				}
				uReq += sep + "passcode=" + url.QueryEscape(p.cfg.Password) + "&auth=" + url.QueryEscape(p.cfg.Password)
			}
			req, err := http.NewRequest(http.MethodGet, uReq, nil)
			if err != nil {
				if !hadSuccess200 {
					lastDiag = fmt.Sprintf("req err: %v", err)
				}
				continue
			}
			token := h.Token
			if token == "" {
				token = p.cfg.Password
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			if p.cfg.Password != "" {
				req.Header.Set("X-Api-Key", p.cfg.Password)
				req.Header.Set("x-custom-auth", p.cfg.Password)
				req.Header.Set("x-admin-passcode", p.cfg.Password)
				req.Header.Set("x-admin-auth", p.cfg.Password)
			}
			resp, err := p.cfg.HTTPClient.Do(req)
			if err != nil {
				if !hadSuccess200 {
					lastDiag = fmt.Sprintf("do err: %v", err)
				}
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				if !hadSuccess200 {
					lastDiag = fmt.Sprintf("http %d url=%s body=%s", resp.StatusCode, u, truncate(string(body), 80))
				}
				continue
			}
			hadSuccess200 = true
			// 1. Direct {"code": "123456"} JSON response
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err == nil {
				if c, _ := doc["code"].(string); c != "" {
					return c, nil
				}
			}
			// 2. dreamhunter2333/cloudflare_temp_email & array/text response
			raw := string(body)
			if code := extractCode(raw); code != "" {
				return code, nil
			}

			// 2b. If /api/mails returned a list of mail items, fetch individual mail details /api/mail/:id
			var anyVal any
			if err := json.Unmarshal(body, &anyVal); err == nil {
				var items []map[string]any
				if arr, ok := anyVal.([]any); ok {
					for _, item := range arr {
						if m, ok := item.(map[string]any); ok {
							items = append(items, m)
						}
					}
				} else if doc, ok := anyVal.(map[string]any); ok {
					for _, k := range []string{"mails", "messages", "results", "data"} {
						if arr, ok := doc[k].([]any); ok {
							for _, item := range arr {
								if m, ok := item.(map[string]any); ok {
									items = append(items, m)
								}
							}
							break
						}
					}
				}
				for _, item := range items {
					var mailID string
					if idVal, ok := item["id"]; ok {
						mailID = fmt.Sprintf("%v", idVal)
					}
					if mailID == "" {
						continue
					}
					for _, dPath := range []string{"/api/mail/", "/api/mails/"} {
						dReq, err := http.NewRequest(http.MethodGet, apiBase+dPath+mailID, nil)
						if err != nil {
							continue
						}
						if token != "" {
							dReq.Header.Set("Authorization", "Bearer "+token)
						}
						if p.cfg.Password != "" {
							dReq.Header.Set("X-Api-Key", p.cfg.Password)
							dReq.Header.Set("x-custom-auth", p.cfg.Password)
							dReq.Header.Set("x-admin-passcode", p.cfg.Password)
							dReq.Header.Set("x-admin-auth", p.cfg.Password)
						}
						dResp, err := p.cfg.HTTPClient.Do(dReq)
						if err != nil {
							continue
						}
						dBody, _ := io.ReadAll(io.LimitReader(dResp.Body, 2<<20))
						_ = dResp.Body.Close()
						if dResp.StatusCode == 200 {
							if code := extractCode(string(dBody)); code != "" {
								return code, nil
							}
						}
					}
				}
			}

			lastDiag = fmt.Sprintf("HTTP 200 (接口连通正常, 正在等待验证码邮件, 当前收件箱: %s)", truncate(raw, 70))
		}
		return lastDiag, nil
	case "lol":
		resp, err := p.cfg.HTTPClient.Get("https://api.tempmail.lol/v2/inbox?token=" + url.QueryEscape(h.Token))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		var data map[string]any
		_ = json.Unmarshal(body, &data)
		items, _ := data["emails"].([]any)
		if items == nil {
			items, _ = data["messages"].([]any)
		}
		var b strings.Builder
		for _, it := range items {
			m, _ := it.(map[string]any)
			if m == nil {
				continue
			}
			fmt.Fprintf(&b, "%v\n%v\n%v\n", m["subject"], m["body"], m["html"])
		}
		return b.String(), nil
	case "mt":
		req, _ := http.NewRequest(http.MethodGet, h.Base+"/messages", nil)
		req.Header.Set("Authorization", "Bearer "+h.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		var data map[string]any
		_ = json.Unmarshal(body, &data)
		msgs, _ := data["hydra:member"].([]any)
		if len(msgs) == 0 {
			return "", nil
		}
		m0, _ := msgs[0].(map[string]any)
		id, _ := m0["id"].(string)
		req2, _ := http.NewRequest(http.MethodGet, h.Base+"/messages/"+id, nil)
		req2.Header.Set("Authorization", "Bearer "+h.Token)
		resp2, err := p.cfg.HTTPClient.Do(req2)
		if err != nil {
			return "", err
		}
		defer resp2.Body.Close()
		b2, _ := io.ReadAll(io.LimitReader(resp2.Body, 2<<20))
		return string(b2), nil
	case "testmail":
		return p.testmailFetch(h)
	default:
		return "", fmt.Errorf("unknown handle kind")
	}
}

func (p *Provider) testmailFetch(h Handle) (string, error) {
	key := strings.TrimSpace(p.cfg.TestmailAPIKey)
	ns := strings.TrimSpace(p.cfg.TestmailNamespace)
	if key == "" || ns == "" {
		return "", fmt.Errorf("testmail not configured")
	}
	// Prefer short poll without livequery (avoids 307 long hangs under proxy).
	q := url.Values{}
	q.Set("apikey", key)
	q.Set("namespace", ns)
	q.Set("tag", h.Tag)
	q.Set("limit", "5")
	if h.Timestamp > 0 {
		q.Set("timestamp_from", fmt.Sprintf("%d", h.Timestamp-2000))
	}
	// Direct to api.testmail.app — do not force register proxy if NO_PROXY includes it;
	// still use HTTPClient which may have proxy from env.
	u := "https://api.testmail.app/api/json?" + q.Encode()
	// Longer timeout client for occasional slow inbox
	client := p.cfg.HTTPClient
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == 429 {
		return "", fmt.Errorf("testmail rate limited")
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("testmail http=%d body=%s", resp.StatusCode, truncate(string(body), 80))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	if r, _ := data["result"].(string); r == "fail" {
		msg, _ := data["message"].(string)
		return "", fmt.Errorf("testmail fail: %s", msg)
	}
	emails, _ := data["emails"].([]any)
	var b strings.Builder
	for _, it := range emails {
		m, _ := it.(map[string]any)
		if m == nil {
			continue
		}
		fmt.Fprintf(&b, "%v\n%v\n%v\n%v\n", m["subject"], m["text"], m["html"], m["body"])
	}
	return b.String(), nil
}

func extractCode(text string) string {
	for _, re := range codeRe {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return strings.ReplaceAll(m[1], "-", "")
		}
	}
	return ""
}

func domainBanned(emailOrDomain string) bool {
	dom := strings.ToLower(strings.TrimSpace(emailOrDomain))
	if i := strings.LastIndexByte(dom, '@'); i >= 0 {
		dom = dom[i+1:]
	}
	if _, ok := bannedDomains[dom]; ok {
		return true
	}
	parts := strings.Split(dom, ".")
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := bannedDomains[strings.Join(parts[i:], ".")]; ok {
			return true
		}
	}
	return false
}

func domainOf(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return email[i+1:]
	}
	return email
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (p *Provider) fetchCFDomains() ([]string, error) {
	if p.cfg.API == "" {
		return nil, fmt.Errorf("EMAIL_API is empty")
	}
	apiBase := strings.TrimRight(p.cfg.API, "/")
	endpoints := []string{
		apiBase + "/open_api/settings",
		apiBase + "/api/domains",
	}

	for _, u := range endpoints {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		if p.cfg.Password != "" {
			req.Header.Set("Authorization", "Bearer "+p.cfg.Password)
			req.Header.Set("X-Api-Key", p.cfg.Password)
			req.Header.Set("x-custom-auth", p.cfg.Password)
			req.Header.Set("x-admin-passcode", p.cfg.Password)
			req.Header.Set("x-admin-auth", p.cfg.Password)
		}
		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}

		var doms []string
		// 1. Array response directly or {"results": [...]} / {"data": [...]} / {"defaultDomains": [...]}
		var anyVal any
		if err := json.Unmarshal(body, &anyVal); err == nil {
			var list []any
			if arr, ok := anyVal.([]any); ok {
				list = arr
			} else if doc, ok := anyVal.(map[string]any); ok {
				if d, ok := doc["defaultDomains"].([]any); ok {
					list = d
				} else if d, ok := doc["results"].([]any); ok {
					list = d
				} else if d, ok := doc["data"].([]any); ok {
					list = d
				}
			}
			for _, item := range list {
				if s, ok := item.(string); ok && s != "" {
					s = strings.TrimSpace(strings.TrimPrefix(s, "@"))
					if s != "" {
						doms = append(doms, s)
					}
				} else if m, ok := item.(map[string]any); ok {
					if dom, ok := m["domain"].(string); ok && dom != "" {
						doms = append(doms, strings.TrimSpace(dom))
					}
				}
			}
		}
		if len(doms) > 0 {
			return doms, nil
		}
	}
	return nil, fmt.Errorf("未能从 /open_api/settings 或 /api/domains 自动获取到有效域名")
}

func (p *Provider) cfTempCreate(password string) (Handle, error) {
	domain := p.cfg.Domain
	if domain == "" {
		if doms, err := p.fetchCFDomains(); err == nil && len(doms) > 0 {
			domain = doms[rand.Intn(len(doms))]
		}
	}

	apiBase := strings.TrimRight(p.cfg.API, "/")
	name := "oc" + randStr(10)
	payload := map[string]any{
		"name":         name,
		"enablePrefix": true,
	}
	if domain != "" {
		payload["domain"] = domain
	}

	raw, _ := json.Marshal(payload)
	for _, path := range []string{"/api/new_address", "/admin/new_address"} {
		req, err := http.NewRequest(http.MethodPost, apiBase+path, bytes.NewReader(raw))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if p.cfg.Password != "" {
			req.Header.Set("Authorization", "Bearer "+p.cfg.Password)
			req.Header.Set("X-Api-Key", p.cfg.Password)
			req.Header.Set("x-custom-auth", p.cfg.Password)
			req.Header.Set("x-admin-passcode", p.cfg.Password)
			req.Header.Set("x-admin-auth", p.cfg.Password)
		}
		resp, err := p.cfg.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err == nil {
				addr, _ := doc["address"].(string)
				jwtToken, _ := doc["jwt"].(string)
				if addr != "" && jwtToken != "" {
					return Handle{Kind: "custom", Email: addr, Password: password, Token: jwtToken}, nil
				}
			}
		}
	}

	if domain == "" {
		return Handle{}, fmt.Errorf("custom 邮箱模式: 未配置 EMAIL_DOMAIN 且从 %s 创建新地址失败", p.cfg.API)
	}
	email := fmt.Sprintf("%s@%s", name, domain)
	return Handle{Kind: "custom", Email: email, Password: password}, nil
}
