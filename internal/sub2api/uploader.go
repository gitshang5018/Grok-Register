package sub2api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grok-free-register/grok-reg/internal/cpa"
)

type Config struct {
	Enabled    bool
	BaseURL    string // e.g. http://127.0.0.1:8000
	Key        string
	Path       string // e.g. /api/v1/admin/accounts/import
	TimeoutSec int
	Retries    int
}

type Result struct {
	OK     bool
	Email  string
	Status int
	Body   string
	Err    error
}

type Uploader struct {
	cfg    Config
	client *http.Client
	logf   func(string, ...any)
}

func NewUploader(cfg Config, logf func(string, ...any)) *Uploader {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	to := time.Duration(cfg.TimeoutSec) * time.Second
	if to <= 0 {
		to = 30 * time.Second
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = "http://127.0.0.1:8000"
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = "/api/v1/admin/accounts/import"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	cfg.BaseURL = base
	cfg.Path = path

	return &Uploader{
		cfg: cfg,
		client: &http.Client{
			Timeout:   to,
			Transport: &http.Transport{Proxy: nil},
		},
		logf: logf,
	}
}

func (u *Uploader) Enabled() bool {
	if !u.cfg.Enabled {
		return false
	}
	if strings.TrimSpace(u.cfg.Key) == "" {
		u.logf("[sub2api] SUB2API_ENABLED=1 but SUB2API_KEY empty; skip")
		return false
	}
	if strings.TrimSpace(u.cfg.BaseURL) == "" {
		u.logf("[sub2api] SUB2API_BASE_URL empty; skip")
		return false
	}
	return true
}

func (u *Uploader) Endpoint() string {
	return u.cfg.BaseURL + u.cfg.Path
}

func (u *Uploader) ImportFile(path string) Result {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{Err: err}
	}
	var doc cpa.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Result{Err: err}
	}
	return u.ImportDocument(doc)
}

func (u *Uploader) ImportDocument(doc cpa.Document) Result {
	res := Result{Email: doc.Email}
	if !u.Enabled() {
		res.Err = fmt.Errorf("sub2api disabled")
		return res
	}

	payload := map[string]any{
		"platform":      "grok",
		"provider":      "grok",
		"type":          "xai",
		"email":         doc.Email,
		"sub":           doc.Sub,
		"access_token":  doc.AccessToken,
		"refresh_token": doc.RefreshToken,
		"id_token":      doc.IDToken,
		"expires_in":    doc.ExpiresIn,
		"credentials":   doc,
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		res.Err = err
		return res
	}

	retries := u.cfg.Retries
	if retries < 0 {
		retries = 0
	}

	var last Result
	endpoint := u.Endpoint()

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * 400 * time.Millisecond
			time.Sleep(backoff)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(rawPayload))
		if err != nil {
			last = Result{Email: doc.Email, Err: err}
			continue
		}

		key := strings.TrimSpace(u.cfg.Key)
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-Api-Key", key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := u.client.Do(req)
		if err != nil {
			last = Result{Email: doc.Email, Err: err}
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		last = Result{
			OK:     resp.StatusCode >= 200 && resp.StatusCode < 300,
			Email:  doc.Email,
			Status: resp.StatusCode,
			Body:   string(body),
		}

		if last.OK {
			u.logf("[sub2api] 自动导入 SUB2API 成功: %s", doc.Email)
			return last
		}
	}

	if last.Err != nil {
		u.logf("[sub2api] 导入 SUB2API 失败 %s err=%v", doc.Email, last.Err)
	} else {
		u.logf("[sub2api] 导入 SUB2API 失败 %s status=%d body=%s", doc.Email, last.Status, truncate(last.Body, 200))
	}
	return last
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
