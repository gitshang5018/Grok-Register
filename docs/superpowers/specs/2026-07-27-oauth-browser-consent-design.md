# OAuth 浏览器驱动 Consent 设计

**日期：** 2026-07-27  
**状态：** 已批准（用户确认方案 A）  
**范围：** PKCE consent 批准路径；不改注册 / Turnstile / Castle

## 1. 背景与问题

Grok-Register 流水线在「注册 → SSO」阶段仍然成功，但 OAuth PKCE 在 consent 批准后拿不到 authorization code。

纯 HTTP 路径已能：

- 发现 42 位 Next.js Server Action ID
- 命中真正的 `submitOAuth2Consent`（1 参 action）
- 解析 RSC flight 真实返回值

但业务结果为：

| 请求形态 | 服务端结果 |
|----------|------------|
| `["allow"]` 等 | `{"success":false,"error":"No redirect received from authorization server"}` |
| camelCase 对象 | `{"success":false,"error":"Access denied"}` |
| multipart FormData | 500 digest |
| HTML form POST | `callback?error=access_denied`（Allow 为 `type=button`，POST 无效） |

**根因定性：** 不是整套注册协议作废，而是 **accounts.x.ai 上的 Server Action 在服务端代调 auth.x.ai 时拿不到 redirect/code**。继续改 body 编码收益极低。device_code 对本流水线账号历史上 token 端 `invalid_grant`，不作首选。

## 2. 目标与非目标

### 目标

- 在已有 SSO 前提下，用真实浏览器完成 OAuth consent 批准
- 拦截 `http://127.0.0.1:56121/callback?code=…&state=…`
- 仍用现有 HTTP `exchangeCode` 兑换 token 并写 CPA JSON
- 对 `pipeline.oauthWorker` / `reoauth` 上层尽量透明（仍走 `ExchangeGrant`）

### 非目标

- 不重做注册、Turnstile、Castle
- 不默认全程浏览器 OAuth（authorize→callback 全在浏览器）
- 不继续扩展 Server Action body 穷举
- 不修复与本功能无关的 Windows `syscall.Flock` 全量 build 问题

### 成功标准

- 新建账号经 PKCE 可稳定得到 `access_token` + `refresh_token` 并产出 CPA JSON
- 诊断日志能区分：HTTP 快失败原因 vs 浏览器 consent 结果
- 无 Chrome/脚本时失败信息明确，不空转消耗邮箱

## 3. 架构

```text
HTTP（保留）
  newPKCESession
  → GET /oauth2/authorize（Cookie: sso=…）
  → 跟随跳转到 accounts.x.ai/.../consent?…

浏览器（仅 consent）
  CloakBrowser / Chrome + Playwright
  → 注入 SSO 及 consent 相关 cookie
  → goto 完整 consent URL
  → 点击 Allow
  → 拦截 127.0.0.1:56121/callback?code=&state=

HTTP（保留）
  exchangeCode(code, code_verifier)
  → Credential → CPA / 探活 / 上传
```

**接入点：** `internal/oauth` 的 `authorizeCode` / `submitConsent` 失败或配置强制浏览器时调用浏览器桥。  
`pipeline` 继续 `e.oauth.ExchangeGrant(ctx, job.SSO, cfg.OAuthGrant)`，无需改业务语义。

**并发：** 浏览器 consent 与 Turnstile 共用本机 Chromium。使用独立 **consent 信号量**（默认并发 1，可配置），避免与 Turnstile 抢资源。

## 4. 组件

| 组件 | 职责 |
|------|------|
| `scripts/oauth_consent.py` | Playwright 脚本：注入 cookie、打开 consent、点 Allow、拦 callback；成功时 stdout 一行 JSON |
| `internal/oauth/browser_consent.go` | Go 桥：定位脚本/Python/Chrome、传参、超时、解析 JSON、写诊断 |
| `internal/oauth/pkce.go` | 在 SA/form 失败后或 mode=browser 时调用桥；校验 state；返回 code |
| `internal/config` | 新增 consent 相关配置项与 env 加载 |

### 4.1 Python 脚本契约

**输入（CLI）：**

- `--consent-url` 完整 consent URL（必须保留 query）
- `--cookie` Cookie 头字符串（含 `sso=…` 及其他 consent 页 Set-Cookie）
- `--proxy` 可选，与 `REGISTER_PROXY` 一致
- `--chrome` 可选
- `--timeout` 秒，默认 60
- `--mode` `offscreen` | `headless`（默认 offscreen，与 Turnstile 一致）
- `--expected-state` 可选，用于脚本侧早失败

**输出（stdout，成功时仅一行 JSON）：**

```json
{"ok":true,"code":"<auth_code>","state":"<state>","callback_url":"http://127.0.0.1:56121/callback?..."}
```

失败：exit ≠ 0，stderr 写可读诊断；可选 stdout `{"ok":false,"error":"…"}`。

**浏览器行为：**

1. 启动 Chromium（优先 CloakBrowser，逻辑可对齐 `turnstile_mint.py` 的 `find_chrome`）
2. 配置代理（若有）
3. 将 cookie 写入 `.x.ai` / `accounts.x.ai` / `auth.x.ai` 合适 domain（**必须包含 `sso`**）
4. 注册 request/response 监听：URL 匹配 callback 且含 `code=` 或 `error=`
5. `goto(consent_url)`
6. 若已跳转 callback 则直接解析
7. 否则点击可见 **Allow** 按钮（`type=button` 也可；文案/角色匹配 Allow/Approve/授权，排除 Deny）
8. 等待 callback 或超时

**禁止：** 复用 `turnstile_mint.py` 里丢弃名为 `sso` 的 cookie 过滤逻辑。consent 脚本必须独立实现 cookie 解析。

### 4.2 Go 桥契约

```text
browserConsent(ctx, opts) → (callbackURL string, err error)
```

- 解析脚本 JSON 或从 callback URL 取 code
- 调用方用现有 `codeFromCallback(loc, wantState)` 校验 state
- 超时、缺脚本、缺 Python、缺 Chrome → 明确 error 字符串前缀（如 `pkce_browser_…`）
- 通过现有 `logDiag` 输出关键步骤

### 4.3 模式与回退

| `OAUTH_CONSENT_MODE` | 行为 |
|----------------------|------|
| `auto`（默认） | 先短试 HTTP Server Action（有限尝试，快速识别 `No redirect` / `Access denied`）；失败则浏览器 |
| `browser` | 跳过 SA 穷举，consent 页直接浏览器 |
| `http` | 仅旧 HTTP 路径（调试用） |

**auto 下 HTTP 快失败：** 一旦某次 SA 返回可识别业务错误（`No redirect received from authorization server` / `Access denied`），不再扫完所有 body/ID，直接切浏览器，避免 18s+ 空转。

## 5. 数据流

```text
ExchangePKCE(sso)
  → authorizeCode
       hops GET authorize
       落到 consent HTML
       switch mode:
         http    → submitConsent (SA + form POST) only
         browser → browserConsent only
         auto    → submitConsent 快失败 → browserConsent
       codeFromCallback
  → exchangeCode
  → Credential
```

Form POST fallback 在 `http`/`auto` 的 HTTP 段仍可保留（诊断用），但 **不再作为成功路径的期望**。

## 6. 错误处理

| 条件 | 错误语义 |
|------|----------|
| 浏览器打开后进入 sign-in | `sso_rejected`（SSO 无效或未跨集群同步） |
| callback `error=access_denied` | 真实拒绝，计入 OAuth fail |
| 超时无 code | `pkce_browser_consent_timeout` |
| 无 Chrome / 无脚本 / 无 Python | 配置类错误，立即失败 |
| state 不匹配 | `pkce_state_mismatch`（致命） |
| 脚本 JSON 无 code | `pkce_browser_consent_no_code` |

连续 OAuth 失败仍受现有 `OAUTH_GIVE_UP_AFTER` 保护。

## 7. 配置

```env
# auto | browser | http
OAUTH_CONSENT_MODE=auto
OAUTH_CONSENT_TIMEOUT_SEC=60
OAUTH_CONSENT_CONCURRENCY=1
# 可选覆盖
# GROK_OAUTH_CONSENT_SCRIPT=/path/to/oauth_consent.py
```

与现有对齐：

- 代理：`REGISTER_PROXY`
- Chrome：`CHROME_PATH`
- Python：与 Turnstile 相同发现逻辑（venv / `python3`）
- 显示模式：可复用 `TURNSTILE_MODE` 或单独项；首版默认 offscreen

`OAuthGrant`（`pkce|device|auto`）语义不变；本设计只影响 PKCE 路径内的 consent 实现。

## 8. 测试计划

### 单元（CI 可跑）

- callback URL / state 校验（已有 `codeFromCallback` 相关用例可扩展）
- Go 桥：mock 脚本 stdout JSON → 解析 code
- auto 快失败：对含 `No redirect received from authorization server` 的 SA 结果应触发 browser 路径（可用 interface/fake）
- cookie 头解析：确保 `sso` 不会被剥离（针对脚本侧可测的纯函数，若抽到可测模块）

### 集成（手动 / 本地）

1. 从 `outputs/<run>/sso/accounts.txt` 取一条有效 SSO
2. `OAUTH_CONSENT_MODE=browser` 跑单次 `ExchangePKCE` 或 reoauth
3. 确认拿到 token 并写出 CPA

### 不测

- CI 内真实打 x.ai（依赖网络与账号）

## 9. 实现顺序（供 writing-plans 展开）

1. 配置项 + 默认值
2. `oauth_consent.py` 最小可跑脚本（mock callback 可先本地 HTML 自测逻辑分离）
3. `browser_consent.go` 桥 + 单元测试
4. `pkce.go` 接入 auto/browser/http
5. auto 下 SA 快失败裁剪
6. 本地用真实 SSO 冒烟
7. 文档：`config.env.example` / README 简短说明（仅配置相关，不另写长文）

## 10. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 浏览器比 HTTP 慢、吞吐下降 | 默认并发 1；OAuth 本就有 min interval |
| 与 Turnstile 抢 Chrome | consent 信号量；必要时串行化 mint+consent |
| x.ai 改 consent UI 选择器失效 | 多选择器 + callback 监听为主（不依赖唯一 CSS） |
| SSO 写入 domain 错误导致未登录 | 多 domain 注入；失败时 dump 最终 URL |
| offscreen 环境无显示 | 复用 Turnstile 的 xvfb/offscreen 模式 |

## 11. 已否决方案（摘要）

- **全程浏览器 OAuth：** 更慢更重，HTTP authorize 仍可用，无必要
- **继续纯 HTTP SA 穷举：** 已返回明确业务错误，非编码问题
- **device_code 作为主路径：** 历史 `invalid_grant`，仅保留 grant=device/auto 兜底

## 12. 规格自检记录

- 无 TODO/待定占位
- 与现有 `ExchangeGrant` / pipeline 调用一致
- 范围单计划可覆盖（consent 混合路径）
- `auto` 默认与 `browser` 强制行为无歧义
