#!/usr/bin/env bash
# Grok-Register 一键部署（含浏览器 OAuth consent）
#
# 在 Linux / macOS 上执行（推荐 root/sudo）：
#
#   curl -fsSL https://raw.githubusercontent.com/gitshang5018/Grok-Register/main/scripts/one-click-deploy.sh | sudo bash
#
# 指定分支（例如功能分支尚未合并 main 时）：
#
#   curl -fsSL https://raw.githubusercontent.com/gitshang5018/Grok-Register/feat/oauth-browser-consent/scripts/one-click-deploy.sh | sudo bash
#
# 非交互：
#
#   curl -fsSL ... | sudo NONINTERACTIVE=1 bash
#
# 强制 browser consent（部署后写入 config，不覆盖已有键）：
#
#   curl -fsSL ... | sudo OAUTH_CONSENT_MODE=browser bash
#
# 等价于调用 scripts/install.sh，并默认带上 OAuth consent 相关环境。

set -euo pipefail

REPO_RAW_BASE="${REPO_RAW_BASE:-https://raw.githubusercontent.com/gitshang5018/Grok-Register}"
BRANCH="${BRANCH:-main}"
REPO_URL="${REPO_URL:-https://github.com/gitshang5018/Grok-Register.git}"

# 默认启用 auto consent（HTTP 失败后浏览器）；可用环境变量覆盖
export OAUTH_CONSENT_MODE="${OAUTH_CONSENT_MODE:-auto}"
export BRANCH
export REPO_URL

echo "[*] Grok-Register 一键部署"
echo "    branch=${BRANCH}"
echo "    OAUTH_CONSENT_MODE=${OAUTH_CONSENT_MODE}"
echo

INSTALL_URL="${REPO_RAW_BASE}/${BRANCH}/scripts/install.sh"
if ! curl -fsSL "$INSTALL_URL" | bash -s -- "$@"; then
  echo "[x] 通过 raw 拉取 install.sh 失败，尝试 git clone 本地执行…" >&2
  TMP="$(mktemp -d)"
  cleanup() { rm -rf "$TMP"; }
  trap cleanup EXIT
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP/repo"
  bash "$TMP/repo/scripts/install.sh" "$@"
fi

# 部署后若存在 config.env，补齐 consent 键（install 升级路径也会做；此处双保险）
GROK_HOME_OPT="${GROK_HOME:-${HOME}/.grok}"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  REAL_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
  if [ -n "${REAL_HOME:-}" ]; then
    GROK_HOME_OPT="${GROK_HOME:-${REAL_HOME}/.grok}"
  fi
fi
CFG="${GROK_HOME_OPT}/config.env"
if [ -f "$CFG" ]; then
  set_if_missing() {
    local k="$1" v="$2"
    if ! grep -qE "^${k}=" "$CFG" 2>/dev/null; then
      printf '%s=%s\n' "$k" "$v" >>"$CFG"
      echo "[+] config 补齐: $k=$v"
    fi
  }
  set_if_missing "OAUTH_CONSENT_MODE" "${OAUTH_CONSENT_MODE}"
  set_if_missing "OAUTH_CONSENT_TIMEOUT_SEC" "${OAUTH_CONSENT_TIMEOUT_SEC:-60}"
  set_if_missing "OAUTH_CONSENT_CONCURRENCY" "${OAUTH_CONSENT_CONCURRENCY:-1}"
fi

echo
echo "[✓] 一键部署流程结束。编辑配置:  \${COMMAND:-grok} config"
echo "    启动:  grok start -t 1 --thread 1"
echo "    仅 OAuth:  grok reoauth /path/to/accounts.txt -w 1"
