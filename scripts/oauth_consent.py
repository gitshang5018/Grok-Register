#!/usr/bin/env python3
"""OAuth PKCE consent via Playwright. Prints one JSON line to stdout on success.

Unlike turnstile_mint.py, this script MUST keep the sso cookie.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import json
import os
import re
import sys
import time
from typing import Any
from urllib.parse import parse_qs, urlparse


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.exists(env):
        return env
    homes = []
    h = os.path.expanduser("~")
    if h:
        homes.append(h)
    homes.extend(["/root", "/home/charles"])
    matches: list[str] = []
    for home in homes:
        base = os.path.join(home, ".cloakbrowser")
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome")))
        matches.extend(
            glob.glob(
                os.path.join(
                    base,
                    "chromium-*/Chromium.app/Contents/MacOS/Chromium",
                )
            )
        )
        # Windows CloakBrowser
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome.exe")))
    if matches:
        return sorted(matches)[-1]
    for p in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if os.path.exists(p):
            return p
    return ""


def parse_cookie_header(raw: str) -> list[dict]:
    """Parse Cookie header. KEEP sso / sso-rw (critical for OAuth consent)."""
    out: list[dict] = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name:
            continue
        out.append(
            {
                "name": name,
                "value": val,
                "domain": ".x.ai",
                "path": "/",
            }
        )
    return out


def has_display() -> bool:
    return bool(
        (os.environ.get("DISPLAY") or "").strip()
        or (os.environ.get("WAYLAND_DISPLAY") or "").strip()
    )


def resolve_launch_mode(mode: str) -> tuple[str, bool]:
    """offscreen = headed Chromium (needs DISPLAY or xvfb-run from Go bridge).

    On bare VPS without DISPLAY, fall back to headless so launch still works;
    prefer: apt install xvfb, then Go wraps with xvfb-run -a (sets DISPLAY).
    """
    mode = (mode or "offscreen").strip().lower()
    if mode in ("", "auto"):
        mode = "offscreen"
    if mode == "headless":
        return "headless", True
    if has_display() or sys.platform.startswith("win"):
        return "offscreen", False
    print(
        "no DISPLAY; falling back to headless for oauth consent. "
        "On VPS install xvfb and re-run (Go uses xvfb-run -a when available): "
        "apt-get install -y xvfb",
        file=sys.stderr,
    )
    return "headless", True


def launch_args(label: str) -> list[str]:
    # VPS / root / Docker: --no-sandbox and disable-dev-shm-usage are required
    # or Chromium is often signal:killed (OOM / sandbox) with empty stdout.
    args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]
    if label == "offscreen":
        args.extend(
            [
                "--window-position=-32000,-32000",
                "--window-size=1280,900",
            ]
        )
    return args


def is_callback(url: str) -> bool:
    u = (url or "").lower()
    return ("127.0.0.1:56121" in u or "localhost:56121" in u) and (
        "code=" in u or "error=" in u
    )


def parse_callback(url: str) -> dict[str, Any]:
    q = parse_qs(urlparse(url).query)
    code = (q.get("code") or [""])[0]
    state = (q.get("state") or [""])[0]
    err = (q.get("error") or [""])[0]
    desc = (q.get("error_description") or [""])[0]
    if err:
        return {
            "ok": False,
            "error": err if not desc else f"{err}: {desc}",
            "callback_url": url,
            "state": state,
        }
    if not code:
        return {"ok": False, "error": "callback_missing_code", "callback_url": url}
    return {
        "ok": True,
        "code": code,
        "state": state,
        "callback_url": url,
    }


_ALLOW_RE = re.compile(r"(?i)^(allow|approve|授权|同意|允许)$")
_DENY_RE = re.compile(r"(?i)deny|拒绝|取消|cancel")


async def click_allow(page) -> bool:
    # role=button first
    try:
        buttons = page.get_by_role("button")
        count = await buttons.count()
        for i in range(count):
            btn = buttons.nth(i)
            try:
                text = (await btn.inner_text() or "").strip()
            except Exception:
                continue
            if _DENY_RE.search(text):
                continue
            if _ALLOW_RE.search(text) or re.search(r"(?i)allow|approve|授权|同意|允许", text):
                if await btn.is_visible():
                    await btn.click(timeout=5000)
                    return True
    except Exception as e:
        print(f"role button scan: {e}", file=sys.stderr)

    # CSS buttons
    try:
        loc = page.locator("button, [role=button]")
        count = await loc.count()
        for i in range(count):
            el = loc.nth(i)
            try:
                text = (await el.inner_text() or "").strip()
            except Exception:
                continue
            if _DENY_RE.search(text):
                continue
            if re.search(r"(?i)allow|approve|授权|同意|允许", text):
                if await el.is_visible():
                    await el.click(timeout=5000)
                    return True
    except Exception as e:
        print(f"css button scan: {e}", file=sys.stderr)
    return False


async def add_cookies(context, cookies: list[dict]) -> None:
    domains = [".x.ai", "accounts.x.ai", "auth.x.ai"]
    for c in cookies:
        added = False
        for dom in domains:
            try:
                await context.add_cookies(
                    [
                        {
                            "name": c["name"],
                            "value": c["value"],
                            "domain": dom,
                            "path": c.get("path") or "/",
                        }
                    ]
                )
                added = True
            except Exception:
                pass
        if not added:
            try:
                await context.add_cookies(
                    [
                        {
                            "name": c["name"],
                            "value": c["value"],
                            "url": "https://accounts.x.ai/",
                            "path": "/",
                        }
                    ]
                )
            except Exception as e:
                print(f"cookie skip {c.get('name')}: {e}", file=sys.stderr)


async def run_consent(
    consent_url: str,
    cookie_header: str,
    proxy: str,
    chrome: str,
    timeout: float,
    mode: str,
    expected_state: str,
) -> dict[str, Any]:
    from playwright.async_api import async_playwright

    label, use_headless = resolve_launch_mode(mode)
    launch: dict = {
        "executable_path": chrome,
        "headless": use_headless,
        "args": launch_args(label),
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    cookies = parse_cookie_header(cookie_header)
    if not any(c["name"].lower() == "sso" for c in cookies):
        print("warning: no sso cookie in --cookie", file=sys.stderr)

    captured: list[str] = []

    def maybe_capture(url: str) -> None:
        if url and is_callback(url):
            captured.append(url)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch)
        try:
            context = await browser.new_context(viewport={"width": 1280, "height": 900})
            await context.add_init_script(
                'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'
            )
            await add_cookies(context, cookies)
            page = await context.new_page()

            page.on("framenavigated", lambda frame: maybe_capture(frame.url))
            page.on("request", lambda req: maybe_capture(req.url))

            def on_response(resp) -> None:
                try:
                    maybe_capture(resp.url)
                except Exception:
                    pass

            page.on("response", on_response)

            await page.goto(consent_url, timeout=int(timeout * 1000), wait_until="domcontentloaded")
            maybe_capture(page.url)
            if captured:
                return parse_callback(captured[-1])

            # Sign-in redirect?
            cur = (page.url or "").lower()
            if "sign-in" in cur or "sign-up" in cur or "login" in cur:
                return {
                    "ok": False,
                    "error": f"sso_rejected final_url={page.url}",
                }

            clicked = await click_allow(page)
            if not clicked:
                print("Allow button not found; waiting for callback anyway", file=sys.stderr)

            deadline = time.time() + timeout
            while time.time() < deadline:
                maybe_capture(page.url)
                if captured:
                    result = parse_callback(captured[-1])
                    if expected_state and result.get("ok") and result.get("state"):
                        if result["state"] != expected_state:
                            return {
                                "ok": False,
                                "error": f"pkce_state_mismatch got={result['state']}",
                                "callback_url": result.get("callback_url", ""),
                            }
                    return result
                await page.wait_for_timeout(250)

            return {
                "ok": False,
                "error": f"pkce_browser_consent_timeout url={page.url}",
            }
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="OAuth PKCE browser consent")
    ap.add_argument("--consent-url", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument("--mode", default="offscreen", choices=("offscreen", "headless", "auto"))
    ap.add_argument("--expected-state", default="")
    args = ap.parse_args()

    chrome = args.chrome.strip() or find_chrome()
    if not chrome:
        print(json.dumps({"ok": False, "error": "chrome not found"}, ensure_ascii=False))
        print("chrome not found", file=sys.stderr)
        return 1

    try:
        result = asyncio.run(
            run_consent(
                consent_url=args.consent_url,
                cookie_header=args.cookie,
                proxy=args.proxy.strip(),
                chrome=chrome,
                timeout=max(5.0, float(args.timeout)),
                mode=args.mode,
                expected_state=args.expected_state.strip(),
            )
        )
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        print(f"oauth_consent error: {e}", file=sys.stderr)
        return 1

    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
