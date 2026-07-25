#!/usr/bin/env python3
"""Mint Castle request_token via Playwright + real Chromium.

xAI accounts.x.ai enables Castle (enableCastle=true, castlePk=pk_...).
Empty castleRequestToken → botFlagDetails "castle_token: no_token event=$registration".

Usage:
  castle_mint.py [--pk PK] [--url URL] [--proxy URL] [--chrome PATH]
                 [--cookie 'a=b'] [--ua UA] [--timeout 60] [--mode offscreen|headless|auto]

Prints only the token to stdout on success; errors to stderr, exit 1.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import re
import sys
import time


DEFAULT_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up?redirect=grok-com"
# Browser build that exposes createRequestToken (Castle docs + npm dist).
CASTLE_CDN = (
    "https://cdn.jsdelivr.net/npm/@castleio/castle-js@2.4.0/dist/castle.browser.js"
)


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
                    "chromium-*/chrome-win/chrome.exe",
                )
            )
        )
        matches.extend(
            glob.glob(
                os.path.join(
                    base,
                    "chromium-*/Chromium.app/Contents/MacOS/Chromium",
                )
            )
        )
        # Windows cloak layout
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome.exe")))
    if matches:
        return sorted(matches)[-1]
    for p in (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ):
        if os.path.exists(p):
            return p
    return ""


def parse_cookie_header(raw: str) -> list[dict]:
    out: list[dict] = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name, val = name.strip(), val.strip()
        if not name or name.lower() in {"sso", "sso-rw"}:
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
    mode = (mode or "offscreen").strip().lower()
    if mode in ("", "auto"):
        mode = "offscreen"
    if mode == "headless":
        return "headless", True
    # Windows usually has a desktop session
    if sys.platform == "win32" or has_display():
        return "offscreen", False
    print(
        "warn: CASTLE mode=offscreen but no $DISPLAY; using headless fallback",
        file=sys.stderr,
    )
    return "headless-no-display", True


def launch_args(label: str) -> list[str]:
    args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--disable-dev-shm-usage",
    ]
    if label == "offscreen":
        args.extend(
            [
                "--window-position=-32000,-32000",
                "--window-size=800,600",
            ]
        )
    return args


def scrape_pk_from_html(html: str) -> str:
    if not html:
        return ""
    for pat in (
        r'castlePk\\":\\"([^\\"]+)',
        r'castlePk":"([^"]+)',
        r'"(pk_[A-Za-z0-9]{16,})"',
    ):
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return ""


async def mint(
    pk: str,
    page_url: str,
    proxy: str,
    chrome: str,
    cookies: list[dict],
    timeout: float,
    ua: str,
    mode: str = "offscreen",
) -> str:
    from playwright.async_api import async_playwright

    label, use_headless = resolve_launch_mode(mode)
    launch: dict = {
        "executable_path": chrome,
        "headless": use_headless,
        "args": launch_args(label),
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch)
        try:
            ctx_kwargs: dict = {
                "viewport": {"width": 800, "height": 600},
                # first-party cookies / storage for Castle __cuid
                "locale": "en-US",
            }
            if ua:
                ctx_kwargs["user_agent"] = ua
            context = await browser.new_context(**ctx_kwargs)
            await context.add_init_script(
                'Object.defineProperty(navigator,"webdriver",{get:()=>undefined})'
            )
            if cookies:
                for c in cookies:
                    try:
                        await context.add_cookies(
                            [
                                {
                                    "name": c["name"],
                                    "value": c["value"],
                                    "domain": c.get("domain") or ".x.ai",
                                    "path": c.get("path") or "/",
                                }
                            ]
                        )
                    except Exception:
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
                        except Exception:
                            pass

            page = await context.new_page()
            await page.goto(page_url, timeout=45000, wait_until="domcontentloaded")
            await page.wait_for_timeout(800)

            # Prefer page-embedded pk if caller left it empty / default
            if not pk or pk == DEFAULT_PK:
                try:
                    html = await page.content()
                    scraped = scrape_pk_from_html(html)
                    if scraped:
                        pk = scraped
                except Exception:
                    pass
            if not pk:
                pk = DEFAULT_PK

            # Load Castle browser build and configure on this origin (first-party).
            # Wait a bit so SDK can collect device signals (docs: init early).
            await page.add_script_tag(url=CASTLE_CDN)
            await page.wait_for_function(
                "() => !!(window.Castle && typeof window.Castle.configure === 'function')",
                timeout=15000,
            )
            await page.evaluate(
                """(pk) => {
                  window.__castle_sdk = window.Castle.configure({ pk: pk, timeout: 2000 });
                  return true;
                }""",
                pk,
            )
            # Let fingerprint collectors run
            await page.wait_for_timeout(1200)
            # light human-ish activity
            try:
                await page.mouse.move(120, 160, steps=6)
                await page.mouse.move(240, 220, steps=8)
                await page.mouse.wheel(0, 120)
            except Exception:
                pass
            await page.wait_for_timeout(400)

            deadline = time.time() + max(5.0, timeout)
            last_err = ""
            while time.time() < deadline:
                try:
                    tok = await page.evaluate(
                        """async () => {
                          const c = window.__castle_sdk || window.Castle;
                          if (!c || typeof c.createRequestToken !== 'function') {
                            throw new Error('Castle.createRequestToken missing');
                          }
                          const t = await c.createRequestToken();
                          return t || '';
                        }"""
                    )
                    if tok and isinstance(tok, str) and len(tok) > 20:
                        return tok
                    last_err = "empty token"
                except Exception as exc:
                    last_err = f"{type(exc).__name__}: {exc}"
                await page.wait_for_timeout(300)

            raise RuntimeError(f"castle timeout ({last_err})")
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pk", default=os.environ.get("CASTLE_PK", DEFAULT_PK))
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--proxy", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--ua", default="")
    ap.add_argument("--timeout", type=float, default=60)
    ap.add_argument(
        "--mode",
        default=os.environ.get("CASTLE_MODE")
        or os.environ.get("TURNSTILE_MODE")
        or "offscreen",
        choices=("offscreen", "headless", "auto"),
    )
    args = ap.parse_args()

    chrome = args.chrome.strip() or find_chrome()
    if not chrome:
        print("chrome not found", file=sys.stderr)
        return 1
    cookies = parse_cookie_header(args.cookie)
    try:
        token = asyncio.run(
            mint(
                pk=(args.pk or "").strip() or DEFAULT_PK,
                page_url=args.url.strip() or DEFAULT_URL,
                proxy=args.proxy.strip(),
                chrome=chrome,
                cookies=cookies,
                timeout=args.timeout,
                ua=args.ua.strip(),
                mode=args.mode,
            )
        )
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not token or len(token) <= 20:
        print("empty token", file=sys.stderr)
        return 1
    # token only
    if "\n" in token:
        token = token.splitlines()[0].strip()
    sys.stdout.write(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
