
#!/usr/bin/env python3
"""
Human-reachable URL checker using Playwright (Chromium).

Goal: Decide if a typical human using a real browser could reach each URL,
even if basic bot-like requests fail. We use a real browser, execute JS,
wait for redirects, and detect common bot-challenge interstitials.

Input:  Excel/CSV with a column named "url" (case-insensitive).
Outputs:
  - CSV: link_check_results.csv
  - Folder: screenshots/ (PNG per URL)
  - Optional: JSON summary per run (link_check_results.json)

Install (first time):
  python -m pip install -r requirements.txt
  python -m playwright install chromium

Usage:
  python human_link_check.py --input urls.xlsx --sheet Sheet1 --concurrency 6
  # or CSV:
  python human_link_check.py --input urls.csv --concurrency 6

Notes:
  - Heuristics classify pages as: reachable | challenge | protected | broken | timeout | dns_error.
  - "reachable" means we loaded non-challenge content in a real browser context.
  - "challenge" means anti-bot wall detected (e.g., Cloudflare "Just a moment...") and not bypassed within timeout.
  - "protected" means site is up but requires auth or is geo/IP blocked; a human could reach landing page but content gated.
  - "broken" means HTTP error (4xx/5xx) or fatal nav error likely not due to bot checks.
  - Headless is used; for stubborn sites, try --headed for a quick pass locally.
"""

import asyncio
import argparse
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from playwright.async_api import async_playwright, TimeoutError as PWTimeout


# ----------------------- Heuristics & Utilities -----------------------

CHALLENGE_PATTERNS = [
    r"just a moment",  # Cloudflare
    r"checking your browser",
    r"verifying you are human",
    r"verify you are human",
    r"are you a robot",
    r"robot check",
    r"captcha",
    r"cf-chl",  # Cloudflare challenge token
    r"cdn-cgi",
    r"akamai",
    r"perimeterx",
    r"datadome",
    r"sucuri",
    r"access denied",
]

PROTECTED_PATTERNS = [
    r"sign in",
    r"log in",
    r"forbidden",
    r"not authorized",
    r"country/region not supported",
    r"geo.?blocked",
]


def classify_page_text(text: str) -> str:
    t = (text or "").lower()
    for pat in CHALLENGE_PATTERNS:
        if re.search(pat, t):
            return "challenge"
    for pat in PROTECTED_PATTERNS:
        if re.search(pat, t):
            return "protected"
    return "unknown"


def normalize_url(u: str) -> str:
    if not u:
        return u
    u = u.strip()
    if not u:
        return u
    # If missing scheme, assume https
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    return u


def is_probably_html(content_type: str | None) -> bool:
    if not content_type:
        return True  # many sites don't set it properly
    return "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower()


# ----------------------- Core Checker -----------------------

async def check_url(browser, url: str, timeout_ms: int = 25000, headed: bool = False, screenshot_dir: Path | None = None) -> dict:
    result = {
        "url": url,
        "final_url": None,
        "status": "broken",          # default; will refine
        "http_status": None,
        "title": None,
        "notes": "",
        "elapsed_sec": None,
        "screenshot": None,
    }

    start = time.time()
    page = None
    try:
        context = await browser.new_context(
            locale="en-US",
            timezone_id="America/New_York",
            user_agent=(
                # Recent stable Chrome UA (Windows 10 x64)
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/127.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1366, "height": 768},
            java_script_enabled=True,
            ignore_https_errors=False,
            # Extra HTTP headers to look more like a real browser session
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        page = await context.new_page()

        # Set a reasonable default timeout for each step
        page.set_default_navigation_timeout(timeout_ms)
        page.set_default_timeout(timeout_ms)

        # Navigate
        resp = await page.goto(url, wait_until="domcontentloaded")

        # If MIME type looks non-HTML, still allow (some sites serve weird headers)
        if resp:
            result["http_status"] = resp.status
            ct = resp.headers.get("content-type", "")
            if not is_probably_html(ct):
                # Still try to load; but mark note
                result["notes"] += f"[non-HTML content-type: {ct}] "

        # Give pages time to redirect/execute JS
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout_ms // 2)
        except PWTimeout:
            pass

        # Light human-like interaction: small scroll to trigger lazy loads
        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.3)")
            await asyncio.sleep(0.3)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(0.3)
            await page.evaluate("window.scrollTo(0, 0)")
        except Exception:
            pass

        # Gather info
        result["final_url"] = page.url
        try:
            result["title"] = await page.title()
        except Exception:
            result["title"] = None

        # Heuristic: page text size & challenge detection
        body_text = ""
        try:
            body_text = await page.inner_text("body")
            if body_text:
                body_text = body_text[:20000]
        except Exception:
            pass

        # Another hint: presence of visible h1 or main content
        has_h1 = False
        try:
            h1 = await page.locator("h1").first.text_content(timeout=1000)
            has_h1 = bool(h1 and h1.strip())
        except Exception:
            has_h1 = False

        classification = classify_page_text(body_text)

        # Decide status
        if (result["http_status"] and 200 <= result["http_status"] < 400) or result["http_status"] is None:
            if classification == "challenge":
                result["status"] = "challenge"
            else:
                text_len = len(body_text or "")
                if text_len > 200 or has_h1 or (result["title"] and len(result["title"]) > 0):
                    result["status"] = "reachable"
                else:
                    result["status"] = "protected" if classification == "protected" else "reachable"
        else:
            if result["http_status"] in (401, 403):
                result["status"] = "challenge" if classification == "challenge" else "protected"
            elif result["http_status"] and 400 <= result["http_status"] < 600:
                result["status"] = "broken"
            else:
                result["status"] = "broken"

        # Screenshot (for debugging)
        if screenshot_dir:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            from urllib.parse import urlparse as _urlparse
            fname = re.sub(r"[^a-zA-Z0-9_-]+", "_", (_urlparse(result["final_url"] or url).netloc or "page"))
            ts = int(time.time() * 1000)
            path = screenshot_dir / f"{fname}_{ts}.png"
            try:
                await page.screenshot(path=path, full_page=False)
                result["screenshot"] = str(path)
            except Exception:
                pass

        await context.close()

    except PWTimeout:
        result["status"] = "timeout"
        result["notes"] += "[navigation timeout] "
        try:
            if page:
                result["final_url"] = page.url
        except Exception:
            pass
    except Exception as e:
        msg = f"[error: {type(e).__name__}: {e}] "
        result["notes"] += msg
        # crude DNS hint
        if "ERR_NAME_NOT_RESOLVED" in msg or "getaddrinfo failed" in msg or "Name or service not known" in msg:
            result["status"] = "dns_error"
        else:
            result["status"] = "broken"
    finally:
        result["elapsed_sec"] = round(time.time() - start, 2)
        try:
            if page and not page.is_closed():
                await page.context.close()
        except Exception:
            pass

    return result


async def worker(name: int, queue: asyncio.Queue, browser, results: list, timeout_ms: int, screenshot_dir: Path):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            return
        idx, url = item
        try:
            res = await check_url(browser, url, timeout_ms=timeout_ms, screenshot_dir=screenshot_dir)
            results[idx] = res
            print(f"[worker {name}] {url} -> {res['status']} ({res.get('http_status')})")
        except Exception:
            traceback.print_exc()
        finally:
            queue.task_done()


async def run_checker(input_path: str, sheet: str | None, url_col: str, concurrency: int, timeout_ms: int, headed: bool, output_csv: str, output_json: str):
    # Load URLs
    input_path = Path(input_path)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if input_path.suffix.lower() in (".xlsx", ".xls"):
        df = pd.read_excel(input_path, sheet_name=sheet)
    else:
        df = pd.read_csv(input_path)

    # Find URL column (case-insensitive), default "url"
    url_candidates = [c for c in df.columns if c.lower() == url_col.lower()]
    if not url_candidates:
        # Try to infer: first column containing something that looks like a URL
        for c in df.columns:
            if df[c].astype(str).str.contains(r"https?://|www\.", case=False, regex=True).any():
                url_candidates = [c]
                break
    if not url_candidates:
        print("Could not find a URL column. Please specify with --url-col", file=sys.stderr)
        sys.exit(2)
    url_col = url_candidates[0]

    urls = [normalize_url(str(u)) for u in df[url_col].astype(str).tolist() if str(u).strip()]
    n = len(urls)
    results = [None] * n

    screenshot_dir = Path("screenshots")
    screenshot_dir.mkdir(exist_ok=True)

    # Launch browser
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed, args=[
            "--disable-blink-features=AutomationControlled",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-sandbox",
        ])

        # Producer-Consumer
        queue = asyncio.Queue()
        for i, u in enumerate(urls):
            queue.put_nowait((i, u))

        workers = []
        for w in range(concurrency):
            workers.append(asyncio.create_task(worker(w+1, queue, browser, results, timeout_ms, screenshot_dir)))
        # Add sentinels
        for _ in workers:
            queue.put_nowait(None)

        await queue.join()
        for w in workers:
            w.cancel()
        await browser.close()

    # Save outputs
    out_df = pd.DataFrame(results)
    out_df.to_csv(output_csv, index=False)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\nWrote: {output_csv}")
    print(f"Wrote: {output_json}")
    print(f"Screenshots: {screenshot_dir.resolve()}")


def main():
    parser = argparse.ArgumentParser(description="Human-reachable URL checker using a real browser (Playwright).")
    parser.add_argument("--input", required=True, help="Path to input Excel/CSV")
    parser.add_argument("--sheet", default=None, help="Excel sheet name (if Excel).")
    parser.add_argument("--url-col", default="url", help="Column name containing URLs (case-insensitive).")
    parser.add_argument("--concurrency", type=int, default=6, help="How many pages to check in parallel.")
    parser.add_argument("--timeout-ms", type=int, default=25000, help="Per-URL timeout in milliseconds.")
    parser.add_argument("--headed", action="store_true", help="Run with a visible browser (for local debugging).")
    parser.add_argument("--output-csv", default="link_check_results.csv", help="Path for results CSV.")
    parser.add_argument("--output-json", default="link_check_results.json", help="Path for results JSON.")
    args = parser.parse_args()

    asyncio.run(run_checker(
        input_path=args.input,
        sheet=args.sheet,
        url_col=args.url_col,
        concurrency=args.concurrency,
        timeout_ms=args.timeout_ms,
        headed=args.headed,
        output_csv=args.output_csv,
        output_json=args.output_json
    ))


if __name__ == "__main__":
    main()
