#!/usr/bin/env python3
"""
Human-reachable URL checker using Playwright (Chromium).

Features:
- Real browser (Chromium via Playwright) with JS + redirects + light scrolling
- Detects bot walls (Cloudflare/Akamai/PerimeterX/Datadome/etc.)
- Multiple URL columns via --url-cols "ColA,ColB,ColC"
- Ignores empty/NaN cells, extracts URLs from mixed-text cells, and dedupes
- Robust column-name matching (case-insensitive; trims/normalizes whitespace)
- Falls back to scanning ALL columns if none of the requested names match
- Adds a 'verdict' column aligned with your rule:
    reachable  -> working
    protected  -> working (gated)
    challenge  -> working (bot-blocked)
    broken     -> not_working
    dns_error  -> not_working (dns)
    timeout    -> inconclusive (timeout)

Outputs:
  - CSV: link_check_results.csv (or per-shard names if passed via args)
  - JSON: link_check_results.json
  - Folder: screenshots/ (PNG per URL)

Install (first time):
  python -m pip install -r requirements.txt
  python -m playwright install chromium
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

# Find URLs *inside* cells (http(s), www., or bare domains)
URL_FIND_RE = re.compile(
    r'((?:https?://|ftp://)[^\s<>"\'\)\]]+|'
    r'www\.[^\s<>"\'\)\]]+|'
    r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>"\'\)\]]*)?)'
)

TRAILING_PUNCT = '.,);]}>\"\''
WS_NORM_RE = re.compile(r'\s+', re.UNICODE)

def normalize_ws(s: str) -> str:
    return WS_NORM_RE.sub(' ', s.strip())

def normalize_col_key(s: str) -> str:
    # Lowercase, collapse spaces, strip
    return normalize_ws(str(s)).lower()

def extract_urls_from_cell(val) -> list[str]:
    if val is None:
        return []
    s = str(val)
    if not s.strip():
        return []
    urls = []
    for m in URL_FIND_RE.finditer(s):
        candidate = m.group(0).strip().strip(TRAILING_PUNCT)
        if candidate:
            urls.append(candidate)
    return urls

def normalize_url(u: str) -> str:
    if not u:
        return u
    u = u.strip()
    if not u:
        return u
    # If missing scheme, assume https
    if not re.match(r"^(?:https?|ftp)://", u, re.I):
        u = "https://" + u
    return u

def classify_page_text(text: str) -> str:
    t = (text or "").lower()
    for pat in CHALLENGE_PATTERNS:
        if re.search(pat, t):
            return "challenge"
    for pat in PROTECTED_PATTERNS:
        if re.search(pat, t):
            return "protected"
    return "unknown"

def is_probably_html(content_type: str | None) -> bool:
    if not content_type:
        return True  # many sites don't set it properly
    return "text/html" in content_type.lower() or "application/xhtml+xml" in content_type.lower()

def verdict_from_status(status: str) -> str:
    if status == "reachable":
        return "working"
    if status == "protected":
        return "working (gated)"
    if status == "challenge":
        return "working (bot-blocked)"
    if status == "dns_error":
        return "not_working (dns)"
    if status == "broken":
        return "not_working"
    if status == "timeout":
        return "inconclusive (timeout)"
    return "unknown"

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
        "verdict": "unknown",
    }

    start = time.time()
    page = None
    try:
        context = await browser.new_context(
            locale="en-US",
            timezone_id="America/New_York",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/127.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1366, "height": 768},
            java_script_enabled=True,
            ignore_https_errors=False,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        page = await context.new_page()

        page.set_default_navigation_timeout(timeout_ms)
        page.set_default_timeout(timeout_ms)

        resp = await page.goto(url, wait_until="domcontentloaded")

        if resp:
            result["http_status"] = resp.status
            ct = resp.headers.get("content-type", "")
            if not is_probably_html(ct):
                result["notes"] += f"[non-HTML content-type: {ct}] "

        try:
            await page.wait_for_load_state("networkidle", timeout=timeout_ms // 2)
        except PWTimeout:
            pass

        try:
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight * 0.3)")
            await asyncio.sleep(0.3)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(0.3)
            await page.evaluate("window.scrollTo(0, 0)")
        except Exception:
            pass

        result["final_url"] = page.url
        try:
            result["title"] = await page.title()
        except Exception:
            result["title"] = None

        body_text = ""
        try:
            body_text = await page.inner_text("body")
            if body_text:
                body_text = body_text[:20000]
        except Exception:
            pass

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

        if screenshot_dir:
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            import re as _re
            from urllib.parse import urlparse as _urlparse
            fname = _re.sub(r"[^a-zA-Z0-9_-]+", "_", (_urlparse(result["final_url"] or url).netloc or "page"))
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

    result["verdict"] = verdict_from_status(result["status"])
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

def collect_urls(df, url_col: str | None, url_cols: list[str] | None):
    # Build normalized column lookup
    col_map = {normalize_col_key(c): c for c in df.columns}

    selected_cols = []
    if url_cols:
        for raw in url_cols:
            key = normalize_col_key(raw)
            if key in col_map:
                selected_cols.append(col_map[key])
            else:
                print(f"[warn] URL column not found (will try fallback later): {raw}", file=sys.stderr)

    scan_all = False
    if url_cols and not selected_cols:
        print("[warn] None of the requested URL columns matched; scanning ALL columns instead.", file=sys.stderr)
        scan_all = True

    urls = []
    def add_series(series):
        for val in series.tolist():
            for u in extract_urls_from_cell(val):
                urls.append(normalize_url(u))

    if scan_all:
        for c in df.columns:
            add_series(df[c])
    else:
        if selected_cols:
            for c in selected_cols:
                add_series(df[c])
        elif url_col and normalize_col_key(url_col) in col_map:
            add_series(df[col_map[normalize_col_key(url_col)]])
        else:
            # Fallback: scan all columns
            for c in df.columns:
                add_series(df[c])

    # Deduplicate, preserve order
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped

async def run_checker(input_path: str, sheet: str | None, url_col: str | None, url_cols: list[str] | None,
                      concurrency: int, timeout_ms: int, headed: bool, output_csv: str, output_json: str):
    input_path = Path(input_path)
    if not input_path.exists():
        print(f"Input not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if input_path.suffix.lower() in (".xlsx", ".xls"):
        df = pd.read_excel(input_path, sheet_name=sheet)
    else:
        df = pd.read_csv(input_path)

    urls = collect_urls(df, url_col=url_col, url_cols=url_cols)
    n = len(urls)
    if n == 0:
        # Write empty outputs and succeed so empty shards don't fail the job
        pd.DataFrame([], columns=[
            "url","final_url","status","http_status","title","notes","elapsed_sec","screenshot","verdict"
        ]).to_csv(output_csv, index=False)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump([], f)
        print("No URLs found in this shard; wrote empty results.")
        return

    results = [None] * n

    screenshot_dir = Path("screenshots")
    screenshot_dir.mkdir(exist_ok=True)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=not headed, args=[
            "--disable-blink-features=AutomationControlled",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-sandbox",
        ])

        queue = asyncio.Queue()
        for i, u in enumerate(urls):
            queue.put_nowait((i, u))

        workers = []
        for w in range(concurrency):
            workers.append(asyncio.create_task(worker(w+1, queue, browser, results, timeout_ms, screenshot_dir)))
        for _ in workers:
            queue.put_nowait(None)

        await queue.join()
        for w in workers:
            w.cancel()
        await browser.close()

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
    parser.add_argument("--url-col", default=None, help="Single column name containing URLs (case-insensitive).")
    parser.add_argument("--url-cols", default=None, help="Comma-separated list of URL column names (e.g., 'A,B,C').")
    parser.add_argument("--concurrency", type=int, default=6, help="How many pages to check in parallel.")
    parser.add_argument("--timeout-ms", type=int, default=25000, help="Per-URL timeout in milliseconds.")
    parser.add_argument("--headed", action="store_true", help="Run with a visible browser (for local debugging).")
    parser.add_argument("--output-csv", default="link_check_results.csv", help="Path for results CSV.")
    parser.add_argument("--output-json", default="link_check_results.json", help="Path for results JSON.")
    args = parser.parse_args()

    url_cols = [c.strip() for c in args.url_cols.split(",")] if args.url_cols else None

    asyncio.run(run_checker(
        input_path=args.input,
        sheet=args.sheet,
        url_col=args.url_col,
        url_cols=url_cols,
        concurrency=args.concurrency,
        timeout_ms=args.timeout_ms,
        headed=args.headed,
        output_csv=args.output_csv,
        output_json=args.output_json
    ))

if __name__ == "__main__":
    main()
