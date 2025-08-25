#!/usr/bin/env python3
"""
FAST human-reachable URL checker.

Design:
- Stage 1 (fast, default): concurrent HTTP HEAD→GET using aiohttp (no browser).
  • Counts as WORKING if we can reach the server and get:
      - 2xx–3xx status (OK/redirect)
      - 403 (treat as working per request)
      - 401 (working, gated/auth)
      - 429 (working, rate-limited)
  • 404/410 -> not_working
  • 5xx -> not_working
  • Timeouts/DNS/SSL errors -> not_working (with reason)
  • If GET body is HTML and contains common bot walls/CAPTCHAs, mark status=challenge
    (verdict = working (bot-blocked))

- Stage 2 (optional): Playwright browser fallback ONLY if requested via --browser-fallback,
  used when Stage 1 is inconclusive. (We keep this optional for speed.)

Multi-column & robust parsing:
- Use --url-cols "Col A,Col B,Col C" (case-insensitive; whitespace-normalized).
- Extracts URLs from mixed-text cells; ignores blanks/NaN; dedupes.

Verdicts:
  reachable           -> working
  protected (401/forbidden/gated) -> working (gated)
  challenge (CAPTCHA/bot wall)    -> working (bot-blocked)
  403                               -> working (403)
  429                               -> working (rate-limited)
  broken/5xx/404/410               -> not_working
  dns_error                         -> not_working (dns)
  timeout                           -> inconclusive (timeout)
"""

import asyncio
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

import ssl
import pandas as pd
import aiohttp
from aiohttp import ClientTimeout

# ---------- Config ----------

CHALLENGE_PATTERNS = [
    r"just a moment", r"checking your browser", r"verifying you are human",
    r"verify you are human", r"are you a robot", r"robot check", r"captcha",
    r"cf-chl", r"cdn-cgi", r"akamai", r"perimeterx", r"datadome", r"sucuri",
]
PROTECTED_PATTERNS = [r"sign in", r"log in", r"forbidden", r"not authorized"]
URL_FIND_RE = re.compile(
    r'((?:https?://|ftp://)[^\s<>"\'\)\]]+|'
    r'www\.[^\s<>"\'\)\]]+|'
    r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>"\'\)\]]*)?)'
)
TRAILING_PUNCT = '.,);]}>\"\''
WS_NORM_RE = re.compile(r'\s+', re.UNICODE)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")

# ---------- Helpers ----------

def normalize_ws(s: str) -> str:
    return WS_NORM_RE.sub(' ', s.strip())

def normalize_col_key(s: str) -> str:
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
    if not re.match(r"^(?:https?|ftp)://", u, re.I):
        u = "https://" + u
    return u

def classify_text(text: str) -> str:
    t = (text or "").lower()
    for pat in CHALLENGE_PATTERNS:
        if re.search(pat, t):
            return "challenge"
    for pat in PROTECTED_PATTERNS:
        if re.search(pat, t):
            return "protected"
    return "unknown"

def verdict_from_status(status: str, http_status: int | None) -> str:
    # Forced working classes first
    if status == "challenge":
        return "working (bot-blocked)"
    if status == "protected":
        return "working (gated)"
    # HTTP-code based mapping
    if http_status is not None:
        if 200 <= http_status < 400:
            return "working"
        if http_status == 403:
            return "working (403)"
        if http_status == 401:
            return "working (gated)"
        if http_status == 429:
            return "working (rate-limited)"
        if http_status in (404, 410):
            return "not_working"
        if 500 <= http_status < 600:
            return "not_working"
    # Non-HTTP classes
    if status == "dns_error":
        return "not_working (dns)"
    if status == "timeout":
        return "inconclusive (timeout)"
    if status == "reachable":
        return "working"
    if status == "broken":
        return "not_working"
    return "unknown"

# ---------- URL collection ----------

def collect_urls(df, url_col: str | None, url_cols: list[str] | None):
    col_map = {normalize_col_key(c): c for c in df.columns}
    selected_cols = []
    if url_cols:
        for raw in url_cols:
            key = normalize_col_key(raw)
            if key in col_map:
                selected_cols.append(col_map[key])
            else:
                print(f"[warn] URL column not found (fallback to scan-all if none match): {raw}", file=sys.stderr)
    scan_all = False
    if url_cols and not selected_cols:
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
            for c in df.columns:
                add_series(df[c])

    # dedupe
    seen, deduped = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped

# ---------- Fast probe (HEAD->GET) ----------

async def fast_probe(session: aiohttp.ClientSession, url: str, timeout_ms: int):
    """
    Returns dict with: url, final_url, http_status, status, notes, elapsed_sec, verdict
    """
    result = {
        "url": url, "final_url": None, "http_status": None,
        "status": "broken", "title": None, "notes": "", "elapsed_sec": None,
        "screenshot": None,  # kept for schema compatibility
        "verdict": "unknown",
    }
    t0 = time.time()
    try:
        # HEAD first
        try:
            async with session.head(url, allow_redirects=True) as r:
                result["http_status"] = r.status
                result["final_url"] = str(r.url)
                # If good code, classify quickly
                if 200 <= r.status < 400 or r.status in (401, 403, 429):
                    result["status"] = "reachable" if 200 <= r.status < 400 else \
                                       ("protected" if r.status == 401 else "challenge" if r.status in (403,) else "reachable")
                    result["notes"] += f"[HEAD {r.status}] "
        except aiohttp.ClientResponseError as e:
            result["http_status"] = e.status
            result["notes"] += f"[HEAD error {e.status}] "
        except Exception as e:
            result["notes"] += f"[HEAD exception {type(e).__name__}] "

        # If we still don't have a decisive answer or want HTML signals, do a tiny GET
        need_get = True
        if result["http_status"] is not None:
            if (200 <= result["http_status"] < 400) or result["http_status"] in (401, 403, 429, 404, 410, *range(500,600)):
                need_get = False  # already decisive

        if need_get:
            async with session.get(url, allow_redirects=True) as r:
                result["http_status"] = r.status
                result["final_url"] = str(r.url)
                ctype = r.headers.get("Content-Type", "")
                # Peek limited body for CAPTCHA/bot-wall signals (HTML only)
                body_text = ""
                if "html" in ctype.lower():
                    body_bytes = await r.content.read(65536)
                    try:
                        body_text = body_bytes.decode(errors="ignore")
                    except Exception:
                        body_text = ""
                    cls = classify_text(body_text)
                    if cls == "challenge":
                        result["status"] = "challenge"
                        result["notes"] += "[GET challenge detected] "
                    elif cls == "protected":
                        result["status"] = "protected"
                        result["notes"] += "[GET protected/gated] "

                # If not set by challenge/protected, map by code
                if result["status"] not in ("challenge", "protected"):
                    if 200 <= r.status < 400:
                        result["status"] = "reachable"
                    elif r.status == 401:
                        result["status"] = "protected"
                    elif r.status == 403:
                        # Treat as working (bot-blocked)
                        result["status"] = "challenge"
                    elif r.status == 429:
                        # Treat as working (rate-limited)
                        result["status"] = "reachable"
                        result["notes"] += "[rate-limited] "
                    elif r.status in (404, 410):
                        result["status"] = "broken"
                    elif 500 <= r.status < 600:
                        result["status"] = "broken"
                    else:
                        result["status"] = "broken"

                if "html" not in ctype.lower():
                    result["notes"] += f"[{r.status} {ctype}] "

        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        return result

    except asyncio.TimeoutError:
        result["status"] = "timeout"
        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        result["notes"] += "[timeout] "
        return result
    except aiohttp.ClientConnectorError as e:
        result["status"] = "dns_error" if "Name or service not known" in str(e) or "nodename nor servname provided" in str(e) else "broken"
        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        result["notes"] += f"[connect {type(e).__name__}] "
        return result
    except ssl.SSLError as e:
        result["status"] = "broken"
        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        result["notes"] += "[ssl error] "
        return result
    except Exception as e:
        result["status"] = "broken"
        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        result["notes"] += f"[error {type(e).__name__}] "
        return result

# ---------- Optional browser fallback (kept minimal; disabled by default) ----------

async def browser_fallback_check(url: str, timeout_ms: int):
    try:
        from playwright.async_api import async_playwright, TimeoutError as PWTimeout
    except Exception:
        return None  # playwright not available

    result = {
        "url": url, "final_url": None, "http_status": None,
        "status": "broken", "title": None, "notes": "[browser fallback] ",
        "elapsed_sec": None, "screenshot": None, "verdict": "unknown",
    }
    t0 = time.time()
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=[
                "--disable-blink-features=AutomationControlled",
                "--no-default-browser-check","--disable-gpu","--disable-dev-shm-usage","--no-sandbox",
            ])
            ctx = await browser.new_context(
                locale="en-US", timezone_id="America/New_York",
                user_agent=UA, viewport={"width":1366,"height":768},
                java_script_enabled=True, ignore_https_errors=False,
                extra_http_headers={"Accept-Language":"en-US,en;q=0.9","DNT":"1","Upgrade-Insecure-Requests":"1"},
            )
            page = await ctx.new_page()
            page.set_default_navigation_timeout(timeout_ms)
            page.set_default_timeout(timeout_ms)
            resp = await page.goto(url, wait_until="domcontentloaded")
            if resp:
                result["http_status"] = resp.status
            await page.wait_for_load_state("networkidle", timeout=timeout_ms//2)
            result["final_url"] = page.url
            txt = ""
            try:
                txt = await page.inner_text("body")
            except Exception:
                pass
            cls = classify_text(txt)
            if cls == "challenge":
                result["status"] = "challenge"
            elif cls == "protected":
                result["status"] = "protected"
            else:
                result["status"] = "reachable"
            await ctx.close()
            await browser.close()
    except Exception as e:
        result["status"] = "broken"
        result["notes"] += f"[fallback error {type(e).__name__}] "
    result["elapsed_sec"] = round(time.time() - t0, 2)
    result["verdict"] = verdict_from_status(result["status"], result["http_status"])
    return result

# ---------- Orchestration ----------

async def run_checker(input_path: str, sheet: str | None, url_col: str | None, url_cols: list[str] | None,
                      concurrency: int, timeout_ms: int, browser_fallback: bool,
                      output_csv: str, output_json: str):
    ip = Path(input_path)
    if not ip.exists():
        print(f"Input not found: {ip}", file=sys.stderr); sys.exit(1)

    df = pd.read_excel(ip, sheet_name=sheet) if ip.suffix.lower() in (".xlsx",".xls") else pd.read_csv(ip)
    urls = collect_urls(df, url_col=url_col, url_cols=url_cols)
    if not urls:
        pd.DataFrame([], columns=["url","final_url","status","http_status","title","notes","elapsed_sec","screenshot","verdict"]).to_csv(output_csv, index=False)
        with open(output_json, "w", encoding="utf-8") as f: json.dump([], f)
        print("No URLs found in this shard; wrote empty results."); return

    timeout = ClientTimeout(total=timeout_ms/1000.0, connect=5, sock_read=7)
    ssl_ctx = ssl.create_default_context()
    connector = aiohttp.TCPConnector(limit=concurrency*2, ssl=ssl_ctx)
    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "DNT": "1"}

    sem = asyncio.Semaphore(concurrency)
    results = [None] * len(urls)

    async def task(i, u):
        async with sem:
            async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
                fast_res = await fast_probe(session, u, timeout_ms=timeout_ms)
            if browser_fallback and fast_res["verdict"] in ("unknown", "not_working", "inconclusive (timeout)"):
                fb = await browser_fallback_check(u, timeout_ms=timeout_ms)
                if fb and fb["verdict"].startswith("working"):
                    results[i] = fb
                    return
            results[i] = fast_res

    await asyncio.gather(*[task(i, u) for i, u in enumerate(urls)])

    out_df = pd.DataFrame(results)
    out_df.to_csv(output_csv, index=False)
    with open(output_json, "w", encoding="utf-8") as f: json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"Wrote: {output_csv} ({len(out_df)} rows)")

def main():
    p = argparse.ArgumentParser(description="Fast human-reachable URL checker (HTTP-first; optional browser fallback).")
    p.add_argument("--input", required=True, help="Path to input Excel/CSV")
    p.add_argument("--sheet", default=None, help="Excel sheet name (if Excel).")
    p.add_argument("--url-col", default=None, help="Single URL column name.")
    p.add_argument("--url-cols", default=None, help="Comma-separated list of URL column names.")
    p.add_argument("--concurrency", type=int, default=20, help="Parallel HTTP checks per shard.")
    p.add_argument("--timeout-ms", type=int, default=12000, help="Per-URL total timeout (ms).")
    p.add_argument("--browser-fallback", action="store_true", help="Use Playwright only on inconclusive results.")
    p.add_argument("--output-csv", default="link_check_results.csv")
    p.add_argument("--output-json", default="link_check_results.json")
    args = p.parse_args()
    url_cols = [c.strip() for c in args.url_cols.split(",")] if args.url_cols else None
    asyncio.run(run_checker(args.input, args.sheet, args.url_col, url_cols,
                            args.concurrency, args.timeout_ms, args.browser_fallback,
                            args.output_csv, args.output_json))

if __name__ == "__main__":
    main()
