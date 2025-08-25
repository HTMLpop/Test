
#!/usr/bin/env python3
# FAST human-reachable URL checker (HTTP-only)
# - No browser, no screenshots
# - Treat 2xx/3xx/401/403/429 as working (with labels), 404/410/5xx as not working
# - Detect basic CAPTCHA/bot walls in HTML and mark as challenge (still working)
# - Robust URL extraction from multiple columns; fuzzy header matching
# - Concurrent HEAD->GET with aiohttp

import asyncio
import argparse
import json
import re
import sys
import time
from pathlib import Path

import ssl
import pandas as pd
import aiohttp
from aiohttp import ClientTimeout

# -------- Config --------
CHALLENGE_PATTERNS = [
    "just a moment", "checking your browser", "verifying you are human",
    "verify you are human", "are you a robot", "robot check", "captcha",
    "cf-chl", "cdn-cgi", "akamai", "perimeterx", "datadome", "sucuri",
]
PROTECTED_PATTERNS = ["sign in", "log in", "forbidden", "not authorized"]

URL_FIND_RE = re.compile(
    r'((?:https?://|ftp://)[^\s<>"\'"'\)\]]+|'
    r'www\.[^\s<>"\'"'\)\]]+|'
    r'(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<>"\'"'\)\]]*)?)'
)
TRAILING_PUNCT = '.,);]}>"\''
WS_NORM_RE = re.compile(r'\s+', re.UNICODE)
PUNC_NORM_RE = re.compile(r'[^a-z0-9]+')
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/127.0.0.0 Safari/537.36")

# -------- Helpers --------
def normalize_ws(s: str) -> str:
    return WS_NORM_RE.sub(' ', str(s).strip())

def normalize_col_key(s: str) -> str:
    return PUNC_NORM_RE.sub(' ', str(s).lower()).strip()

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
    if not re.match(r'^(?:https?|ftp)://', u, re.I):
        u = 'https://' + u
    return u

def classify_text(text: str) -> str:
    t = (text or "").lower()
    for pat in CHALLENGE_PATTERNS:
        if pat in t:
            return "challenge"
    for pat in PROTECTED_PATTERNS:
        if pat in t:
            return "protected"
    return "unknown"

def verdict_from_status(status: str, http_status: int | None) -> str:
    if status == "challenge":
        return "working (bot-blocked)"
    if status == "protected":
        return "working (gated)"
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
    if status == "dns_error":
        return "not_working (dns)"
    if status == "timeout":
        return "inconclusive (timeout)"
    if status == "reachable":
        return "working"
    if status == "broken":
        return "not_working"
    return "unknown"

# -------- URL collection --------
def collect_urls(df, url_col: str | None, url_cols: list[str] | None):
    col_map = {PUNC_NORM_RE.sub(' ', str(c).lower()).strip(): c for c in df.columns}

    selected_cols = []
    if url_cols:
        for raw in url_cols:
            key = PUNC_NORM_RE.sub(' ', str(raw).lower()).strip()
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
        elif url_col:
            key = PUNC_NORM_RE.sub(' ', str(url_col).lower()).strip()
            if key in col_map:
                add_series(df[col_map[key]])
            else:
                for c in df.columns:
                    add_series(df[c])
        else:
            for c in df.columns:
                add_series(df[c])

    seen, deduped = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped

# -------- Fast probe --------
async def fast_probe(session: aiohttp.ClientSession, url: str, timeout_ms: int):
    result = {
        "url": url, "final_url": None, "http_status": None,
        "status": "broken", "title": None, "notes": "", "elapsed_sec": None,
        "screenshot": None, "verdict": "unknown",
    }
    t0 = time.time()
    try:
        # HEAD
        try:
            async with session.head(url, allow_redirects=True) as r:
                result["http_status"] = r.status
                result["final_url"] = str(r.url)
                if 200 <= r.status < 400:
                    result["status"] = "reachable"; result["notes"] += f"[HEAD {r.status}] "
                elif r.status == 401:
                    result["status"] = "protected"; result["notes"] += "[HEAD 401] "
                elif r.status == 403:
                    result["status"] = "challenge"; result["notes"] += "[HEAD 403] "
                elif r.status == 429:
                    result["status"] = "reachable"; result["notes"] += "[HEAD 429] "
                elif r.status in (404, 410):
                    result["status"] = "broken"; result["notes"] += f"[HEAD {r.status}] "
                elif 500 <= r.status < 600:
                    result["status"] = "broken"; result["notes"] += f"[HEAD {r.status}] "
        except aiohttp.ClientResponseError as e:
            result["http_status"] = e.status; result["notes"] += f"[HEAD error {e.status}] "
        except asyncio.CancelledError:
            result["status"] = "broken"; result["notes"] += "[HEAD cancelled] "
        except Exception as e:
            result["notes"] += f"[HEAD {type(e).__name__}] "

        need_get = True
        if result["http_status"] is not None:
            if (200 <= result["http_status"] < 400) or result["http_status"] in (401,403,429,404,410,*range(500,600)):
                need_get = False

        if need_get:
            async with session.get(url, allow_redirects=True) as r:
                result["http_status"] = r.status
                result["final_url"] = str(r.url)
                ctype = (r.headers.get("Content-Type") or "").lower()

                body_text = ""
                if "html" in ctype:
                    body_bytes = await r.content.read(65536)
                    try:
                        body_text = body_bytes.decode(errors="ignore")
                    except Exception:
                        body_text = ""
                    cls = classify_text(body_text)
                    if cls == "challenge":
                        result["status"] = "challenge"; result["notes"] += "[GET challenge] "
                    elif cls == "protected":
                        result["status"] = "protected"; result["notes"] += "[GET protected] "

                if result["status"] not in ("challenge","protected"):
                    if 200 <= r.status < 400:
                        result["status"] = "reachable"
                    elif r.status == 401:
                        result["status"] = "protected"
                    elif r.status == 403:
                        result["status"] = "challenge"
                    elif r.status == 429:
                        result["status"] = "reachable"; result["notes"] += "[rate-limited] "
                    elif r.status in (404, 410):
                        result["status"] = "broken"
                    elif 500 <= r.status < 600:
                        result["status"] = "broken"
                    else:
                        result["status"] = "broken"

                if "html" not in ctype:
                    result["notes"] += f"[{r.status} {ctype}] "

        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"])
        return result

    except asyncio.TimeoutError:
        result["status"] = "timeout"; result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"]); result["notes"] += "[timeout] "
        return result
    except aiohttp.ClientConnectorError as e:
        msg = str(e).lower()
        result["status"] = "dns_error" if ("name or service not known" in msg or "nodename nor servname" in msg or "temporary failure in name resolution" in msg) else "broken"
        result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"]); result["notes"] += f"[connect {type(e).__name__}] "
        return result
    except ssl.SSLError:
        result["status"] = "broken"; result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"]); result["notes"] += "[ssl error] "
        return result
    except asyncio.CancelledError:
        result["status"] = "broken"; result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"]); result["notes"] += "[cancelled] "
        return result
    except Exception as e:
        result["status"] = "broken"; result["elapsed_sec"] = round(time.time() - t0, 2)
        result["verdict"] = verdict_from_status(result["status"], result["http_status"]); result["notes"] += f"[error {type(e).__name__}] "
        return result

# -------- Orchestration --------
async def run_checker(input_path: str, sheet: str | None, url_col: str | None, url_cols: list[str] | None,
                      concurrency: int, timeout_ms: int,
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
    connector = aiohttp.TCPConnector(limit=concurrency*2, ssl=ssl_ctx, ttl_dns_cache=60)
    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "DNT": "1"}

    sem = asyncio.Semaphore(concurrency)
    results = [None] * len(urls)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers=headers) as session:
        async def task(i, u):
            async with sem:
                res = await fast_probe(session, u, timeout_ms=timeout_ms)
                results[i] = res

        finished = await asyncio.gather(*[task(i, u) for i, u in enumerate(urls)], return_exceptions=True)
        for i, item in enumerate(finished):
            if isinstance(item, Exception) and results[i] is None:
                results[i] = {
                    "url": urls[i], "final_url": None, "http_status": None,
                    "status": "broken", "title": None, "notes": f"[gather {type(item).__name__}]", "elapsed_sec": None,
                    "screenshot": None, "verdict": "not_working"
                }

    out_df = pd.DataFrame(results)
    out_df.to_csv(output_csv, index=False)
    with open(output_json, "w", encoding="utf-8") as f: json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"Wrote: {output_csv} ({len(out_df)} rows)")

def main():
    p = argparse.ArgumentParser(description="Fast human-reachable URL checker (HTTP-only).")
    p.add_argument("--input", required=True, help="Path to input Excel/CSV")
    p.add_argument("--sheet", default=None, help="Excel sheet name (if Excel).")
    p.add_argument("--url-col", default=None, help="Single URL column name.")
    p.add_argument("--url-cols", default=None, help="Comma-separated list of URL column names.")
    p.add_argument("--concurrency", type=int, default=24, help="Parallel HTTP checks per shard.")
    p.add_argument("--timeout-ms", type=int, default=10000, help="Per-URL total timeout (ms).")
    p.add_argument("--output-csv", default="link_check_results.csv")
    p.add_argument("--output-json", default="link_check_results.json")
    args = p.parse_args()
    url_cols = [c.strip() for c in args.url_cols.split(",")] if args.url_cols else None
    asyncio.run(run_checker(args.input, args.sheet, args.url_col, url_cols,
                            args.concurrency, args.timeout_ms,
                            args.output_csv, args.output_json))

if __name__ == "__main__":
    main()
