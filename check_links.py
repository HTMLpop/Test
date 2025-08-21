#!/usr/bin/env python3
import asyncio, ssl, argparse, sys
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import aiohttp

DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=20, connect=10)
HEADERS = {"User-Agent": "LinkChecker/1.0 (+github-actions)"}

def pick_column(df, user_col):
    if user_col and user_col in df.columns:
        return user_col
    # try a column with 'url' in the name
    candidates = [c for c in df.columns if "url" in str(c).lower()]
    if candidates:
        return candidates[0]
    # else scan for a column that looks like URLs
    for c in df.columns:
        series = df[c].astype(str).str.strip()
        if series.str.startswith(("http://", "https://")).mean() > 0.5:
            return c
    # fallback to first column
    return df.columns[0]

def categorize(status, error):
    if error:
        return "error"  # dns, timeout, ssl, etc.
    if status is None:
        return "error"
    if status in (401, 403):  # site exists but blocks bots/auth
        return "blocked"
    if status >= 500:
        return "broken"
    if status in (404, 410):
        return "broken"
    if 400 <= status < 500:
        # treat other 4xx as 'maybe blocked' unless you prefer 'broken'
        return "blocked"
    return "ok"

async def fetch_status(session, url):
    """
    Try HEAD first for speed; if method not allowed or suspicious, fall back to GET.
    If SSL fails, retry with verify disabled (flagged as ssl_error).
    """
    ssl_error = False
    final_url = None
    status = None
    error = None

    async def attempt(method, verify_ssl=True):
        nonlocal final_url, status
        try:
            resp = await session.request(
                method, url, allow_redirects=True, timeout=DEFAULT_TIMEOUT, ssl=verify_ssl
            )
            status = resp.status
            final_url = str(resp.url)
            await resp.release()
            return True
        except (aiohttp.ClientSSLError, ssl.SSLError):
            return "ssl_fail"
        except Exception as e:
            nonlocal_error = e
            return nonlocal_error

    # HEAD attempt
    res = await attempt("HEAD", verify_ssl=True)
    if res is True:
        if status in (405, 400, 501):  # some servers dislike HEAD
            res = await attempt("GET", verify_ssl=True)
    if res == "ssl_fail":
        # retry with ssl disabled and mark
        ssl_error = True
        res = await attempt("GET", verify_ssl=False)
    if isinstance(res, Exception):
        error = f"{type(res).__name__}: {res}"
    elif res is not True and res is not None:
        # unexpected marker
        error = str(res)

    return status, final_url or url, error, ssl_error

async def worker(name, session, urls, start_idx, total, verbose):
    results = []
    for i, url in enumerate(urls, start=start_idx+1):
        if not isinstance(url, str) or not url.lower().startswith(("http://","https://")):
            results.append((url, None, url, "InvalidURL", False))
            if verbose:
                print(f"[{i}/{total}] INVALID {url}", flush=True)
            continue
        status, final_url, error, ssl_error = await fetch_status(session, url)
        if verbose:
            tag = error.split(":")[0] if error else status
            print(f"[{i}/{total}] {tag} {url}", flush=True)
        results.append((url, status, final_url, error, ssl_error))
    return results

async def run(input_xlsx, sheet, colname, out_csv, out_xlsx, shard_index, shard_count, concurrency, verbose):
    df = pd.read_excel(input_xlsx, sheet_name=sheet, engine="openpyxl")
    url_col = pick_column(df, colname)
    urls = df[url_col].astype(str).str.strip().tolist()

    # sharding
    if shard_count > 1:
        urls = [u for idx, u in enumerate(urls) if idx % shard_count == shard_index]

    total = len(urls)
    connector = aiohttp.TCPConnector(limit=concurrency, ttl_dns_cache=300)
    async with aiohttp.ClientSession(headers=HEADERS, timeout=DEFAULT_TIMEOUT, connector=connector) as session:
        # simple chunked sequential to respect concurrency connector
        results = await worker("w", session, urls, 0, total, verbose)

    # build report
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    rows = []
    for url, status, final_url, error, ssl_error in results:
        rows.append({
            "url": url,
            "status": status,
            "category": categorize(status, error),
            "final_url": final_url,
            "error": error,
            "ssl_error": bool(ssl_error),
            "checked_at": now
        })
    rep = pd.DataFrame(rows)

    rep.to_csv(out_csv, index=False)
    print(f"Saved CSV report to {out_csv}", flush=True)

    if out_xlsx:
        # merge status back to original dataframe using the original column
        merged = df.copy()
        # make a dict for fast map
        status_map = {r["url"]: (r["status"], r["category"], r["final_url"], r["error"]) for r in rows}
        merged["status"] = merged[url_col].map(lambda u: status_map.get(str(u), (None, None, None, None))[0])
        merged["category"] = merged[url_col].map(lambda u: status_map.get(str(u), (None, None, None, None))[1])
        merged["final_url"] = merged[url_col].map(lambda u: status_map.get(str(u), (None, None, None, None))[2])
        merged["error"] = merged[url_col].map(lambda u: status_map.get(str(u), (None, None, None, None))[3])
        merged.to_excel(out_xlsx, index=False)
        print(f"Saved Excel with status to {out_xlsx}", flush=True)

def main():
    p = argparse.ArgumentParser(description="Async broken link checker for Excel.")
    p.add_argument("--input", default="urls.xlsx", help="Path to input Excel")
    p.add_argument("--sheet", default=None, help="Sheet name (optional)")
    p.add_argument("--column", default=None, help="Column name that holds URLs (auto-detect if omitted)")
    p.add_argument("--output", default="reports/link_report.csv", help="Output CSV path")
    p.add_argument("--output-xlsx", default="", help="Optional: write updated Excel with status")
    p.add_argument("--shard-index", type=int, default=0, help="Shard index (0-based)")
    p.add_argument("--shard-count", type=int, default=1, help="Total number of shards")
    p.add_argument("--concurrency", type=int, default=100, help="Parallel connections (connector limit)")
    p.add_argument("--verbose", action="store_true", help="Print each URL status")
    args = p.parse_args()

    # ensure reports folder exists
    import os
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    if args.output_xlsx:
        os.makedirs(os.path.dirname(args.output_xlsx) or ".", exist_ok=True)

    asyncio.run(run(
        input_xlsx=args.input,
        sheet=args.sheet,
        colname=args.column,
        out_csv=args.output,
        out_xlsx=args.output_xlsx or None,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        concurrency=args.concurrency,
        verbose=args.verbose
    ))

if __name__ == "__main__":
    # unbuffered prints for live logs in CI
    sys.stdout.reconfigure(line_buffering=True)
    main()
