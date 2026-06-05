#!/usr/bin/env python3
"""
╔══════════════════════════════════════╗
║        SITE CHECKER v1.0             ║
║   Website Health & Status Monitor    ║
╚══════════════════════════════════════╝
Usage:
  python sitechecker.py <url>
  python sitechecker.py <url1> <url2> ...
  python sitechecker.py --file urls.txt
"""

import sys
import time
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import argparse
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
R  = "\033[0m"       # Reset
BLD= "\033[1m"       # Bold
RED= "\033[91m"      # Red
GRN= "\033[92m"      # Green
YLW= "\033[93m"      # Yellow
BLU= "\033[94m"      # Blue
MAG= "\033[95m"      # Magenta
CYN= "\033[96m"      # Cyan
GRY= "\033[90m"      # Gray
WHT= "\033[97m"      # White

# ─── Config ───────────────────────────────────────────────────────────────────
TIMEOUT        = 10      # seconds
WARN_TIME_MS   = 1000    # response time warning threshold (ms)
SLOW_TIME_MS   = 3000    # response time "slow" threshold (ms)

# ─── HTTP Status code descriptions ────────────────────────────────────────────
HTTP_STATUS = {
    200: ("OK", GRN),
    201: ("Created", GRN),
    204: ("No Content", GRN),
    301: ("Moved Permanently", YLW),
    302: ("Found (Redirect)", YLW),
    304: ("Not Modified", YLW),
    400: ("Bad Request", YLW),
    401: ("Unauthorized", YLW),
    403: ("Forbidden", RED),
    404: ("Not Found", RED),
    408: ("Request Timeout", RED),
    429: ("Too Many Requests", YLW),
    500: ("Internal Server Error", RED),
    502: ("Bad Gateway", RED),
    503: ("Service Unavailable", RED),
    504: ("Gateway Timeout", RED),
}

def banner():
    print(f"""
{CYN}{BLD}╔══════════════════════════════════════════════╗
║  ███████╗██╗████████╗███████╗                ║
║  ██╔════╝██║╚══██╔══╝██╔════╝                ║
║  ███████╗██║   ██║   █████╗                  ║
║  ╚════██║██║   ██║   ██╔══╝                  ║
║  ███████║██║   ██║   ███████╗                ║
║  ╚══════╝╚═╝   ╚═╝   ╚══════╝  CHECKER v1.0 ║
╚══════════════════════════════════════════════╝{R}
{GRY}  Website Health & Status Monitor
  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}
""")

def normalize_url(url: str) -> str:
    """Add https:// if no scheme provided."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def dns_lookup(hostname: str) -> dict:
    """Perform DNS resolution and return info."""
    try:
        start = time.time()
        ip = socket.gethostbyname(hostname)
        elapsed = (time.time() - start) * 1000
        return {"ok": True, "ip": ip, "ms": round(elapsed, 2)}
    except socket.gaierror as e:
        return {"ok": False, "error": str(e)}

def ssl_check(hostname: str, port: int = 443) -> dict:
    """Check SSL certificate validity and expiry."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(TIMEOUT)
            s.connect((hostname, port))
            cert = s.getpeercert()

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expire_dt - now).days
            return {
                "ok": True,
                "expires": expire_dt.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "subject": dict(x[0] for x in cert.get("subject", [])),
            }
        return {"ok": True, "expires": "unknown", "days_left": -1}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"Cert invalid: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_check(url: str) -> dict:
    """Perform HTTP request and gather response info."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SiteChecker/1.0 (health monitor)",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }
        )
        start = time.time()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            elapsed_ms = (time.time() - start) * 1000
            headers = dict(resp.headers)
            # Read a small chunk to get content info
            content = resp.read(512)
            return {
                "ok": True,
                "status": resp.status,
                "final_url": resp.url,
                "elapsed_ms": round(elapsed_ms, 2),
                "headers": headers,
                "server": headers.get("Server", headers.get("server", "N/A")),
                "content_type": headers.get("Content-Type", headers.get("content-type", "N/A")),
                "redirected": resp.url != url,
            }
    except urllib.error.HTTPError as e:
        return {
            "ok": False,
            "status": e.code,
            "elapsed_ms": None,
            "error": str(e.reason),
        }
    except urllib.error.URLError as e:
        return {"ok": False, "status": None, "elapsed_ms": None, "error": str(e.reason)}
    except Exception as e:
        return {"ok": False, "status": None, "elapsed_ms": None, "error": str(e)}

def speed_label(ms: float) -> tuple:
    """Return speed label and color based on response time."""
    if ms < WARN_TIME_MS:
        return f"Fast ({ms}ms)", GRN
    elif ms < SLOW_TIME_MS:
        return f"Slow ({ms}ms)", YLW
    else:
        return f"Very Slow ({ms}ms)", RED

def check_site(url: str) -> dict:
    """Run all checks on a single URL."""
    url = normalize_url(url)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    result = {
        "url": url,
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
    }

    # DNS
    result["dns"] = dns_lookup(hostname)

    # HTTP
    result["http"] = http_check(url)

    # SSL (only for HTTPS)
    if parsed.scheme == "https":
        result["ssl"] = ssl_check(hostname, port)
    else:
        result["ssl"] = None

    return result

def print_result(result: dict, index: int = None, total: int = None):
    """Pretty-print the check result for one URL."""
    url      = result["url"]
    hostname = result["hostname"]
    dns      = result["dns"]
    http     = result["http"]
    ssl      = result.get("ssl")

    # Header
    counter = f"[{index}/{total}] " if index and total else ""
    print(f"\n{BLD}{WHT}{'─'*54}{R}")
    print(f"  {CYN}{BLD}{counter}🌐  {url}{R}")
    print(f"{BLD}{WHT}{'─'*54}{R}")

    # ── DNS ──
    print(f"\n  {BLD}{BLU}[ DNS ]{R}")
    if dns["ok"]:
        print(f"    {GRN}✔  Resolved{R}  →  {WHT}{dns['ip']}{R}  {GRY}({dns['ms']}ms){R}")
    else:
        print(f"    {RED}✘  Failed{R}  →  {dns['error']}")
        print(f"\n  {RED}{BLD}⛔  Site is UNREACHABLE (DNS failed){R}\n")
        return

    # ── HTTP ──
    print(f"\n  {BLD}{BLU}[ HTTP ]{R}")
    if http["ok"]:
        code = http["status"]
        desc, color = HTTP_STATUS.get(code, (f"Status {code}", YLW))
        speed_lbl, speed_color = speed_label(http["elapsed_ms"])

        print(f"    {color}●  {BLD}{code}{R} {color}{desc}{R}")
        print(f"    {GRY}⏱  Response   :{R} {speed_color}{speed_lbl}{R}")
        print(f"    {GRY}🖥  Server     :{R} {WHT}{http['server']}{R}")
        print(f"    {GRY}📄  Content    :{R} {WHT}{http['content_type'].split(';')[0]}{R}")

        if http["redirected"]:
            print(f"    {YLW}↪  Redirected to: {http['final_url']}{R}")

        # Overall status label
        if code == 200 and http["elapsed_ms"] < SLOW_TIME_MS:
            status_icon = f"{GRN}{BLD}✅  UP & HEALTHY{R}"
        elif code == 200:
            status_icon = f"{YLW}{BLD}⚠️  UP but SLOW{R}"
        elif 300 <= code < 400:
            status_icon = f"{YLW}{BLD}🔀  REDIRECTING{R}"
        elif 400 <= code < 500:
            status_icon = f"{RED}{BLD}❌  CLIENT ERROR{R}"
        else:
            status_icon = f"{RED}{BLD}🔴  SERVER ERROR / DOWN{R}"
    else:
        print(f"    {RED}✘  Request failed: {http['error']}{R}")
        status_icon = f"{RED}{BLD}🔴  DOWN / UNREACHABLE{R}"

    # ── SSL ──
    if ssl is not None:
        print(f"\n  {BLD}{BLU}[ SSL / TLS ]{R}")
        if ssl["ok"]:
            days = ssl["days_left"]
            exp  = ssl["expires"]
            if days > 30:
                cert_color, cert_icon = GRN, "✔"
            elif days > 7:
                cert_color, cert_icon = YLW, "⚠"
            else:
                cert_color, cert_icon = RED, "✘"
            print(f"    {cert_color}{cert_icon}  Valid{R}  — expires {WHT}{exp}{R}  {GRY}({days} days left){R}")
            cn = ssl.get("subject", {}).get("commonName", "N/A")
            print(f"    {GRY}🔐  Common Name: {WHT}{cn}{R}")
        else:
            print(f"    {RED}✘  SSL Error: {ssl['error']}{R}")
            status_icon = f"{RED}{BLD}🔴  SSL / CERT PROBLEM{R}"

    # ── Final verdict ──
    print(f"\n  {BLD}STATUS:{R}  {status_icon}")
    print(f"{BLD}{WHT}{'─'*54}{R}\n")

def main():
    parser = argparse.ArgumentParser(
        description="SiteChecker — Website health & status monitor",
        epilog="Example:\n  python sitechecker.py google.com github.com\n  python sitechecker.py --file urls.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("urls", nargs="*", help="URL(s) to check")
    parser.add_argument("--file", "-f", help="Text file with one URL per line")
    parser.add_argument("--json", "-j", action="store_true", help="Output raw JSON")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner")
    parser.add_argument("--workers", "-w", type=int, default=5, help="Parallel workers (default: 5)")
    args = parser.parse_args()

    urls = list(args.urls)

    if args.file:
        try:
            with open(args.file) as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            urls.extend(file_urls)
        except FileNotFoundError:
            print(f"{RED}Error: file '{args.file}' not found.{R}")
            sys.exit(1)

    if not urls:
        parser.print_help()
        print(f"\n{YLW}⚠  No URLs given. Try:{R}\n  python sitechecker.py google.com github.com\n")
        sys.exit(0)

    if not args.no_banner:
        banner()

    print(f"  {GRY}Checking {BLD}{WHT}{len(urls)}{R}{GRY} site(s) with {args.workers} workers...{R}")

    results = []

    if len(urls) == 1:
        result = check_site(urls[0])
        results.append(result)
        if not args.json:
            print_result(result)
    else:
        # Parallel checks
        ordered = {}
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(check_site, u): i for i, u in enumerate(urls)}
            for future in as_completed(futures):
                idx = futures[future]
                ordered[idx] = future.result()

        for i in range(len(urls)):
            results.append(ordered[i])
            if not args.json:
                print_result(ordered[i], index=i+1, total=len(urls))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        # Summary table
        if len(results) > 1:
            print(f"\n{BLD}{CYN}{'═'*54}")
            print(f"  SUMMARY ({len(results)} sites)")
            print(f"{'═'*54}{R}")
            for r in results:
                http = r.get("http", {})
                code = http.get("status", "ERR")
                ms   = http.get("elapsed_ms")
                if http.get("ok") and code == 200:
                    icon  = f"{GRN}✅"
                    state = f"{GRN}UP{R}"
                elif http.get("ok") and isinstance(code, int) and code < 400:
                    icon  = f"{YLW}⚠️"
                    state = f"{YLW}{code}{R}"
                else:
                    icon  = f"{RED}🔴"
                    state = f"{RED}DOWN{R}"
                ms_str = f"{ms}ms" if ms else "N/A"
                print(f"  {icon}  {WHT}{r['hostname']:<35}{R}  {state}  {GRY}{ms_str}{R}")
            print(f"{BLD}{CYN}{'═'*54}{R}\n")

if __name__ == "__main__":
    main()
    
