#!/usr/bin/env python3
"""
HALIM-SOC SITE CHECKER
by Halim-Soc
"""

import sys
import time
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Colors ───────────────────────────────────────────────────────────────────
R   = "\033[0m"
BLD = "\033[1m"
RED = "\033[91m"
GRN = "\033[92m"
YLW = "\033[93m"
BLU = "\033[94m"
CYN = "\033[96m"
GRY = "\033[90m"
WHT = "\033[97m"

TIMEOUT      = 10
WARN_TIME_MS = 1000
SLOW_TIME_MS = 3000

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

def clear():
    print("\033[2J\033[H", end="")

def banner():
    clear()
    print(f"""
{CYN}{BLD}╔═══════════════════════════════════════════════════════╗
║  ██╗  ██╗ █████╗ ██╗     ██╗███╗   ███╗             ║
║  ██║  ██║██╔══██╗██║     ██║████╗ ████║             ║
║  ███████║███████║██║     ██║██╔████╔██║             ║
║  ██╔══██║██╔══██║██║     ██║██║╚██╔╝██║             ║
║  ██║  ██║██║  ██║███████╗██║██║ ╚═╝ ██║             ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝             ║
║                                                       ║
║           --  S O C  S I T E  C H E C K E R  --      ║
║                      by  Halim-Soc                    ║
╚═══════════════════════════════════════════════════════╝{R}
{GRY}  Website Health & Status Monitor
  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}
""")

# ─── Core check functions ──────────────────────────────────────────────────────

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def dns_lookup(hostname):
    try:
        start = time.time()
        ip = socket.gethostbyname(hostname)
        elapsed = (time.time() - start) * 1000
        return {"ok": True, "ip": ip, "ms": round(elapsed, 2)}
    except socket.gaierror as e:
        return {"ok": False, "error": str(e)}

def ssl_check(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(TIMEOUT)
            s.connect((hostname, port))
            cert = s.getpeercert()
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expire_dt - datetime.now(timezone.utc)).days
            return {"ok": True, "expires": expire_dt.strftime("%Y-%m-%d"), "days_left": days_left,
                    "subject": dict(x[0] for x in cert.get("subject", []))}
        return {"ok": True, "expires": "unknown", "days_left": -1}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": f"Cert invalid: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_check(url):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Halim-Soc SiteChecker/1.0",
            "Accept": "text/html,*/*",
        })
        start = time.time()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            elapsed_ms = (time.time() - start) * 1000
            headers = dict(resp.headers)
            resp.read(512)
            return {
                "ok": True, "status": resp.status,
                "final_url": resp.url,
                "elapsed_ms": round(elapsed_ms, 2),
                "server": headers.get("Server", headers.get("server", "N/A")),
                "content_type": headers.get("Content-Type", headers.get("content-type", "N/A")),
                "redirected": resp.url != url,
            }
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "elapsed_ms": None, "error": str(e.reason)}
    except urllib.error.URLError as e:
        return {"ok": False, "status": None, "elapsed_ms": None, "error": str(e.reason)}
    except Exception as e:
        return {"ok": False, "status": None, "elapsed_ms": None, "error": str(e)}

def speed_label(ms):
    if ms < WARN_TIME_MS:
        return f"Fast ({ms}ms)", GRN
    elif ms < SLOW_TIME_MS:
        return f"Slow ({ms}ms)", YLW
    else:
        return f"Very Slow ({ms}ms)", RED

def check_site(url):
    url = normalize_url(url)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result = {"url": url, "hostname": hostname, "timestamp": datetime.now().isoformat()}
    result["dns"]  = dns_lookup(hostname)
    result["http"] = http_check(url)
    result["ssl"]  = ssl_check(hostname, port) if parsed.scheme == "https" else None
    return result

def print_result(result, index=None, total=None):
    dns  = result["dns"]
    http = result["http"]
    ssl  = result.get("ssl")
    counter = f"[{index}/{total}] " if index and total else ""

    print(f"\n{BLD}{WHT}{'─'*54}{R}")
    print(f"  {CYN}{BLD}{counter}  {result['url']}{R}")
    print(f"{BLD}{WHT}{'─'*54}{R}")

    print(f"\n  {BLD}{BLU}[ DNS ]{R}")
    if dns["ok"]:
        print(f"    {GRN}OK  Resolved  -->  {WHT}{dns['ip']}{R}  {GRY}({dns['ms']}ms){R}")
    else:
        print(f"    {RED}GAGAL  --> {dns['error']}{R}")
        print(f"\n  {RED}{BLD}  Site TIDAK BISA DIAKSES (DNS gagal){R}\n")
        return

    print(f"\n  {BLD}{BLU}[ HTTP ]{R}")
    if http["ok"]:
        code = http["status"]
        desc, color = HTTP_STATUS.get(code, (f"Status {code}", YLW))
        speed_lbl, speed_color = speed_label(http["elapsed_ms"])
        print(f"    {color}  {BLD}{code}{R} {color}{desc}{R}")
        print(f"    {GRY}Respon     :{R} {speed_color}{speed_lbl}{R}")
        print(f"    {GRY}Server     :{R} {WHT}{http['server']}{R}")
        print(f"    {GRY}Konten     :{R} {WHT}{http['content_type'].split(';')[0]}{R}")
        if http["redirected"]:
            print(f"    {YLW}>> Redirect ke: {http['final_url']}{R}")
        if code == 200 and http["elapsed_ms"] < SLOW_TIME_MS:
            status_icon = f"{GRN}{BLD}[OK] UP & NORMAL{R}"
        elif code == 200:
            status_icon = f"{YLW}{BLD}[!!] UP tapi LAMBAT{R}"
        elif 300 <= code < 400:
            status_icon = f"{YLW}{BLD}[>>] REDIRECT{R}"
        elif 400 <= code < 500:
            status_icon = f"{RED}{BLD}[X] ERROR CLIENT{R}"
        else:
            status_icon = f"{RED}{BLD}[X] SERVER ERROR / DOWN{R}"
    else:
        print(f"    {RED}Gagal konek: {http['error']}{R}")
        status_icon = f"{RED}{BLD}[X] DOWN / TIDAK BISA DIAKSES{R}"

    if ssl is not None:
        print(f"\n  {BLD}{BLU}[ SSL / TLS ]{R}")
        if ssl["ok"]:
            days = ssl["days_left"]
            exp  = ssl["expires"]
            cert_color = GRN if days > 30 else (YLW if days > 7 else RED)
            cert_icon  = "OK" if days > 30 else ("!!" if days > 7 else "XX")
            print(f"    {cert_color}[{cert_icon}] Valid{R}  -- expired {WHT}{exp}{R}  {GRY}({days} hari lagi){R}")
            cn = ssl.get("subject", {}).get("commonName", "N/A")
            print(f"    {GRY}Nama    : {WHT}{cn}{R}")
        else:
            print(f"    {RED}SSL Error: {ssl['error']}{R}")
            status_icon = f"{RED}{BLD}[X] MASALAH SSL / SERTIFIKAT{R}"

    print(f"\n  {BLD}STATUS:  {status_icon}")
    print(f"{BLD}{WHT}{'─'*54}{R}\n")

# ─── MENU FUNCTIONS ────────────────────────────────────────────────────────────

def menu_cek_satu():
    banner()
    print(f"  {CYN}{BLD}[ CEK 1 WEBSITE ]{R}\n")
    url = input(f"  {WHT}Masukkan URL website{R} {GRY}(contoh: google.com){R}\n  > ").strip()
    if not url:
        print(f"\n  {RED}URL tidak boleh kosong!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return
    print(f"\n  {GRY}Sedang mengecek, tunggu sebentar...{R}\n")
    result = check_site(url)
    print_result(result)
    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

def menu_cek_banyak():
    banner()
    print(f"  {CYN}{BLD}[ CEK BANYAK WEBSITE ]{R}\n")
    print(f"  {GRY}Masukkan URL satu per satu.")
    print(f"  Ketik 'selesai' kalau sudah.{R}\n")
    urls = []
    while True:
        url = input(f"  {WHT}URL ke-{len(urls)+1}{R} {GRY}(atau 'selesai'){R}: ").strip()
        if url.lower() == "selesai":
            break
        if url:
            urls.append(url)
    if not urls:
        print(f"\n  {RED}Tidak ada URL yang dimasukkan!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return
    print(f"\n  {GRY}Mengecek {len(urls)} website secara bersamaan...{R}\n")
    ordered = {}
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(check_site, u): i for i, u in enumerate(urls)}
        for future in as_completed(futures):
            idx = futures[future]
            ordered[idx] = future.result()
    results = [ordered[i] for i in range(len(urls))]
    for i, r in enumerate(results):
        print_result(r, index=i+1, total=len(results))
    # Summary
    print(f"\n{BLD}{CYN}{'═'*54}")
    print(f"  HALIM-SOC | RINGKASAN ({len(results)} website)")
    print(f"{'═'*54}{R}")
    for r in results:
        http = r.get("http", {})
        code = http.get("status", "ERR")
        ms   = http.get("elapsed_ms")
        if http.get("ok") and code == 200:
            icon  = f"{GRN}[OK]"
            state = f"{GRN}UP{R}"
        elif http.get("ok") and isinstance(code, int) and code < 400:
            icon  = f"{YLW}[!!]"
            state = f"{YLW}{code}{R}"
        else:
            icon  = f"{RED}[X] "
            state = f"{RED}DOWN{R}"
        ms_str = f"{ms}ms" if ms else "N/A"
        print(f"  {icon}  {WHT}{r['hostname']:<35}{R}  {state}  {GRY}{ms_str}{R}")
    print(f"{BLD}{CYN}{'═'*54}{R}\n")
    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

def menu_dari_file():
    banner()
    print(f"  {CYN}{BLD}[ CEK DARI FILE .TXT ]{R}\n")
    print(f"  {GRY}Buat file teks dulu, isi dengan URL per baris.")
    print(f"  Contoh isi file:{R}")
    print(f"    google.com")
    print(f"    github.com")
    print(f"    tokopedia.com\n")
    nama_file = input(f"  {WHT}Nama file{R} {GRY}(contoh: daftar.txt){R}\n  > ").strip()
    if not nama_file:
        print(f"\n  {RED}Nama file tidak boleh kosong!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return
    try:
        with open(nama_file) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not urls:
            print(f"\n  {RED}File kosong atau tidak ada URL di dalamnya!{R}")
            input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
            return
        print(f"\n  {GRY}Ditemukan {len(urls)} URL. Mengecek...{R}\n")
        ordered = {}
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(check_site, u): i for i, u in enumerate(urls)}
            for future in as_completed(futures):
                idx = futures[future]
                ordered[idx] = future.result()
        results = [ordered[i] for i in range(len(urls))]
        for i, r in enumerate(results):
            print_result(r, index=i+1, total=len(results))
        print(f"\n{BLD}{CYN}{'═'*54}")
        print(f"  HALIM-SOC | RINGKASAN ({len(results)} website)")
        print(f"{'═'*54}{R}")
        for r in results:
            http = r.get("http", {})
            code = http.get("status", "ERR")
            ms   = http.get("elapsed_ms")
            if http.get("ok") and code == 200:
                icon  = f"{GRN}[OK]"
                state = f"{GRN}UP{R}"
            elif http.get("ok") and isinstance(code, int) and code < 400:
                icon  = f"{YLW}[!!]"
                state = f"{YLW}{code}{R}"
            else:
                icon  = f"{RED}[X] "
                state = f"{RED}DOWN{R}"
            ms_str = f"{ms}ms" if ms else "N/A"
            print(f"  {icon}  {WHT}{r['hostname']:<35}{R}  {state}  {GRY}{ms_str}{R}")
        print(f"{BLD}{CYN}{'═'*54}{R}\n")
    except FileNotFoundError:
        print(f"\n  {RED}File '{nama_file}' tidak ditemukan!{R}")
    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

def menu_tentang():
    banner()
    print(f"  {CYN}{BLD}[ TENTANG TOOLS INI ]{R}\n")
    print(f"  {WHT}Nama    :{R} Halim-Soc Site Checker")
    print(f"  {WHT}Dibuat  :{R} Halim-Soc")
    print(f"  {WHT}Versi   :{R} 2.0 (Menu Edition)\n")
    print(f"  {BLU}Apa yang dicek:{R}")
    print(f"  {GRY}  DNS    {R}-- Apakah alamat website bisa ditemukan")
    print(f"  {GRY}  HTTP   {R}-- Apakah website bisa diakses & kode statusnya")
    print(f"  {GRY}  Respon {R}-- Seberapa cepat website merespon")
    print(f"  {GRY}  SSL    {R}-- Apakah sertifikat keamanan masih valid\n")
    print(f"  {BLU}Arti status:{R}")
    print(f"  {GRN}  [OK] UP & NORMAL   {R}-- Website jalan normal")
    print(f"  {YLW}  [!!] UP tapi LAMBAT{R}-- Website nyala tapi lambat")
    print(f"  {YLW}  [>>] REDIRECT      {R}-- Diarahkan ke alamat lain")
    print(f"  {RED}  [X]  DOWN          {R}-- Website mati / tidak bisa diakses\n")
    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

# ─── IP TRACKER ───────────────────────────────────────────────────────────────

def menu_ip_tracker():
    banner()
    print(f"  {CYN}{BLD}[ IP TRACKER ]{R}\n")
    print(f"  {GRY}Catatan: Lokasi dari IP hanya akurat sampai level")
    print(f"  kota/ISP, bukan alamat persis.{R}\n")
    ip = input(f"  {WHT}Masukkan IP address{R} {GRY}(contoh: 8.8.8.8){R}\n  > ").strip()
    if not ip:
        print(f"\n  {RED}IP tidak boleh kosong!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return

    print(f"\n  {GRY}Sedang melacak, tunggu sebentar...{R}\n")

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,lat,lon,query"
        req = urllib.request.Request(url, headers={"User-Agent": "Halim-Soc IPTracker/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "fail":
            print(f"  {RED}Gagal: {data.get('message', 'IP tidak valid')}{R}")
            input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
            return

        lat  = data.get("lat", 0)
        lon  = data.get("lon", 0)
        maps = f"https://maps.google.com/?q={lat},{lon}"

        print(f"  {BLD}{WHT}{'─'*50}{R}")
        print(f"  {CYN}{BLD}  HASIL LACAK IP{R}")
        print(f"  {BLD}{WHT}{'─'*50}{R}\n")
        print(f"  {GRY}IP Address  :{R} {WHT}{data.get('query', ip)}{R}")
        print(f"  {GRY}Negara      :{R} {WHT}{data.get('country', 'N/A')}{R}")
        print(f"  {GRY}Provinsi    :{R} {WHT}{data.get('regionName', 'N/A')}{R}")
        print(f"  {GRY}Kota        :{R} {WHT}{data.get('city', 'N/A')}{R}")
        print(f"  {GRY}ISP         :{R} {WHT}{data.get('isp', 'N/A')}{R}")
        print(f"  {GRY}Organisasi  :{R} {WHT}{data.get('org', 'N/A')}{R}")
        print(f"  {GRY}Koordinat   :{R} {WHT}{lat}, {lon}{R}")
        print(f"\n  {BLD}{GRN}[ LINK GOOGLE MAPS ]{R}")
        print(f"  {YLW}{maps}{R}")
        print(f"\n  {GRY}Copy link di atas, paste di Chrome untuk lihat lokasinya!{R}")
        print(f"\n  {BLD}{WHT}{'─'*50}{R}\n")

    except Exception as e:
        print(f"  {RED}Error: {e}{R}\n")

    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

# ─── PORT SCANNER ─────────────────────────────────────────────────────────────

def menu_port_scanner():
    banner()
    print(f"  {CYN}{BLD}[ PORT SCANNER ]{R}\n")
    print(f"  {GRY}Cek port mana aja yang terbuka di sebuah server.{R}\n")
    target = input(f"  {WHT}Masukkan IP / domain{R} {GRY}(contoh: google.com){R}\n  > ").strip()
    if not target:
        print(f"\n  {RED}Target tidak boleh kosong!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return

    mode = input(f"\n  {WHT}Mode scan:{R}\n  {CYN}1.{R} Port umum (cepat)\n  {CYN}2.{R} Port 1-1024 (lengkap)\n  > ").strip()

    if mode == "1":
        ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,27017]
        label = "Port Umum"
    else:
        ports = list(range(1, 1025))
        label = "Port 1-1024"

    print(f"\n  {GRY}Scanning {label} pada {target}...{R}\n")

    # resolve hostname
    try:
        ip = socket.gethostbyname(target)
        print(f"  {GRY}IP: {WHT}{ip}{R}\n")
    except:
        print(f"  {RED}Gagal resolve hostname!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return

    open_ports = []

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            s.close()
            return port if result == 0 else None
        except:
            return None

    PORT_NAMES = {
        21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
        80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
        3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 6379:"Redis",
        8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"HTTP-Alt", 27017:"MongoDB"
    }

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, p): p for p in ports}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result:
                open_ports.append(result)
            if mode == "1":
                print(f"  {GRY}Scanning... {done}/{len(ports)}{R}", end="\r")

    open_ports.sort()
    print(f"\n\n  {BLD}{WHT}{'─'*50}{R}")
    if open_ports:
        print(f"  {GRN}{BLD}Port terbuka ditemukan: {len(open_ports)}{R}\n")
        for p in open_ports:
            nama = PORT_NAMES.get(p, "Unknown")
            print(f"    {GRN}[OPEN]{R}  {WHT}{p:<6}{R}  {CYN}{nama}{R}")
    else:
        print(f"  {YLW}Tidak ada port terbuka yang ditemukan.{R}")
    print(f"  {BLD}{WHT}{'─'*50}{R}\n")
    input(f"  {GRY}Tekan ENTER untuk kembali ke menu...{R}")

# ─── DNS LOOKUP ───────────────────────────────────────────────────────────────

def menu_dns_lookup():
    banner()
    print(f"  {CYN}{BLD}[ DNS LOOKUP ]{R}\n")
    print(f"  {GRY}Cek semua record DNS dari sebuah domain.{R}\n")
    domain = input(f"  {WHT}Masukkan domain{R} {GRY}(contoh: google.com){R}\n  > ").strip()
    if not domain:
        print(f"\n  {RED}Domain tidak boleh kosong!{R}")
        input(f"\n  {GRY}Tekan ENTER untuk kembali...{R}")
        return

    domain = domain.replace("https://","").replace("http://","").strip("/")
    print(f"\n  {GRY}Mengambil info DNS untuk {domain}...{R}\n")

    print(f"  {BLD}{WHT}{'─'*50}{R}")
    print(f"  {CYN}{BLD}  HASIL DNS LOOKUP: {domain}{R}")
    print(f"  {BLD}{WHT}{'─'*50}{R}\n")

    # A record (IPv4)
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set([r[4][0] for r in results]))
        for ip in ips:
            print(f"  {GRY}A (IPv4)    :{R} {WHT}{ip}{R}")
    except:
        print(f"  {GRY}A (IPv4)    :{R} {RED}Tidak ditemukan{R}")

    # AAAA record (IPv6)
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET6)
        ips = list(set([r[4][0] for r in results]))
        for ip in ips:
            print(f"  {GRY}AAAA (IPv6) :{R} {WHT}{ip}{R}")
    except:
        print(f"  {GRY}AAAA (IPv6) :{R} {RED}Tidak ditemukan{R}")

    # Reverse DNS
    try:
       
