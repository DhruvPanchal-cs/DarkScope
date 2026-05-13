"""
opsec_detector.py — OPSEC Failure Detector
============================================
Analyzes every crawled .onion page for operational security mistakes.
Assigns an OPSEC Risk Score (0-100) per site.
Run after crawler.py.

OPSEC Failures Detected (10 checks):
  1.  IP addresses exposed in HTML
  2.  Clearnet links in page source
  3.  CDN resource loading (JS/CSS from clearnet CDNs)
  4.  Real email addresses (non-.onion)
  5.  CMS fingerprints (WordPress, Drupal, etc.)
  6.  Timezone leaks via HTTP Date header
  7.  Bitcoin address reuse (blockchain-traceable)
  8.  Usernames (cross-platform correlation risk)
  9.  PGP key exposure + MIT keyserver lookup (NEW)
  10. Tracking pixels / analytics scripts

Usage:
    python opsec_detector.py
    python opsec_detector.py --reanalyze   (reanalyze all pages)
"""

import re
import time
import datetime
import argparse
import hashlib

import requests
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, TOR_PROXY, REQUEST_TIMEOUT, KEYSERVER_URL, KEYSERVER_TIMEOUT, USER_AGENT

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── OPSEC Check Patterns ──────────────────────────────────────────────────────

# CDN domains that reveal hosting infrastructure
CDN_PATTERNS = [
    (r'amazonaws\.com',     'AWS S3/CloudFront'),
    (r'cloudflare\.com',    'Cloudflare'),
    (r'cloudfront\.net',    'AWS CloudFront'),
    (r'fastly\.net',        'Fastly CDN'),
    (r'akamai(?:ai)?\.net', 'Akamai'),
    (r'googleapis\.com',    'Google APIs'),
    (r'bootstrapcdn\.com',  'Bootstrap CDN'),
    (r'cdn\.jquery\.com',   'jQuery CDN'),
    (r'digitalocean\.com',  'DigitalOcean'),
    (r'linode\.com',        'Linode'),
    (r'vultr\.com',         'Vultr'),
    (r'heroku\.com',        'Heroku'),
    (r'netlify\.com',       'Netlify'),
    (r'github\.io',         'GitHub Pages'),
]

# CMS fingerprint patterns
CMS_PATTERNS = {
    'WordPress': [r'wp-content/', r'wp-includes/', r'wp-login\.php'],
    'Drupal':    [r'sites/default/', r'drupal\.js', r'/node/\d+'],
    'Joomla':    [r'option=com_', r'joomla', r'com_content'],
    'Django':    [r'csrfmiddlewaretoken', r'__admin__'],
    'Laravel':   [r'laravel_session', r'XSRF-TOKEN'],
    'Nginx':     [r'nginx\.conf', r'nginx error'],
}

# Tracking / analytics patterns (OPSEC failure — site is tracking visitors)
TRACKING_PATTERNS = [
    (r'google-analytics\.com',  'Google Analytics'),
    (r'googletagmanager\.com',  'Google Tag Manager'),
    (r'facebook\.net',          'Facebook Pixel'),
    (r'hotjar\.com',            'Hotjar'),
    (r'segment\.com',           'Segment Analytics'),
    (r'mixpanel\.com',          'Mixpanel'),
    (r'ga\.js',                 'Google Analytics JS'),
    (r"gtag\('config'",         'Google Tag'),
    (r'_gaq\.push',             'Google Analytics Legacy'),
    (r'fbq\(',                  'Facebook Pixel Call'),
]

# Real email pattern (non-.onion — traceable to real identity)
REAL_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@(?!.*\.onion)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    re.IGNORECASE
)

# Public IP address in HTML
IP_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# PGP public key block
PGP_KEY_RE = re.compile(
    r'-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----',
    re.IGNORECASE
)

# PGP fingerprint (40 hex chars, often displayed as 10 groups of 4)
PGP_FINGERPRINT_RE = re.compile(
    r'\b(?:[0-9A-F]{4}\s?){10}\b',
    re.IGNORECASE
)

# Clearnet URLs
CLEARNET_URL_RE = re.compile(
    r'https?://(?!(?:[a-z2-7]{10,60}\.onion))'
    r'(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?'
)

# Username extraction
USERNAME_RE = re.compile(
    r'(?:posted by|author:|username:|by user|nick:|handle:)\s*([a-zA-Z0-9_\-\.]{4,20})',
    re.IGNORECASE
)

# Private/reserved IP ranges — these are NOT leaks
PRIVATE_PREFIXES = (
    '127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
    '172.19.', '172.20.', '0.0.0.', '255.255.', '224.',
)

# Domains to whitelist (not a leak — known safe/example domains)
WHITELIST_DOMAINS = {
    'example.com', 'w3.org', 'schema.org', 'openstreetmap.org',
    'wikipedia.org', 'creativecommons.org', 'ietf.org', 'rfc-editor.org',
}

# ── Score Calculation ─────────────────────────────────────────────────────────

DEDUCTION_TABLE = {
    'ip_exposed':       30,   # Critical — direct IP exposure
    'clearnet_links':   15,   # High — reveals hosting
    'cdn_resources':    15,   # High — CDN fingerprinting
    'real_emails':      15,   # High — traceable identity
    'tracking':         20,   # Critical — actively tracking visitors
    'cms_detected':     10,   # Medium — server software revealed
    'timezone_leak':    10,   # Medium — geographic hint
    'bitcoin_reuse':    10,   # Medium — blockchain traceable
    'pgp_on_keyserver': 10,   # Medium — identity link confirmed
    'usernames_found':   5,   # Low — cross-platform risk
}

def calculate_opsec_score(failures: dict) -> int:
    """
    Score 0-100. Lower = worse OPSEC.
    Deduct points per failure type. Floor at 0.
    """
    score = 100
    for failure_type, items in failures.items():
        if items and failure_type in DEDUCTION_TABLE:
            score -= DEDUCTION_TABLE[failure_type]
    return max(0, score)


def get_risk_level(score: int) -> tuple:
    if score >= 80: return 'LOW',      Fore.GREEN
    if score >= 60: return 'MEDIUM',   Fore.YELLOW
    if score >= 40: return 'HIGH',     Fore.MAGENTA
    return               'CRITICAL',  Fore.RED

# ── PGP Keyserver Lookup ──────────────────────────────────────────────────────

def extract_pgp_fingerprint(key_block: str) -> str:
    """
    Attempt to extract a PGP fingerprint from a key block or nearby text.
    Returns fingerprint string (40 hex chars) or empty string.
    """
    # Try to find a fingerprint pattern near the key block
    match = PGP_FINGERPRINT_RE.search(key_block)
    if match:
        # Normalize: remove spaces, uppercase
        fp = re.sub(r'\s', '', match.group(0)).upper()
        if len(fp) == 40:
            return fp
    return ''


def lookup_pgp_keyserver(fingerprint: str) -> dict:
    """
    Query keys.openpgp.org to check if a PGP key exists on clearnet keyservers.
    If found, this is a real OPSEC failure — the operator's key is publicly linked.

    Uses clearnet (not Tor) — keyserver doesn't have onion address.
    Returns dict with found status and identity info.
    """
    if not fingerprint or len(fingerprint) != 40:
        return {'found': False}

    result = {'found': False, 'fingerprint': fingerprint}
    try:
        url = f"{KEYSERVER_URL}{fingerprint}"
        r   = requests.get(url, timeout=KEYSERVER_TIMEOUT)

        if r.status_code == 200:
            data = r.json()
            # keys.openpgp.org returns user IDs attached to the key
            uids = []
            for key_data in data.get('keys', []):
                for uid in key_data.get('userids', []):
                    uid_str = uid.get('uid', '')
                    if uid_str:
                        uids.append(uid_str)

            result['found']       = True
            result['userids']     = uids[:5]
            result['status_code'] = r.status_code

        elif r.status_code == 404:
            result['found'] = False   # Key not on keyserver — good OPSEC

    except Exception as e:
        result['error'] = str(e)[:50]

    return result

# ── OPSEC Analysis ────────────────────────────────────────────────────────────

def detect_opsec_failures(url: str, html: str, headers: dict) -> dict:
    """
    Run all 10 OPSEC checks on a page.
    Returns dict of failures — each key maps to list of found items.
    """
    failures = {k: [] for k in DEDUCTION_TABLE.keys()}
    text_lower = html.lower()

    # ── Check 1: Public IP addresses in HTML ─────────────────
    all_ips = IP_RE.findall(html)
    public_ips = [
        ip for ip in set(all_ips)
        if not any(ip.startswith(p) for p in PRIVATE_PREFIXES)
    ]
    failures['ip_exposed'] = public_ips[:5]

    # ── Check 2: Clearnet links in source ────────────────────
    clearnet_urls = CLEARNET_URL_RE.findall(html)
    filtered = []
    for u in clearnet_urls:
        from urllib.parse import urlparse as _up
        try:
            domain = _up(u).netloc.lower()
            if domain not in WHITELIST_DOMAINS:
                filtered.append(u)
        except Exception:
            pass
    failures['clearnet_links'] = list(set(filtered))[:10]

    # ── Check 3: CDN resources ────────────────────────────────
    cdn_found = []
    for pattern, cdn_name in CDN_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            cdn_found.append(cdn_name)
    failures['cdn_resources'] = list(set(cdn_found))

    # ── Check 4: Real email addresses ────────────────────────
    real_emails = REAL_EMAIL_RE.findall(html)
    failures['real_emails'] = list(set(real_emails))[:10]

    # ── Check 5: CMS detection ────────────────────────────────
    cms_detected = []
    for cms_name, patterns in CMS_PATTERNS.items():
        if any(re.search(p, text_lower) for p in patterns):
            cms_detected.append(cms_name)
    failures['cms_detected'] = cms_detected

    # ── Check 6: Timezone leak from Date header ───────────────
    tz_leaks = []
    for h in ['Date', 'Last-Modified', 'Expires']:
        val = headers.get(h, '')
        if val:
            tz_match = re.search(r'([+-]\d{4}|GMT[+-]\d+)', val)
            if tz_match and tz_match.group(1) not in ('GMT', '+0000', '-0000'):
                tz_leaks.append(f"{h}: {val[:60]}")
    failures['timezone_leak'] = tz_leaks

    # ── Check 7: Bitcoin address reuse ────────────────────────
    btc_re  = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{6,87})\b')
    btc_addrs = list(set(btc_re.findall(html)))[:5]
    failures['bitcoin_reuse'] = btc_addrs

    # ── Check 8: Usernames for correlation ───────────────────
    usernames = [
        m for m in USERNAME_RE.findall(html)
        if len(m) >= 4
    ]
    failures['usernames_found'] = list(set(usernames))[:10]

    # ── Check 9: PGP keys + keyserver lookup (NEW) ───────────
    pgp_blocks      = PGP_KEY_RE.findall(html)
    pgp_ks_matches  = []
    if pgp_blocks:
        for block in pgp_blocks[:3]:
            fp = extract_pgp_fingerprint(block)
            if fp:
                ks_result = lookup_pgp_keyserver(fp)
                if ks_result.get('found'):
                    # Real OPSEC failure — key is on public keyserver
                    pgp_ks_matches.append({
                        'fingerprint': fp,
                        'userids':     ks_result.get('userids', []),
                    })
                    print(f"    {Fore.RED}🔑 PGP KEY ON KEYSERVER! "
                          f"FP: {fp[:16]}...{Style.RESET_ALL}")
                    if ks_result.get('userids'):
                        print(f"    Identity: {ks_result['userids'][0][:60]}")
                time.sleep(0.5)  # rate limit keyserver
    failures['pgp_on_keyserver'] = pgp_ks_matches

    # ── Check 10: Tracking pixels / analytics ────────────────
    tracking_found = []
    for pattern, tracker_name in TRACKING_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            tracking_found.append(tracker_name)
    failures['tracking'] = list(set(tracking_found))

    return failures

# ── Main Runner ───────────────────────────────────────────────────────────────

def run_opsec_detector(reanalyze: bool = False):
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  OPSEC FAILURE DETECTOR{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  10 checks | Score 0-100 | PGP Keyserver Lookup{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")

    query = {} if reanalyze else {'opsec_score': {'$exists': False}}
    pages = list(db.pages.find(query, {'_id': 1, 'url': 1, 'title': 1}))

    if not pages:
        print(f"\n  {Fore.GREEN}✓ All pages already analyzed!{Style.RESET_ALL}")
        print_opsec_stats()
        return

    print(f"\n  Pages to analyze: {Fore.CYAN}{len(pages)}{Style.RESET_ALL}")
    print(f"  Tor proxy: socks5h://127.0.0.1:9150\n")
    print(f"{'─'*60}")

    # Tor session for fetching pages
    tor_session = requests.Session()
    tor_session.proxies = TOR_PROXY
    tor_session.headers.update({'User-Agent': USER_AGENT})

    critical_count = 0
    high_count     = 0
    errors         = 0

    for i, page in enumerate(pages):
        url   = page.get('url', '')
        title = (page.get('title') or 'No Title')[:45]

        if not url:
            continue

        try:
            # Fetch page with headers for full analysis
            r       = tor_session.get(url, timeout=REQUEST_TIMEOUT)
            headers = dict(r.headers)
            html    = r.text

            failures = detect_opsec_failures(url, html, headers)
            score    = calculate_opsec_score(failures)
            level, color = get_risk_level(score)

            if level == 'CRITICAL': critical_count += 1
            if level == 'HIGH':     high_count     += 1

            # Store to MongoDB
            db.pages.update_one(
                {'_id': page['_id']},
                {'$set': {
                    'opsec_score':       score,
                    'opsec_level':       level,
                    'opsec_failures':    failures,
                    'opsec_analyzed_at': datetime.datetime.now(datetime.timezone.utc),
                }}
            )

            # Console output
            score_bar = '█' * (score // 10) + '░' * (10 - score // 10)
            print(f"\n  [{Fore.CYAN}{i+1:04d}/{len(pages)}{Style.RESET_ALL}] "
                  f"{color}{level:<8}{Style.RESET_ALL} "
                  f"Score: {score:3d}/100 [{score_bar}]")
            print(f"           {title}")

            if failures['ip_exposed']:
                print(f"           {Fore.RED}🚨 IP EXPOSED: {failures['ip_exposed'][:2]}{Style.RESET_ALL}")
            if failures['tracking']:
                print(f"           {Fore.RED}📊 TRACKING: {failures['tracking']}{Style.RESET_ALL}")
            if failures['clearnet_links']:
                print(f"           {Fore.YELLOW}🔗 Clearnet links: {len(failures['clearnet_links'])}{Style.RESET_ALL}")
            if failures['cdn_resources']:
                print(f"           {Fore.YELLOW}☁  CDN detected: {failures['cdn_resources']}{Style.RESET_ALL}")
            if failures['real_emails']:
                print(f"           {Fore.YELLOW}📧 Real emails: {failures['real_emails'][:2]}{Style.RESET_ALL}")
            if failures['cms_detected']:
                print(f"           ℹ  CMS: {failures['cms_detected']}{Style.RESET_ALL}")
            if failures['pgp_on_keyserver']:
                print(f"           {Fore.RED}🔑 PGP on keyserver! "
                      f"FP: {failures['pgp_on_keyserver'][0]['fingerprint'][:16]}...{Style.RESET_ALL}")

        except requests.exceptions.ConnectionError:
            print(f"  [{Fore.RED}OFFLINE{Style.RESET_ALL}] ({i+1:04d}) {title} — site unreachable")
            errors += 1
        except requests.exceptions.Timeout:
            print(f"  [{Fore.YELLOW}TIMEOUT{Style.RESET_ALL}] ({i+1:04d}) {title}")
            errors += 1
        except Exception as e:
            print(f"  [{Fore.RED}ERROR{Style.RESET_ALL}]   ({i+1:04d}) {title} — {str(e)[:50]}")
            errors += 1

        time.sleep(1)

    # Final summary
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  OPSEC ANALYSIS COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*60}")
    print(f"  Analyzed  : {len(pages) - errors}/{len(pages)} pages")
    print(f"  {Fore.RED}CRITICAL  : {critical_count} sites{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}HIGH      : {high_count} sites{Style.RESET_ALL}")
    print(f"  Errors    : {errors}")
    print_opsec_stats()


def print_opsec_stats():
    """Print distribution table from DB."""
    print(f"\n  OPSEC Risk Distribution:")
    print(f"  {'LEVEL':<12} {'COUNT':>6}  {'AVG SCORE':>10}")
    print(f"  {'─'*32}")
    pipeline = [
        {'$match':  {'opsec_level': {'$exists': True}}},
        {'$group':  {'_id': '$opsec_level',
                     'count': {'$sum': 1},
                     'avg':   {'$avg': '$opsec_score'}}},
        {'$sort':   {'avg': 1}},
    ]
    for r in db.pages.aggregate(pipeline):
        avg   = round(r.get('avg') or 0, 1)
        level = r['_id']
        color = (Fore.RED    if level == 'CRITICAL' else
                 Fore.MAGENTA if level == 'HIGH'    else
                 Fore.YELLOW  if level == 'MEDIUM'  else Fore.GREEN)
        print(f"  {color}{level:<12}{Style.RESET_ALL} {r['count']:>6}  {avg:>9}/100")

    print(f"\n  Most Common Failures:")
    checks = list(DEDUCTION_TABLE.keys())
    for check in checks:
        count = db.pages.count_documents(
            {f'opsec_failures.{check}': {'$exists': True, '$ne': []}}
        )
        if count > 0:
            deduction = DEDUCTION_TABLE[check]
            print(f"    {check:<25}: {count:3d} sites  (-{deduction} pts)")
    print()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OPSEC Failure Detector')
    parser.add_argument('--reanalyze', action='store_true',
                        help='Reanalyze all pages (including already analyzed)')
    args = parser.parse_args()
    run_opsec_detector(reanalyze=args.reanalyze)