"""
header_fingerprint.py — HTTP Header Fingerprinting Engine
==========================================================
Extracts HTTP response headers from all crawled .onion sites.
Run after crawler.py.

Features:
  - Server software identification (Apache, Nginx, IIS, etc.)
  - ETag correlation — detect same physical server running
    multiple .onion sites (unique research finding)
  - CDN detection via response headers
  - CMS detection via header signatures
  - IP leakage via X-Forwarded-For / X-Real-IP headers
  - Security header scoring (HSTS, CSP, X-Frame-Options, etc.)
  - Session cookie & tracking detector (merged from OPSEC)
  - Fingerprint hash — SHA256 of server characteristics

Usage:
    python header_fingerprint.py
    python header_fingerprint.py --reanalyze
    python header_fingerprint.py --correlate-only
"""

import re
import time
import datetime
import hashlib
import argparse

import requests
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, TOR_PROXY, USER_AGENT
REQUEST_TIMEOUT = 15  # headers need shorter timeout than crawl

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── Header Analysis Patterns ──────────────────────────────────────────────────

# Headers worth extracting
INTERESTING_HEADERS = [
    'Server', 'X-Powered-By', 'X-Generator', 'X-Drupal-Cache',
    'X-Varnish', 'X-Cache', 'X-Frame-Options', 'X-Content-Type-Options',
    'X-XSS-Protection', 'Content-Security-Policy', 'Strict-Transport-Security',
    'ETag', 'Last-Modified', 'Date', 'Via', 'Set-Cookie',
    'CF-Ray', 'X-Amz-Cf-Id', 'X-Forwarded-For', 'X-Real-IP',
    'X-Originating-IP', 'Alt-Svc', 'Access-Control-Allow-Origin',
    'X-Runtime', 'X-Request-Id', 'X-Correlation-Id',
]

# Server software signatures
SERVER_SIGNATURES = [
    ('Apache',         r'Apache(?:/[\d\.]+)?'),
    ('Nginx',          r'nginx(?:/[\d\.]+)?'),
    ('IIS',            r'Microsoft-IIS(?:/[\d\.]+)?'),
    ('Lighttpd',       r'lighttpd(?:/[\d\.]+)?'),
    ('Caddy',          r'Caddy'),
    ('Gunicorn',       r'gunicorn(?:/[\d\.]+)?'),
    ('Tornado',        r'TornadoServer(?:/[\d\.]+)?'),
    ('Node.js',        r'Node\.js'),
    ('Python/Flask',   r'Werkzeug(?:/[\d\.]+)?'),
    ('Python',         r'Python(?:/[\d\.]+)?'),
    ('PHP',            r'PHP(?:/[\d\.]+)?'),
    ('OpenResty',      r'openresty(?:/[\d\.]+)?'),
]

# CDN detection via headers
CDN_HEADER_SIGNATURES = [
    ('CF-Ray',          'Cloudflare'),
    ('X-Amz-Cf-Id',    'AWS CloudFront'),
    ('X-Varnish',       'Varnish Cache'),
    ('X-Cache',         'Generic CDN/Cache'),
    ('X-CDN',           'Generic CDN'),
    ('Fastly-Debug-Digest', 'Fastly'),
    ('X-Served-By',     'Fastly/CDN'),
]

# CMS detection via headers
CMS_HEADER_SIGNATURES = [
    ('X-Drupal-Cache',  'Drupal'),
    ('X-Drupal-Dynamic-Cache', 'Drupal'),
    ('X-Generator',     None),       # value IS the CMS
    ('X-Powered-By',    None),       # value may contain CMS info
]

# Security headers (presence = good security practice)
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy':   'CSP',
    'X-Frame-Options':           'X-Frame',
    'X-Content-Type-Options':    'X-Content-Type',
    'X-XSS-Protection':          'XSS-Protection',
    'Referrer-Policy':           'Referrer-Policy',
    'Permissions-Policy':        'Permissions-Policy',
}

# Suspicious cookie patterns (tracking / session management)
TRACKING_COOKIE_PATTERNS = [
    (r'_ga=',           'Google Analytics'),
    (r'_gid=',          'Google Analytics'),
    (r'_fbp=',          'Facebook Pixel'),
    (r'__utm',          'Google Analytics (legacy)'),
    (r'intercom-',      'Intercom'),
    (r'mixpanel',       'Mixpanel'),
    (r'amplitude',      'Amplitude Analytics'),
]

# ── Header Extraction ─────────────────────────────────────────────────────────

def fetch_headers(url: str, session: requests.Session) -> tuple:
    """
    Fetch HTTP headers using HEAD request first, fall back to GET.
    Returns (headers_dict, status_code).
    """
    try:
        r = session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code < 400:
            return dict(r.headers), r.status_code
    except Exception:
        pass

    # HEAD failed or returned error — try GET
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        return dict(r.headers), r.status_code
    except Exception as e:
        return {}, 0

# ── Header Analysis ───────────────────────────────────────────────────────────

def analyze_headers(headers: dict, url: str = '') -> dict:
    """
    Analyze HTTP response headers and extract intelligence.
    Returns structured analysis dict.
    """
    analysis = {
        'raw_headers':        {},
        'server_software':    None,
        'powered_by':         None,
        'cms_detected':       None,
        'cdn_detected':       None,
        'etag':               None,
        'etag_hash':          None,
        'last_modified':      None,
        'timezone':           None,
        'ip_leaked':          [],
        'security_headers':   {},
        'security_score':     0,
        'fingerprint_hash':   None,
        'cookies':            [],
        'tracking_cookies':   [],
        'interesting_headers': {},
    }

    if not headers:
        return analysis

    # Store all interesting headers (case-insensitive lookup)
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for h in INTERESTING_HEADERS:
        val = headers.get(h) or headers_lower.get(h.lower())
        if val:
            analysis['raw_headers'][h]        = val
            analysis['interesting_headers'][h] = val

    # ── Server software ───────────────────────────────────────
    server_val = headers.get('Server', '') or headers_lower.get('server', '')
    for name, pattern in SERVER_SIGNATURES:
        if re.search(pattern, server_val, re.IGNORECASE):
            analysis['server_software'] = server_val
            break

    # ── X-Powered-By ─────────────────────────────────────────
    xpb = headers.get('X-Powered-By') or headers_lower.get('x-powered-by')
    if xpb:
        analysis['powered_by'] = xpb

    # ── ETag — key for server correlation ────────────────────
    etag_raw = headers.get('ETag') or headers_lower.get('etag')
    if etag_raw:
        # Strip quotes and W/ prefix
        etag_clean = re.sub(r'^[Ww]/"?|"$', '', etag_raw.strip()).strip('"\'')
        if etag_clean:
            analysis['etag']      = etag_clean
            analysis['etag_hash'] = hashlib.md5(etag_clean.encode()).hexdigest()

    # ── Date / Last-Modified → timezone leak ─────────────────
    date_val = headers.get('Date') or headers_lower.get('date') or ''
    if date_val:
        analysis['last_modified'] = date_val
        tz_match = re.search(r'([+-]\d{4}|GMT[+-]\d+)', date_val)
        if tz_match:
            tz = tz_match.group(1)
            if tz not in ('GMT', '+0000', '-0000', 'GMT+0'):
                analysis['timezone'] = tz

    # ── CDN detection ─────────────────────────────────────────
    for header_name, cdn_name in CDN_HEADER_SIGNATURES:
        if (headers.get(header_name) or headers_lower.get(header_name.lower())):
            analysis['cdn_detected'] = cdn_name
            break

    # ── CMS detection ─────────────────────────────────────────
    for header_name, cms_name in CMS_HEADER_SIGNATURES:
        val = headers.get(header_name) or headers_lower.get(header_name.lower())
        if val:
            if cms_name is None:
                # The header VALUE is the CMS identifier
                analysis['cms_detected'] = val[:50]
            else:
                analysis['cms_detected'] = cms_name
            break

    # ── IP leakage via proxy headers ──────────────────────────
    for h in ['X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
              'True-Client-IP', 'CF-Connecting-IP']:
        val = headers.get(h) or headers_lower.get(h.lower())
        if val:
            # Filter private IPs
            ips = [ip.strip() for ip in val.split(',')]
            public_ips = [
                ip for ip in ips
                if ip and not any(ip.startswith(p) for p in (
                    '127.', '10.', '192.168.', '172.', '::1'
                ))
            ]
            if public_ips:
                analysis['ip_leaked'].append({
                    'header': h,
                    'value':  val[:100],
                    'public_ips': public_ips,
                })

    # ── Security headers ──────────────────────────────────────
    sec = {}
    for header_name, label in SECURITY_HEADERS.items():
        present = bool(
            headers.get(header_name) or
            headers_lower.get(header_name.lower())
        )
        sec[label] = present
    sec['security_score'] = sum(1 for v in sec.values() if v is True)
    analysis['security_headers'] = sec
    analysis['security_score']   = sec['security_score']

    # ── Cookie analysis ───────────────────────────────────────
    set_cookie = headers.get('Set-Cookie') or headers_lower.get('set-cookie', '')
    if set_cookie:
        # Cookie flags
        has_httponly  = 'httponly'  in set_cookie.lower()
        has_secure    = 'secure'    in set_cookie.lower()
        has_samesite  = 'samesite'  in set_cookie.lower()
        analysis['cookies'] = [{
            'raw':       set_cookie[:200],
            'httponly':  has_httponly,
            'secure':    has_secure,
            'samesite':  has_samesite,
        }]
        # Check for tracking cookies
        for pattern, tracker in TRACKING_COOKIE_PATTERNS:
            if re.search(pattern, set_cookie, re.IGNORECASE):
                analysis['tracking_cookies'].append(tracker)

    # ── Fingerprint hash ──────────────────────────────────────
    # Hash of server characteristics — same hash = likely same server
    fp_parts = [
        x for x in [
            analysis['server_software'],
            analysis['powered_by'],
            analysis['cms_detected'],
            analysis['etag_hash'],
        ] if x
    ]
    if fp_parts:
        analysis['fingerprint_hash'] = hashlib.sha256(
            '|'.join(fp_parts).encode()
        ).hexdigest()[:16]

    return analysis

# ── ETag Correlation ──────────────────────────────────────────────────────────

def find_etag_correlations():
    """
    Find .onion sites sharing the same ETag hash.
    Shared ETag = same physical file server = same operator running multiple sites.
    This is a unique research finding — no other tool detects this.
    """
    print(f"\n  {Fore.CYAN}ETag Correlation Analysis{Style.RESET_ALL}")
    print(f"  {'─'*50}")

    pipeline = [
        {'$match':  {
            'headers.etag_hash': {
                '$exists': True,
                '$nin': [None, '', 'None']
            }
        }},
        {'$group':  {
            '_id':   '$headers.etag_hash',
            'count': {'$sum': 1},
            'sites': {'$push': {'title': '$title', 'url': '$url', 'domain': '$domain'}},
        }},
        {'$match':  {'count': {'$gt': 1}}},
        {'$sort':   {'count': -1}},
    ]
    correlations = list(db.pages.aggregate(pipeline))

    if correlations:
        print(f"  {Fore.RED}🚨 ETag Correlations Found — "
              f"same server running multiple .onion sites:{Style.RESET_ALL}")
        for c in correlations[:10]:
            etag_id = (c.get('_id') or '')[:8]
            print(f"\n    ETag: {etag_id}... → {c['count']} sites share this server")
            for site in c['sites'][:4]:
                title = (site.get('title') or 'No Title')[:40]
                url   = (site.get('url')   or '')[:55]
                print(f"      • {title}")
                print(f"        {Fore.BLUE}{url}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ No ETag correlations found{Style.RESET_ALL}")

    # Fingerprint hash correlations
    print(f"\n  {Fore.CYAN}Fingerprint Hash Correlations{Style.RESET_ALL}")
    fp_pipeline = [
        {'$match':  {
            'headers.fingerprint_hash': {'$exists': True, '$ne': None}
        }},
        {'$group':  {
            '_id':   '$headers.fingerprint_hash',
            'count': {'$sum': 1},
            'sites': {'$push': '$title'},
        }},
        {'$match':  {'count': {'$gt': 1}}},
        {'$sort':   {'count': -1}},
    ]
    fp_corrs = list(db.pages.aggregate(fp_pipeline))
    if fp_corrs:
        print(f"  {Fore.YELLOW}⚠ {len(fp_corrs)} fingerprint groups "
              f"(same server config):{Style.RESET_ALL}")
        for c in fp_corrs[:5]:
            print(f"    FP {c['_id']}: {c['count']} sites")
    else:
        print(f"  {Fore.GREEN}✓ No fingerprint correlations found{Style.RESET_ALL}")

    # Server software distribution
    print(f"\n  Server Software Distribution:")
    sv_pipeline = [
        {'$match':  {'headers.server_software': {'$exists': True, '$ne': None}}},
        {'$group':  {'_id': '$headers.server_software', 'count': {'$sum': 1}}},
        {'$sort':   {'count': -1}},
        {'$limit':  10},
    ]
    for r in db.pages.aggregate(sv_pipeline):
        if r['_id']:
            print(f"    {r['_id']:<40}: {r['count']} sites")

    # CDN usage summary
    cdn_pipeline = [
        {'$match':  {'headers.cdn_detected': {'$exists': True, '$ne': None}}},
        {'$group':  {'_id': '$headers.cdn_detected', 'count': {'$sum': 1}}},
        {'$sort':   {'count': -1}},
    ]
    cdn_results = list(db.pages.aggregate(cdn_pipeline))
    if cdn_results:
        print(f"\n  CDN Usage (OPSEC failures):")
        for r in cdn_results:
            if r['_id']:
                print(f"    {Fore.YELLOW}{r['_id']:<40}{Style.RESET_ALL}: {r['count']} sites")

# ── Main Runner ───────────────────────────────────────────────────────────────

def run_header_fingerprinting(reanalyze: bool = False, correlate_only: bool = False):
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  HTTP HEADER FINGERPRINTING ENGINE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Server ID | ETag Correlation | Security Scoring{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")

    if correlate_only:
        find_etag_correlations()
        return

    query = {} if reanalyze else {'headers': {'$exists': False}}
    pages = list(db.pages.find(query, {'_id': 1, 'url': 1, 'title': 1}))

    if not pages:
        print(f"\n  {Fore.GREEN}✓ All pages fingerprinted!{Style.RESET_ALL}")
        find_etag_correlations()
        return

    print(f"\n  Pages to fingerprint: {Fore.CYAN}{len(pages)}{Style.RESET_ALL}\n")
    print(f"{'─'*60}")

    tor_session = requests.Session()
    tor_session.proxies = TOR_PROXY
    tor_session.headers.update({'User-Agent': USER_AGENT})

    server_found  = 0
    cdn_found     = 0
    ip_leaked     = 0
    cms_found     = 0
    etag_found    = 0
    tracking_cook = 0
    errors        = 0

    for i, page in enumerate(pages):
        url   = page.get('url', '')
        title = (page.get('title') or 'No Title')[:45]

        if not url:
            continue

        try:
            headers, status = fetch_headers(url, tor_session)

            if not headers:
                print(f"  [{Fore.YELLOW}NO HEADERS{Style.RESET_ALL}] ({i+1:04d}) {title}")
                errors += 1
                continue

            analysis = analyze_headers(headers, url)

            db.pages.update_one(
                {'_id': page['_id']},
                {'$set': {
                    'headers':             analysis,
                    'headers_fetched_at':  datetime.datetime.now(datetime.timezone.utc),
                }}
            )

            # Update counters
            if analysis['server_software']: server_found  += 1
            if analysis['cdn_detected']:    cdn_found     += 1
            if analysis['ip_leaked']:       ip_leaked     += 1
            if analysis['cms_detected']:    cms_found     += 1
            if analysis['etag']:            etag_found    += 1
            if analysis['tracking_cookies']:tracking_cook += 1

            # Build findings string
            findings = []
            if analysis['server_software']:
                findings.append(f"🖥 {analysis['server_software'][:20]}")
            if analysis['cdn_detected']:
                findings.append(f"{Fore.YELLOW}☁ CDN:{analysis['cdn_detected']}{Style.RESET_ALL}")
            if analysis['ip_leaked']:
                findings.append(f"{Fore.RED}🚨 IP LEAKED{Style.RESET_ALL}")
            if analysis['cms_detected']:
                findings.append(f"📦 {analysis['cms_detected']}")
            if analysis['etag']:
                findings.append(f"🏷 ETag:{analysis['etag'][:8]}...")
            if analysis['tracking_cookies']:
                findings.append(f"{Fore.RED}📊 TRACKING:{analysis['tracking_cookies'][0]}{Style.RESET_ALL}")
            if analysis['security_score'] > 0:
                findings.append(f"{Fore.GREEN}🔒 SecScore:{analysis['security_score']}/7{Style.RESET_ALL}")

            status_str = Fore.GREEN + 'OK' + Style.RESET_ALL if status < 400 else Fore.RED + str(status) + Style.RESET_ALL
            print(f"\n  [{Fore.CYAN}{i+1:04d}/{len(pages)}{Style.RESET_ALL}] "
                  f"HTTP {status_str} | {title}")
            if findings:
                print(f"           {' | '.join(findings)}")
            else:
                print(f"           No significant headers")

        except requests.exceptions.Timeout:
            print(f"  [{Fore.YELLOW}TIMEOUT{Style.RESET_ALL}] ({i+1:04d}) {title}")
            errors += 1
        except requests.exceptions.ConnectionError:
            print(f"  [{Fore.RED}OFFLINE{Style.RESET_ALL}] ({i+1:04d}) {title}")
            errors += 1
        except Exception as e:
            print(f"  [{Fore.RED}ERROR{Style.RESET_ALL}]   ({i+1:04d}) {title} — {str(e)[:50]}")
            errors += 1

        time.sleep(0.5)

    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  FINGERPRINTING COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*60}")
    print(f"  Analyzed   : {len(pages) - errors}/{len(pages)}")
    print(f"  Server ID  : {server_found}")
    print(f"  CDN found  : {cdn_found}")
    print(f"  IP leaked  : {ip_leaked}")
    print(f"  CMS found  : {cms_found}")
    print(f"  ETag found : {etag_found}")
    print(f"  Tracking 🍪: {tracking_cook}")
    print(f"  Errors     : {errors}")

    find_etag_correlations()

# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP Header Fingerprinting Engine')
    parser.add_argument('--reanalyze',      action='store_true',
                        help='Reanalyze all pages')
    parser.add_argument('--correlate-only', action='store_true',
                        help='Only run ETag correlation analysis')
    args = parser.parse_args()
    run_header_fingerprinting(
        reanalyze=args.reanalyze,
        correlate_only=args.correlate_only
    )