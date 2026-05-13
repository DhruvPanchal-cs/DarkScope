"""
dns_analyzer.py — DNS Leakage Analyzer
========================================
Detects when .onion sites load clearnet resources,
revealing their real hosting infrastructure.

Research significance:
  When a .onion site loads a JavaScript file from googleapis.com,
  the visitor's browser makes a DNS request to googleapis.com —
  bypassing Tor entirely. This reveals both the visitor's IP
  and the site's CDN/hosting provider. This is a critical OPSEC
  failure that no other dark web tool quantifies at scale.

Features:
  - Detects external scripts, stylesheets, images, iframes, forms,
    WebSockets, DNS prefetch hints
  - Severity scoring: NONE / LOW / MEDIUM / HIGH / CRITICAL
  - Exposed domain aggregation across all crawled sites
  - Identifies most-common clearnet infrastructure providers
  - Stores structured leakage data per page in MongoDB

Usage:
    python dns_analyzer.py
    python dns_analyzer.py --reanalyze
    python dns_analyzer.py --stats-only
"""

import re
import time
import datetime
import argparse
from urllib.parse import urlparse

import requests
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, TOR_PROXY, USER_AGENT
REQUEST_TIMEOUT = 20

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── Known CDN / Hosting Providers ────────────────────────────────────────────

INFRASTRUCTURE_MAP = {
    'googleapis.com':      'Google APIs',
    'gstatic.com':         'Google Static',
    'ajax.googleapis.com': 'Google Ajax CDN',
    'cdn.jsdelivr.net':    'jsDelivr CDN',
    'cdnjs.cloudflare.com':'Cloudflare CDN',
    'unpkg.com':           'UNPKG CDN',
    'bootstrapcdn.com':    'Bootstrap CDN',
    'fontawesome.com':     'Font Awesome',
    'fonts.googleapis.com':'Google Fonts',
    'fonts.gstatic.com':   'Google Fonts Static',
    'jquery.com':          'jQuery CDN',
    'cloudfront.net':      'AWS CloudFront',
    'amazonaws.com':       'AWS S3',
    'akamaiedge.net':      'Akamai Edge',
    'fastly.net':          'Fastly CDN',
    'github.io':           'GitHub Pages',
    'githubusercontent.com':'GitHub Raw Content',
    'netlify.app':         'Netlify',
    'vercel.app':          'Vercel',
    'heroku.com':          'Heroku',
    'digitalocean.com':    'DigitalOcean',
    'vultr.com':           'Vultr',
    'linode.com':          'Linode/Akamai',
}

SEVERITY_WEIGHTS = {
    'scripts':     3,
    'iframes':     3,
    'forms':       2,
    'stylesheets': 2,
    'images':      1,
    'websockets':  4,
    'prefetch':    1,
}

WHITELIST_DOMAINS = {
    'localhost', '127.0.0.1', 'w3.org', 'schema.org',
    'example.com', 'iana.org', 'rfc-editor.org',
}

# ── Resource Extraction ───────────────────────────────────────────────────────

def extract_external_resources(html, base_url):
    leaks = {
        'scripts':     [],
        'stylesheets': [],
        'images':      [],
        'iframes':     [],
        'forms':       [],
        'websockets':  [],
        'prefetch':    [],
        'all_domains': [],
    }

    def is_external(url_str):
        if not url_str:
            return False
        url_str = url_str.strip()
        if url_str.startswith(('data:', 'javascript:', '#')):
            return False
        if url_str.startswith('//'):
            return True
        if url_str.startswith('/') and not url_str.startswith('//'):
            return False
        if '.onion' in url_str:
            return False
        if url_str.startswith('http'):
            return True
        return False

    def extract_domain(url_str):
        try:
            if url_str.startswith('//'):
                url_str = 'https:' + url_str
            return urlparse(url_str).netloc.lower()
        except Exception:
            return ''

    # Scripts
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1).strip()
        if is_external(src):
            leaks['scripts'].append(src[:200])

    # Stylesheets
    for match in re.finditer(
        r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE
    ):
        href = match.group(1).strip()
        if is_external(href):
            leaks['stylesheets'].append(href[:200])

    # Images
    for match in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1).strip()
        if is_external(src) and not src.startswith('data:'):
            leaks['images'].append(src[:150])

    # Iframes
    for match in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1).strip()
        if is_external(src):
            leaks['iframes'].append(src[:200])

    # Forms
    for match in re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE):
        action = match.group(1).strip()
        if is_external(action):
            leaks['forms'].append(action[:200])

    # WebSockets
    for match in re.finditer(
        r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', html, re.IGNORECASE
    ):
        ws = match.group(1).strip()
        if ('wss://' in ws or 'ws://' in ws) and '.onion' not in ws:
            leaks['websockets'].append(ws[:200])

    # DNS Prefetch
    for match in re.finditer(
        r'<link[^>]+rel=["\']dns-prefetch["\'][^>]*href=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    ):
        href = match.group(1).strip()
        if is_external(href):
            leaks['prefetch'].append(href[:150])

    # Aggregate unique clearnet domains
    all_resources = (
        leaks['scripts'] + leaks['stylesheets'] +
        leaks['images']  + leaks['iframes'] +
        leaks['websockets'] + leaks['prefetch']
    )
    domains = set()
    for url_str in all_resources:
        d = extract_domain(url_str)
        if d and d not in WHITELIST_DOMAINS and '.onion' not in d:
            domains.add(d)
    leaks['all_domains'] = list(domains)

    # Deduplicate and limit
    for key in ['scripts', 'stylesheets', 'images', 'iframes',
                'forms', 'websockets', 'prefetch']:
        leaks[key] = list(set(leaks[key]))[:15]

    return leaks


def calculate_leak_severity(leaks):
    score = 0
    for resource_type, weight in SEVERITY_WEIGHTS.items():
        score += len(leaks.get(resource_type, [])) * weight

    if score == 0:  return 'NONE',     0
    if score <= 3:  return 'LOW',      score
    if score <= 10: return 'MEDIUM',   score
    if score <= 20: return 'HIGH',     score
    return                'CRITICAL',  score


def categorize_domains(domains):
    categorized = {}
    for domain in domains:
        for pattern, provider in INFRASTRUCTURE_MAP.items():
            if domain.endswith(pattern) or domain == pattern:
                categorized[domain] = provider
                break
        else:
            categorized[domain] = 'Unknown'
    return categorized


# ── Main Analysis ─────────────────────────────────────────────────────────────

def run_dns_analyzer(reanalyze=False, stats_only=False):
    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DNS LEAKAGE ANALYZER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Detects clearnet resources loaded by .onion sites{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*62}{Style.RESET_ALL}")

    if stats_only:
        print_leakage_stats()
        return

    query = {} if reanalyze else {
        'dns_leakage': {'$exists': False},
        'text':        {'$exists': True},
    }
    pages = list(db.pages.find(query, {'_id': 1, 'url': 1, 'title': 1, 'text': 1}))

    if not pages:
        print(f"\n  {Fore.GREEN}All pages already analyzed!{Style.RESET_ALL}")
        print_leakage_stats()
        return

    print(f"\n  Pages to analyze: {Fore.CYAN}{len(pages)}{Style.RESET_ALL}\n")

    tor_session = requests.Session()
    tor_session.proxies = TOR_PROXY
    tor_session.headers.update({'User-Agent': USER_AGENT})

    severity_counts = {'NONE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    all_exposed_domains = {}
    errors = 0

    for i, page in enumerate(pages):
        url   = page.get('url', '')
        title = (page.get('title') or 'No Title')[:45]
        if not url:
            continue

        try:
            html = ''
            try:
                r    = tor_session.get(url, timeout=REQUEST_TIMEOUT)
                html = r.text
            except Exception:
                html = page.get('text', '')

            if not html:
                continue

            leaks        = extract_external_resources(html, url)
            severity, score = calculate_leak_severity(leaks)
            domain_cats  = categorize_domains(leaks['all_domains'])

            for domain in leaks['all_domains']:
                all_exposed_domains[domain] = all_exposed_domains.get(domain, 0) + 1

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            db.pages.update_one(
                {'_id': page['_id']},
                {'$set': {
                    'dns_leakage':           leaks,
                    'dns_leak_severity':     severity,
                    'dns_leak_score':        score,
                    'dns_domain_categories': domain_cats,
                    'dns_analyzed_at':       datetime.datetime.now(datetime.timezone.utc),
                }}
            )

            if severity != 'NONE':
                color = (Fore.RED    if severity == 'CRITICAL' else
                         Fore.YELLOW if severity in ('HIGH', 'MEDIUM') else
                         Fore.GREEN)
                print(f"\n  [{Fore.CYAN}{i+1:04d}/{len(pages)}{Style.RESET_ALL}] "
                      f"{color}{severity:<8}{Style.RESET_ALL} score:{score:3d} | {title}")
                if leaks['scripts']:
                    print(f"           {Fore.RED}Scripts({len(leaks['scripts'])}): "
                          f"{leaks['scripts'][0][:55]}{Style.RESET_ALL}")
                if leaks['iframes']:
                    print(f"           {Fore.RED}Iframes({len(leaks['iframes'])}): "
                          f"{leaks['iframes'][0][:55]}{Style.RESET_ALL}")
                if leaks['all_domains']:
                    known = [f"{d}[{domain_cats.get(d,'?')}]"
                             for d in leaks['all_domains'][:3]]
                    print(f"           Domains: {', '.join(known)}")
            else:
                print(f"  [{Fore.CYAN}{i+1:04d}/{len(pages)}{Style.RESET_ALL}] "
                      f"{Fore.GREEN}NONE{Style.RESET_ALL} | {title}")

        except Exception as e:
            errors += 1
            print(f"  [ERROR] ({i+1:04d}) {title} — {str(e)[:50]}")

        time.sleep(0.8)

    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  DNS LEAKAGE ANALYSIS COMPLETE{Style.RESET_ALL}")
    print(f"  Analyzed: {len(pages)-errors}/{len(pages)} | Errors: {errors}")
    print(f"\n  Severity Distribution:")
    for level, count in severity_counts.items():
        if count > 0:
            color = (Fore.RED    if level == 'CRITICAL' else
                     Fore.YELLOW if level in ('HIGH','MEDIUM') else
                     Fore.GREEN)
            bar = '█' * min(count, 30)
            print(f"    {color}{level:<10}{Style.RESET_ALL} {bar} ({count})")

    if all_exposed_domains:
        print(f"\n  Most Exposed Infrastructure:")
        for domain, count in sorted(
            all_exposed_domains.items(), key=lambda x: -x[1]
        )[:10]:
            provider = INFRASTRUCTURE_MAP.get(domain, 'Unknown')
            print(f"    {domain:<40}: {count:3d} sites [{provider}]")

    print_leakage_stats()


def print_leakage_stats():
    print(f"\n  DNS Leakage DB Summary:")
    pipeline = [
        {'$match':  {'dns_leak_severity': {'$exists': True}}},
        {'$group':  {'_id': '$dns_leak_severity', 'count': {'$sum': 1}}},
        {'$sort':   {'count': -1}},
    ]
    for r in db.pages.aggregate(pipeline):
        level = r['_id']
        color = (Fore.RED    if level == 'CRITICAL' else
                 Fore.YELLOW if level in ('HIGH','MEDIUM') else
                 Fore.GREEN)
        print(f"    {color}{level:<10}{Style.RESET_ALL}: {r['count']} sites")

    domain_pipeline = [
        {'$match':  {'dns_leakage.all_domains': {'$exists': True, '$ne': []}}},
        {'$unwind': '$dns_leakage.all_domains'},
        {'$group':  {'_id': '$dns_leakage.all_domains', 'count': {'$sum': 1}}},
        {'$sort':   {'count': -1}},
        {'$limit':  8},
    ]
    results = list(db.pages.aggregate(domain_pipeline))
    if results:
        print(f"\n  Most Leaked Clearnet Domains:")
        for r in results:
            provider = INFRASTRUCTURE_MAP.get(r['_id'], 'Unknown')
            print(f"    {r['_id']:<40}: {r['count']:3d} [{provider}]")
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Leakage Analyzer')
    parser.add_argument('--reanalyze',  action='store_true')
    parser.add_argument('--stats-only', action='store_true')
    args = parser.parse_args()
    run_dns_analyzer(reanalyze=args.reanalyze, stats_only=args.stats_only)