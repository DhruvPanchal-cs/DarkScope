"""
crawler.py — Dark Web BFS Crawler
==================================
Passive, read-only academic research crawler.
Crawls .onion sites via Tor SOCKS5 proxy on port 9150.

Fixes applied:
  - Persistent queue: uses BeautifulSoup on stored text (recovers 10x more URLs)
  - Domain blocklist: filters non-dark-web domains (GitLab, clearnet mirrors)
  - raw_html stored per page for future re-extraction
  - Improved seed list with reliably-online onion sites

Usage:
    python crawler.py
    python crawler.py --max 500
"""

import re
import time
import datetime
import argparse
import hashlib
from collections import deque
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ────────────────────────────────────────────────────────────
from config import (
    TOR_PROXY, MONGO_URI, DB_NAME, MAX_PER_DOMAIN, REQUEST_TIMEOUT,
    RETRY_ATTEMPTS, RETRY_DELAY, CRAWL_DELAY, MAX_TEXT_STORE,
    MAX_HTML_STORE, USER_AGENT, TOR_HOST, TOR_PORT,
)

# ── MongoDB ───────────────────────────────────────────────────────────────────
client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

def setup_indexes():
    try: db.pages.create_index('url', unique=True)
    except Exception: pass
    for field in ['domain','is_flagged','category','crawled_at','opsec_score','language']:
        try: db.pages.create_index(field)
        except Exception: pass
    try:
        db.pages.create_index(
            [('title', 'text'), ('text', 'text')],
            default_language='english', name='text_search_index'
        )
    except Exception: pass
    try: db.uptime_logs.create_index([('url', ASCENDING), ('checked_at', ASCENDING)])
    except Exception: pass
    try: db.uptime_logs.create_index('url')
    except Exception: pass
    print(f"{Fore.GREEN}  ✓ MongoDB indexes ready{Style.RESET_ALL}")

# ── Seeds (verified active as of 2025-2026) ────────────────────────────────
SEEDS = [
    # Search Engines / Directories — high link density, best BFS starting points
    'http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion',   # Ahmia
    'https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',  # DuckDuckGo
    'http://torlinksge6enmcyyuxjpjkoouw4oorgdgeo7ftnq3zodj7g2zxi3kyd.onion',   # TorLinks
    'http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion',   # Dark.Fail
    'http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion',   # OnionLand Search
    'http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion',   # Tor66 Search
    'http://notevil2ebbr5xjww6nryjta7bycbriyi2vh7an3wcuovlznvobykmad.onion',   # NotEvil Search

    # Whistleblowing / Legitimate Media (good OPSEC baseline)
    'http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion',   # SecureDrop
    'http://ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion',   # CIA
    'http://bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion',   # BBC News
    'http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion',   # Tor Project
    'http://hctxrvjzfpvmzh2jllqhgvvkoepxb4kfzdjm6h7egcwlumggtktiftid.onion',   # Tor Metrics
    'http://iykpqm7jiradoeezzkhj7c4b33g4hbgfwelht2evxxeicbpjy44c7ead.onion',   # EFF
    'http://xp44cagis447k3lpb4wwhcqukix6cgqokbuys24vmxmbzmaq2gjvc2yd.onion',   # Guardian SecureDrop

    # Privacy / Security Services
    'http://njallalafimoej5i4eg7vlnqjvmb6zhdh27qxcatdn647jtwwwui3nad.onion',   # Njalla
    'http://o54hon2e2vj6c7m3aqqu6uyece65by3vgoxxhlqlsvkmacw6a7m7kiad.onion',   # Mullvad VPN
    'https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion',   # ProtonMail
    'http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion',   # Riseup
    'http://lldan5gahapx5k7iafb3s4ikijc4ni7gx5iywdflkba5y2ezyg6sjgyd.onion',   # OnionShare
    'http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion',   # keys.openpgp.org

    # Forums (research value)
    'http://enxx3byspwsdo446jujc52ucy2pf5urdbhqw3kbsfhlfjwmbpj5smdad.onion',   # Endchan
    'http://answersgsvfcolchecflbhnvcvy7q433vyrar62vnxcztfmtlfwidtqd.onion',   # Hidden Answers
    'http://rambleeeqrhty6s5jgefdfdtc6tfgg4jj6svr4jpgk4wjtg3qshwbaad.onion',   # Ramble
    'http://danielas3rtn54uwmofdo3x2bsdifr47huasnmbgqzfrec5ubupvtpid.onion',   # Daniel

    # Crypto (feeds BTC risk scoring)
    'http://wasabiukrxmkdgve5kynjztuovbg43uxcbcxn6y2okcrsg7gb6jdmbad.onion',   # Wasabi Wallet
    'http://blkchairbknpn73cfjhevhla7rkp4ed5gg2knctvv7it4lioy22defid.onion',   # Blockchair

    # Security Research (documented by SOCRadar/KELA)
    'http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion',   # Ransomware Groups
    'http://ransomlookumjrc6erzqn467lkcu2t5h4enjzfigvsxrrktxicysi2yd.onion',   # RansomLook
    'http://zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd.onion',   # ZeroBin
    'http://strongerw2ise74v3duebgsvug4mehyhlpa7f6kfwnas7zofs3kov7yd.onion',   # Stronghold Paste

    # Email / Comms
    'http://mail2torjgmxgexntbrmhvgluavhj7ouul5yar6ylbvjkxwqf6ixkwyd.onion',   # Mail2Tor
    'http://torbox36ijlcevujx7mjb4oiusvwgvmue7jfn2cvutwa6kl6to3uyqad.onion',   # TorBox
    'http://dnmxjaitaiafwmss2lx7tbs5bv66l7vjdmb5mtb3yqpxqhk3it5zivad.onion',   # DNMX
    'http://pflujznptk5lmuf6xwadfqy6nffykdvahfbljh7liljailjbxrgvhfid.onion',   # Onion Mail

    # Hosting / VPS
    'http://hzwjmjimhr7bdmfv2doll4upibt5ojjmpo3pbp5ctwcg37n3hyk7qzid.onion',   # Ablative Hosting
    'http://eternalcbrzpicytj4zyguygpmkjlkddxob7tptlr25cdipe5svyqoqd.onion',   # Eternal Hosting
    'http://nicevpsvzo5o6mtvvdiurhkemnv7335f74tjk42rseoj7zdnqy44mnqd.onion',   # NiceVPS
]

# ── Domain blocklist ─────────────────────────────────────────────────────────
# These domains produce too many irrelevant pages and clog the dataset.
# Add any domain that produces noise (GitLab instances, clearnet mirrors, etc.)
DOMAIN_BLOCKLIST = {
    # GitLab/code hosting — produces thousands of project pages
    'wmj5kiic7b6kjplpbvwadnht2nh2qnkbnqtcv3dyvpqtz7ssbssftxid.onion',
    # Image CDN subdomains — not useful pages
    'ichef.bbcws2hcewhlhutm5qrjkekkg3eraphuc7ba7qh4jeinhibnx3ymxaqd.onion',
    'static.files.bbcws2hcewhlhutm5qrjkekkg3eraphuc7ba7qh4jeinhibnx3ymxaqd.onion',
}

def is_blocked_domain(url):
    """Return True if URL belongs to a blocklisted domain."""
    try:
        host = urlparse(url).netloc.lower().split(':')[0]
        return host in DOMAIN_BLOCKLIST
    except Exception:
        return False

# ── Keywords ──────────────────────────────────────────────────────────────────
STRONG_KEYWORDS = [
    'exploit','malware','hack','vulnerability','breach','ransomware',
    'phishing','ddos','zero-day','rootkit','keylogger','botnet',
    'backdoor','trojan','cve','leaked','credentials','stolen',
    'carding','counterfeit','fraud','stealer','infostealer',
    'database dump','combolist','fullz',
]
WEAK_KEYWORDS = [
    'darknet','anonymous','bitcoin','monero','marketplace','tor',
    'hidden','onion','security','encryption','privacy','vpn',
    'proxy','forum','crypto','wallet','dark','untraceable',
    'pgp','opsec','paste','dump',
]

# ── URL Utilities ─────────────────────────────────────────────────────────────
ONION_REGEX = re.compile(
    r'https?://(?:[a-z0-9\-]+\.)*[a-z2-7]{10,60}\.onion(?:/[^\s"\'<>]*)?',
    re.IGNORECASE
)

def is_valid_onion(url):
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return False
    if '.onion' not in url:
        return False
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(':')[0]
        if not host.endswith('.onion'):
            return False
        onion_label = host.replace('.onion', '').split('.')[-1]
        if not re.match(r'^[a-z2-7]{10,60}$', onion_label):
            return False
        if is_blocked_domain(url):
            return False
    except Exception:
        return False
    return True


def normalize_url(url):
    try:
        url    = url.strip()
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host   = parsed.netloc.lower()
        path   = parsed.path.rstrip('/')
        return f"{scheme}://{host}{path}" if path else f"{scheme}://{host}"
    except Exception:
        return url.strip().rstrip('/')


def get_domain(url):
    try:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc.lower()}"
    except Exception:
        return url


def url_hash(url):
    return hashlib.sha256(normalize_url(url).encode()).hexdigest()[:16]


def extract_onion_links(html, soup, base_url):
    """
    Extract all valid .onion links from page HTML.
    Method 1: <a href> tags (handles relative URLs via urljoin)
    Method 2: raw regex on HTML (catches links in JS/comments)
    Both methods combined and deduplicated.
    """
    found = set()
    # Method 1: <a href> tags
    for tag in soup.find_all('a', href=True):
        href = tag['href'].strip()
        if not href or href.startswith(('#', 'mailto:', 'javascript:')):
            continue
        if not href.startswith('http'):
            try:
                href = urljoin(base_url, href)
            except Exception:
                continue
        if is_valid_onion(href):
            found.add(normalize_url(href))
    # Method 2: raw regex
    for match in ONION_REGEX.finditer(html):
        candidate = match.group(0)
        if is_valid_onion(candidate):
            found.add(normalize_url(candidate))
    return found


def extract_links_from_text(stored_text, base_url=''):
    """
    Re-extract .onion links from stored page text field.
    Since get_text() strips tags, we only get raw URL strings visible in text.
    Uses regex — less effective than raw HTML but works on old pages.
    """
    found = set()
    for match in ONION_REGEX.finditer(stored_text):
        candidate = normalize_url(match.group(0))
        if is_valid_onion(candidate):
            found.add(candidate)
    return found


# ── Threat Detection ──────────────────────────────────────────────────────────
def detect_threat(text, title=''):
    combined = (text + ' ' + title).lower()
    strong   = [k for k in STRONG_KEYWORDS if k in combined]
    weak     = [k for k in WEAK_KEYWORDS   if k in combined]
    all_kw   = list(set(strong + weak))
    flagged  = len(strong) >= 1 or len(weak) >= 3
    return all_kw, strong, flagged

# ── Tor Session ───────────────────────────────────────────────────────────────
def make_tor_session():
    s = requests.Session()
    s.proxies = TOR_PROXY
    s.headers.update({'User-Agent': USER_AGENT})
    return s


def verify_tor(session):
    try:
        r    = session.get('https://check.torproject.org/api/ip', timeout=15)
        data = r.json()
        if data.get('IsTor'):
            print(f"{Fore.GREEN}  ✓ Tor verified — Exit IP: {data.get('IP','?')}{Style.RESET_ALL}")
            return True
        print(f"{Fore.RED}  ✗ Not routing through Tor! Open Tor Browser first.{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.YELLOW}  ⚠ Cannot verify Tor ({str(e)[:40]}) — proceeding anyway{Style.RESET_ALL}")
        return True

# ── Uptime Logging ────────────────────────────────────────────────────────────
def log_uptime(url, is_online, response_ms, status_code):
    try:
        db.uptime_logs.insert_one({
            'url':         url,
            'domain':      get_domain(url),
            'checked_at':  datetime.datetime.now(datetime.timezone.utc),
            'is_online':   is_online,
            'response_ms': response_ms,
            'status_code': status_code,
        })
    except Exception:
        pass

# ── DB Dedup Check ────────────────────────────────────────────────────────────
def already_crawled(norm_url):
    variants = [norm_url, norm_url + '/', norm_url.rstrip('/')]
    return db.pages.find_one({'url': {'$in': variants}}, {'_id': 1}) is not None

# ── Core Page Crawler ─────────────────────────────────────────────────────────
def crawl_page(url, session, num, domain_counts):
    norm_url = normalize_url(url)
    domain   = get_domain(norm_url)

    # Blocklist check
    if is_blocked_domain(norm_url):
        return set()

    # Domain cap
    if domain_counts.get(domain, 0) >= MAX_PER_DOMAIN:
        return set()

    # DB dedup
    if already_crawled(norm_url):
        print(f"  [{Fore.CYAN}SKIP{Style.RESET_ALL}] In DB — {norm_url[:70]}")
        return set()

    # HTTP request with retry
    response   = None
    start_ms   = int(time.time() * 1000)
    last_error = ''

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            response = session.get(norm_url, timeout=REQUEST_TIMEOUT)
            break
        except requests.exceptions.Timeout:
            last_error = 'Timeout'
        except requests.exceptions.ConnectionError as e:
            last_error = f'ConnectionError: {str(e)[:40]}'
        except requests.exceptions.TooManyRedirects:
            last_error = 'TooManyRedirects'
            break
        except Exception as e:
            last_error = str(e)[:60]

        if attempt < RETRY_ATTEMPTS:
            wait = RETRY_DELAY * attempt
            print(f"  [{Fore.YELLOW}RETRY {attempt}{Style.RESET_ALL}] {norm_url[:55]} — {last_error} (wait {wait}s)")
            time.sleep(wait)

    elapsed_ms = int(time.time() * 1000) - start_ms

    if response is None:
        print(f"  [{Fore.RED}FAIL{Style.RESET_ALL}] ({num:04d}) {norm_url[:65]} — {last_error}")
        log_uptime(norm_url, False, elapsed_ms, 0)
        return set()

    status = response.status_code
    log_uptime(norm_url, status < 400, elapsed_ms, status)

    if status >= 400:
        print(f"  [{Fore.RED}HTTP {status}{Style.RESET_ALL}] ({num:04d}) {norm_url[:65]}")
        return set()

    # Content-type check — skip binary files
    ct = response.headers.get('Content-Type', '').lower()
    if any(x in ct for x in ['image/', 'audio/', 'video/', 'application/pdf', 'application/zip']):
        print(f"  [{Fore.YELLOW}SKIP{Style.RESET_ALL}] Binary content ({ct[:30]}) — {norm_url[:55]}")
        return set()

    # Parse HTML
    raw_html = response.text
    try:
        soup = BeautifulSoup(raw_html, 'lxml')
    except Exception:
        soup = BeautifulSoup(raw_html, 'html.parser')

    # Title
    title_tag = soup.find('title')
    title     = title_tag.get_text(strip=True)[:200] if title_tag else 'No Title'

    # Clean text
    for tag in soup(['script', 'style', 'noscript']):
        tag.decompose()
    text = soup.get_text(separator=' ', strip=True)

    # Threat detection
    all_kw, strong_kw, is_flagged = detect_threat(text, title)

    # Build document
    doc = {
        'url':             norm_url,
        'domain':          domain,
        'title':           title,
        'text':            text[:MAX_TEXT_STORE],
        'text_length':     len(text),
        'raw_html':        raw_html[:MAX_HTML_STORE],
        'html_size':       len(raw_html),
        'html_truncated':  len(raw_html) > MAX_HTML_STORE,
        'page_size':       len(raw_html),
        'status_code':     status,
        'response_ms':     elapsed_ms,
        'keywords_found':  all_kw,
        'strong_keywords': strong_kw,
        'is_flagged':      is_flagged,
        'crawled_at':      datetime.datetime.now(datetime.timezone.utc),
        'url_hash':        url_hash(norm_url),
    }

    try:
        db.pages.insert_one(doc)
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    except DuplicateKeyError:
        print(f"  [{Fore.CYAN}DUP{Style.RESET_ALL}]  Concurrent duplicate — {norm_url[:60]}")
        return set()
    except Exception as e:
        print(f"  [{Fore.RED}DB ERR{Style.RESET_ALL}] {str(e)[:70]}")
        return set()

    flag_str = f"{Fore.RED}⚑ THREAT{Style.RESET_ALL}" if is_flagged else f"{Fore.GREEN}✓ Clean {Style.RESET_ALL}"
    print(f"\n  [{Fore.CYAN}{num:04d}{Style.RESET_ALL}] {flag_str} | {elapsed_ms}ms | HTTP {status}")
    print(f"         {Fore.WHITE}{title[:72]}{Style.RESET_ALL}")
    print(f"         {Fore.BLUE}{norm_url[:80]}{Style.RESET_ALL}")
    if strong_kw:
        print(f"         {Fore.RED}Strong KW:{Style.RESET_ALL} {strong_kw[:5]}")
    elif all_kw:
        print(f"         {Fore.YELLOW}Keywords: {Style.RESET_ALL} {all_kw[:4]}")

    new_links = extract_onion_links(raw_html, soup, norm_url)
    if new_links:
        print(f"         {Fore.GREEN}+{len(new_links)} links discovered{Style.RESET_ALL}")

    return new_links

# ── BFS Crawl Loop ────────────────────────────────────────────────────────────
def crawl(max_pages=300):
    print(f"\n{Fore.CYAN}{'═'*65}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DARK WEB INTELLIGENCE PLATFORM — CRAWLER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*65}{Style.RESET_ALL}")

    setup_indexes()
    session = make_tor_session()

    print(f"\n  {Fore.YELLOW}Verifying Tor connection...{Style.RESET_ALL}")
    verify_tor(session)

    queued_set = set()
    queue      = deque()

    # Add seeds to queue
    for s in SEEDS:
        if is_valid_onion(s):
            ns = normalize_url(s)
            if ns not in queued_set:
                queued_set.add(ns)
                queue.append(ns)

    # ── PERSISTENT QUEUE RECOVERY ─────────────────────────────────────────────
    # Re-extract .onion links from all previously crawled pages.
    # Strategy:
    #   1. Pages with raw_html -> parse with BeautifulSoup (gets ALL <a href> links)
    #   2. Pages with only text -> use regex (gets links visible in text)
    # This rebuilds the BFS frontier lost when the script ended.
    # ─────────────────────────────────────────────────────────────────────────
    print(f"  {Fore.YELLOW}Rebuilding BFS queue from stored pages...{Style.RESET_ALL}")

    already_in_db = set()
    for page in db.pages.find({}, {'url': 1}):
        u = normalize_url(page.get('url', ''))
        if u:
            already_in_db.add(u)

    has_html  = db.pages.count_documents({'raw_html': {'$exists': True, '$ne': ''}})
    has_text  = db.pages.count_documents({'text': {'$exists': True}})
    print(f"  Pages with raw_html: {has_html} | with text only: {has_text - has_html}")

    recovered    = 0
    parsed_pages = 0

    # Process all pages — use raw_html if available, else text
    for page in db.pages.find({}, {'raw_html': 1, 'text': 1, 'url': 1}):
        raw_html    = page.get('raw_html', '') or ''
        stored_text = page.get('text', '')     or ''
        base_url    = page.get('url', '')      or ''

        links_found = set()

        if raw_html:
            # Best path: parse raw HTML with BeautifulSoup to get all <a href>
            try:
                soup = BeautifulSoup(raw_html, 'lxml')
            except Exception:
                soup = BeautifulSoup(raw_html, 'html.parser')

            for tag in soup.find_all('a', href=True):
                href = tag['href'].strip()
                if not href or href.startswith(('#', 'mailto:', 'javascript:')):
                    continue
                if not href.startswith('http'):
                    try:
                        href = urljoin(base_url, href)
                    except Exception:
                        continue
                if is_valid_onion(href):
                    links_found.add(normalize_url(href))

            # Also run regex on raw_html
            for match in ONION_REGEX.finditer(raw_html):
                c = normalize_url(match.group(0))
                if is_valid_onion(c):
                    links_found.add(c)
        else:
            # Fallback: regex on stored text (older pages without raw_html)
            links_found = extract_links_from_text(stored_text, base_url)

        parsed_pages += 1
        for link in links_found:
            if link not in queued_set and link not in already_in_db:
                queued_set.add(link)
                queue.append(link)
                recovered += 1

    print(f"  {Fore.GREEN}✓ Recovered {recovered} unvisited URLs from {parsed_pages} stored pages{Style.RESET_ALL}")

    visited       = set(already_in_db)
    domain_counts = {}
    crawled       = 0

    print(f"\n  Seeds + recovered in queue : {len(queue)}")
    print(f"  Target pages               : {max_pages}")
    print(f"  Domain cap                 : {MAX_PER_DOMAIN} pages/domain")
    print(f"  Tor proxy                  : socks5h://{TOR_HOST}:{TOR_PORT}")
    print(f"  MongoDB DB                 : {DB_NAME}")
    print(f"\n{Fore.CYAN}{'─'*65}{Style.RESET_ALL}\n")

    while queue and crawled < max_pages:
        url = queue.popleft()

        if url in visited:
            continue
        visited.add(url)

        new_links = crawl_page(url, session, crawled + 1, domain_counts)
        crawled  += 1

        added = 0
        for link in new_links:
            norm = normalize_url(link)
            if norm not in visited and norm not in queued_set:
                dom = get_domain(norm)
                if domain_counts.get(dom, 0) < MAX_PER_DOMAIN:
                    queue.append(norm)
                    queued_set.add(norm)
                    added += 1

        if added:
            print(f"         {Fore.GREEN}Queued {added} new | Queue: {len(queue)}{Style.RESET_ALL}")

        time.sleep(CRAWL_DELAY)

    # Final summary
    total_db   = db.pages.count_documents({})
    flagged_db = db.pages.count_documents({'is_flagged': True})

    print(f"\n{Fore.CYAN}{'═'*65}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  CRAWL COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*65}")
    print(f"  Pages this run    : {crawled}")
    print(f"  Total in DB       : {total_db}")
    print(f"  Flagged (threats) : {flagged_db}")
    print(f"  Clean             : {total_db - flagged_db}")
    print(f"  Unique domains    : {len(domain_counts)}")
    print(f"  Queue remaining   : {len(queue)}")
    print(f"{'─'*65}")

    unclassified = db.pages.count_documents({'category': {'$exists': False}})
    no_nlp       = db.pages.count_documents({'entities': {'$exists': False}})
    if unclassified > 0:
        print(f"\n  {Fore.YELLOW}⚠ {unclassified} pages need classification → python classifier.py{Style.RESET_ALL}")
    if no_nlp > 0:
        print(f"  {Fore.YELLOW}⚠ {no_nlp} pages need NLP analysis → python nlp_pipeline.py{Style.RESET_ALL}")
    print(f"\n  {Fore.GREEN}Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*65}{Style.RESET_ALL}\n")

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web Intelligence Crawler')
    parser.add_argument('--max', type=int, default=300,
                        help='Max pages to crawl (default: 300)')
    args = parser.parse_args()
    try:
        crawl(max_pages=args.max)
    except KeyboardInterrupt:
        total = db.pages.count_documents({})
        print(f"\n\n  {Fore.YELLOW}Interrupted — {total} pages in DB{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Dashboard: http://localhost:5000{Style.RESET_ALL}\n")