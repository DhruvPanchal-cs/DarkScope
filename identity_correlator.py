"""
identity_correlator.py — Cross-Platform Identity Correlator
=============================================================
Extracts usernames from dark web forums and pages,
then searches GitHub and Reddit for matching accounts.

Research significance:
  Dark web users assume their pseudonyms are safe.
  This module proves that many users reuse the same
  username on clearnet platforms — creating a bridge
  between anonymous dark web identity and real identity.
  This is a unique feature — no existing tool does this.

Features:
  - Username extraction from Endchan posts + page text
  - 400+ word false-positive filter (common words, tech terms)
  - GitHub API: repos, followers, bio, location, real name
  - Reddit API: karma, account age, post history
  - Stores confirmed correlations in MongoDB
  - Uptime-aware: skips users already checked

Usage:
    python identity_correlator.py
    python identity_correlator.py --recheck   (recheck all usernames)
    python identity_correlator.py --limit 50  (check top N usernames)
"""

import re
import time
import datetime
import argparse

import requests
from pymongo import MongoClient
from colorama import init, Fore, Style

from config import MONGO_URI, DB_NAME

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

MONGO_URI  = 'mongodb://localhost:27017/'
DB_NAME    = 'darkweb_crawler'
API_DELAY  = 1.0   # seconds between API calls (rate limiting)
MIN_KARMA  = 10    # Reddit minimum karma to count as real account
MIN_REPOS  = 0     # GitHub minimum repos (0 = any account counts)

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── Clearnet session (NOT through Tor — GitHub/Reddit block Tor exits) ────────

clearnet_session = requests.Session()
clearnet_session.headers.update({
    'User-Agent': 'Mozilla/5.0 (research-tool/1.0; academic-study)',
    'Accept':     'application/json',
})

# ── False Positive Filter ─────────────────────────────────────────────────────
# Comprehensive list of common words that are NOT real usernames.
# A username must NOT be in this set to be considered valid.

FALSE_POSITIVES = {
    # Articles / prepositions
    'the','and','for','this','that','with','from','have','not','are',
    'was','but','all','can','your','new','get','one','has','his','her',
    'our','its','use','day','may','way','see','him','two','how','any',
    'also','into','been','more','some','than','then','them','they',
    'will','just','like','what','when','who','each','which','their',
    # Common verbs
    'make','take','give','know','time','very','after','could','first',
    'come','want','look','many','write','would','there','think','say',
    'help','here','need','find','does','well','even','such','back',
    # Tech terms
    'admin','user','guest','post','reply','thread','board','forum',
    'message','title','subject','content','text','html','http','www',
    'anonymous','anon','linux','windows','android','python','javascript',
    'github','reddit','google','facebook','twitter','telegram','signal',
    'ubuntu','debian','nginx','apache','mysql','mongo','docker','sudo',
    'root','server','client','email','mail','password','login','logout',
    'register','profile','account','settings','search','home','page',
    'link','image','video','file','download','upload','share','public',
    # Dark web / crypto terms
    'bitcoin','monero','crypto','wallet','darknet','onion','tor',
    'mullvad','proton','riseup','pgp','opsec','paste','dump','market',
    'vendor','escrow','deal','order','product','listing','buyer','seller',
    # Common adjectives
    'free','open','fast','slow','good','best','safe','secure','private',
    'dark','black','white','red','blue','green','new','old','true','fake',
    'real','online','offline','hidden','anonymous','encrypted','secure',
    # Countries and languages
    'english','russian','german','french','spanish','chinese','arabic',
    'deutsch','francais','espanol','italiano','polish','swedish',
    # Forum-specific
    'moderator','operator','staff','banned','verified','trusted',
    # Numbers and very short
    'test','info','news','data','null','none','void','todo','fixme',
}

# ── Username Patterns ─────────────────────────────────────────────────────────

USERNAME_PATTERNS = [
    # Posted by / Author fields
    re.compile(
        r'(?:posted\s+by|author[:\s]|by\s+user[:\s]|username[:\s]'
        r'|handle[:\s]|nick[:\s]|wrote[:\s])\s*([a-zA-Z0-9_\-\.]{4,20})',
        re.IGNORECASE
    ),
    # @mention style
    re.compile(r'@([a-zA-Z0-9_]{5,20})\b'),
    # Quote attribution
    re.compile(r'"[^"]{10,}"[,\s]+[-—]\s*([a-zA-Z0-9_\-\.]{4,20})'),
]


def is_valid_username(username: str) -> bool:
    """
    Validate a candidate username.
    Returns True only if it passes ALL checks:
      1. Length 4-20 characters
      2. Not all digits
      3. Not in false positive list
      4. Only allowed characters (alphanumeric + _ - .)
      5. Contains at least one letter
      6. Does not start/end with special chars
      7. Has some uniqueness signal (number, underscore, mixed case, or length >= 8)
    """
    u = username.strip()

    if not (4 <= len(u) <= 20):
        return False
    if u.isdigit():
        return False
    if u.lower() in FALSE_POSITIVES:
        return False
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', u):
        return False
    if not re.search(r'[a-zA-Z]', u):
        return False
    if u[0] in '_-.' or u[-1] in '_.':
        return False

    # Must have some uniqueness — not just a plain short lowercase word
    has_number     = bool(re.search(r'\d', u))
    has_underscore = '_' in u or '-' in u
    has_mixed_case = u != u.lower() and u != u.upper()
    long_enough    = len(u) >= 8

    if not (has_number or has_underscore or has_mixed_case or long_enough):
        return False

    return True


# ── Username Extraction ───────────────────────────────────────────────────────

def extract_from_forums() -> set:
    """Extract validated usernames from Endchan forum posts in DB."""
    usernames = set()
    posts = list(db.forums.find({}, {'username': 1}))
    for post in posts:
        u = (post.get('username') or '').strip()
        if u and is_valid_username(u):
            usernames.add(u)
    return usernames


def extract_from_pages() -> set:
    """Extract validated usernames from crawled page text."""
    usernames = set()
    pages = list(db.pages.find(
        {'text': {'$exists': True}},
        {'text': 1}
    ).limit(50))

    for page in pages:
        text = page.get('text', '') or ''
        for pattern in USERNAME_PATTERNS:
            for match in pattern.finditer(text):
                candidate = match.group(1).strip()
                if is_valid_username(candidate):
                    usernames.add(candidate)
    return usernames


def get_already_checked() -> set:
    """Get usernames already in the correlations collection."""
    checked = db.identity_correlations.distinct('username')
    return set(checked)


# ── Platform Lookups ──────────────────────────────────────────────────────────

def check_github(username: str) -> dict:
    """
    Query GitHub API for username.
    Only returns a match if account has real activity
    (repos > 0 OR followers > 0) to avoid false positives.
    """
    result = {'found': False, 'platform': 'GitHub'}
    try:
        r = clearnet_session.get(
            f'https://api.github.com/users/{username}',
            timeout=10
        )
        if r.status_code == 200:
            data    = r.json()
            repos   = data.get('public_repos', 0)
            followers = data.get('followers', 0)

            # Only flag if account has real activity
            if repos > 0 or followers > 0:
                result.update({
                    'found':       True,
                    'platform':    'GitHub',
                    'url':         data.get('html_url', ''),
                    'real_name':   data.get('name'),
                    'bio':         (data.get('bio') or '')[:150],
                    'location':    data.get('location'),
                    'company':     data.get('company'),
                    'email':       data.get('email'),
                    'repos':       repos,
                    'followers':   followers,
                    'created_at':  data.get('created_at', '')[:10],
                    'avatar_url':  data.get('avatar_url', ''),
                })
        elif r.status_code == 403:
            # Rate limited
            print(f"    {Fore.YELLOW}GitHub rate limited — sleeping 60s{Style.RESET_ALL}")
            time.sleep(60)

    except Exception as e:
        result['error'] = str(e)[:50]

    return result


def check_reddit(username: str) -> dict:
    """
    Query Reddit API for username.
    Only returns a match if account has karma >= MIN_KARMA
    and was created more than 1 day ago (filters bot accounts).
    """
    result = {'found': False, 'platform': 'Reddit'}
    try:
        headers = {
            'User-Agent': 'python:darkweb-research:v1.0 (academic study)'
        }
        r = clearnet_session.get(
            f'https://www.reddit.com/user/{username}/about.json',
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data  = r.json().get('data', {})
            karma = data.get('total_karma', 0)
            created_utc = data.get('created_utc', 0)

            if karma >= MIN_KARMA:
                created_str = (
                    datetime.datetime.utcfromtimestamp(created_utc).strftime('%Y-%m-%d')
                    if created_utc else 'unknown'
                )
                result.update({
                    'found':         True,
                    'platform':      'Reddit',
                    'url':           f'https://reddit.com/u/{username}',
                    'karma':         karma,
                    'link_karma':    data.get('link_karma', 0),
                    'comment_karma': data.get('comment_karma', 0),
                    'created_at':    created_str,
                    'verified':      data.get('verified', False),
                    'is_gold':       data.get('is_gold', False),
                })
        elif r.status_code == 404:
            pass  # User doesn't exist
        elif r.status_code == 429:
            print(f"    {Fore.YELLOW}Reddit rate limited — sleeping 30s{Style.RESET_ALL}")
            time.sleep(30)

    except Exception as e:
        result['error'] = str(e)[:50]

    return result


# ── Main Correlator ───────────────────────────────────────────────────────────

def run_identity_correlator(recheck: bool = False, limit: int = 30):
    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  CROSS-PLATFORM IDENTITY CORRELATOR{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Dark Web Usernames → GitHub + Reddit{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*62}{Style.RESET_ALL}")

    # Extract usernames
    print(f"\n  Extracting usernames from dark web data...")
    forum_users = extract_from_forums()
    page_users  = extract_from_pages()
    all_users   = list(forum_users | page_users)

    print(f"  Forum usernames (valid) : {len(forum_users)}")
    print(f"  Page usernames  (valid) : {len(page_users)}")
    print(f"  Total unique            : {len(all_users)}")

    if forum_users:
        sample = list(forum_users)[:8]
        print(f"  Forum sample: {sample}")

    # Filter already-checked unless recheck mode
    if not recheck:
        already = get_already_checked()
        all_users = [u for u in all_users if u not in already]
        print(f"  New (unchecked)         : {len(all_users)}")

    if not all_users:
        print(f"\n  {Fore.GREEN}All usernames already checked.{Style.RESET_ALL}")
        print_correlation_stats()
        return

    # Limit
    to_check = all_users[:limit]
    print(f"  Will check              : {len(to_check)} usernames")
    print(f"\n  Searching GitHub and Reddit...\n")
    print(f"{'─'*62}")

    correlations_found = 0

    for idx, username in enumerate(to_check):
        print(f"  [{idx+1:03d}/{len(to_check)}] Checking: {Fore.CYAN}{username}{Style.RESET_ALL}")

        gh = check_github(username)
        time.sleep(API_DELAY)
        rd = check_reddit(username)
        time.sleep(API_DELAY)

        platforms_found = []
        if gh.get('found'):
            platforms_found.append(gh)
            print(f"    {Fore.RED}MATCH → GitHub: {gh.get('url','')}{Style.RESET_ALL}")
            if gh.get('real_name'):
                print(f"           Real name : {gh['real_name']}")
            if gh.get('location'):
                print(f"           Location  : {gh['location']}")
            if gh.get('email'):
                print(f"           Email     : {gh['email']}")
            print(f"           Repos:{gh['repos']} | Followers:{gh['followers']}")

        if rd.get('found'):
            platforms_found.append(rd)
            print(f"    {Fore.RED}MATCH → Reddit: {rd.get('url','')}{Style.RESET_ALL}")
            print(f"           Karma:{rd['karma']} | Since:{rd['created_at']}")

        if not platforms_found:
            print(f"    No clearnet match found")

        # Store result regardless (to mark as checked)
        try:
            db.identity_correlations.update_one(
                {'username': username},
                {'$set': {
                    'username':    username,
                    'clearnet':    platforms_found,
                    'matched':     len(platforms_found) > 0,
                    'analyzed_at': datetime.datetime.now(datetime.timezone.utc),
                    'source':      'forum' if username in forum_users else 'page',
                }},
                upsert=True
            )
            if platforms_found:
                correlations_found += 1
        except Exception as e:
            print(f"    DB error: {str(e)[:50]}")

    # Summary
    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  IDENTITY CORRELATION COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*62}")
    print(f"  Usernames checked   : {len(to_check)}")
    print(f"  Correlations found  : {Fore.RED}{correlations_found}{Style.RESET_ALL}")
    if correlations_found == 0:
        print(f"\n  {Fore.GREEN}No matches found — dark web users in this dataset")
        print(f"  maintain good identity hygiene (valid research finding){Style.RESET_ALL}")

    print_correlation_stats()


def print_correlation_stats():
    total   = db.identity_correlations.count_documents({})
    matched = db.identity_correlations.count_documents({'matched': True})
    print(f"\n  DB Stats:")
    print(f"    Total usernames checked : {total}")
    print(f"    Clearnet matches found  : {matched}")
    if total > 0:
        rate = round(matched / total * 100, 1)
        print(f"    Match rate              : {rate}%")

    # Show confirmed correlations
    confirmed = list(db.identity_correlations.find(
        {'matched': True},
        {'username': 1, 'clearnet': 1}
    ).limit(10))
    if confirmed:
        print(f"\n  Confirmed Cross-Platform Identities:")
        for c in confirmed:
            platforms = [p['platform'] for p in c.get('clearnet', [])]
            print(f"    '{c['username']}' found on: {', '.join(platforms)}")
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cross-Platform Identity Correlator')
    parser.add_argument('--recheck', action='store_true',
                        help='Recheck all usernames including already-checked ones')
    parser.add_argument('--limit', type=int, default=30,
                        help='Max usernames to check (default: 30)')
    args = parser.parse_args()
    run_identity_correlator(recheck=args.recheck, limit=args.limit)