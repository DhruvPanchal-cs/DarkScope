"""
forum_crawler.py — Dark Web Forum Crawler
==========================================
Crawls Endchan imageboard/forum via Tor proxy.
Run after crawler.py (independently).

Fixes applied:
  - config.py centralised configuration
  - Proper pagination via actual HTML next-links (not ?page=N)
  - Loop detection to prevent infinite pagination

Usage:
    python forum_crawler.py
    python forum_crawler.py --board tech
    python forum_crawler.py --max-threads 20
"""

import re
import time
import datetime
import argparse

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration (centralised — edit config.py, not here) ───────────────────
from config import (
    MONGO_URI, DB_NAME, TOR_PROXY, REQUEST_TIMEOUT,
    BOARD_DELAY, THREAD_DELAY, USER_AGENT,
)

# ── Forums Configuration ──────────────────────────────────────────────────────

FORUMS = [
    {
        'name':   'Endchan',
        'base':   'http://enxx3byspwsdo446jujc52ucy2pf5urdbhqw3kbsfhlfjwmbpj5smdad.onion',
        'boards': ['/b/', '/tech/', '/pol/', '/os/', '/ausneets/', '/operate/'],
        'type':   'endchan',
    },
]

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

def setup_indexes():
    try:
        db.forums.create_index(
            [('forum', 1), ('board', 1), ('dedup_key', 1)],
            unique=True, sparse=True, name='forum_dedup_index'
        )
        db.forums.create_index('forum')
        db.forums.create_index('board')
        db.forums.create_index('crawled_at')
        db.forums.create_index('username')
        print(f"{Fore.GREEN}  ✓ Forum indexes ready{Style.RESET_ALL}")
    except Exception:
        pass

# ── HTTP Session ──────────────────────────────────────────────────────────────

def make_session():
    s = requests.Session()
    s.proxies = TOR_PROXY
    s.headers.update({'User-Agent': USER_AGENT})
    return s


def safe_get(session, url):
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        return r if r.status_code == 200 else None
    except requests.exceptions.Timeout:
        print(f"    {Fore.YELLOW}⚠ Timeout: {url[:60]}{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"    {Fore.RED}✗ Connection failed: {url[:60]}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}✗ Error: {str(e)[:50]}{Style.RESET_ALL}")
    return None

# ── Pagination — FIXED ────────────────────────────────────────────────────────

def get_next_page_url(soup, base_url):
    """
    Find the actual next-page link from parsed Endchan HTML.
    Returns full next-page URL or None if last page.

    FIX: Previously used ?page=N which Endchan ignores — it always
    returns the same board root regardless of the page parameter.
    Now we follow ACTUAL links from the page HTML.

    Checks (in priority order):
      1. <a rel="next"> — HTML standard
      2. Links with text: Next, >, ›, >>
      3. Numbered page links like /b/2.html
    """
    if soup is None:
        return None

    # Pattern 1: <a rel="next">
    for a in soup.find_all('a', href=True):
        rel = a.get('rel', [])
        if isinstance(rel, list):
            rel = ' '.join(rel)
        if 'next' in rel.lower():
            href = a['href']
            if href and not href.startswith('#'):
                return (base_url + href) if href.startswith('/') else href

    # Pattern 2: Text-based next links
    next_texts = {'next', '>', '\u203a', '>>', 'next page', '\u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0430\u044f'}
    for a in soup.find_all('a', href=True):
        text = a.get_text(strip=True).lower()
        if text in next_texts:
            href = a['href']
            if href and not href.startswith('#'):
                return (base_url + href) if href.startswith('/') else href

    # Pattern 3: Numbered page links (page 2+)
    page_links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        m = re.search(r'[/?]([2-9][0-9]*)(?:\.html)?$', href)
        if m:
            try:
                page_links.append((int(m.group(1)), href))
            except ValueError:
                pass
    if page_links:
        page_links.sort(key=lambda x: x[0])
        _, max_href = page_links[-1]
        return (base_url + max_href) if max_href.startswith('/') else max_href

    return None

# ── Endchan Parser ────────────────────────────────────────────────────────────

def parse_endchan_board(html, base_url, board):
    try:
        soup = BeautifulSoup(html, 'lxml')
    except Exception:
        soup = BeautifulSoup(html, 'html.parser')

    threads = []
    thread_containers = (
        soup.find_all('div', class_='opCell') or
        soup.find_all('article', class_='post') or
        soup.find_all('div', class_='thread') or
        soup.find_all('section', class_='threadCell') or
        soup.find_all('div', id=re.compile(r'^thread'))
    )

    for container in thread_containers[:30]:
        subject_el = (
            container.find(class_='labelSubject') or
            container.find(class_='subject') or
            container.find('h2') or container.find('h3') or
            container.find(class_='postSubject')
        )
        subject = subject_el.get_text(strip=True)[:200] if subject_el else 'No Subject'

        content_el = (
            container.find(class_='divMessage') or
            container.find(class_='message') or
            container.find(class_='postMessage') or
            container.find(class_='body') or
            container.find('p')
        )
        content = content_el.get_text(strip=True)[:800] if content_el else ''

        name_el = (
            container.find(class_='linkName') or
            container.find(class_='name') or
            container.find(class_='poster') or
            container.find(class_='postName')
        )
        username = name_el.get_text(strip=True)[:50] if name_el else 'Anonymous'

        post_id = str(container.get('id') or container.get('data-id') or '')[:50]

        if post_id:
            dedup_key = post_id
        else:
            import hashlib
            dedup_key = hashlib.md5(
                (subject + content[:100]).encode('utf-8', errors='replace')
            ).hexdigest()[:16]

        if content or subject != 'No Subject':
            threads.append({
                'forum':      'Endchan',
                'board':      board.strip('/'),
                'subject':    subject,
                'content':    content,
                'username':   username,
                'post_id':    post_id,
                'dedup_key':  dedup_key,
                'url':        base_url + board,
                'crawled_at': datetime.datetime.now(datetime.timezone.utc),
            })

    return threads

# ── Board Crawler — PAGINATION FIXED ─────────────────────────────────────────

def crawl_endchan_board(session, base_url, board, max_threads=30):
    """
    Crawl a single Endchan board using proper next-link pagination.

    FIX: Old code constructed ?page=N URLs which Endchan ignores.
    New code follows actual anchor links found in the page HTML.
    Loop detection prevents infinite cycles.
    """
    all_posts    = []
    current_url  = base_url + board
    visited_urls = set()
    page_num     = 1

    print(f"\n  {Fore.CYAN}Board: {board}{Style.RESET_ALL} — {current_url}")

    while len(all_posts) < max_threads and page_num <= 5:
        if current_url in visited_urls:
            print(f"    {Fore.YELLOW}Loop detected — same URL seen twice, stopping{Style.RESET_ALL}")
            break
        visited_urls.add(current_url)

        print(f"    Fetching page {page_num}: {current_url[:70]}")
        r = safe_get(session, current_url)

        if r is None:
            print(f"    {Fore.RED}✗ Page {page_num} unreachable{Style.RESET_ALL}")
            break

        try:
            soup = BeautifulSoup(r.text, 'lxml')
        except Exception:
            soup = BeautifulSoup(r.text, 'html.parser')

        posts = parse_endchan_board(r.text, base_url, board)
        print(f"    Found {len(posts)} threads on page {page_num}")

        if not posts:
            print(f"    No posts — end of board")
            break

        all_posts.extend(posts)

        if len(posts) < 3:
            print(f"    Only {len(posts)} posts — treating as last page")
            break

        # Follow ACTUAL next-page link (not constructed ?page=N)
        next_url = get_next_page_url(soup, base_url)

        if not next_url:
            print(f"    No next-page link found — end of board")
            break

        if next_url in visited_urls:
            print(f"    Next link already visited — stopping")
            break

        current_url = next_url
        page_num   += 1
        time.sleep(THREAD_DELAY)

    return all_posts[:max_threads]

# ── Save Posts ────────────────────────────────────────────────────────────────

def save_posts(posts):
    saved = 0
    duplicates = 0
    for post in posts:
        try:
            result = db.forums.update_one(
                {
                    'forum':     post['forum'],
                    'board':     post['board'],
                    'dedup_key': post['dedup_key'],
                },
                {'$setOnInsert': post},
                upsert=True
            )
            if result.upserted_id:
                saved += 1
            else:
                duplicates += 1
        except DuplicateKeyError:
            duplicates += 1
        except Exception as e:
            print(f"    {Fore.RED}DB error: {str(e)[:50]}{Style.RESET_ALL}")
    return saved, duplicates

# ── Forum Status ──────────────────────────────────────────────────────────────

def check_forum_status(session, base_url):
    try:
        r = session.get(base_url, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            try:
                soup = BeautifulSoup(r.text, 'lxml')
            except Exception:
                soup = BeautifulSoup(r.text, 'html.parser')
            title = soup.title.get_text(strip=True) if soup.title else 'Unknown'
            links = len(soup.find_all('a', href=True))
            return True, title[:60], links, r.status_code
        return False, f'HTTP {r.status_code}', 0, r.status_code
    except Exception as e:
        return False, str(e)[:40], 0, 0

# ── Main Runner ───────────────────────────────────────────────────────────────

def run_forum_crawler(target_board=None, max_threads=30):
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DARK WEB FORUM CRAWLER{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Pagination: follows real HTML links (not ?page=N){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\n  {Fore.YELLOW}⚠ Tor Browser must be open and connected{Style.RESET_ALL}\n")

    setup_indexes()
    session     = make_session()
    total_saved = 0
    total_dups  = 0

    for forum in FORUMS:
        print(f"\n{'─'*60}")
        print(f"  {Fore.CYAN}Forum: {forum['name']}{Style.RESET_ALL}")
        print(f"  URL: {forum['base']}")

        is_online, title, links, status = check_forum_status(session, forum['base'])
        print(f"  Status: HTTP {status} | Online: {'✓' if is_online else '✗'} | Title: {title}")

        if not is_online:
            print(f"  {Fore.RED}✗ Forum offline — skipping{Style.RESET_ALL}")
            continue

        print(f"  {Fore.GREEN}✓ Forum LIVE — crawling boards...{Style.RESET_ALL}")

        boards = forum['boards']
        if target_board:
            board_path = f"/{target_board.strip('/')}/"
            boards = [b for b in boards if b == board_path]
            if not boards:
                print(f"  {Fore.YELLOW}⚠ Board '{target_board}' not in config{Style.RESET_ALL}")
                continue

        for board in boards:
            posts = crawl_endchan_board(session, forum['base'], board, max_threads)
            print(f"    → {len(posts)} posts extracted from {board}")

            saved, dups = save_posts(posts)
            print(f"    → {Fore.GREEN}{saved} new{Style.RESET_ALL} saved | "
                  f"{Fore.YELLOW}{dups} duplicates{Style.RESET_ALL} skipped")

            total_saved += saved
            total_dups  += dups
            time.sleep(BOARD_DELAY)

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  FORUM CRAWL COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*60}")
    print(f"  New posts saved : {total_saved}")
    print(f"  Duplicates      : {total_dups}")
    total_db = db.forums.count_documents({})
    print(f"  Total in DB     : {total_db}")

    if total_db > 0:
        print(f"\n  Board Breakdown:")
        pipeline = [
            {'$group': {'_id': {'forum': '$forum', 'board': '$board'}, 'count': {'$sum': 1}}},
            {'$sort':  {'count': -1}},
        ]
        for r in db.forums.aggregate(pipeline):
            print(f"    {r['_id']['forum']}/{r['_id']['board']:<15}: {r['count']} posts")

        named = db.forums.count_documents({'username': {'$nin': ['Anonymous', '', None]}})
        print(f"\n  Named users (non-Anonymous): {named}")
        print(f"  Anonymous posts            : {total_db - named}")

    print(f"\n  {Fore.GREEN}Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web Forum Crawler')
    parser.add_argument('--board',       type=str, default=None,
                        help='Crawl specific board only (e.g., tech, pol, b)')
    parser.add_argument('--max-threads', type=int, default=30,
                        help='Max threads per board (default: 30)')
    args = parser.parse_args()
    run_forum_crawler(target_board=args.board, max_threads=args.max_threads)