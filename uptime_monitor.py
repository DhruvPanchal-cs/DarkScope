"""
uptime_monitor.py — Dark Web Uptime Monitor
=============================================
Tracks availability of every crawled .onion site over time.

Research significance:
  Dark web sites are notoriously unstable. No existing tool
  tracks uptime longitudinally. This module gives you real
  data: "Site X was online 34% of the time over 7 days" —
  a genuine temporal dimension that TorBot/OnionScan lack.

Features:
  - Pings all crawled .onion URLs via Tor proxy
  - Stores result in uptime_logs collection per check
  - Computes uptime % per domain from historical data
  - Detects sites that just came online / went offline
  - Can run as background thread or standalone script
  - Configurable check interval (default: 60 minutes)

Usage:
    python uptime_monitor.py                  (run once then exit)
    python uptime_monitor.py --continuous     (run forever, 60min interval)
    python uptime_monitor.py --interval 30    (check every 30 minutes)
    python uptime_monitor.py --stats          (show stats only)
"""

import time
import datetime
import argparse
import threading

import requests
from pymongo import MongoClient, ASCENDING
from colorama import init, Fore, Style

from config import MONGO_URI, DB_NAME, TOR_PROXY, USER_AGENT

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

# MONGO_URI via config.py
# DB_NAME via config.py
# TOR_PROXY via config.py
PING_TIMEOUT     = 15    # seconds per site ping
PING_DELAY       = 0.5   # seconds between pings (rate limiting)
CHECK_INTERVAL   = 3600  # seconds between full check cycles (1 hour)
USER_AGENT       = 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

def setup_uptime_indexes():
    """Ensure all indexes exist for uptime_logs collection."""
    db.uptime_logs.create_index([('url', ASCENDING), ('checked_at', ASCENDING)])
    db.uptime_logs.create_index('domain')
    db.uptime_logs.create_index('checked_at')
    db.uptime_logs.create_index('is_online')

# ── Ping Logic ────────────────────────────────────────────────────────────────

def ping_url(url: str, session: requests.Session) -> dict:
    """
    Ping a single .onion URL via Tor.
    Returns result dict with timing and status info.
    Uses HEAD request first (faster), falls back to GET.
    """
    start_ms = int(time.time() * 1000)
    result = {
        'url':         url,
        'is_online':   False,
        'status_code': 0,
        'response_ms': 0,
        'error':       None,
        'checked_at':  datetime.datetime.now(datetime.timezone.utc),
    }

    try:
        # Try HEAD first — faster, less bandwidth
        try:
            r = session.head(url, timeout=PING_TIMEOUT, allow_redirects=True)
        except Exception:
            # HEAD not supported — try GET
            r = session.get(url, timeout=PING_TIMEOUT)

        elapsed         = int(time.time() * 1000) - start_ms
        result['status_code'] = r.status_code
        result['response_ms'] = elapsed
        result['is_online']   = r.status_code < 500   # 1xx-4xx = reachable

    except requests.exceptions.Timeout:
        result['error']       = 'timeout'
        result['response_ms'] = int(time.time() * 1000) - start_ms
    except requests.exceptions.ConnectionError as e:
        err_str = str(e)
        if 'SOCKS' in err_str:
            result['error'] = 'tor_circuit_failed'
        else:
            result['error'] = 'connection_refused'
        result['response_ms'] = int(time.time() * 1000) - start_ms
    except Exception as e:
        result['error']       = str(e)[:80]
        result['response_ms'] = int(time.time() * 1000) - start_ms

    return result


def log_uptime_result(result: dict):
    """Store a ping result in uptime_logs and update pages collection."""
    try:
        # Add to uptime_logs
        db.uptime_logs.insert_one(result.copy())

        # Update the pages document with latest uptime info
        uptime_pct = compute_uptime_pct(result['url'])
        db.pages.update_one(
            {'url': result['url']},
            {'$set': {
                'last_checked':     result['checked_at'],
                'last_online':      result['checked_at'] if result['is_online'] else None,
                'last_status_code': result['status_code'],
                'uptime_pct':       uptime_pct,
            }}
        )
    except Exception:
        pass  # Never crash the monitor for logging errors


def compute_uptime_pct(url: str, days: int = 7) -> float:
    """
    Compute uptime percentage for a URL over the last N days.
    Returns float 0.0-100.0.
    """
    try:
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        total = db.uptime_logs.count_documents({
            'url':        url,
            'checked_at': {'$gte': cutoff},
        })
        if total == 0:
            return 0.0
        online = db.uptime_logs.count_documents({
            'url':        url,
            'is_online':  True,
            'checked_at': {'$gte': cutoff},
        })
        return round(online / total * 100, 1)
    except Exception:
        return 0.0


def get_domain_uptime_stats(days: int = 7) -> list:
    """
    Aggregate uptime stats per domain from uptime_logs.
    Returns list sorted by uptime % ascending (worst first).
    """
    try:
        cutoff   = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        pipeline = [
            {'$match': {'checked_at': {'$gte': cutoff}}},
            {'$group': {
                '_id':         '$url',
                'total':       {'$sum': 1},
                'online':      {'$sum': {'$cond': ['$is_online', 1, 0]}},
                'avg_ms':      {'$avg': '$response_ms'},
                'last_status': {'$last': '$status_code'},
                'last_check':  {'$last': '$checked_at'},
                'is_online':   {'$last': '$is_online'},
            }},
            {'$project': {
                'url':        '$_id',
                'total':      1,
                'online':     1,
                'uptime_pct': {'$round': [
                    {'$multiply': [
                        {'$divide': ['$online', '$total']}, 100
                    ]}, 1
                ]},
                'avg_ms':     {'$round': ['$avg_ms', 0]},
                'last_status':1,
                'last_check': 1,
                'is_online':  1,
            }},
            {'$sort': {'uptime_pct': 1}},
        ]
        return list(db.uptime_logs.aggregate(pipeline))
    except Exception:
        return []


# ── Main Check Cycle ──────────────────────────────────────────────────────────

def run_check_cycle(session: requests.Session) -> dict:
    """
    Ping all unique URLs from the pages collection.
    Returns summary dict.
    """
    # Get all unique URLs from pages collection
    urls = db.pages.distinct('url')

    if not urls:
        print(f"  {Fore.YELLOW}No pages in DB yet. Run crawler.py first.{Style.RESET_ALL}")
        return {'total': 0, 'online': 0, 'offline': 0}

    print(f"\n  {Fore.CYAN}Checking {len(urls)} sites...{Style.RESET_ALL}")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    online_count  = 0
    offline_count = 0
    newly_online  = []
    newly_offline = []

    for i, url in enumerate(urls):
        # Get previous status for change detection
        prev_log = db.uptime_logs.find_one(
            {'url': url},
            sort=[('checked_at', -1)]
        )
        prev_online = prev_log.get('is_online', None) if prev_log else None

        # Ping
        result = ping_url(url, session)
        log_uptime_result(result)

        is_online = result['is_online']
        status    = result['status_code']
        ms        = result['response_ms']
        error     = result.get('error', '')

        if is_online:
            online_count += 1
        else:
            offline_count += 1

        # Detect state changes
        if prev_online is not None:
            if is_online and not prev_online:
                newly_online.append(url)
            elif not is_online and prev_online:
                newly_offline.append(url)

        # Console output
        if is_online:
            status_str = f"{Fore.GREEN}ONLINE {Style.RESET_ALL} {status:3d} {ms:5d}ms"
        else:
            err_short  = (error or 'unknown')[:20]
            status_str = f"{Fore.RED}OFFLINE{Style.RESET_ALL} [{err_short}]"

        print(f"  [{i+1:04d}/{len(urls)}] {status_str} | {url[:60]}")

        time.sleep(PING_DELAY)

    # State change alerts
    if newly_online:
        print(f"\n  {Fore.GREEN}▲ Sites that came ONLINE this cycle:{Style.RESET_ALL}")
        for u in newly_online[:5]:
            print(f"    + {u[:70]}")

    if newly_offline:
        print(f"\n  {Fore.RED}▼ Sites that went OFFLINE this cycle:{Style.RESET_ALL}")
        for u in newly_offline[:5]:
            print(f"    - {u[:70]}")

    total = len(urls)
    print(f"\n  {'─'*50}")
    print(f"  Cycle complete: {online_count}/{total} online "
          f"({round(online_count/total*100,1) if total else 0}%)")

    return {
        'total':         total,
        'online':        online_count,
        'offline':       offline_count,
        'newly_online':  len(newly_online),
        'newly_offline': len(newly_offline),
    }


def print_uptime_stats(days: int = 7):
    """Print uptime statistics from the database."""
    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  UPTIME STATISTICS (last {days} days){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*62}{Style.RESET_ALL}")

    total_logs = db.uptime_logs.count_documents({})
    if total_logs == 0:
        print(f"  No uptime data yet. Run: python uptime_monitor.py")
        return

    print(f"  Total pings recorded: {total_logs}")

    stats = get_domain_uptime_stats(days=days)
    if not stats:
        print(f"  No data for last {days} days.")
        return

    # Overall online rate
    all_online = sum(1 for s in stats if s.get('is_online'))
    print(f"  Currently online    : {all_online}/{len(stats)} sites")
    print(f"  Avg uptime rate     : "
          f"{round(sum(s.get('uptime_pct',0) for s in stats)/len(stats), 1)}%")

    print(f"\n  {'URL':<52} {'UPTIME':>7} {'AVG MS':>7} {'STATUS'}")
    print(f"  {'─'*80}")

    # Show worst performers first, then best
    for s in stats[:10]:   # Bottom 10 (worst uptime)
        pct     = s.get('uptime_pct', 0)
        avg_ms  = int(s.get('avg_ms', 0))
        online  = s.get('is_online', False)
        url     = (s.get('url') or s.get('_id') or '')[:50]

        color   = (Fore.GREEN  if pct >= 80 else
                   Fore.YELLOW if pct >= 50 else
                   Fore.RED)
        status  = f"{Fore.GREEN}●{Style.RESET_ALL}" if online else f"{Fore.RED}○{Style.RESET_ALL}"
        print(f"  {url:<52} {color}{pct:>6.1f}%{Style.RESET_ALL} "
              f"{avg_ms:>6}ms {status}")

    if len(stats) > 10:
        print(f"\n  ... and {len(stats)-10} more sites")
        # Show top performers
        print(f"\n  Top 5 most reliable sites:")
        for s in sorted(stats, key=lambda x: -x.get('uptime_pct', 0))[:5]:
            pct = s.get('uptime_pct', 0)
            url = (s.get('url') or s.get('_id') or '')[:55]
            print(f"    {Fore.GREEN}{pct:5.1f}%{Style.RESET_ALL} — {url}")

    print()


# ── Background Thread Runner ──────────────────────────────────────────────────

def run_as_background_thread(interval: int = CHECK_INTERVAL):
    """
    Run uptime monitor as a background thread.
    Called by app.py to auto-start monitoring when dashboard starts.
    """
    def _worker():
        session = requests.Session()
        session.proxies = TOR_PROXY
        session.headers.update({'User-Agent': USER_AGENT})

        while True:
            try:
                run_check_cycle(session)
            except Exception as e:
                print(f"[Uptime Monitor] Error: {e}")
            time.sleep(interval)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t


# ── Entry Point ───────────────────────────────────────────────────────────────

def run_uptime_monitor(continuous: bool = False, interval: int = 60, stats: bool = False):
    setup_uptime_indexes()

    print(f"\n{Fore.CYAN}{'='*62}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DARK WEB UPTIME MONITOR{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Tracking availability of crawled .onion sites{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*62}{Style.RESET_ALL}")

    if stats:
        print_uptime_stats()
        return

    session = requests.Session()
    session.proxies = TOR_PROXY
    session.headers.update({'User-Agent': USER_AGENT})

    if continuous:
        print(f"  Mode     : CONTINUOUS (every {interval} minutes)")
        print(f"  Press Ctrl+C to stop\n")
        while True:
            try:
                run_check_cycle(session)
                print(f"\n  Next check in {interval} minutes...")
                time.sleep(interval * 60)
            except KeyboardInterrupt:
                print(f"\n  {Fore.YELLOW}Monitor stopped.{Style.RESET_ALL}")
                break
    else:
        print(f"  Mode     : SINGLE RUN\n")
        run_check_cycle(session)
        print_uptime_stats()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web Uptime Monitor')
    parser.add_argument('--continuous', action='store_true',
                        help='Run continuously at set interval')
    parser.add_argument('--interval', type=int, default=60,
                        help='Check interval in minutes for continuous mode (default: 60)')
    parser.add_argument('--stats', action='store_true',
                        help='Show uptime stats from DB only')
    args = parser.parse_args()

    try:
        run_uptime_monitor(
            continuous=args.continuous,
            interval=args.interval,
            stats=args.stats
        )
    except KeyboardInterrupt:
        print(f"\n  {Fore.YELLOW}Interrupted.{Style.RESET_ALL}")
        print_uptime_stats()