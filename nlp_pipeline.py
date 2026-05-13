"""
nlp_pipeline.py — NLP & Entity Extraction Pipeline
=====================================================
Processes all crawled pages from MongoDB.
Run after crawler.py.

Features:
  - spaCy NER: ORG, PERSON, GPE, MONEY, PRODUCT entities
  - Regex extraction: emails, Bitcoin, Monero, PGP keys,
    phone numbers, onion URLs, API keys
  - Credential dump detector (email:pass, structured dumps)
  - Language detection via langdetect
  - Bitcoin address risk scoring via BlockCypher API (free tier)

Usage:
    python nlp_pipeline.py
    python nlp_pipeline.py --reprocess   (reprocess all pages)
    python nlp_pipeline.py --btc-only    (only score BTC addresses)
"""

import re
import time
import datetime
import argparse
from typing import Optional

import requests
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Try importing optional libraries gracefully ───────────────────────────────

try:
    import spacy
    nlp = spacy.load('en_core_web_sm')
    SPACY_OK = True
except Exception as e:
    print(f"{Fore.YELLOW}  ⚠ spaCy not available: {e}{Style.RESET_ALL}")
    print(f"    Run: python -m spacy download en_core_web_sm")
    SPACY_OK  = False
    nlp        = None

try:
    from langdetect import detect as lang_detect
    from langdetect import DetectorFactory
    from langdetect.lang_detect_exception import LangDetectException
    DetectorFactory.seed = 42   # reproducible results
    LANGDETECT_OK = True
except Exception:
    LANGDETECT_OK = False

# ── Configuration ─────────────────────────────────────────────────────────────

# ── Configuration (centralised — edit config.py, not here) ───────────────────
from config import (
    MONGO_URI, DB_NAME, BLOCKCYPHER_BASE, BTC_API_DELAY,
    MIN_TEXT_FOR_NLP, SPACY_MAX_CHARS, BTC_MAX_PER_PAGE,
)

# Language code → human name mapping
LANG_NAMES = {
    'en': 'English',   'ru': 'Russian',   'de': 'German',
    'fr': 'French',    'es': 'Spanish',   'zh': 'Chinese',
    'ar': 'Arabic',    'pt': 'Portuguese','ja': 'Japanese',
    'ko': 'Korean',    'it': 'Italian',   'nl': 'Dutch',
    'pl': 'Polish',    'sv': 'Swedish',   'fa': 'Persian',
    'tr': 'Turkish',   'uk': 'Ukrainian', 'vi': 'Vietnamese',
}

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── Regex Patterns ────────────────────────────────────────────────────────────

PATTERNS = {
    # Email addresses (both clearnet and .onion)
    'emails': re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        re.IGNORECASE
    ),
    # Bitcoin addresses: P2PKH (1...), P2SH (3...), Bech32 (bc1...)
    'bitcoin': re.compile(
        r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{6,87})\b'
    ),
    # Monero addresses (start with 4, 95 chars)
    'monero': re.compile(
        r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    ),
    # PGP public key block markers
    'pgp_keys': re.compile(
        r'-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----',
        re.IGNORECASE
    ),
    # Phone numbers (international format)
    'phone': re.compile(
        r'\b(?:\+?[1-9]\d{0,2}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4,6}\b'
    ),
    # .onion URLs in page text
    'onion_urls': re.compile(
        r'https?://[a-z2-7]{10,60}\.onion(?:/[^\s"\'<>]*)?',
        re.IGNORECASE
    ),
    # API keys / tokens (requires context keyword nearby)
    'api_keys': re.compile(
        r'(?:api[_\-]?key|token|secret|bearer|authorization)'
        r'[\s:="\'\[]+([a-zA-Z0-9_\-]{20,80})',
        re.IGNORECASE
    ),
}

# Credential dump patterns
CRED_PATTERNS = [
    # email:password or email;password
    re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        r'[\s]*[:;|][\s]*\S{4,64}',
        re.MULTILINE
    ),
    # username:hash (32+ char hash = likely credential dump)
    re.compile(
        r'[a-zA-Z0-9_\-\.]{3,30}:[a-fA-F0-9]{32,64}\b'
    ),
]

# Common false-positive IPs to ignore
PRIVATE_IP_PREFIXES = ('127.', '192.168.', '10.', '172.16.', '0.0.0.0', '255.')

# ── Entity Extraction ─────────────────────────────────────────────────────────

def extract_regex_entities(text: str) -> dict:
    """
    Extract structured entities using regex patterns.
    Returns dict with lists of found entities per type.
    """
    entities = {}

    for name, pattern in PATTERNS.items():
        if name == 'pgp_keys':
            matches = pattern.findall(text)
            # Store just the header lines, not full key blocks (too long)
            entities[name] = [m[:100] for m in matches[:5]]
        elif name == 'api_keys':
            matches = pattern.findall(text)
            entities[name] = list(set(matches))[:10]
        else:
            matches = pattern.findall(text)
            # Deduplicate and limit
            entities[name] = list(set(matches))[:20]

    # Filter emails — remove obviously fake/example ones
    if entities.get('emails'):
        entities['emails'] = [
            e for e in entities['emails']
            if not any(x in e.lower() for x in
                       ['example.com', 'test.com', 'foo.bar', 'domain.com'])
        ][:15]

    # Filter phone — remove numbers that are too short or too long
    if entities.get('phone'):
        entities['phone'] = [
            p for p in entities['phone']
            if 10 <= len(re.sub(r'\D', '', p)) <= 15
        ][:10]

    return entities


def extract_spacy_entities(text: str) -> list:
    """
    Run spaCy NER on text.
    Returns list of {text, label} dicts for relevant entity types.
    """
    if not SPACY_OK or not nlp:
        return []
    try:
        doc  = nlp(text[:SPACY_MAX_CHARS])
        keep = {'ORG', 'PERSON', 'GPE', 'MONEY', 'PRODUCT', 'LOC', 'EVENT'}
        seen = set()
        ents = []
        for ent in doc.ents:
            if ent.label_ in keep:
                key = (ent.text.strip(), ent.label_)
                if key not in seen and len(ent.text.strip()) > 2:
                    seen.add(key)
                    ents.append({'text': ent.text.strip(), 'label': ent.label_})
        return ents[:30]
    except Exception:
        return []


def detect_credential_dumps(text: str) -> list:
    """
    Detect structured credential dumps in page text.
    Distinguishes between single credentials and bulk dumps.
    """
    credentials = []

    for pattern in CRED_PATTERNS:
        matches = pattern.findall(text)
        for match in matches[:15]:
            match_str = match.strip()
            if len(match_str) < 10:
                continue
            # Estimate if this is a bulk dump (many consecutive matches)
            cred_type = 'email:password' if '@' in match_str else 'username:hash'
            credentials.append({
                'type':  cred_type,
                'value': match_str[:120],
            })

    # Count lines that look like credential entries to detect bulk dumps
    lines      = text.split('\n')
    cred_lines = sum(1 for l in lines if ':' in l and '@' in l and len(l) < 120)
    is_dump    = cred_lines > 10

    return credentials[:20], is_dump, cred_lines


def detect_language(text: str) -> tuple:
    """
    Detect language of page text.
    Returns (lang_code, lang_name).
    Falls back to 'en'/'English' on failure.
    """
    if not LANGDETECT_OK:
        return 'en', 'English'
    try:
        # Use first 500 chars — enough for detection
        sample    = text[:500].strip()
        if len(sample) < 20:
            return 'unknown', 'Unknown'
        lang_code = lang_detect(sample)
        lang_name = LANG_NAMES.get(lang_code, lang_code.upper())
        return lang_code, lang_name
    except LangDetectException:
        return 'unknown', 'Unknown'
    except Exception:
        return 'en', 'English'

# ── Bitcoin Risk Scoring ──────────────────────────────────────────────────────

def score_bitcoin_address(address: str, session: requests.Session, retry: bool = True) -> dict:
    """
    Query BlockCypher API to get transaction history for a BTC address.
    Assigns risk level based on transaction volume and balance.

    BlockCypher free tier: 200 req/hr = 1 request per 18 seconds.
    BTC_API_DELAY in config.py is set to 18.0 — do not lower it.

    Risk levels:
      CRITICAL  — >100 transactions (active mixer/market wallet)
      HIGH      — >20 transactions
      MEDIUM    — >5 transactions
      LOW       — 1-5 transactions
      UNUSED    — 0 transactions (fresh/empty address)
      UNKNOWN   — API unavailable
    """
    result = {
        'address':        address,
        'tx_count':       0,
        'total_received': 0,
        'balance':        0,
        'risk_level':     'UNKNOWN',
        'risk_score':     0,
        'api_success':    False,
    }
    try:
        url = f"{BLOCKCYPHER_BASE}/{address}?limit=1"
        r   = session.get(url, timeout=10)

        if r.status_code == 200:
            try:
                data = r.json()
            except ValueError:
                result['error'] = 'Invalid JSON response from BlockCypher'
                return result

            tx_count       = data.get('n_tx', 0)
            total_received = data.get('total_received', 0)
            balance        = data.get('balance', 0)

            # Convert satoshis to BTC
            total_btc   = round(total_received / 1e8, 8)
            balance_btc = round(balance / 1e8, 8)

            # Risk scoring
            if tx_count > 100:
                risk_level, risk_score = 'CRITICAL', 90
            elif tx_count > 20:
                risk_level, risk_score = 'HIGH', 70
            elif tx_count > 5:
                risk_level, risk_score = 'MEDIUM', 40
            elif tx_count > 0:
                risk_level, risk_score = 'LOW', 15
            else:
                risk_level, risk_score = 'UNUSED', 0

            result.update({
                'tx_count':       tx_count,
                'total_received': total_btc,
                'balance':        balance_btc,
                'risk_level':     risk_level,
                'risk_score':     risk_score,
                'api_success':    True,
            })

        elif r.status_code == 429:
            # Rate limited — BlockCypher free tier exhausted (200 req/hr)
            # Sleep 65 seconds then retry once
            print(f"    {Fore.RED}BlockCypher rate limit (429) — sleeping 65s then retrying{Style.RESET_ALL}")
            time.sleep(65)
            if retry:
                return score_bitcoin_address(address, session, retry=False)
            else:
                result['error'] = 'Rate limited (429) — retry also failed'

        else:
            result['error'] = f'HTTP {r.status_code} from BlockCypher'
            print(f"    {Fore.YELLOW}BlockCypher returned HTTP {r.status_code} for {address[:20]}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        result['error'] = 'BlockCypher API timeout'
    except Exception as e:
        result['error'] = str(e)[:50]

    return result


def score_all_btc_addresses(btc_addresses: list, session: requests.Session) -> list:
    """
    Score a list of BTC addresses via BlockCypher API.
    Respects 200 req/hr free tier limit (BTC_API_DELAY = 18s between calls).
    Returns list of scored dicts.
    """
    scored = []
    for addr in btc_addresses[:BTC_MAX_PER_PAGE]:
        result = score_bitcoin_address(addr, session)
        scored.append(result)
        if result.get('api_success'):
            # Only delay after successful calls — failed calls don't count
            time.sleep(BTC_API_DELAY)
        else:
            time.sleep(1)  # Short delay on failure, don't waste time
    return scored

# ── Main Pipeline ─────────────────────────────────────────────────────────────

def run_nlp_pipeline(reprocess: bool = False, btc_only: bool = False):
    """
    Main entry point. Processes all unprocessed pages from MongoDB.

    Args:
        reprocess: If True, reprocess pages that already have entities
        btc_only:  If True, only run BTC risk scoring on existing entities
    """
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  NLP PIPELINE — Entity Extraction & Analysis{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"  spaCy NER     : {'✓ Active' if SPACY_OK else '✗ Unavailable'}")
    print(f"  LangDetect    : {'✓ Active' if LANGDETECT_OK else '✗ Unavailable'}")
    print(f"  BTC Scoring   : ✓ BlockCypher API (free tier)")
    print(f"  Mode          : {'REPROCESS ALL' if reprocess else 'NEW PAGES ONLY'}")

    # ── BTC-only mode ─────────────────────────────────────────
    if btc_only:
        run_btc_scoring_only()
        return

    # ── Query pages to process ────────────────────────────────
    query = {} if reprocess else {'entities': {'$exists': False}, 'text': {'$exists': True}}
    pages = list(db.pages.find(query, {'_id': 1, 'url': 1, 'title': 1, 'text': 1}))
    total = len(pages)

    if total == 0:
        print(f"\n  {Fore.GREEN}✓ All pages already processed!{Style.RESET_ALL}")
        print_summary()
        return

    print(f"\n  Pages to process: {Fore.CYAN}{total}{Style.RESET_ALL}\n")
    print(f"{'─'*60}")

    # Create a clearnet session for BlockCypher (NOT through Tor)
    btc_session = requests.Session()
    btc_session.headers.update({'User-Agent': 'Mozilla/5.0'})

    # Counters
    emails_total  = 0
    btc_total     = 0
    monero_total  = 0
    pgp_total     = 0
    creds_total   = 0
    dumps_total   = 0
    lang_counts   = {}
    errors        = 0

    for i, page in enumerate(pages):
        try:
            text  = page.get('text', '')
            title = page.get('title', '')

            if not text or len(text) < MIN_TEXT_FOR_NLP:
                continue

            # ── Regex entity extraction ───────────────────────
            regex_ents = extract_regex_entities(text)

            # ── spaCy NER ─────────────────────────────────────
            spacy_ents = extract_spacy_entities(text)

            # ── Credential detection ──────────────────────────
            creds, is_dump, dump_line_count = detect_credential_dumps(text)

            # ── Language detection ────────────────────────────
            lang_code, lang_name = detect_language(text)

            # ── BTC risk scoring ──────────────────────────────
            btc_addresses = regex_ents.get('bitcoin', [])
            btc_risk      = []
            if btc_addresses:
                btc_risk = score_all_btc_addresses(btc_addresses, btc_session)

            # ── Build update document ─────────────────────────
            entities_doc = {
                'emails':     regex_ents.get('emails', []),
                'bitcoin':    btc_addresses,
                'monero':     regex_ents.get('monero', []),
                'pgp_keys':   regex_ents.get('pgp_keys', []),
                'phone':      regex_ents.get('phone', []),
                'onion_urls': regex_ents.get('onion_urls', []),
                'api_keys':   regex_ents.get('api_keys', []),
                'spacy_ents': spacy_ents,
            }

            db.pages.update_one(
                {'_id': page['_id']},
                {'$set': {
                    'entities':          entities_doc,
                    'btc_risk':          btc_risk,
                    'credentials':       creds,
                    'has_credentials':   len(creds) > 0,
                    'is_credential_dump': is_dump,
                    'dump_line_count':   dump_line_count,
                    'language':          lang_code,
                    'lang_name':         lang_name,
                    'nlp_processed_at':  datetime.datetime.now(datetime.timezone.utc),
                }}
            )

            # Update counters
            emails_total += len(entities_doc['emails'])
            btc_total    += len(btc_addresses)
            monero_total += len(entities_doc['monero'])
            pgp_total    += len(entities_doc['pgp_keys'])
            creds_total  += len(creds)
            if is_dump:
                dumps_total += 1
            lang_counts[lang_name] = lang_counts.get(lang_name, 0) + 1

            # Console output
            status_parts = []
            if entities_doc['emails']:
                status_parts.append(f"📧{len(entities_doc['emails'])}")
            if btc_addresses:
                status_parts.append(f"₿{len(btc_addresses)}")
            if entities_doc['monero']:
                status_parts.append(f"ɱ{len(entities_doc['monero'])}")
            if entities_doc['pgp_keys']:
                status_parts.append(f"🔑PGP")
            if creds:
                status_parts.append(f"{'🚨DUMP' if is_dump else f'🔓{len(creds)}creds'}")
            if spacy_ents:
                status_parts.append(f"🏷{len(spacy_ents)}ents")

            status_str = ' | '.join(status_parts) if status_parts else 'No entities'
            lang_str   = f"[{lang_code}]"
            title_str  = (title or 'No Title')[:50]

            print(f"  [{Fore.CYAN}{i+1:04d}/{total}{Style.RESET_ALL}] "
                  f"{Fore.YELLOW}{lang_str}{Style.RESET_ALL} "
                  f"{title_str}")
            print(f"           {status_str}")

            # BTC risk highlights
            if btc_risk:
                critical = [b for b in btc_risk if b.get('risk_level') == 'CRITICAL']
                if critical:
                    print(f"           {Fore.RED}⚠ CRITICAL BTC: {critical[0]['address'][:20]}... "
                          f"({critical[0]['tx_count']} txns){Style.RESET_ALL}")

        except Exception as e:
            errors += 1
            print(f"  [{Fore.RED}ERR {i+1:04d}{Style.RESET_ALL}] "
                  f"{page.get('title','?')[:40]} — {str(e)[:50]}")
            continue

    # ── Final Summary ──────────────────────────────────────────
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  NLP PIPELINE COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*60}")
    print(f"  Pages processed    : {total - errors}/{total}")
    print(f"  Errors skipped     : {errors}")
    print(f"{'─'*60}")
    print(f"  📧 Emails found    : {emails_total}")
    print(f"  ₿  BTC addresses   : {btc_total}")
    print(f"  ɱ  Monero addrs    : {monero_total}")
    print(f"  🔑 PGP keys        : {pgp_total}")
    print(f"  🔓 Credentials     : {creds_total}")
    print(f"  🚨 Credential dumps: {dumps_total}")
    print(f"{'─'*60}")
    print(f"  Language breakdown :")
    for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1])[:10]:
        bar = '█' * min(count, 30)
        print(f"    {lang:<15} {bar} ({count})")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")


def run_btc_scoring_only():
    """
    Run BTC risk scoring on pages that have bitcoin addresses
    but haven't been scored yet.
    """
    print(f"\n  {Fore.YELLOW}BTC-ONLY MODE — scoring existing addresses{Style.RESET_ALL}\n")
    pages = list(db.pages.find(
        {
            'entities.bitcoin': {'$exists': True, '$ne': []},
            'btc_risk':         {'$exists': False}
        },
        {'_id': 1, 'title': 1, 'entities.bitcoin': 1}
    ))
    print(f"  Pages with unscored BTC addresses: {len(pages)}")

    btc_session = requests.Session()
    btc_session.headers.update({'User-Agent': 'Mozilla/5.0'})
    scored_count = 0

    for page in pages:
        addresses = page.get('entities', {}).get('bitcoin', [])
        if not addresses:
            continue
        btc_risk = score_all_btc_addresses(addresses, btc_session)
        db.pages.update_one(
            {'_id': page['_id']},
            {'$set': {'btc_risk': btc_risk}}
        )
        scored_count += len(btc_risk)
        print(f"  Scored {len(btc_risk)} addresses for: {page.get('title','?')[:40]}")

    print(f"\n  {Fore.GREEN}✓ BTC scoring complete — {scored_count} addresses scored{Style.RESET_ALL}")


def print_summary():
    """Print summary stats from MongoDB."""
    total     = db.pages.count_documents({'entities': {'$exists': True}})
    with_btc  = db.pages.count_documents({'entities.bitcoin': {'$ne': []}})
    with_email= db.pages.count_documents({'entities.emails':  {'$ne': []}})
    with_creds= db.pages.count_documents({'has_credentials':  True})
    dumps     = db.pages.count_documents({'is_credential_dump': True})
    print(f"\n  Current NLP stats:")
    print(f"    Processed pages  : {total}")
    print(f"    With BTC addrs   : {with_btc}")
    print(f"    With emails      : {with_email}")
    print(f"    With credentials : {with_creds}")
    print(f"    Credential dumps : {dumps}")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web NLP Pipeline')
    parser.add_argument('--reprocess', action='store_true',
                        help='Reprocess all pages including already processed ones')
    parser.add_argument('--btc-only', action='store_true',
                        help='Only run BTC risk scoring on existing entities')
    args = parser.parse_args()
    run_nlp_pipeline(reprocess=args.reprocess, btc_only=args.btc_only)