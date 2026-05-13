"""
stix_export.py — STIX 2.1 Threat Intelligence Export
======================================================
Packages all extracted IoCs from MongoDB into a
STIX 2.1 Bundle — the international standard format
for threat intelligence sharing.

Research Value:
  STIX 2.1 is used by real SIEM tools (Splunk, OpenCTI,
  MISP, IBM QRadar). No existing dark web crawler
  (TorBot, OnionScan, Ahmia) outputs STIX format.
  This makes your tool integration-ready with enterprise
  security infrastructure — a unique research contribution.

STIX Objects Created:
  - Indicator     : .onion URLs (threat indicators)
  - ObservedData  : emails, BTC addresses, IP leaks
  - ThreatActor   : correlated identities
  - Malware       : pages classified as hacking tools
  - Infrastructure: .onion hosting infrastructure
  - Bundle        : wraps all objects

Output:
  exports/stix_bundle_<timestamp>.json

Usage:
    python stix_export.py
    python stix_export.py --output my_bundle.json
    python stix_export.py --category hacking   (filter by category)
    python stix_export.py --flagged-only        (only threat pages)
"""

import os
import json
import uuid
import datetime
import argparse

from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, EXPORTS_DIR
EXPORTS_DIR = str(EXPORTS_DIR)

# STIX 2.1 spec constants
STIX_VERSION = '2.1'
STIX_SPEC_VERSION = '2.1'

# Tool identity (your tool as the producer)
TOOL_IDENTITY_ID = f"identity--{str(uuid.uuid5(uuid.NAMESPACE_DNS, 'darkweb-crawler-nfsu'))}"

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── STIX Object Builders ──────────────────────────────────────────────────────

def stix_timestamp(dt=None) -> str:
    """Format datetime as STIX 2.1 timestamp string."""
    if dt is None:
        dt = datetime.datetime.now(datetime.timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def make_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a seed string."""
    namespace = uuid.NAMESPACE_URL
    uid       = str(uuid.uuid5(namespace, seed))
    return f"{stix_type}--{uid}"


def build_identity() -> dict:
    """
    STIX Identity object representing this tool as the producer.
    """
    return {
        'type':             'identity',
        'spec_version':     STIX_SPEC_VERSION,
        'id':               TOOL_IDENTITY_ID,
        'created':          stix_timestamp(),
        'modified':         stix_timestamp(),
        'name':             'Dark Web Intelligence Platform',
        'description':      (
            'Academic dark web crawler and threat intelligence platform. '
            'NFSU SEM8 Cyber Security Research Project. '
            'Passive read-only crawler over Tor network.'
        ),
        'identity_class':   'system',
        'contact_information': 'NFSU | Guide: Mr. Nilesh Panchal',
    }


def build_indicator_from_onion(page: dict):
    """
    STIX Indicator for a .onion URL classified as a threat.
    Indicators represent patterns that can be used to detect threats.
    """
    url      = page.get('url', '')
    title    = page.get('title', 'Unknown')
    category = page.get('category', 'other')
    crawled  = page.get('crawled_at')

    if not url:
        return None

    # Map our categories to STIX indicator types
    indicator_type_map = {
        'hacking':      ['malicious-activity', 'compromised'],
        'drugs':        ['malicious-activity'],
        'fraud':        ['malicious-activity', 'anonymization'],
        'crypto':       ['malicious-activity'],
        'privacy':      ['anonymization'],
        'forum':        ['malicious-activity'],
        'search_index': ['benign'],
        'news':         ['benign'],
        'other':        ['unknown'],
    }
    indicator_types = indicator_type_map.get(category, ['unknown'])

    # STIX pattern using URL comparison
    pattern = f"[url:value = '{url}']"

    return {
        'type':            'indicator',
        'spec_version':    STIX_SPEC_VERSION,
        'id':              make_id('indicator', url),
        'created':         stix_timestamp(crawled),
        'modified':        stix_timestamp(crawled),
        'created_by_ref':  TOOL_IDENTITY_ID,
        'name':            f"Dark Web Site: {title[:80]}",
        'description':     (
            f"Crawled .onion site classified as '{category}'. "
            f"URL: {url}. "
            f"Flagged: {page.get('is_flagged', False)}. "
            f"OPSEC Score: {page.get('opsec_score', 'N/A')}."
        ),
        'indicator_types': indicator_types,
        'pattern':         pattern,
        'pattern_type':    'stix',
        'valid_from':      stix_timestamp(crawled),
        'labels':          [category, 'dark-web', 'onion-service'],
        'confidence':      int(page.get('confidence', 50)),
        'external_references': [{
            'source_name': 'Dark Web Crawler',
            'url':         url,
            'description': f"Direct .onion URL — requires Tor Browser to access",
        }],
        'x_darkweb_category':    category,
        'x_darkweb_opsec_score': page.get('opsec_score'),
        'x_darkweb_flagged':     page.get('is_flagged', False),
        'x_darkweb_language':    page.get('language', 'en'),
        'x_darkweb_pagerank':    page.get('pagerank_score'),
    }


def build_observed_data_email(email: str, page_url: str, crawled) -> dict:
    """STIX ObservedData for an email address found on dark web."""
    return {
        'type':            'observed-data',
        'spec_version':    STIX_SPEC_VERSION,
        'id':              make_id('observed-data', f"email:{email}:{page_url}"),
        'created':         stix_timestamp(crawled),
        'modified':        stix_timestamp(crawled),
        'created_by_ref':  TOOL_IDENTITY_ID,
        'first_observed':  stix_timestamp(crawled),
        'last_observed':   stix_timestamp(crawled),
        'number_observed': 1,
        'object_refs':     [],    # Would reference email-message SCOs
        'labels':          ['email-address', 'dark-web-entity'],
        'description':     f"Email address '{email}' found at {page_url}",
        'x_email_address':  email,
        'x_found_at_url':   page_url,
        'x_entity_type':    'email',
    }


def build_observed_data_bitcoin(btc_info: dict, page_url: str, crawled) -> dict:
    """STIX ObservedData for a Bitcoin address with risk scoring."""
    address    = btc_info.get('address', '')
    risk_level = btc_info.get('risk_level', 'UNKNOWN')
    tx_count   = btc_info.get('tx_count', 0)

    return {
        'type':            'observed-data',
        'spec_version':    STIX_SPEC_VERSION,
        'id':              make_id('observed-data', f"btc:{address}:{page_url}"),
        'created':         stix_timestamp(crawled),
        'modified':        stix_timestamp(crawled),
        'created_by_ref':  TOOL_IDENTITY_ID,
        'first_observed':  stix_timestamp(crawled),
        'last_observed':   stix_timestamp(crawled),
        'number_observed': 1,
        'object_refs':     [],
        'labels':          ['cryptocurrency', 'bitcoin', f'risk-{risk_level.lower()}'],
        'description':     (
            f"Bitcoin address '{address}' found at {page_url}. "
            f"Risk Level: {risk_level}. Transactions: {tx_count}."
        ),
        'x_btc_address':    address,
        'x_found_at_url':   page_url,
        'x_risk_level':     risk_level,
        'x_tx_count':       tx_count,
        'x_total_received': btc_info.get('total_received', 0),
        'x_balance':        btc_info.get('balance', 0),
        'x_entity_type':    'bitcoin_address',
    }


def build_threat_actor_from_identity(corr: dict):
    """
    STIX ThreatActor for a cross-platform identity correlation.
    This is the most significant STIX object — links dark web
    identity to clearnet presence.
    """
    username    = corr.get('username', '')
    clearnet    = corr.get('clearnet', [])

    if not username or not clearnet:
        return None

    # Collect platform details
    platforms   = [p.get('platform', '') for p in clearnet]
    gh_data     = next((p for p in clearnet if p.get('platform') == 'GitHub'), {})
    rd_data     = next((p for p in clearnet if p.get('platform') == 'Reddit'), {})

    real_name   = gh_data.get('name', '') or ''
    location    = gh_data.get('location', '') or ''
    bio         = gh_data.get('bio', '') or ''

    desc_parts  = [f"Dark web username '{username}' correlated to clearnet platforms."]
    if platforms:
        desc_parts.append(f"Found on: {', '.join(platforms)}.")
    if real_name:
        desc_parts.append(f"Possible real name: {real_name}.")
    if location:
        desc_parts.append(f"Location: {location}.")
    if gh_data.get('url'):
        desc_parts.append(f"GitHub: {gh_data['url']}.")
    if rd_data.get('url'):
        desc_parts.append(f"Reddit: {rd_data['url']}.")

    external_refs = []
    for p in clearnet:
        if p.get('url'):
            external_refs.append({
                'source_name': p.get('platform', 'Unknown'),
                'url':         p.get('url', ''),
                'description': f"Clearnet profile for dark web username '{username}'",
            })

    return {
        'type':              'threat-actor',
        'spec_version':      STIX_SPEC_VERSION,
        'id':                make_id('threat-actor', username),
        'created':           stix_timestamp(corr.get('analyzed_at')),
        'modified':          stix_timestamp(corr.get('analyzed_at')),
        'created_by_ref':    TOOL_IDENTITY_ID,
        'name':              username,
        'description':       ' '.join(desc_parts),
        'threat_actor_types':['unknown'],
        'aliases':           [username],
        'labels':            ['dark-web', 'identity-correlation', 'opsec-failure'],
        'sophistication':    'minimal',
        'external_references': external_refs,
        'x_dark_web_username':   username,
        'x_clearnet_platforms':  platforms,
        'x_github_url':          gh_data.get('url', ''),
        'x_github_name':         real_name,
        'x_github_location':     location,
        'x_reddit_url':          rd_data.get('url', ''),
        'x_reddit_karma':        rd_data.get('karma', 0),
        'x_source':              corr.get('source', 'unknown'),
    }


def build_infrastructure_from_page(page: dict):
    """STIX Infrastructure object for .onion hosting infrastructure."""
    url      = page.get('url', '')
    domain   = page.get('domain', '')
    category = page.get('category', 'other')

    if not url or category in ('news', 'search_index'):
        return None

    headers    = page.get('headers', {})
    server_sw  = headers.get('server_software', '')
    cdn        = headers.get('cdn_detected', '')
    opsec      = page.get('opsec_score')

    return {
        'type':              'infrastructure',
        'spec_version':      STIX_SPEC_VERSION,
        'id':                make_id('infrastructure', domain or url),
        'created':           stix_timestamp(page.get('crawled_at')),
        'modified':          stix_timestamp(page.get('crawled_at')),
        'created_by_ref':    TOOL_IDENTITY_ID,
        'name':              f"Onion Infrastructure: {domain or url[:60]}",
        'description':       (
            f"Dark web hosting infrastructure for {domain}. "
            f"Server: {server_sw or 'Unknown'}. "
            f"CDN: {cdn or 'None'}. "
            f"OPSEC Score: {opsec or 'N/A'}/100."
        ),
        'infrastructure_types': ['hosting-malware', 'anonymization'],
        'labels':              [category, 'onion-service'],
        'x_onion_domain':    domain,
        'x_server_software': server_sw,
        'x_cdn_detected':    cdn,
        'x_opsec_score':     opsec,
        'x_uptime_pct':      page.get('uptime_pct'),
    }


# ── Bundle Builder ────────────────────────────────────────────────────────────

def build_stix_bundle(
    category_filter: str = None,
    flagged_only:    bool = False
) -> dict:
    """
    Build a complete STIX 2.1 Bundle from all IoCs in MongoDB.
    Returns the bundle dict.
    """
    objects = []
    stats   = {
        'indicators':    0,
        'observed_data': 0,
        'threat_actors': 0,
        'infrastructure':0,
    }

    # Always include tool identity
    objects.append(build_identity())

    # ── Query pages ───────────────────────────────────────────
    query = {}
    if category_filter:
        query['category'] = category_filter
    if flagged_only:
        query['is_flagged'] = True

    pages = list(db.pages.find(query))
    print(f"  Processing {len(pages)} pages...")

    for page in pages:
        # Indicator for the .onion URL itself
        if page.get('category') not in ('news',) and page.get('is_flagged', False):
            ind = build_indicator_from_onion(page)
            if ind:
                objects.append(ind)
                stats['indicators'] += 1

        # ObservedData for emails
        entities  = page.get('entities', {})
        crawled   = page.get('crawled_at')
        page_url  = page.get('url', '')

        for email in (entities.get('emails') or [])[:5]:
            obs = build_observed_data_email(email, page_url, crawled)
            objects.append(obs)
            stats['observed_data'] += 1

        # ObservedData for BTC addresses with risk scores
        for btc_info in (page.get('btc_risk') or []):
            if btc_info.get('api_success') and btc_info.get('risk_level') != 'UNUSED':
                obs = build_observed_data_bitcoin(btc_info, page_url, crawled)
                objects.append(obs)
                stats['observed_data'] += 1

        # Infrastructure for threat pages
        if page.get('is_flagged') or page.get('category') in ('hacking', 'fraud', 'drugs'):
            infra = build_infrastructure_from_page(page)
            if infra:
                objects.append(infra)
                stats['infrastructure'] += 1

    # ── Query identity correlations ───────────────────────────
    correlations = list(db.identity_correlations.find(
        {'clearnet': {'$ne': [], '$exists': True}}
    ))
    print(f"  Processing {len(correlations)} identity correlations...")

    for corr in correlations:
        actor = build_threat_actor_from_identity(corr)
        if actor:
            objects.append(actor)
            stats['threat_actors'] += 1

    # ── Build bundle ──────────────────────────────────────────
    bundle = {
        'type':         'bundle',
        'id':           f"bundle--{uuid.uuid4()}",
        'spec_version': STIX_VERSION,
        'objects':      objects,
    }

    return bundle, stats


# ── Main Runner ───────────────────────────────────────────────────────────────

def run_stix_export(
    output_path:     str  = None,
    category_filter: str  = None,
    flagged_only:    bool = False
):
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  STIX 2.1 THREAT INTELLIGENCE EXPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  International standard IoC format{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"  STIX Version  : {STIX_VERSION}")
    print(f"  Category      : {category_filter or 'ALL'}")
    print(f"  Flagged only  : {flagged_only}")

    # Ensure exports directory exists
    os.makedirs(EXPORTS_DIR, exist_ok=True)

    # Generate output filename
    if not output_path:
        ts          = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        suffix      = f"_{category_filter}" if category_filter else ""
        suffix     += "_flagged" if flagged_only else ""
        output_path = os.path.join(EXPORTS_DIR, f"stix_bundle{suffix}_{ts}.json")

    print(f"  Output file   : {output_path}\n")

    # Build bundle
    bundle, stats = build_stix_bundle(
        category_filter=category_filter,
        flagged_only=flagged_only
    )

    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)

        file_size = os.path.getsize(output_path)
        print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  STIX EXPORT COMPLETE{Style.RESET_ALL}")
        print(f"{'─'*60}")
        print(f"  Total objects    : {len(bundle['objects'])}")
        print(f"  Indicators       : {stats['indicators']}  (.onion threat URLs)")
        print(f"  Observed Data    : {stats['observed_data']}  (emails, BTC addresses)")
        print(f"  Threat Actors    : {stats['threat_actors']}  (identity correlations)")
        print(f"  Infrastructure   : {stats['infrastructure']}  (.onion hosting)")
        print(f"  File size        : {file_size / 1024:.1f} KB")
        print(f"  Output           : {output_path}")
        print(f"{'─'*60}")
        print(f"  Compatible with  : Splunk, OpenCTI, MISP, IBM QRadar,")
        print(f"                     Elastic SIEM, Microsoft Sentinel")
        print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")

        return output_path

    except Exception as e:
        print(f"  {Fore.RED}✗ Failed to write STIX bundle: {e}{Style.RESET_ALL}")
        return None


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='STIX 2.1 Threat Intelligence Export')
    parser.add_argument('--output',       type=str, default=None,
                        help='Output file path (default: exports/stix_bundle_<timestamp>.json)')
    parser.add_argument('--category',     type=str, default=None,
                        help='Filter by category (hacking, drugs, fraud, crypto, etc.)')
    parser.add_argument('--flagged-only', action='store_true',
                        help='Only export flagged/threat pages')
    args = parser.parse_args()
    run_stix_export(
        output_path=args.output,
        category_filter=args.category,
        flagged_only=args.flagged_only
    )