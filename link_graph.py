"""
link_graph.py — Link Graph Builder + PageRank
===============================================
Builds a directed graph of .onion site connections
from crawled link data, computes PageRank scores,
and exports D3.js-ready JSON for dashboard visualization.

Research Value:
  PageRank on the dark web link graph identifies the most
  "important" .onion sites — those most linked-to by others.
  This is network science applied to dark web topology.
  No existing tool (TorBot, OnionScan, Ahmia) does this.

Output:
  - graph.json in project folder (D3.js force graph data)
  - PageRank scores stored back to MongoDB pages collection

Usage:
    python link_graph.py
    python link_graph.py --top 20    (show top 20 by PageRank)
    python link_graph.py --no-store  (compute but don't save)
"""

import re
import json
import datetime
import argparse
from urllib.parse import urlparse
from collections import defaultdict

import math
import networkx as nx
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, PAGERANK_ALPHA, MAX_GRAPH_NODES, MAX_GRAPH_EDGES, GRAPH_JSON
GRAPH_OUTPUT = str(GRAPH_JSON)
PAGERANK_ALPHA     = PAGERANK_ALPHA
MAX_NODES          = MAX_GRAPH_NODES
MAX_EDGES          = MAX_GRAPH_EDGES

# PageRank settings
PAGERANK_ALPHA      = 0.85    # damping factor (standard value)
PAGERANK_MAX_ITER   = 100
PAGERANK_TOLERANCE  = 1.0e-6

# D3.js graph settings
MAX_NODES           = 200     # limit for browser performance
MAX_EDGES           = 500
MIN_PAGERANK_DISPLAY= 0.0001  # filter out very low-ranked nodes

# Category colors for D3.js nodes
CATEGORY_COLORS = {
    'hacking':      '#ff1744',
    'drugs':        '#d500f9',
    'fraud':        '#ff6d00',
    'crypto':       '#ffd600',
    'privacy':      '#00e5ff',
    'news':         '#69ff47',
    'search_index': '#2979ff',
    'forum':        '#ff4081',
    'other':        '#607d8b',
}

ONION_RE = re.compile(
    r'https?://(?:[a-z0-9\-]+\.)*[a-z2-7]{10,60}\.onion(?:/[^\s"\'<>]*)?',
    re.IGNORECASE
)

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── URL Normalization ─────────────────────────────────────────────────────────

def get_domain(url: str) -> str:
    """Extract base domain from URL."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc.lower()}"
    except Exception:
        return url


def normalize_url(url: str) -> str:
    """Normalize URL for consistent node identification."""
    try:
        p    = urlparse(url.strip())
        host = p.netloc.lower()
        path = p.path.rstrip('/')
        return f"{p.scheme}://{host}{path}" if path else f"{p.scheme}://{host}"
    except Exception:
        return url.strip().rstrip('/')

# ── Graph Construction ────────────────────────────────────────────────────────

def build_graph() -> tuple:
    """
    Build a directed graph of .onion links from MongoDB.

    Node = a crawled .onion URL (or domain)
    Edge = a link from page A to page B found during crawling

    Strategy:
      1. All crawled pages are nodes
      2. For each page, re-extract .onion links from stored text
         and add directed edges to target pages
      3. Only add edges to nodes that exist in our DB
         (ensures graph stays within our crawled dataset)

    Returns: (DiGraph, node_metadata_dict)
    """
    print(f"  Loading pages from MongoDB...")
    pages = list(db.pages.find(
        {'text': {'$exists': True}},
        {
            '_id': 1, 'url': 1, 'title': 1, 'text': 1,
            'domain': 1, 'category': 1, 'confidence': 1,
            'is_flagged': 1, 'opsec_score': 1, 'response_ms': 1,
            'language': 1, 'uptime_pct': 1,
        }
    ))
    print(f"  Loaded {len(pages)} pages")

    # Build URL → page metadata lookup
    url_to_meta = {}
    domain_to_urls = defaultdict(list)

    for page in pages:
        url    = page.get('url', '')
        domain = page.get('domain', get_domain(url))
        if url:
            url_to_meta[url]    = page
            url_to_meta[normalize_url(url)] = page
            domain_to_urls[domain].append(url)

    all_known_urls  = set(url_to_meta.keys())
    all_known_domains = set(domain_to_urls.keys())

    # ── Build directed graph ───────────────────────────────────
    G = nx.DiGraph()

    # Add all crawled pages as nodes
    for page in pages:
        url      = page.get('url', '')
        norm_url = normalize_url(url)
        if not url:
            continue

        domain   = page.get('domain', get_domain(url))
        category = page.get('category', 'other')
        title    = (page.get('title') or 'No Title')[:60]

        G.add_node(norm_url, **{
            'title':       title,
            'domain':      domain,
            'category':    category,
            'confidence':  page.get('confidence', 0),
            'is_flagged':  page.get('is_flagged', False),
            'opsec_score': page.get('opsec_score'),
            'language':    page.get('language', 'en'),
            'uptime_pct':  page.get('uptime_pct'),
        })

    print(f"  Graph nodes (crawled pages): {G.number_of_nodes()}")

    # Add edges by extracting links from page text
    edges_added = 0
    for page in pages:
        src_url  = normalize_url(page.get('url', ''))
        text     = page.get('text', '') or ''

        if not src_url or not text:
            continue

        # Extract .onion links from stored page text
        found_urls = set()
        for match in ONION_RE.finditer(text):
            candidate = normalize_url(match.group(0))
            found_urls.add(candidate)
            # Also add domain-only variant
            found_urls.add(get_domain(match.group(0)))

        for target_url in found_urls:
            # Only add edge if target is in our crawled dataset
            target_in_db = (
                target_url in all_known_urls or
                get_domain(target_url) in all_known_domains
            )
            if target_in_db and target_url != src_url:
                # Find the actual node URL for the target domain
                target_node = target_url
                if target_url not in G.nodes and get_domain(target_url) in domain_to_urls:
                    domain_urls = domain_to_urls[get_domain(target_url)]
                    if domain_urls:
                        target_node = normalize_url(domain_urls[0])

                if target_node in G.nodes and target_node != src_url:
                    if not G.has_edge(src_url, target_node):
                        G.add_edge(src_url, target_node)
                        edges_added += 1

    print(f"  Graph edges (links between pages): {edges_added}")
    return G, url_to_meta


# ── PageRank Computation ──────────────────────────────────────────────────────

def compute_pagerank(G: nx.DiGraph) -> dict:
    """
    Compute PageRank scores on the directed link graph.

    PageRank assigns importance scores based on link structure.
    A page with many inbound links from other important pages
    gets a high PageRank — identifying "hub" sites in the
    dark web ecosystem.

    Returns dict: url -> pagerank_score
    """
    if G.number_of_nodes() == 0:
        return {}

    # Handle disconnected graphs — PageRank works on any DiGraph
    print(f"  Computing PageRank (α={PAGERANK_ALPHA})...")
    try:
        pr = nx.pagerank(
            G,
            alpha=PAGERANK_ALPHA,
            max_iter=PAGERANK_MAX_ITER,
            tol=PAGERANK_TOLERANCE,
        )
    except nx.PowerIterationFailedConvergence:
        # Fallback with more iterations
        print(f"  {Fore.YELLOW}⚠ PageRank didn't converge — using 500 iterations{Style.RESET_ALL}")
        pr = nx.pagerank(G, alpha=PAGERANK_ALPHA, max_iter=500)

    return pr


def store_pagerank(pr: dict, url_to_meta: dict):
    """Store PageRank scores back to MongoDB pages collection."""
    updated = 0
    for url, score in pr.items():
        page_meta = url_to_meta.get(url)
        if page_meta and '_id' in page_meta:
            try:
                db.pages.update_one(
                    {'_id': page_meta['_id']},
                    {'$set': {
                        'pagerank_score': round(score, 8),
                        'pagerank_computed_at': datetime.datetime.now(datetime.timezone.utc),
                    }}
                )
                updated += 1
            except Exception:
                continue
    return updated


# ── D3.js JSON Export ─────────────────────────────────────────────────────────

def export_d3_graph(
    G:          nx.DiGraph,
    pr:         dict,
    url_to_meta: dict,
    output_path: str = GRAPH_OUTPUT
) -> dict:
    """
    Export graph as D3.js force-directed graph JSON.

    Format:
    {
      "nodes": [
        {
          "id": "url",
          "title": "Site Title",
          "category": "hacking",
          "pagerank": 0.0023,
          "pagerank_rank": 1,
          "color": "#ff1744",
          "is_flagged": true,
          "opsec_score": 45,
          "group": 1
        }, ...
      ],
      "links": [
        {"source": "url_a", "target": "url_b", "value": 1},
        ...
      ],
      "metadata": {
        "total_nodes": 150,
        "total_edges": 320,
        "computed_at": "...",
        "top_sites": [...]
      }
    }
    """
    # Sort nodes by PageRank descending
    sorted_nodes = sorted(pr.items(), key=lambda x: -x[1])

    # Filter and limit nodes for browser performance
    display_nodes = [
        (url, score) for url, score in sorted_nodes
        if score >= MIN_PAGERANK_DISPLAY and url in G.nodes
    ][:MAX_NODES]

    display_url_set = {url for url, _ in display_nodes}

    # Assign PageRank rank
    rank_map = {url: i + 1 for i, (url, _) in enumerate(display_nodes)}

    # Category → group number (for D3 color grouping)
    cat_to_group = {cat: i + 1 for i, cat in enumerate(CATEGORY_COLORS.keys())}

    # ── Build nodes list ──────────────────────────────────────
    nodes = []
    for url, score in display_nodes:
        node_data = G.nodes.get(url, {})
        category  = node_data.get('category', 'other')
        title     = node_data.get('title', url[:40])
        domain    = node_data.get('domain', get_domain(url))

        # Node size proportional to PageRank (log scale for visibility)
        size = max(5, min(40, int(10 + math.log(score * 10000 + 1) * 5)))

        nodes.append({
            'id':          url,
            'title':       title,
            'domain':      domain,
            'category':    category,
            'pagerank':    round(score, 8),
            'pagerank_pct': round(score * 100, 4),
            'pagerank_rank': rank_map[url],
            'color':       CATEGORY_COLORS.get(category, '#607d8b'),
            'size':        size,
            'is_flagged':  node_data.get('is_flagged', False),
            'opsec_score': node_data.get('opsec_score'),
            'language':    node_data.get('language', 'en'),
            'uptime_pct':  node_data.get('uptime_pct'),
            'group':       cat_to_group.get(category, 9),
            'in_degree':   G.in_degree(url),
            'out_degree':  G.out_degree(url),
        })

    # ── Build links list ──────────────────────────────────────
    links = []
    for src, tgt in G.edges():
        if src in display_url_set and tgt in display_url_set:
            links.append({
                'source': src,
                'target': tgt,
                'value':  1,
            })
        if len(links) >= MAX_EDGES:
            break

    # ── Top sites by PageRank (for metadata) ──────────────────
    top_sites = []
    for url, score in sorted_nodes[:20]:
        meta = url_to_meta.get(url, {})
        top_sites.append({
            'rank':     rank_map.get(url, 0),
            'url':      url,
            'title':    (meta.get('title') or 'No Title')[:50],
            'category': meta.get('category', 'other'),
            'pagerank': round(score, 8),
            'in_links': G.in_degree(url),
        })

    # ── Category distribution ──────────────────────────────────
    cat_counts = defaultdict(int)
    for url, _ in display_nodes:
        cat = G.nodes.get(url, {}).get('category', 'other')
        cat_counts[cat] += 1

    graph_data = {
        'nodes': nodes,
        'links': links,
        'metadata': {
            'total_nodes':    G.number_of_nodes(),
            'total_edges':    G.number_of_edges(),
            'display_nodes':  len(nodes),
            'display_edges':  len(links),
            'computed_at':    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'pagerank_alpha': PAGERANK_ALPHA,
            'top_sites':      top_sites,
            'category_dist':  dict(cat_counts),
        }
    }

    # Write JSON
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        print(f"  {Fore.GREEN}✓ Graph saved to {output_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.RED}✗ Failed to save graph: {e}{Style.RESET_ALL}")

    return graph_data


# ── Print Top PageRank Sites ──────────────────────────────────────────────────

def print_top_pagerank(pr: dict, url_to_meta: dict, top_n: int = 15):
    """Print top N pages by PageRank score."""
    print(f"\n  {Fore.CYAN}Top {top_n} Sites by PageRank (Dark Web Hubs):{Style.RESET_ALL}")
    print(f"  {'RANK':<5} {'SCORE':>10}  {'IN-LINKS':>8}  {'CATEGORY':<14} TITLE")
    print(f"  {'─'*70}")

    sorted_pr = sorted(pr.items(), key=lambda x: -x[1])
    shown     = 0

    for url, score in sorted_pr:
        if shown >= top_n:
            break
        meta     = url_to_meta.get(url, {})
        title    = (meta.get('title') or url[:40])[:40]
        category = meta.get('category', 'other')
        shown   += 1

        color = CATEGORY_COLORS.get(category, '#607d8b')
        cat_color = (Fore.RED    if category == 'hacking' else
                     Fore.YELLOW if category in ('fraud', 'drugs') else
                     Fore.CYAN   if category == 'privacy' else
                     Fore.GREEN  if category == 'news' else Style.RESET_ALL)

        print(f"  {shown:<5} {score:>10.6f}  "
              f"{'?':>8}  "
              f"{cat_color}{category:<14}{Style.RESET_ALL} {title}")

    # Network stats
    print(f"\n  {Fore.CYAN}Dark Web Network Statistics:{Style.RESET_ALL}")

# ── Main Runner ───────────────────────────────────────────────────────────────

def run_link_graph(top_n: int = 15, store: bool = True):
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LINK GRAPH BUILDER + PAGERANK{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  NetworkX PageRank on .onion link topology{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")

    # ── Build graph ───────────────────────────────────────────
    G, url_to_meta = build_graph()

    if G.number_of_nodes() == 0:
        print(f"  {Fore.RED}✗ No pages found in DB. Run crawler first.{Style.RESET_ALL}")
        return

    # Basic graph stats
    print(f"\n  Graph Statistics:")
    print(f"    Nodes (pages)    : {G.number_of_nodes()}")
    print(f"    Edges (links)    : {G.number_of_edges()}")
    if G.number_of_nodes() > 0:
        density = nx.density(G)
        print(f"    Graph density    : {density:.6f}")

    # Connected components
    undirected     = G.to_undirected()
    components     = list(nx.connected_components(undirected))
    largest_comp   = max(len(c) for c in components) if components else 0
    print(f"    Components       : {len(components)}")
    print(f"    Largest component: {largest_comp} nodes")

    # ── Compute PageRank ──────────────────────────────────────
    pr = compute_pagerank(G)

    if not pr:
        print(f"  {Fore.YELLOW}⚠ PageRank returned empty — graph may be too sparse{Style.RESET_ALL}")
        pr = {url: 1.0 / G.number_of_nodes() for url in G.nodes()}

    print(f"  {Fore.GREEN}✓ PageRank computed for {len(pr)} nodes{Style.RESET_ALL}")

    # Add in_degree to url_to_meta for display
    for url in url_to_meta:
        if url in G.nodes:
            url_to_meta[url]['_in_degree']  = G.in_degree(url)
            url_to_meta[url]['_out_degree'] = G.out_degree(url)

    # ── Store PageRank to MongoDB ──────────────────────────────
    if store:
        updated = store_pagerank(pr, url_to_meta)
        print(f"  {Fore.GREEN}✓ PageRank stored for {updated} pages in MongoDB{Style.RESET_ALL}")

    # ── Print top sites ───────────────────────────────────────
    print_top_pagerank(pr, url_to_meta, top_n=top_n)

    # Additional network metrics
    try:
        # In-degree centrality (simpler than PageRank, good comparison)
        in_deg   = dict(G.in_degree())
        top_hubs = sorted(in_deg.items(), key=lambda x: -x[1])[:5]
        print(f"\n  Top 5 by In-Degree (most linked-to):")
        for url, deg in top_hubs:
            meta  = url_to_meta.get(url, {})
            title = (meta.get('title') or url[:40])[:45]
            print(f"    {deg:3d} links → {title}")
    except Exception:
        pass

    # ── Export D3.js graph JSON ───────────────────────────────
    print(f"\n  Exporting D3.js graph data...")
    graph_data = export_d3_graph(G, pr, url_to_meta, GRAPH_OUTPUT)

    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  LINK GRAPH COMPLETE{Style.RESET_ALL}")
    print(f"{'─'*60}")
    print(f"  Nodes in graph   : {G.number_of_nodes()}")
    print(f"  Edges in graph   : {G.number_of_edges()}")
    print(f"  D3.js nodes      : {len(graph_data['nodes'])}")
    print(f"  D3.js edges      : {len(graph_data['links'])}")
    print(f"  Output file      : {GRAPH_OUTPUT}")
    print(f"  Dashboard        : http://localhost:5000")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web Link Graph + PageRank')
    parser.add_argument('--top',      type=int, default=15,
                        help='Number of top PageRank sites to display (default: 15)')
    parser.add_argument('--no-store', action='store_true',
                        help='Compute PageRank but do not store to MongoDB')
    args = parser.parse_args()
    run_link_graph(top_n=args.top, store=not args.no_store)