"""
config.py — Central Configuration for DarkScope
=================================================
Single source of truth for all configuration values.
Import from this file in every module.

Usage:
    from config import MONGO_URI, DB_NAME, TOR_PROXY, MAX_PER_DOMAIN

Override via environment variables or .env file:
    MONGO_URI=mongodb://remotehost:27017/ python crawler.py
"""

import os
from pathlib import Path

# Load .env file if present (optional dependency)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not required — env vars can be set manually

# ── MongoDB ───────────────────────────────────────────────────────────────────
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DB_NAME   = os.getenv('DB_NAME',   'darkweb_crawler')

# ── Tor Proxy ─────────────────────────────────────────────────────────────────
TOR_HOST  = os.getenv('TOR_HOST', '127.0.0.1')
TOR_PORT  = int(os.getenv('TOR_PORT', '9150'))
TOR_PROXY = {
    'http':  f'socks5h://{TOR_HOST}:{TOR_PORT}',
    'https': f'socks5h://{TOR_HOST}:{TOR_PORT}',
}

# ── Crawler Settings ──────────────────────────────────────────────────────────
MAX_PER_DOMAIN  = int(os.getenv('MAX_PER_DOMAIN',  '10'))
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '25'))
RETRY_ATTEMPTS  = int(os.getenv('RETRY_ATTEMPTS',  '3'))
RETRY_DELAY     = int(os.getenv('RETRY_DELAY',     '3'))
CRAWL_DELAY     = float(os.getenv('CRAWL_DELAY',   '1.5'))
MAX_TEXT_STORE  = int(os.getenv('MAX_TEXT_STORE',  '5000'))
MAX_HTML_STORE  = int(os.getenv('MAX_HTML_STORE',  '300000'))  # 300KB raw HTML

# ── User Agent ────────────────────────────────────────────────────────────────
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; rv:115.0) '
    'Gecko/20100101 Firefox/115.0'
)

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_DIR     = Path(os.getenv('PROJECT_DIR', os.path.dirname(os.path.abspath(__file__))))
SCREENSHOTS_DIR = PROJECT_DIR / 'screenshots'
EXPORTS_DIR     = PROJECT_DIR / 'exports'
GRAPH_JSON      = PROJECT_DIR / 'graph.json'
MODEL_PATH      = PROJECT_DIR / 'model.pkl'
VECTORIZER_PATH = PROJECT_DIR / 'vectorizer.pkl'

# ── NLP Settings ──────────────────────────────────────────────────────────────
MIN_TEXT_FOR_NLP  = int(os.getenv('MIN_TEXT_FOR_NLP',  '30'))
SPACY_MAX_CHARS   = int(os.getenv('SPACY_MAX_CHARS',   '5000'))

# ── BTC API (BlockCypher free tier: 200 req/hr) ───────────────────────────────
# 200 req/hr = 1 req per 18s to stay safely under limit
BTC_API_DELAY    = float(os.getenv('BTC_API_DELAY', '18.0'))
BTC_MAX_PER_PAGE = int(os.getenv('BTC_MAX_PER_PAGE', '5'))
BLOCKCYPHER_BASE = 'https://api.blockcypher.com/v1/btc/main/addrs'

# ── Classifier ────────────────────────────────────────────────────────────────
TFIDF_MAX_FEATURES  = int(os.getenv('TFIDF_MAX_FEATURES', '5000'))
SIMILARITY_THRESHOLD= float(os.getenv('SIMILARITY_THRESHOLD', '0.85'))
MIN_TEXT_LENGTH     = int(os.getenv('MIN_TEXT_LENGTH', '50'))

# ── OPSEC ─────────────────────────────────────────────────────────────────────
KEYSERVER_URL     = 'https://keys.openpgp.org/vks/v1/by-fingerprint/'
KEYSERVER_TIMEOUT = int(os.getenv('KEYSERVER_TIMEOUT', '10'))

# ── Forum Crawler ─────────────────────────────────────────────────────────────
BOARD_DELAY  = float(os.getenv('BOARD_DELAY',  '2.5'))
THREAD_DELAY = float(os.getenv('THREAD_DELAY', '1.5'))

# ── Uptime Monitor ────────────────────────────────────────────────────────────
CHECK_TIMEOUT        = int(os.getenv('CHECK_TIMEOUT',        '15'))
DEFAULT_INTERVAL_MIN = int(os.getenv('DEFAULT_INTERVAL_MIN', '60'))
MAX_SITES_PER_RUN    = int(os.getenv('MAX_SITES_PER_RUN',    '100'))

# ── Graph / PageRank ──────────────────────────────────────────────────────────
PAGERANK_ALPHA     = float(os.getenv('PAGERANK_ALPHA',     '0.85'))
MAX_GRAPH_NODES    = int(os.getenv('MAX_GRAPH_NODES',      '200'))
MAX_GRAPH_EDGES    = int(os.getenv('MAX_GRAPH_EDGES',      '500'))

# ── Dashboard ────────────────────────────────────────────────────────────────
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
FLASK_DEBUG= os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

# ── Search Input Sanitization ────────────────────────────────────────────────
SEARCH_MAX_LENGTH = int(os.getenv('SEARCH_MAX_LENGTH', '100'))

# ── Ensure directories exist ─────────────────────────────────────────────────
SCREENSHOTS_DIR.mkdir(exist_ok=True)
EXPORTS_DIR.mkdir(exist_ok=True)