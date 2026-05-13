"""
app.py — Dark Web Intelligence Platform Dashboard
==================================================
Flask backend serving the research dashboard.
Auto-starts uptime monitor as background thread.

API Endpoints (15 total):
  /api/stats           — Overview statistics
  /api/entities        — NLP extracted entities
  /api/credentials     — Detected credentials
  /api/forums          — Forum posts
  /api/forum_stats     — Forum statistics
  /api/screenshots     — Screenshot gallery
  /api/search          — Full-text search
  /api/opsec           — OPSEC scores per site
  /api/opsec_stats     — OPSEC distribution stats
  /api/headers         — HTTP header fingerprints
  /api/dns_leakage     — DNS leakage analysis
  /api/identities      — Identity correlations
  /api/graph           — D3.js link graph JSON
  /api/uptime          — Uptime statistics
  /api/clusters        — Content similarity clusters
  /api/export/stix     — Trigger STIX export

Usage:
    python app.py
    Then open: http://localhost:5000
"""

import os
import json
import datetime
import threading

from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_cors import CORS
from pymongo import MongoClient

app = Flask(__name__)
CORS(app)

# ── Configuration ─────────────────────────────────────────────────────────────

# ── Configuration (centralised — edit config.py, not here) ───────────────────
from config import (
    MONGO_URI, DB_NAME, FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    SEARCH_MAX_LENGTH,
)
from config import (
    SCREENSHOTS_DIR, EXPORTS_DIR, GRAPH_JSON,
    PROJECT_DIR,
)
# Convert Path objects to strings for Flask compatibility
SCREENSHOTS_DIR = str(SCREENSHOTS_DIR)
EXPORTS_DIR     = str(EXPORTS_DIR)
GRAPH_JSON      = str(GRAPH_JSON)
PROJECT_DIR     = str(PROJECT_DIR)

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

def ensure_indexes():
    """Create indexes needed for dashboard queries."""
    try:
        db.pages.create_index('url', unique=True)
        db.pages.create_index('crawled_at')
        db.pages.create_index('category')
        db.pages.create_index('is_flagged')
        db.pages.create_index('opsec_score')
        db.pages.create_index('pagerank_score')
        db.pages.create_index('cluster_id')
        try:
            db.pages.create_index(
                [('title', 'text'), ('text', 'text')],
                default_language='english'
            )
        except Exception:
            pass
    except Exception:
        pass

# ── Helper ────────────────────────────────────────────────────────────────────

def serialize_doc(doc: dict) -> dict:
    """Convert MongoDB document to JSON-serializable dict."""
    if '_id' in doc:
        doc['_id'] = str(doc['_id'])
    for key, val in doc.items():
        if isinstance(val, datetime.datetime):
            doc[key] = val.strftime('%Y-%m-%d %H:%M:%S')
    return doc

# ── Static Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return send_from_directory(
        os.path.join(PROJECT_DIR, 'templates'),
        'index.html'
    )


@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    return send_from_directory(SCREENSHOTS_DIR, filename)


@app.route('/graph.json')
def serve_graph():
    if os.path.exists(GRAPH_JSON):
        return send_file(GRAPH_JSON, mimetype='application/json')
    return jsonify({'nodes': [], 'links': [], 'metadata': {}}), 200

# ── API: Overview Stats ───────────────────────────────────────────────────────

@app.route('/api/stats')
def stats():
    try:
        total       = db.pages.count_documents({})
        flagged     = db.pages.count_documents({'is_flagged': True})
        with_ents   = db.pages.count_documents({'entities': {'$exists': True}})
        with_creds  = db.pages.count_documents({'has_credentials': True})
        forums      = db.forums.count_documents({})
        screenshots = db.pages.count_documents({'screenshot_exists': True})
        clusters    = db.pages.count_documents({'cluster_id': {'$exists': True}})
        mirrors     = db.pages.count_documents({'is_mirror': True})
        with_pr     = db.pages.count_documents({'pagerank_score': {'$exists': True}})
        uptime_checked = db.pages.count_documents({'uptime_pct': {'$exists': True}})

        # Keyword distribution
        kw_pipeline = [
            {'$unwind': '$keywords_found'},
            {'$group':  {'_id': '$keywords_found', 'count': {'$sum': 1}}},
            {'$sort':   {'count': -1}},
            {'$limit':  12},
        ]
        keywords = list(db.pages.aggregate(kw_pipeline))

        # Category distribution
        cat_pipeline = [
            {'$match':  {'category': {'$exists': True}}},
            {'$group':  {'_id': '$category',
                         'count': {'$sum': 1},
                         'avg_conf': {'$avg': '$confidence'}}},
            {'$sort':   {'count': -1}},
        ]
        categories = list(db.pages.aggregate(cat_pipeline))
        for c in categories:
            c['avg_conf'] = round(c.get('avg_conf') or 0, 1)

        # Language distribution
        lang_pipeline = [
            {'$match':  {'lang_name': {'$exists': True}}},
            {'$group':  {'_id': '$lang_name', 'count': {'$sum': 1}}},
            {'$sort':   {'count': -1}},
            {'$limit':  10},
        ]
        languages = list(db.pages.aggregate(lang_pipeline))

        # Recent crawls
        recent = list(db.pages.find(
            {},
            {'url': 1, 'title': 1, 'is_flagged': 1, 'keywords_found': 1,
             'crawled_at': 1, 'category': 1, 'confidence': 1,
             'language': 1, 'opsec_score': 1, 'pagerank_score': 1}
        ).sort('crawled_at', -1).limit(25))
        recent = [serialize_doc(p) for p in recent]

        # Top PageRank sites
        top_pr = list(db.pages.find(
            {'pagerank_score': {'$exists': True}},
            {'url': 1, 'title': 1, 'category': 1,
             'pagerank_score': 1, 'is_flagged': 1}
        ).sort('pagerank_score', -1).limit(10))
        top_pr = [serialize_doc(p) for p in top_pr]

        return jsonify({
            'total':           total,
            'flagged':         flagged,
            'clean':           total - flagged,
            'with_entities':   with_ents,
            'with_credentials':with_creds,
            'forum_posts':     forums,
            'screenshots':     screenshots,
            'clusters':        clusters,
            'mirror_sites':    mirrors,
            'with_pagerank':   with_pr,
            'uptime_checked':  uptime_checked,
            'keywords':        keywords,
            'categories':      categories,
            'languages':       languages,
            'recent':          recent,
            'top_pagerank':    top_pr,
        })
    except Exception as e:
        return jsonify({'error': str(e), 'total': 0, 'flagged': 0,
                        'clean': 0, 'keywords': [], 'categories': [],
                        'languages': [], 'recent': []}), 500

# ── API: Entities ─────────────────────────────────────────────────────────────

@app.route('/api/entities')
def entities():
    try:
        pages = list(db.pages.find(
            {'entities': {'$exists': True}},
            {'url': 1, 'title': 1, 'entities': 1,
             'category': 1, 'btc_risk': 1, 'language': 1}
        ).sort('crawled_at', -1).limit(60))

        result = []
        for p in pages:
            ents    = p.get('entities', {})
            emails  = ents.get('emails',     [])
            bitcoin = ents.get('bitcoin',    [])
            monero  = ents.get('monero',     [])
            pgp     = ents.get('pgp_keys',   [])
            spacy_e = ents.get('spacy_ents', [])

            if emails or bitcoin or monero or pgp or spacy_e:
                result.append({
                    'title':    (p.get('title') or '')[:55],
                    'url':      (p.get('url')   or '')[:75],
                    'category': p.get('category', 'unknown'),
                    'language': p.get('language', 'en'),
                    'emails':   emails[:5],
                    'bitcoin':  bitcoin[:5],
                    'monero':   monero[:3],
                    'pgp_keys': len(pgp) > 0,
                    'btc_risk': p.get('btc_risk', []),
                    'orgs':    [e['text'] for e in spacy_e if e.get('label') == 'ORG'][:5],
                    'persons': [e['text'] for e in spacy_e if e.get('label') == 'PERSON'][:5],
                })

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Credentials ──────────────────────────────────────────────────────────

@app.route('/api/credentials')
def credentials():
    try:
        pages = list(db.pages.find(
            {'has_credentials': True},
            {'url': 1, 'title': 1, 'credentials': 1,
             'is_credential_dump': 1, 'dump_line_count': 1, 'crawled_at': 1}
        ).sort('crawled_at', -1).limit(30))
        return jsonify([serialize_doc(p) for p in pages])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Forums ───────────────────────────────────────────────────────────────

@app.route('/api/forums')
def forums():
    try:
        board  = request.args.get('board')
        query  = {'board': board} if board else {}
        posts  = list(db.forums.find(
            query,
            {'forum': 1, 'board': 1, 'subject': 1, 'content': 1,
             'username': 1, 'url': 1, 'crawled_at': 1, 'post_time': 1}
        ).sort('crawled_at', -1).limit(100))
        return jsonify([serialize_doc(p) for p in posts])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/forum_stats')
def forum_stats():
    try:
        total = db.forums.count_documents({})
        pipeline = [
            {'$group': {'_id': {'forum': '$forum', 'board': '$board'},
                        'count': {'$sum': 1}}},
            {'$sort':  {'count': -1}},
        ]
        boards = list(db.forums.aggregate(pipeline))
        named  = db.forums.count_documents(
            {'username': {'$nin': ['Anonymous', '', None]}}
        )
        return jsonify({
            'total':  total,
            'boards': boards,
            'named_users': named,
            'anonymous':   total - named,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Screenshots ──────────────────────────────────────────────────────────

@app.route('/api/screenshots')
def screenshots():
    try:
        pages = list(db.pages.find(
            {'screenshot_exists': True},
            {'url': 1, 'title': 1, 'category': 1,
             'is_flagged': 1, 'screenshot': 1, 'keywords_found': 1}
        ))
        result = []
        for p in pages:
            filepath = p.get('screenshot', '')
            filename = os.path.basename(filepath) if filepath else ''
            if filename:
                result.append({
                    'title':    (p.get('title') or 'No Title'),
                    'url':      p.get('url', ''),
                    'category': p.get('category', 'other'),
                    'flagged':  p.get('is_flagged', False),
                    'keywords': (p.get('keywords_found') or [])[:4],
                    'filename': filename,
                })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Search ───────────────────────────────────────────────────────────────

@app.route('/api/search')
def search():
    try:
        q = request.args.get('q', '').strip()
        if not q:
            return jsonify([])

        try:
            results = list(db.pages.find(
                {'$text': {'$search': q}},
                {'url': 1, 'title': 1, 'keywords_found': 1, 'category': 1,
                 'confidence': 1, 'crawled_at': 1, 'is_flagged': 1,
                 'score': {'$meta': 'textScore'}}
            ).sort([('score', {'$meta': 'textScore'})]).limit(20))
        except Exception:
            results = list(db.pages.find(
                {'$or': [
                    {'title': {'$regex': q, '$options': 'i'}},
                    {'text':  {'$regex': q, '$options': 'i'}},
                ]},
                {'url': 1, 'title': 1, 'keywords_found': 1,
                 'category': 1, 'confidence': 1, 'crawled_at': 1, 'is_flagged': 1}
            ).limit(20))

        cleaned = []
        for r in results:
            r.pop('score', None)
            cleaned.append(serialize_doc(r))
        return jsonify(cleaned)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: OPSEC ────────────────────────────────────────────────────────────────

@app.route('/api/opsec')
def opsec():
    try:
        level  = request.args.get('level')
        query  = {'opsec_score': {'$exists': True}}
        if level:
            query['opsec_level'] = level.upper()

        pages = list(db.pages.find(
            query,
            {'url': 1, 'title': 1, 'opsec_score': 1,
             'opsec_level': 1, 'opsec_failures': 1, 'category': 1}
        ).sort('opsec_score', 1).limit(80))
        return jsonify([serialize_doc(p) for p in pages])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/opsec_stats')
def opsec_stats():
    try:
        pipeline = [
            {'$match':  {'opsec_level': {'$exists': True}}},
            {'$group':  {'_id': '$opsec_level',
                         'count':     {'$sum': 1},
                         'avg_score': {'$avg': '$opsec_score'}}},
            {'$sort':   {'avg_score': 1}},
        ]
        dist = list(db.pages.aggregate(pipeline))
        for d in dist:
            d['avg_score'] = round(d.get('avg_score') or 0, 1)

        total_analyzed = db.pages.count_documents({'opsec_score': {'$exists': True}})
        critical       = db.pages.count_documents({'opsec_level': 'CRITICAL'})
        ip_leaked      = db.pages.count_documents(
            {'opsec_failures.ip_exposed': {'$exists': True, '$ne': []}}
        )
        with_tracking  = db.pages.count_documents(
            {'opsec_failures.tracking': {'$exists': True, '$ne': []}}
        )
        with_cdn       = db.pages.count_documents(
            {'opsec_failures.cdn_resources': {'$exists': True, '$ne': []}}
        )

        return jsonify({
            'distribution':    dist,
            'total_analyzed':  total_analyzed,
            'critical_count':  critical,
            'ip_leaked_count': ip_leaked,
            'tracking_count':  with_tracking,
            'cdn_count':       with_cdn,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Headers ──────────────────────────────────────────────────────────────

@app.route('/api/headers')
def headers():
    try:
        pages = list(db.pages.find(
            {'headers': {'$exists': True}},
            {'url': 1, 'title': 1, 'headers': 1, 'category': 1}
        ).limit(80))
        result = []
        for p in pages:
            h = p.get('headers', {})
            result.append({
                'title':          (p.get('title') or '')[:55],
                'url':            (p.get('url')   or '')[:75],
                'category':       p.get('category', ''),
                'server':         h.get('server_software'),
                'powered_by':     h.get('powered_by'),
                'cms':            h.get('cms_detected'),
                'cdn':            h.get('cdn_detected'),
                'ip_leaked':      h.get('ip_leaked', []),
                'etag':           h.get('etag'),
                'timezone':       h.get('timezone'),
                'security_score': h.get('security_score', 0),
                'fingerprint':    h.get('fingerprint_hash'),
                'tracking_cookies': h.get('tracking_cookies', []),
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/header_stats')
def header_stats():
    try:
        # Server distribution
        sv_pipeline = [
            {'$match':  {'headers.server_software': {'$exists': True, '$ne': None}}},
            {'$group':  {'_id': '$headers.server_software', 'count': {'$sum': 1}}},
            {'$sort':   {'count': -1}}, {'$limit': 10},
        ]
        servers = list(db.pages.aggregate(sv_pipeline))

        # ETag correlations
        etag_pipeline = [
            {'$match':  {'headers.etag_hash': {'$nin': [None, '', 'None']}}},
            {'$group':  {'_id': '$headers.etag_hash',
                         'count': {'$sum': 1},
                         'sites': {'$push': '$title'}}},
            {'$match':  {'count': {'$gt': 1}}},
            {'$sort':   {'count': -1}},
        ]
        etag_corrs = list(db.pages.aggregate(etag_pipeline))
        # Clean up None etag_ids
        etag_corrs = [e for e in etag_corrs if e.get('_id')]

        return jsonify({
            'servers':         servers,
            'etag_correlations': len(etag_corrs),
            'etag_details':    etag_corrs[:5],
            'total_with_headers': db.pages.count_documents(
                {'headers': {'$exists': True}}
            ),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: DNS Leakage ──────────────────────────────────────────────────────────

@app.route('/api/dns_leakage')
def dns_leakage():
    try:
        severity = request.args.get('severity')
        query    = {'dns_leak_severity': {'$exists': True}}
        if severity:
            query['dns_leak_severity'] = severity.upper()
        else:
            query['dns_leak_severity'] = {'$ne': 'NONE'}

        pages = list(db.pages.find(
            query,
            {'url': 1, 'title': 1, 'dns_leakage': 1,
             'dns_leak_severity': 1, 'dns_leak_score': 1, 'category': 1}
        ).sort('dns_leak_score', -1).limit(50))

        result = []
        for p in pages:
            leak = p.get('dns_leakage', {})
            result.append({
                'title':       (p.get('title') or '')[:55],
                'url':         (p.get('url')   or '')[:75],
                'category':    p.get('category', ''),
                'severity':    p.get('dns_leak_severity', 'NONE'),
                'score':       p.get('dns_leak_score', 0),
                'scripts':     len(leak.get('scripts', [])),
                'stylesheets': len(leak.get('stylesheets', [])),
                'images':      len(leak.get('images', [])),
                'iframes':     len(leak.get('iframes', [])),
                'forms':       len(leak.get('forms', [])),
                'domains':     leak.get('all_domains', [])[:6],
                'annotations': leak.get('annotations', {}),
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/dns_stats')
def dns_stats():
    try:
        pipeline = [
            {'$match':  {'dns_leak_severity': {'$exists': True}}},
            {'$group':  {'_id': '$dns_leak_severity',
                         'count': {'$sum': 1},
                         'avg':   {'$avg': '$dns_leak_score'}}},
            {'$sort':   {'avg': -1}},
        ]
        dist = list(db.pages.aggregate(pipeline))

        domain_pipeline = [
            {'$match':  {'dns_leakage.all_domains': {'$exists': True, '$ne': []}}},
            {'$unwind': '$dns_leakage.all_domains'},
            {'$group':  {'_id': '$dns_leakage.all_domains', 'count': {'$sum': 1}}},
            {'$sort':   {'count': -1}}, {'$limit': 10},
        ]
        top_domains = list(db.pages.aggregate(domain_pipeline))

        return jsonify({
            'distribution': dist,
            'top_domains':  top_domains,
            'total_with_leaks': db.pages.count_documents(
                {'dns_leak_severity': {'$nin': ['NONE', None]}}
            ),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Identity Correlations ────────────────────────────────────────────────

@app.route('/api/identities')
def identities():
    try:
        matched_only = request.args.get('matched', 'true').lower() == 'true'
        query = {'clearnet': {'$ne': [], '$exists': True}} if matched_only else {}

        corrs = list(db.identity_correlations.find(
            query,
            {'username': 1, 'clearnet': 1, 'analyzed_at': 1, 'source': 1}
        ).sort('analyzed_at', -1).limit(60))
        return jsonify([serialize_doc(c) for c in corrs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Link Graph ───────────────────────────────────────────────────────────

@app.route('/api/graph')
def graph():
    try:
        if os.path.exists(GRAPH_JSON):
            with open(GRAPH_JSON, 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
        return jsonify({
            'nodes': [], 'links': [],
            'metadata': {'message': 'Run link_graph.py to generate graph data'}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/graph_stats')
def graph_stats():
    try:
        with_pr    = db.pages.count_documents({'pagerank_score': {'$exists': True}})
        top_pr     = list(db.pages.find(
            {'pagerank_score': {'$exists': True}},
            {'title': 1, 'url': 1, 'category': 1, 'pagerank_score': 1}
        ).sort('pagerank_score', -1).limit(10))

        return jsonify({
            'pages_with_pagerank': with_pr,
            'top_pagerank':        [serialize_doc(p) for p in top_pr],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Uptime ───────────────────────────────────────────────────────────────

@app.route('/api/uptime')
def uptime():
    try:
        pages = list(db.pages.find(
            {'uptime_pct': {'$exists': True}},
            {'url': 1, 'title': 1, 'domain': 1, 'category': 1,
             'uptime_pct': 1, 'avg_response_ms': 1, 'uptime_checks': 1}
        ).sort('uptime_pct', -1).limit(60))
        return jsonify([serialize_doc(p) for p in pages])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/uptime_stats')
def uptime_stats():
    try:
        total_logs  = db.uptime_logs.count_documents({})
        online_logs = db.uptime_logs.count_documents({'is_online': True})
        overall_pct = round(online_logs / total_logs * 100, 1) if total_logs > 0 else 0

        # Recent 24h logs
        cutoff   = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
        recent   = db.uptime_logs.count_documents({'checked_at': {'$gte': cutoff}})
        recent_on= db.uptime_logs.count_documents(
            {'checked_at': {'$gte': cutoff}, 'is_online': True}
        )

        # Average response time
        pipeline = [
            {'$match':  {'is_online': True, 'response_ms': {'$gt': 0}}},
            {'$group':  {'_id': None, 'avg_ms': {'$avg': '$response_ms'}}},
        ]
        avg_result = list(db.uptime_logs.aggregate(pipeline))
        avg_ms     = round(avg_result[0]['avg_ms']) if avg_result else 0

        return jsonify({
            'total_checks':   total_logs,
            'overall_pct':    overall_pct,
            'avg_response_ms':avg_ms,
            'recent_24h':     recent,
            'recent_24h_pct': round(recent_on / recent * 100, 1) if recent > 0 else 0,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/uptime_history')
def uptime_history():
    """Return uptime log history for a specific domain."""
    try:
        domain = request.args.get('domain', '')
        if not domain:
            return jsonify([])
        logs = list(db.uptime_logs.find(
            {'domain': domain},
            {'checked_at': 1, 'is_online': 1, 'response_ms': 1, 'status_code': 1}
        ).sort('checked_at', -1).limit(50))
        return jsonify([serialize_doc(l) for l in logs])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: Clusters ─────────────────────────────────────────────────────────────

@app.route('/api/clusters')
def clusters():
    try:
        pipeline = [
            {'$match':  {'cluster_id': {'$exists': True}}},
            {'$group':  {
                '_id':       '$cluster_id',
                'size':      {'$sum': 1},          # count members directly
                'is_mirror': {'$first': '$is_mirror'},
                'pages':     {'$push': {
                    'title':    '$title',
                    'url':      '$url',
                    'category': '$category',
                }},
            }},
            {'$sort':  {'size': -1}},
            {'$limit': 50},
        ]
        result = list(db.pages.aggregate(pipeline))
        all_ids = db.pages.distinct('cluster_id')
        mirror_count = sum(1 for r in result if r.get('size', 0) > 1)
        return jsonify({
            'total_clusters':  len(all_ids),
            'mirror_clusters': mirror_count,
            'clusters':        result[:30],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── API: STIX Export ──────────────────────────────────────────────────────────

@app.route('/api/export/stix')
def export_stix():
    """Trigger STIX 2.1 export and return download link."""
    try:
        from stix_export import run_stix_export

        category = request.args.get('category')
        flagged  = request.args.get('flagged', 'false').lower() == 'true'

        output_path = run_stix_export(
            category_filter=category,
            flagged_only=flagged
        )

        if output_path and os.path.exists(output_path):
            return send_file(
                output_path,
                mimetype='application/json',
                as_attachment=True,
                download_name=os.path.basename(output_path)
            )
        return jsonify({'error': 'Export failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Startup ───────────────────────────────────────────────────────────────────

def start_uptime_monitor():
    """Start uptime monitor background thread."""
    try:
        from uptime_monitor import run_as_background_thread
        thread = run_as_background_thread(interval=60)
        print(f"  ✓ Uptime monitor started (checks every 60 min)")
        return thread
    except Exception as e:
        print(f"  ⚠ Uptime monitor failed to start: {e}")
        return None


if __name__ == '__main__':
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    os.makedirs(EXPORTS_DIR, exist_ok=True)

    print("\n" + "═"*60)
    print("  DARK WEB INTELLIGENCE PLATFORM")
    print("  Dashboard: http://localhost:5000")
    print("═"*60)

    ensure_indexes()

    # Start background uptime monitoring
    monitor_thread = start_uptime_monitor()

    print(f"  MongoDB: {MONGO_URI}{DB_NAME}")
    print(f"  Total pages: {db.pages.count_documents({})}")
    print(f"  Starting Flask server...")
    print("═"*60 + "\n")

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG, threaded=True)