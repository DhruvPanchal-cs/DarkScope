"""
classifier.py — ML Classifier + Content Similarity Clustering
==============================================================
Run after crawler.py and nlp_pipeline.py.

Features:
  - Rule-based auto-labeling (7 threat categories)
  - TF-IDF + Logistic Regression classifier
  - Saves model.pkl + vectorizer.pkl
  - Content similarity clustering via cosine distance
    (detects mirror sites and duplicate content)
  - Cluster labels stored back to MongoDB

Categories (threat-priority order):
  hacking, drugs, fraud, crypto, privacy, news, search_index,
  forum, other

Usage:
    python classifier.py
    python classifier.py --reclassify   (reclassify all pages)
    python classifier.py --cluster-only (only run clustering)
"""

import os
import datetime
import argparse
from collections import Counter

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import normalize as sk_normalize
from pymongo import MongoClient
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

from config import MONGO_URI, DB_NAME, TFIDF_MAX_FEATURES, SIMILARITY_THRESHOLD, MIN_TEXT_LENGTH, MODEL_PATH, VECTORIZER_PATH
MODEL_PATH      = str(MODEL_PATH)
VECTORIZER_PATH = str(VECTORIZER_PATH)
MODEL_PATH     = 'model.pkl'
VECTORIZER_PATH= 'vectorizer.pkl'

# TF-IDF settings
TFIDF_MAX_FEATURES = 5000
TFIDF_NGRAM_RANGE  = (1, 2)
TFIDF_MIN_DF       = 1        # include terms that appear in at least 1 doc

# Clustering settings
SIMILARITY_THRESHOLD = 0.85   # cosine similarity >= this = same cluster
MIN_TEXT_LENGTH      = 50     # skip pages shorter than this

# Categories in threat-priority order
CATEGORIES = [
    'hacking', 'drugs', 'fraud', 'crypto',
    'privacy', 'news', 'search_index', 'forum', 'other'
]

# ── MongoDB ───────────────────────────────────────────────────────────────────

client = MongoClient(MONGO_URI)
db     = client[DB_NAME]

# ── Auto-Labeling (Rule-Based) ────────────────────────────────────────────────

def auto_label(page: dict) -> str:
    """
    Assign a threat category to a page using keyword rules.
    Checked in priority order — most dangerous first.
    This provides training labels for the ML model.
    """
    text  = page.get('text',  '') or ''
    title = page.get('title', '') or ''
    combined = (text + ' ' + title).lower()

    # Priority 1 — Hacking / Cybercrime (highest threat)
    if any(w in combined for w in [
        'exploit', 'malware', 'ransomware', 'vulnerability', 'zero-day',
        'cve-', 'rootkit', 'keylogger', 'botnet', 'backdoor', 'trojan',
        'ddos', 'phishing', 'hack', 'breach', 'leaked database',
        'stealer', 'infostealer', 'rat ', 'remote access', 'cracking',
        'combolist', 'fullz', 'doxing', 'sql injection', 'xss attack',
    ]):
        return 'hacking'

    # Priority 2 — Drugs
    if any(w in combined for w in [
        'drug', 'weed', 'cannabis', 'cocaine', 'heroin', 'methamphetamine',
        'meth', 'ketamine', 'mdma', 'lsd', 'pills', 'pharmacy',
        'opioid', 'fentanyl', 'amphetamine', 'narcotics', 'vendor',
    ]):
        return 'drugs'

    # Priority 3 — Fraud / Illegal Goods
    if any(w in combined for w in [
        'counterfeit', 'fake id', 'fake passport', 'forged document',
        'stolen card', 'credit card dump', 'cvv', 'carding', 'cloned',
        'gun', 'weapon', 'firearm', 'ammunition', 'fraud', 'scam',
        'money laundering', 'wire fraud', 'identity theft',
    ]):
        return 'fraud'

    # Priority 4 — Cryptocurrency / Finance
    if any(w in combined for w in [
        'bitcoin', 'monero', 'ethereum', 'crypto', 'blockchain',
        'btc', 'wallet', 'cryptocurrency', 'wasabi', 'coin mixer',
        'tumbler', 'defi', 'nft', 'exchange', 'trading',
    ]):
        return 'crypto'

    # Priority 5 — Privacy / Security Tools
    if any(w in combined for w in [
        'privacy', 'anonymous', 'anonymity', 'vpn', 'encryption',
        'pgp', 'opsec', 'operational security', 'tor browser',
        'onionshare', 'protonmail', 'riseup', 'signal', 'tails',
        'whonix', 'secure email', 'end-to-end', 'mullvad', 'njalla',
    ]):
        return 'privacy'

    # Priority 6 — News / Journalism
    if any(w in combined for w in [
        'news', 'journalist', 'journalism', 'reporter', 'article',
        'bbc', 'nytimes', 'new york times', 'media', 'press release',
        'breaking news', 'investigation', 'whistleblow', 'securedrop',
        'intercept', 'propublica',
    ]):
        return 'news'

    # Priority 7 — Search Engines / Directories / Indexes
    if any(w in combined for w in [
        'search engine', 'directory', 'index', 'hidden wiki', 'ahmia',
        'torch', 'haystak', 'onion links', 'link list', 'catalog',
        'torlinks', 'dark.fail', 'not evil', 'excavator',
    ]):
        return 'search_index'

    # Priority 8 — Forums / Communities
    if any(w in combined for w in [
        'forum', 'thread', 'board', 'post', 'reply', 'community',
        'discussion', 'dread', 'endchan', 'torum', 'topic',
        'subreddit', 'subforum', 'members', 'registered users',
    ]):
        return 'forum'

    return 'other'


# ── Classifier Training ───────────────────────────────────────────────────────

def train_classifier(reclassify: bool = False):
    """
    Train TF-IDF + Logistic Regression on all pages in MongoDB.
    Labels are assigned via auto_label() rule-based function.
    """
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  STEP 1 — Loading & Labeling Pages{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")

    pages = list(db.pages.find(
        {'text': {'$exists': True}},
        {'_id': 1, 'text': 1, 'title': 1}
    ))
    print(f"  Total pages in DB: {len(pages)}")

    if len(pages) < 5:
        print(f"  {Fore.RED}✗ Need at least 5 pages to train. Run crawler.py first.{Style.RESET_ALL}")
        return None, None

    texts, labels, ids = [], [], []

    for p in pages:
        text  = p.get('text',  '') or ''
        title = p.get('title', '') or ''
        if len(text) < MIN_TEXT_LENGTH:
            continue
        label = auto_label(p)
        full_text = title + ' ' + text
        texts.append(full_text)
        labels.append(label)
        ids.append(p['_id'])

        # Store rule-based label immediately
        db.pages.update_one(
            {'_id': p['_id']},
            {'$set': {'category': label}}
        )

    print(f"  Labeled pages    : {len(texts)}")
    print(f"\n  Label distribution (threat-priority order):")
    counts = Counter(labels)
    for cat in CATEGORIES:
        if cat in counts:
            bar = '█' * min(counts[cat], 40)
            print(f"    {Fore.CYAN}{cat:<15}{Style.RESET_ALL} {bar} ({counts[cat]})")

    # Need at least 2 classes to train
    unique_classes = len(set(labels))
    if unique_classes < 2:
        print(f"\n  {Fore.YELLOW}⚠ Only 1 class found — skipping ML training.{Style.RESET_ALL}")
        print(f"    Crawl more diverse pages for multi-class training.")
        return None, None

    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  STEP 2 — Training TF-IDF + Logistic Regression{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"  Features    : {TFIDF_MAX_FEATURES} (n-grams {TFIDF_NGRAM_RANGE})")
    print(f"  Algorithm   : Logistic Regression (balanced class weights)")
    print(f"  Training on : {len(texts)} pages\n")

    # Build TF-IDF matrix
    vectorizer = TfidfVectorizer(
        max_features=TFIDF_MAX_FEATURES,
        stop_words='english',
        ngram_range=TFIDF_NGRAM_RANGE,
        min_df=TFIDF_MIN_DF,
        sublinear_tf=True,        # log(tf) scaling — better for long docs
    )
    X = vectorizer.fit_transform(texts)

    # Train classifier
    model = LogisticRegression(
        max_iter=1000,
        class_weight='balanced',  # handles class imbalance
        C=1.0,
        solver='lbfgs',
        multi_class='multinomial',
    )
    model.fit(X, labels)

    # Training accuracy
    y_pred     = model.predict(X)
    train_acc  = accuracy_score(labels, y_pred)
    print(f"  {Fore.GREEN}✓ Model trained!{Style.RESET_ALL}")
    print(f"  Training accuracy: {Fore.CYAN}{train_acc*100:.1f}%{Style.RESET_ALL}")
    print(f"\n  Classification Report:")
    print(f"  {'─'*50}")
    report = classification_report(labels, y_pred, zero_division=0, target_names=sorted(set(labels)))
    for line in report.split('\n'):
        print(f"  {line}")

    # Save model and vectorizer
    joblib.dump(model,      MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"\n  {Fore.GREEN}✓ Saved: {MODEL_PATH} + {VECTORIZER_PATH}{Style.RESET_ALL}")

    # ── Apply model to all pages ───────────────────────────────
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  STEP 3 — Classifying All Pages{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")

    classified = 0
    for page in db.pages.find({'text': {'$exists': True}}, {'_id': 1, 'text': 1, 'title': 1}):
        text  = page.get('text',  '') or ''
        title = page.get('title', '') or ''
        full  = title + ' ' + text
        if len(full.strip()) < MIN_TEXT_LENGTH:
            continue
        try:
            vec   = vectorizer.transform([full])
            cat   = model.predict(vec)[0]
            proba = model.predict_proba(vec)[0]
            conf  = round(float(max(proba)) * 100, 1)
            db.pages.update_one(
                {'_id': page['_id']},
                {'$set': {'category': cat, 'confidence': conf}}
            )
            classified += 1
        except Exception:
            continue

    print(f"  {Fore.GREEN}✓ Classified {classified} pages{Style.RESET_ALL}")
    print(f"\n  Final breakdown:")
    print(f"  {'CATEGORY':<18} {'COUNT':>6}  {'AVG CONF':>10}")
    print(f"  {'─'*38}")
    pipeline = [
        {'$match':  {'category': {'$exists': True}}},
        {'$group':  {'_id': '$category',
                     'count': {'$sum': 1},
                     'avg':   {'$avg': '$confidence'}}},
        {'$sort':   {'count': -1}},
    ]
    for r in db.pages.aggregate(pipeline):
        avg = round(r.get('avg') or 0, 1)
        print(f"  {r['_id']:<18} {r['count']:>6}  {avg:>9}%")

    return model, vectorizer


# ── Content Similarity Clustering ─────────────────────────────────────────────

def run_clustering(vectorizer=None):
    """
    Group pages by content similarity using cosine distance on TF-IDF vectors.

    Algorithm:
      1. Compute TF-IDF matrix for all pages
      2. L2-normalize vectors (cosine similarity = dot product after normalization)
      3. Greedy clustering: assign page to existing cluster if similarity
         >= SIMILARITY_THRESHOLD with cluster centroid, else create new cluster
      4. Store cluster_id and cluster_label back to MongoDB

    Research value: Reveals mirror sites and copied/rehosted content.
    """
    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  CONTENT SIMILARITY CLUSTERING{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Similarity threshold: {SIMILARITY_THRESHOLD}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")

    # Load vectorizer — use existing or load from file
    if vectorizer is None:
        if os.path.exists(VECTORIZER_PATH):
            vectorizer = joblib.load(VECTORIZER_PATH)
            print(f"  Loaded vectorizer from {VECTORIZER_PATH}")
        else:
            print(f"  {Fore.RED}✗ No vectorizer found. Run classifier first (without --cluster-only).{Style.RESET_ALL}")
            return

    # Load all pages with text
    pages = list(db.pages.find(
        {'text': {'$exists': True}},
        {'_id': 1, 'title': 1, 'text': 1, 'domain': 1, 'category': 1}
    ))

    if len(pages) < 2:
        print(f"  {Fore.YELLOW}⚠ Need at least 2 pages for clustering.{Style.RESET_ALL}")
        return

    print(f"  Pages to cluster: {len(pages)}")

    # Build text corpus
    corpus  = []
    page_ids= []
    for p in pages:
        text = (p.get('title', '') or '') + ' ' + (p.get('text', '') or '')
        if len(text.strip()) >= MIN_TEXT_LENGTH:
            corpus.append(text)
            page_ids.append(p['_id'])

    if len(corpus) < 2:
        print(f"  {Fore.YELLOW}⚠ Not enough valid text content for clustering.{Style.RESET_ALL}")
        return

    # TF-IDF transform and L2 normalize
    print(f"  Building TF-IDF matrix for {len(corpus)} pages...")
    try:
        X        = vectorizer.transform(corpus)
        X_normed = sk_normalize(X, norm='l2')  # enables cosine sim = dot product
    except Exception as e:
        print(f"  {Fore.RED}✗ Vectorization failed: {e}{Style.RESET_ALL}")
        return

    # Convert to dense for efficient dot product
    # Use chunks if memory is a concern (for very large datasets)
    X_dense = X_normed.toarray()

    print(f"  Running greedy cosine clustering...")

    # Greedy clustering
    clusters          = []   # list of {centroid, member_ids, member_indices}
    page_cluster_map  = {}   # page_id -> cluster_id

    for idx, vec in enumerate(X_dense):
        best_cluster  = -1
        best_sim      = 0.0

        for c_idx, cluster in enumerate(clusters):
            # Cosine similarity = dot product (already L2 normalized)
            sim = float(np.dot(cluster['centroid'], vec))
            if sim > best_sim:
                best_sim     = sim
                best_cluster = c_idx

        if best_sim >= SIMILARITY_THRESHOLD:
            # Add to existing cluster — update centroid (running mean)
            clusters[best_cluster]['member_ids'].append(page_ids[idx])
            clusters[best_cluster]['member_indices'].append(idx)
            n = len(clusters[best_cluster]['member_ids'])
            # Incremental centroid update
            old_c = clusters[best_cluster]['centroid']
            new_c = old_c + (vec - old_c) / n
            # Re-normalize centroid
            norm  = np.linalg.norm(new_c)
            clusters[best_cluster]['centroid'] = new_c / norm if norm > 0 else new_c
            page_cluster_map[page_ids[idx]] = best_cluster
        else:
            # Create new cluster
            new_id = len(clusters)
            clusters.append({
                'centroid':       vec.copy(),
                'member_ids':     [page_ids[idx]],
                'member_indices': [idx],
            })
            page_cluster_map[page_ids[idx]] = new_id

    print(f"  {Fore.GREEN}✓ Found {len(clusters)} content clusters{Style.RESET_ALL}")

    # Identify mirror/duplicate clusters (2+ pages, same cluster)
    mirror_clusters = [c for c in clusters if len(c['member_ids']) > 1]
    print(f"  Mirror/duplicate clusters: {len(mirror_clusters)}")

    # Write cluster assignments back to MongoDB
    updated = 0
    for c_idx, cluster in enumerate(clusters):
        size       = len(cluster['member_ids'])
        is_mirror  = size > 1
        label      = f"cluster_{c_idx:04d}"

        for pid in cluster['member_ids']:
            try:
                db.pages.update_one(
                    {'_id': pid},
                    {'$set': {
                        'cluster_id':    c_idx,
                        'cluster_label': label,
                        'cluster_size':  size,
                        'is_mirror':     is_mirror,
                    }}
                )
                updated += 1
            except Exception:
                continue

    print(f"  {Fore.GREEN}✓ Updated {updated} pages with cluster assignments{Style.RESET_ALL}")

    # Print top mirror clusters
    if mirror_clusters:
        print(f"\n  {Fore.YELLOW}Top Mirror/Duplicate Site Clusters:{Style.RESET_ALL}")
        mirror_clusters.sort(key=lambda x: -len(x['member_ids']))
        for i, c in enumerate(mirror_clusters[:10]):
            print(f"    Cluster {i}: {len(c['member_ids'])} similar pages")
            # Show titles of member pages
            for pid in c['member_ids'][:3]:
                page = db.pages.find_one({'_id': pid}, {'title': 1, 'url': 1})
                if page:
                    title = (page.get('title') or 'No Title')[:45]
                    url   = (page.get('url')   or '')[:50]
                    print(f"        • {title}")
                    print(f"          {Fore.BLUE}{url}{Style.RESET_ALL}")

    # Store cluster summary in MongoDB
    try:
        db.cluster_summary.drop()
        cluster_docs = []
        for c_idx, cluster in enumerate(clusters):
            cluster_docs.append({
                'cluster_id':   c_idx,
                'size':         len(cluster['member_ids']),
                'is_mirror':    len(cluster['member_ids']) > 1,
                'member_count': len(cluster['member_ids']),
            })
        if cluster_docs:
            db.cluster_summary.insert_many(cluster_docs)
    except Exception:
        pass

    print(f"\n  {Fore.CYAN}Clustering Summary:{Style.RESET_ALL}")
    print(f"    Total clusters   : {len(clusters)}")
    print(f"    Mirror clusters  : {len(mirror_clusters)}")
    singleton = len(clusters) - len(mirror_clusters)
    print(f"    Unique pages     : {singleton}")
    print(f"    Threshold used   : {SIMILARITY_THRESHOLD} cosine similarity")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dark Web ML Classifier + Clustering')
    parser.add_argument('--reclassify',   action='store_true',
                        help='Reclassify all pages (including already classified)')
    parser.add_argument('--cluster-only', action='store_true',
                        help='Only run clustering (skip classifier training)')
    args = parser.parse_args()

    if args.cluster_only:
        print(f"\n{Fore.CYAN}  CLUSTER-ONLY MODE{Style.RESET_ALL}")
        run_clustering()
    else:
        model, vectorizer = train_classifier(reclassify=args.reclassify)
        print(f"\n")
        run_clustering(vectorizer=vectorizer)

    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  ALL DONE — Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")