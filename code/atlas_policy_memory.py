"""Optional Atlas policy retrieval. Stores policy rules only, never user evidence.

Usage from repository root:
  python code/atlas_policy_memory.py ingest
  python code/atlas_policy_memory.py search "shared support conversation"
"""
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / 'dataset' / 'deletion_rules.csv'
DB_NAME = 'ghosttrace'
COLLECTION_NAME = 'policy_memory'
INDEX_NAME = 'policy_vector_idx'
EMBED_MODEL = os.getenv('GHOSTTRACE_EMBED_MODEL', 'nomic-embed-text')
OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://127.0.0.1:11434').rstrip('/')


def embed(text):
    req = urllib.request.Request(
        OLLAMA_HOST + '/api/embed',
        data=json.dumps({'model': EMBED_MODEL, 'input': text}).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError('Ollama embedding error: ' + exc.read().decode('utf-8', 'replace')) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Ollama connection failed: {exc.reason}') from exc
    vectors = data.get('embeddings')
    if not isinstance(vectors, list) or not vectors or not vectors[0]:
        raise RuntimeError('Ollama returned no embeddings')
    return [float(v) for v in vectors[0]]


def collection():
    uri = os.getenv('MONGODB_URI')
    if not uri:
        raise RuntimeError('Set MONGODB_URI as an environment variable; never commit it.')
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise RuntimeError('Install PyMongo: python -m pip install pymongo dnspython') from exc
    client = MongoClient(uri, serverSelectionTimeoutMS=15000)
    client.admin.command('ping')
    return client[DB_NAME][COLLECTION_NAME]


def policy_text(rule):
    return ('Data category: ' + rule['data_category'] + '. Condition: ' +
            rule['condition'] + '. Required action: ' + rule['required_action'] + '.')


def ingest():
    if not RULES_FILE.exists():
        raise RuntimeError(f'Missing dataset file: {RULES_FILE}')
    with RULES_FILE.open(newline='', encoding='utf-8-sig') as fp:
        rules = list(csv.DictReader(fp))
    coll = collection()
    coll.create_index('rule_id', unique=True)
    dimensions = None
    for rule in rules:
        fields = {k: rule[k] for k in ('rule_id', 'data_category', 'condition', 'required_action')}
        text = policy_text(fields)
        vector = embed(text)
        if dimensions is None:
            dimensions = len(vector)
        elif len(vector) != dimensions:
            raise RuntimeError('Embedding dimensions changed during import')
        coll.update_one(
            {'rule_id': rule['rule_id']},
            {'$set': {**fields, 'text': text, 'embedding': vector, 'embedding_model': EMBED_MODEL}},
            upsert=True,
        )
    if not rules:
        raise RuntimeError('No policy rules found')
    from pymongo.operations import SearchIndexModel
    existing = {x['name'] for x in coll.list_search_indexes()}
    if INDEX_NAME not in existing:
        idx = SearchIndexModel(
            definition={'fields': [
                {'type': 'vector', 'path': 'embedding', 'numDimensions': dimensions, 'similarity': 'cosine'},
            ]},
            name=INDEX_NAME,
            type='vectorSearch',
        )
        coll.create_search_index(model=idx)
    print(f'Upserted {len(rules)} policy rules. Vector dimensions: {dimensions}.')
    print('Atlas index builds asynchronously. Search may need a subsequent retry.')


def search(query, limit):
    if not query.strip():
        raise RuntimeError('Search query cannot be empty')
    coll = collection()
    vector = embed(query)
    pipeline = [
        {'$vectorSearch': {
            'index': INDEX_NAME,
            'path': 'embedding',
            'queryVector': vector,
            'numCandidates': max(50, limit * 10),
            'limit': limit,
        }},
        {'$project': {'_id': 0, 'rule_id': 1, 'data_category': 1,
                      'condition': 1, 'required_action': 1,
                      'score': {'$meta': 'vectorSearchScore'}}},
    ]
    for hit in coll.aggregate(pipeline):
        print(json.dumps(hit, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['ingest', 'search'])
    parser.add_argument('query', nargs='?', default='')
    parser.add_argument('--limit', type=int, default=3)
    args = parser.parse_args()
    if args.command == 'ingest':
        ingest()
    else:
        search(args.query, max(1, min(10, args.limit)))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Atlas policy memory error: {exc}', file=sys.stderr)
        sys.exit(1)
