"""Optional Atlas -> exact policy match -> Gemma advisory workflow.

Does not update MongoDB, deletion verdicts, or output.csv. Run from repo root:
 python code/atlas_gemma_workflow.py --query 'shared customer support conversation' --category SUPPORT_MESSAGE --facts-file policy_facts.json
"""
import argparse
import json
import sys
from pathlib import Path

from atlas_policy_memory import collection, embed, INDEX_NAME
from gemma_agent import interpret


def retrieve_policies(query, limit=5):
    """Retrieve candidates. Similarity scores are NOT applicability decisions."""
    if not isinstance(query, str) or not query.strip() or len(query) > 500:
        raise ValueError('Query must contain 1-500 characters')
    limit = max(1, min(10, int(limit)))
    db = collection()
    pipeline = [
        {'$vectorSearch': {'index': INDEX_NAME, 'path': 'embedding',
                           'queryVector': embed(query), 'numCandidates': max(50, limit * 10),
                           'limit': limit}},
        {'$project': {'_id': 0, 'rule_id': 1, 'data_category': 1,
                      'condition': 1, 'required_action': 1,
                      'score': {'$meta': 'vectorSearchScore'}}},
    ]
    return list(db.aggregate(pipeline))


def select_authoritative_rule(candidates, category, exact_rule=None):
    """Reject vector ranking as a substitute for exact policy identification."""
    if not category or not isinstance(category, str):
        raise ValueError('Supply a known exact data category')
    matches = [hit for hit in candidates if hit.get('data_category') == category
               and (exact_rule is None or hit.get('rule_id') == exact_rule)]
    if len(matches) != 1:
        raise ValueError(f'Found {len(matches)} matching retrieved rules for {category}; '
                         'refusing to choose from similarity scores. '
                         'Use an exact rule ID or review the dataset rules.')
    rule = {key: matches[0][key] for key in
            ('rule_id', 'data_category', 'condition', 'required_action')}
    return rule


def sanitized_facts(facts):
    if not isinstance(facts, dict) or not facts:
        raise ValueError('Supply a nonempty JSON object of non-sensitive facts')
    allowed = {'YES', 'NO', 'UNKNOWN', 'ACTIVE', 'INACTIVE'}
    if any(not isinstance(k, str) or not k.isidentifier() or len(k) > 70
           for k in facts):
        raise ValueError('Fact keys must be short identifiers')
    for value in facts.values():
        if type(value) not in (bool, int, float) and not (type(value) is str and value in allowed):
            raise ValueError('Only boolean, numeric and approved enum facts allowed; no raw user information')
    return facts


def run(query, category, facts, model='gemma3:4b', rule_id=None):
    facts = sanitized_facts(facts)
    candidates = retrieve_policies(query)
    rule = select_authoritative_rule(candidates, category, exact_rule=rule_id)
    advisory = interpret(rule, facts, model=model)
    return {
        'retrieval': {'query': query, 'matched_rule_id': rule['rule_id'],
                      'matched_category': rule['data_category'],
                      'candidate_rule_ids': [hit.get('rule_id') for hit in candidates],
                      'selection_method': 'EXACT_DATA_CATEGORY_AND_OPTIONAL_RULE_ID'},
        'policy': rule,
        'gemma': advisory,
        'audit_impact': 'NONE: advisory only; existing deterministic output unchanged',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--query', required=True, help='Generic, non-PII policy search query')
    parser.add_argument('--category', required=True, help='Exact policy data_category')
    parser.add_argument('--rule-id', help='Optional exact rule ID')
    parser.add_argument('--facts-file', type=Path, required=True,
                        help='Local JSON file containing sanitized factual flags')
    parser.add_argument('--model', default='gemma3:4b')
    args = parser.parse_args()
    try:
        facts = json.loads(args.facts_file.read_text(encoding='utf-8'))
        report = run(args.query, args.category, facts, args.model, args.rule_id)
        print(json.dumps(report, indent=2, ensure_ascii=False))
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        print(f'Atlas-Gemma integration failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
