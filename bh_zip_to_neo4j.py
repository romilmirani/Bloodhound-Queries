#!/usr/bin/env python3
"""
bh_zip_to_neo4j.py

Usage:
    python3 bh_zip_to_neo4j.py --zip /path/to/bloodhound.zip \
        --uri bolt://127.0.0.1:7687 --user neo4j --password secret \
        [--no-clear] [--batch 500]

Notes:
 - Requires: pip install neo4j
 - The script expects nodes.json and relationships.json in the zip (or filenames containing 'nodes'/'relationships').
 - It stores the original BloodHound node id in node property `_bh_id`.
 - Labels are sanitized to [A-Za-z0-9_]. Non-conforming labels will be ignored.
"""

import argparse
import json
import zipfile
from neo4j import GraphDatabase, basic_auth
import re
import sys
from pathlib import Path
from time import time

# --- Configurable defaults ---
DEFAULT_BATCH = 500

# --- Helpers ---
_LABEL_SAFE_RE = re.compile(r'[^A-Za-z0-9_]')

def sanitize_label(lbl: str) -> str:
    """Return a safe label (alphanumeric + underscore). If nothing left, return None."""
    safe = _LABEL_SAFE_RE.sub('', lbl)
    return safe if safe else None

def find_json_in_zip(z: zipfile.ZipFile, key_substr: str):
    """Return name of file in zip where key_substr is in filename (case-insensitive), or None."""
    for name in z.namelist():
        if key_substr.lower() in name.lower() and name.lower().endswith('.json'):
            return name
    return None

def load_json_from_zip(zippath: str, which: str):
    """which should be 'nodes' or 'relationships'"""
    with zipfile.ZipFile(zippath, 'r') as z:
        fname = find_json_in_zip(z, which)
        if not fname:
            raise FileNotFoundError(f"Could not find a JSON file containing '{which}' in {zippath}")
        with z.open(fname) as f:
            data = json.load(f)
            return data

# --- Neo4j operations ---
class Neo4jLoader:
    def __init__(self, uri, user, password, encrypted=False):
        self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
    def close(self):
        if self.driver:
            self.driver.close()

    def clear_db(self):
        with self.driver.session() as s:
            s.run("MATCH (n) DETACH DELETE n")

    def create_node_with_labels(self, tx, labels, props):
        """
        Creates a single node with provided labels and properties.
        labels: list of sanitized label strings (may be empty)
        props: dict
        """
        # Build label portion of cypher text (labels are trusted after sanitize)
        label_str = ":" + ":".join(labels) if labels else ""
        # Use parameterized props
        cypher = f"CREATE (n{label_str} $props) RETURN id(n) as created_id"
        return tx.run(cypher, props=props).single().get('created_id')

    def create_nodes_batch(self, records):
        """
        records: list of dicts like {'labels': [...], 'props': {...}, 'bh_id': 123}
        We'll create nodes one-by-one within a transaction to avoid dynamic label injection complexity in UNWIND.
        """
        created = 0
        with self.driver.session() as s:
            def work(tx):
                nonlocal created
                for r in records:
                    labels = r['labels']
                    props = r['props']
                    created_id = self.create_node_with_labels(tx, labels, props)
                    created += 1
            s.write_transaction(work)
        return created

    def create_relationships_batch(self, rels):
        """
        rels: list of dicts: {'type': 'MemberOf', 'source': source_bh_id, 'target': target_bh_id, 'props': {...}}
        We'll MATCH nodes by _bh_id and create relationships.
        """
        created = 0
        with self.driver.session() as s:
            def work(tx):
                nonlocal created
                for r in rels:
                    cypher = (
                        "MATCH (a {_bh_id: $src}), (b {_bh_id: $tgt}) "
                        f"CREATE (a)-[rel:`{r['type']}`]->(b) "
                        "SET rel += $props "
                        "RETURN id(rel) as rid"
                    )
                    # run and ignore if match not found
                    res = tx.run(cypher, src=r['source'], tgt=r['target'], props=r['props'] or {})
                    row = res.single()
                    if row:
                        created += 1
            s.write_transaction(work)
        return created

# --- Main import logic ---
def import_bloodhound_zip_to_neo4j(zip_path, uri, user, password, clear=True, batch_size=DEFAULT_BATCH):
    start = time()
    print(f"[+] Opening {zip_path} ...")
    nodes = load_json_from_zip(zip_path, 'nodes')
    rels = load_json_from_zip(zip_path, 'relationships')
    print(f"[+] Found {len(nodes)} nodes and {len(rels)} relationships in the zip.")

    loader = Neo4jLoader(uri, user, password)
    try:
        if clear:
            print("[+] Clearing database (MATCH (n) DETACH DELETE n)...")
            loader.clear_db()
            print("[+] Database cleared.")

        # Prepare node records
        node_records = []
        for n in nodes:
            # BloodHound node typical structure: { "id": 123, "labels": ["User"], "properties": {...} }
            bh_id = n.get('id') or n.get('Id') or n.get('nodeId') or None
            labels_raw = n.get('labels') or n.get('Label') or []
            props = n.get('properties') or n.get('Properties') or {}
            # store original id also in props as _bh_id so relationships can match
            props = dict(props)  # copy to avoid modifying original
            props['_bh_id'] = bh_id
            # sanitize labels
            labels = [sanitize_label(lbl) for lbl in labels_raw if sanitize_label(lbl)]
            node_records.append({'labels': labels, 'props': props, 'bh_id': bh_id})

        # Insert nodes in batches
        print("[+] Creating nodes in batches ...")
        total_created_nodes = 0
        for i in range(0, len(node_records), batch_size):
            batch = node_records[i:i+batch_size]
            created = loader.create_nodes_batch(batch)
            total_created_nodes += created
            print(f"    created nodes: {total_created_nodes}/{len(node_records)}")

        # Prepare relationships
        rel_records = []
        for r in rels:
            # typical: { "source": 123, "target": 456, "type": "MemberOf", "properties": {} }
            src = r.get('source') or r.get('Source') or r.get('start') or None
            tgt = r.get('target') or r.get('Target') or r.get('end') or None
            rtype = r.get('type') or r.get('relationshipType') or 'RELATED_TO'
            props = r.get('properties') or {}
            rel_records.append({'type': sanitize_label(rtype) or 'RELATED_TO', 'source': src, 'target': tgt, 'props': props})

        # Create relationships in batches
        print("[+] Creating relationships in batches ...")
        total_created_rels = 0
        for i in range(0, len(rel_records), batch_size):
            batch = rel_records[i:i+batch_size]
            created = loader.create_relationships_batch(batch)
            total_created_rels += created
            print(f"    created rels: {total_created_rels}/{len(rel_records)}")

        elapsed = time() - start
        print(f"[+] Import complete. Nodes created: {total_created_nodes}, relationships created: {total_created_rels}. Time: {elapsed:.1f}s")
    finally:
        loader.close()

# --- CLI ---
def parse_args():
    p = argparse.ArgumentParser(description="Import BloodHound zip into Neo4j without GUI")
    p.add_argument("--zip", "-z", required=True, help="Path to bloodhound zip")
    p.add_argument("--uri", required=True, help="Neo4j bolt uri, e.g. bolt://127.0.0.1:7687")
    p.add_argument("--user", required=True, help="Neo4j user")
    p.add_argument("--password", required=True, help="Neo4j password")
    p.add_argument("--no-clear", action="store_true", help="Do NOT clear the database before importing")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH, help=f"Batch size for inserts (default {DEFAULT_BATCH})")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    zip_path = args.zip
    if not Path(zip_path).exists():
        print(f"Zip file not found: {zip_path}", file=sys.stderr)
        sys.exit(2)
    try:
        import_bloodhound_zip_to_neo4j(zip_path, args.uri, args.user, args.password, clear=not args.no_clear, batch_size=args.batch)
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
