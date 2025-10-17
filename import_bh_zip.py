#!/usr/bin/env python3
"""
import_bh_zip.py

Usage:
  python3 import_bh_zip.py \
    --zip /path/bloodhound.zip \
    --uri bolt://127.0.0.1:7687 --user neo4j --password secret \
    [--batch 1000]

Requires:
  pip install neo4j
"""
import argparse, json, zipfile, re, sys
from pathlib import Path
from time import time
from neo4j import GraphDatabase, basic_auth

DEFAULT_BATCH = 500

LABEL_MAP = {
    "users": "User",
    "groups": "Group",
    "computers": "Computer",
    "domains": "Domain",
    "gpos": "GPO",
    "ous": "OU",
    "containers": "Container",
}

SAFE = re.compile(r"[^A-Za-z0-9_]")
def sanitize(x: str) -> str:
    s = SAFE.sub("", x or "")
    return s if s else None

def find_entity_files(z):
    found = []
    for n in z.namelist():
        if not n.lower().endswith(".json"):
            continue
        base = Path(n).name.lower()
        for key, lbl in LABEL_MAP.items():
            if key in base:
                found.append((n, lbl))
                break
    return found

def load_json_array(z, name_in_zip):
    with z.open(name_in_zip) as f:
        data = json.load(f)
    if isinstance(data, dict) and "data" in data:
        data = data["data"]
    if not isinstance(data, list):
        raise ValueError(f"{name_in_zip}: expected JSON array")
    return data

def get_oid(obj: dict):
    return obj.get("ObjectIdentifier") or obj.get("ObjectID")

def pick_props(obj: dict):
    props = dict(obj.get("Properties") or {})
    for k in ("Name", "DisplayName", "Domain", "ObjectSid", "ObjectGUID", "HighValue"):
        if k in obj:
            props[k] = obj[k]
    return props

def iter_relationships(obj: dict):
    rels = obj.get("Relationships") or {}
    src = get_oid(obj)
    for rtype, targets in rels.items():
        if not isinstance(targets, list): 
            continue
        for t in targets:
            if isinstance(t, str):
                tgt, rprops = t, {}
            elif isinstance(t, dict):
                tgt = t.get("ObjectIdentifier") or t.get("ObjectID") or t.get("Target")
                rprops = {k:v for k,v in t.items() if k not in ("ObjectIdentifier","ObjectID","Target")}
            else:
                continue
            if src and tgt:
                yield src, rtype, tgt, (rprops or {})

class Loader:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))

    def close(self):
        self.driver.close()

    def ensure_unique_constraint(self):
        with self.driver.session() as s:
            s.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Base) REQUIRE n._bh_oid IS UNIQUE")

    def create_nodes(self, label: str, rows, batch: int):
        label = sanitize(label) or "Base"
        cypher = f"""
        UNWIND $rows AS row
        MERGE (n:Base {{_bh_oid: row._bh_oid}})
        ON CREATE SET n += row.props
        SET n:`{label}`
        """
        total = 0
        with self.driver.session() as s:
            for i in range(0, len(rows), batch):
                s.write_transaction(lambda tx: tx.run(cypher, rows=rows[i:i+batch]))
                total += min(batch, len(rows) - i)
        return total

    def create_relationships_grouped(self, rels):
        # group by relationship type (to avoid dynamic rel type per-row)
        grouped = {}
        for r in rels:
            grouped.setdefault(r["rtype"], []).append(r)
        with self.driver.session() as s:
            for rtype, rows in grouped.items():
                q = f"""
                UNWIND $rows AS row
                MATCH (a:Base {{_bh_oid: row.src}}), (b:Base {{_bh_oid: row.tgt}})
                MERGE (a)-[r:`{rtype}`]->(b)
                SET r += row.props
                """
                s.write_transaction(lambda tx: tx.run(q, rows=rows))

def run(zip_path, uri, user, password, batch):
    t0 = time()
    with zipfile.ZipFile(zip_path, "r") as z:
        files = find_entity_files(z)
        if not files:
            raise RuntimeError("No matching entity JSON files found in ZIP (users/groups/computers/domains/gpos/ous/containers).")

        loader = Loader(uri, user, password)
        try:
            print("[+] Ensuring unique constraint on :Base(_bh_oid) ...")
            loader.ensure_unique_constraint()

            # Nodes
            print("[+] Creating nodes ...")
            node_counts = {}
            for name_in_zip, label in files:
                data = load_json_array(z, name_in_zip)
                rows = []
                for obj in data:
                    oid = get_oid(obj)
                    if not oid:
                        continue
                    props = pick_props(obj)
                    props["_bh_label_hint"] = label
                    rows.append({"_bh_oid": oid, "props": props})
                if rows:
                    c = loader.create_nodes(label, rows, batch)
                    node_counts[label] = node_counts.get(label, 0) + c
                    print(f"    {label:<9} +{c}  ({Path(name_in_zip).name})")

            # Relationships
            print("[+] Creating relationships ...")
            rel_buffer, created = [], 0
            def flush():
                nonlocal rel_buffer, created
                if not rel_buffer: return
                loader.create_relationships_grouped(rel_buffer)
                created += len(rel_buffer)
                print(f"    rels total: {created}")
                rel_buffer = []

            for name_in_zip, _label in files:
                data = load_json_array(z, name_in_zip)
                for obj in data:
                    for src, rtype, tgt, rprops in iter_relationships(obj):
                        rel_buffer.append({
                            "src": src,
                            "tgt": tgt,
                            "rtype": sanitize(rtype) or "RELATED_TO",
                            "props": rprops
                        })
                        if len(rel_buffer) >= batch:
                            flush()
                flush()

            dt = time() - t0
            print("\n[+] Import complete.")
            print("    Node counts:", node_counts)
            print(f"    Relationships created: {created}")
            print(f"    Time: {dt:.1f}s")
        finally:
            loader.close()

def parse_args():
    p = argparse.ArgumentParser(description="Import SharpHound split ZIP into Neo4j (no GUI).")
    p.add_argument("--zip", "-z", required=True, help="Path to SharpHound/BloodHound ZIP")
    p.add_argument("--uri", required=True, help="bolt://host:7687 or neo4j://...")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH, help=f"Batch size (default {DEFAULT_BATCH})")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    zp = args.zip
    if not Path(zp).exists():
        print(f"Zip not found: {zp}", file=sys.stderr)
        sys.exit(2)
    try:
        run(zp, args.uri, args.user, args.password, batch=args.batch)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)
