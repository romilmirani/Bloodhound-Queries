#!/usr/bin/env python3
"""
clear_neo4j.py

Usage:
  python3 clear_neo4j.py --uri bolt://127.0.0.1:7687 --user neo4j --password secret [--use-apoc]

Requires:
  pip install neo4j
"""
import argparse
from neo4j import GraphDatabase, basic_auth

def clear_db(uri, user, password, use_apoc=False):
    driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
    try:
        with driver.session() as s:
            if use_apoc:
                # APOC path (faster for huge graphs)
                s.run("CALL apoc.periodic.iterate('MATCH (n) RETURN n','DETACH DELETE n',"
                      "{batchSize:10000, parallel:true}) YIELD batches RETURN batches")
            else:
                s.run("MATCH (n) DETACH DELETE n")
        print("[+] Database cleared.")
    finally:
        driver.close()

def parse_args():
    p = argparse.ArgumentParser(description="Clear all data from Neo4j.")
    p.add_argument("--uri", required=True, help="bolt://host:7687 or neo4j://...")
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--use-apoc", action="store_true", help="Use APOC periodic iterate (faster for big graphs)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    clear_db(args.uri, args.user, args.password, use_apoc=args.use_apoc)
