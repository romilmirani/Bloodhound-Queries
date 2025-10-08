#!/usr/bin/env python3
"""
Usage:
  python bh_terminal_queries.py --uri bolt://127.0.0.1:7687 --user neo4j --password 'pass' [--inspect]
"""

import argparse
import os
import pandas as pd
from neo4j import GraphDatabase

QUERIES = {
    "Non Tier Zero Principals with DCSync Privileges": """
    MATCH (p)-[:CanDCSync]->(d:Domain)
    WHERE COALESCE(p.highvalue,false) = false
    RETURN DISTINCT p.name AS principal, labels(p) AS labels, d.name AS domain, 'CanDCSync' AS reason
    ORDER BY principal
    """,

    "Privileged Accounts not in \"Protected Users\" Group": """
    MATCH (u:User)
    WHERE toInteger(coalesce(u.admincount,0)) = 1
      AND NOT EXISTS {
        MATCH (u)-[:MemberOf]->(g:Group)
        WHERE toUpper(g.name) STARTS WITH 'PROTECTED USERS@'
      }
    RETURN DISTINCT u.name AS user,
           'admincount=1 && not member of PROTECTED USERS' AS reason
    ORDER BY user
    """,

    "Large Default Groups in Local Administrator Groups": """
    MATCH (g:Group)-[:AdminTo]->(c:Computer)
    RETURN g.name AS group, collect(DISTINCT c.name) AS computers, size(collect(DISTINCT c)) AS count, 'AdminTo on computers' AS reason
    ORDER BY count DESC
    """,

    "Generic All Privileges on Tier Zero Groups": """
    MATCH (g:Group {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.name AS principal, g.name AS target_group, 'GenericAll -> T0 group' AS reason
    ORDER BY principal, target_group
    """,

    "Large Default Groups with Generic Write Privileges": """
    MATCH (g:Group)-[:GenericWrite]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'GenericWrite' AS reason
    ORDER BY count DESC
    """,

    "Large Default Groups with Generic All Privileges": """
    MATCH (g:Group)-[:GenericAll]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'GenericAll' AS reason
    ORDER BY count DESC
    """,

    "Large Default Groups with Add Self Privileges": """
    MATCH (g:Group)-[:AddMember]->(o:Group)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS target_groups, size(collect(DISTINCT o)) AS count, 'AddMember' AS reason
    ORDER BY count DESC
    """,

    "Large Default Groups with Force Change Password Privileges": """
    MATCH (g:Group)-[:ForceChangePassword]->(u:User)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT u.name) AS users, size(collect(DISTINCT u)) AS count, 'ForceChangePassword' AS reason
    ORDER BY count DESC
    """,

    "Large Default Groups with Write DACL Privilege": """
    MATCH (g:Group)-[:WriteDacl]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'WriteDacl' AS reason
    ORDER BY count DESC
    """,

    "Large Default Groups with Write Owner Privilege": """
    MATCH (g:Group)-[:WriteOwner]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'WriteOwner' AS reason
    ORDER BY count DESC
    """,

    "Generic All Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.name AS principal, o.name AS target_object, 'GenericAll -> T0 object' AS reason
    ORDER BY principal, target_object
    """,

    "Ownership Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:WriteOwner]-(p)
    RETURN DISTINCT p.name AS principal, o.name AS target_object, 'WriteOwner -> T0 object' AS reason
    ORDER BY principal, target_object
    """,

    "Account Does Not Require Kerberos Pre-Authentication": """
    MATCH (u:User)
    WHERE COALESCE(u.dontreqpreauth,false) = true OR COALESCE(u.require_preauth,true) = false
    RETURN DISTINCT u.name AS user, 'dontreqpreauth=true' AS reason
    ORDER BY user
    """,

    "DES Enabled Kerberos Accounts": """
    MATCH (u:User)
    WHERE (toInteger(coalesce(u.supported_enctypes,0)) % 4) <> 0
       OR toString(coalesce(u.supported_enctypes,'')) CONTAINS 'DES'
       OR toString(coalesce(u.supportedEncryptionTypes,'')) CONTAINS 'DES'
    RETURN DISTINCT u.name AS user, u.supported_enctypes AS supported_enctypes, 'DES present' AS reason
    ORDER BY user
    """,

    "Unconstrained Delegation Configured on Domains": """
    MATCH (c:Computer)
    WHERE COALESCE(c.unconstraineddelegation,false) = true
       OR COALESCE(c.unconstrained_delegation,false) = true
    RETURN DISTINCT c.name AS computer, 'unconstrained delegation' AS reason
    ORDER BY computer
    """,

    "Trust Without SID Filtering": """
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE COALESCE(t.sidFiltering,true) = false OR COALESCE(t.sid_filtering,true) = false
    RETURN a.name AS source_domain, b.name AS target_domain, 'sidFiltering=false' AS reason
    ORDER BY source_domain, target_domain
    """,

    # Kept exactly as you pasted ("Discoverd")
    "NT4 Compatible Trust Discoverd": """
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE (toInteger(coalesce(t.trustattributes,0)) % 32) >= 16
       OR toString(coalesce(t.trusttype,'')) CONTAINS 'NT4'
    RETURN a.name AS source_domain, b.name AS target_domain, t.trusttype AS trust_type, t.trustattributes AS trust_attributes,
           'TreatAsExternal/NT4 indicator' AS reason
    ORDER BY source_domain, target_domain
    """,

    "Group Schema Admins is not Empty": """
    MATCH (g:Group) WHERE g.name =~ '(?i)^schema admins@.*'
    OPTIONAL MATCH (g)<-[:MemberOf]-(m:User)
    RETURN g.name AS group, collect(DISTINCT m.name) AS members, size(collect(DISTINCT m)) AS count
    ORDER BY group
    """,

    "Non-Admin Users Can Add up to 10 Computers to a Domain": """
    MATCH (d:Domain)
    WHERE toInteger(COALESCE(d.machineaccountquota,0)) > 0
    RETURN d.name AS domain, toInteger(d.machineaccountquota) AS machineaccountquota, 'MAQ > 0' AS reason
    ORDER BY domain
    """,

    "User Account with Reversible Password": """
    MATCH (u:User)
    WHERE COALESCE(u.reversible_password,false)=true OR COALESCE(u.reversible_encryption,false)=true
    RETURN DISTINCT u.name AS user, 'reversible password flag present' AS reason
    ORDER BY user
    """,
}

def print_rows(title, keys, rows):
    print(f"\n=== {title} ===")
    count = 0
    for r in rows:
        count += 1
        line = " | ".join([f"{k}: {r.get(k)}" for k in keys])
        print(f"- {line}")
    if count == 0:
        print("(no results)")

def inspect_schema(session):
    print("\n--- Labels ---")
    print([x[0] for x in session.run("CALL db.labels()").values()])
    print("\n--- Relationship Types ---")
    print([x[0] for x in session.run("CALL db.relationshipTypes()").values()])
    print("\n--- Property Keys (sample) ---")
    print([x[0] for x in session.run("CALL db.propertyKeys()").values()][:200])

def run_query(session, name, cypher):
    try:
        res = session.run(cypher)
        rows = [dict(r) for r in res]
        return rows
    except Exception as e:
        print(f"\n[ERROR] {name}: {e}")
        return []

# ---------- CSV helpers (Domain + AffectedAsset only) ----------
def normalize_for_csv(row):
    domain = row.get("domain") or row.get("source_domain") or row.get("target_domain") or ""

    asset = (
        row.get("user")
        or row.get("principal")
        or row.get("computer")
        or row.get("group")
        or row.get("target_object")
        or row.get("target_group")
        or row.get("object")
        or ""
    )

    # For queries that return lists (e.g., groups -> computers/objects), expand rows:
    if isinstance(asset, list):
        asset_list = asset
    elif "computers" in row and isinstance(row["computers"], list):
        asset_list = row["computers"]
    elif "objects" in row and isinstance(row["objects"], list):
        asset_list = row["objects"]
    elif "users" in row and isinstance(row["users"], list):
        asset_list = row["users"]
    elif "members" in row and isinstance(row["members"], list):
        asset_list = row["members"]
    elif "target_groups" in row and isinstance(row["target_groups"], list):
        asset_list = row["target_groups"]
    else:
        asset_list = [asset] if asset else []

    # If domain is empty but asset looks like USER@DOMAIN, infer domain to the right of '@'
    out = []
    for a in asset_list:
        d = domain
        if not d and isinstance(a, str) and '@' in a:
            d = a.split('@', 1)[1]
        out.append({"Domain": d, "AffectedAsset": a})
    return out

def save_finding_csv(finding_name, rows):
    os.makedirs("results", exist_ok=True)
    safe = finding_name.lower().replace(" ", "_").replace('"', "").replace("'", "")
    path = os.path.join("results", f"{safe}.csv")
    flat = []
    for r in rows:
        flat.extend(normalize_for_csv(r))
    df = pd.DataFrame(flat, columns=["Domain", "AffectedAsset"])
    df.to_csv(path, index=False)
    print(f"[+] Saved {len(df)} rows → {path}")
    return df  # return df so we can append to master

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--inspect", action="store_true", help="Print labels/relationship types/property keys")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    master_rows = []

    with driver.session() as s:
        if args.inspect:
            inspect_schema(s)

        # Run supported queries, print, and save CSVs
        for finding, cypher in QUERIES.items():
            rows = run_query(s, finding, cypher)
            if rows:
                keys = list(rows[0].keys())
                print_rows(finding, keys, rows)
                df = save_finding_csv(finding, rows)
                if not df.empty:
                    df2 = df.copy()
                    df2.insert(0, "Finding", finding)
                    master_rows.append(df2)
            else:
                print_rows(finding, ["info"], [])  # prints "(no results)"
                # still create an empty CSV for consistency
                save_finding_csv(finding, [])

        # Print skipped (no queries) for completeness
        print("\n=== Skipped (not available via standard BloodHound data) ===")
        for name, reason in SKIP.items():
            print(f"- {name}: {reason}")

    driver.close()

    # Save master CSV
    if master_rows:
        all_df = pd.concat(master_rows, ignore_index=True)
        all_df.to_csv("results/all_findings_master.csv", index=False)
        print("\n✅ Master CSV saved → results/all_findings_master.csv")
    else:
        print("\n⚠️ No data to save in master CSV.")

if __name__ == "__main__":
    main()
