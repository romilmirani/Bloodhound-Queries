#!/usr/bin/env python3
"""
Query BloodHound/Neo4j and PRINT affected assets to terminal (no CSV writes).
Usage:
  python bh_terminal_queries.py --uri bolt://127.0.0.1:7687 --user neo4j --password 'pass' [--inspect]
"""

import argparse
from neo4j import GraphDatabase

# ----------------------------
# Cypher library (finding name -> query)
# NOTE:
# - Uses case-insensitive name matches for BH-style group names (e.g., 'PROTECTED USERS@corp.local')
# - Handles alternative property spellings commonly seen across BH importer versions
# - Avoids file output; prints to terminal only
# ----------------------------

QUERIES = {
    # 1) DCSync (non T0 optional)
    "Non Tier Zero Principals with DCSync Privileges": """
    // Principals with DCSync rights
    MATCH (p)-[:CanDCSync]->(d:Domain)
    // If you tag Tier Zero/high value, exclude them; otherwise remove the WHERE below
    WHERE COALESCE(p.highvalue,false) = false
    RETURN DISTINCT p.name AS principal, labels(p) AS labels, d.name AS domain, 'CanDCSync' AS reason
    ORDER BY principal
    """,

    # 2) Privileged not in Protected Users
    "Privileged Accounts not in \"Protected Users\" Group": """
    // admincount often set to 1 for privileged users. Protected Users group naming is 'PROTECTED USERS@DOMAIN'
    MATCH (u:User)
    WHERE toInteger(coalesce(u.admincount,0)) = 1
    AND NOT EXISTS {
    MATCH (u)-[:MemberOf]->(g:Group)
    WHERE toUpper(g.name) STARTS WITH 'PROTECTED USERS@'
    }
    RETURN DISTINCT u.name AS user,
       'admincount=1 && not member of PROTECTED USERS' AS reason
    ORDER BY user;
    """,

    # 3) Large Default Groups in Local Administrator Groups  (prints all, you can filter by count on client side)
    "Large Default Groups in Local Administrator Groups": """
    // Groups with local admin rights on computers
    MATCH (g:Group)-[:AdminTo]->(c:Computer)
    RETURN g.name AS group, collect(DISTINCT c.name) AS computers, size(collect(DISTINCT c)) AS count, 'AdminTo on computers' AS reason
    ORDER BY count DESC
    """,

    # 4) Generic All Privileges on Tier Zero Groups
    "Generic All Privileges on Tier Zero Groups": """
    // Principals holding GenericAll over high value (Tier Zero) groups
    MATCH (g:Group {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.name AS principal, g.name AS target_group, 'GenericAll -> T0 group' AS reason
    ORDER BY principal, target_group
    """,

    # 5) Large Default Groups with Generic Write Privileges
    "Large Default Groups with Generic Write Privileges": """
    // 'Default' groups approximated by common names; adjust as needed
    MATCH (g:Group)-[:GenericWrite]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'GenericWrite' AS reason
    ORDER BY count DESC
    """,

    # 6) Large Default Groups with Generic All Privileges
    "Large Default Groups with Generic All Privileges": """
    MATCH (g:Group)-[:GenericAll]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'GenericAll' AS reason
    ORDER BY count DESC
    """,

    # 7) Large Default Groups with Add Self Privileges
    "Large Default Groups with Add Self Privileges": """
    MATCH (g:Group)-[:AddMember]->(o:Group)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS target_groups, size(collect(DISTINCT o)) AS count, 'AddMember' AS reason
    ORDER BY count DESC
    """,

    # 8) Large Default Groups with Force Change Password Privileges
    "Large Default Groups with Force Change Password Privileges": """
    MATCH (g:Group)-[:ForceChangePassword]->(u:User)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT u.name) AS users, size(collect(DISTINCT u)) AS count, 'ForceChangePassword' AS reason
    ORDER BY count DESC
    """,

    # 9) Large Default Groups with Write DACL Privilege
    "Large Default Groups with Write DACL Privilege": """
    MATCH (g:Group)-[:WriteDacl]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'WriteDacl' AS reason
    ORDER BY count DESC
    """,

    # 10) Large Default Groups with Write Owner Privilege
    "Large Default Groups with Write Owner Privilege": """
    MATCH (g:Group)-[:WriteOwner]->(o)
    WHERE g.name =~ '(?i)^(domain users|authenticated users|everyone|domain computers)@.*'
    RETURN DISTINCT g.name AS group, collect(DISTINCT o.name) AS objects, size(collect(DISTINCT o)) AS count, 'WriteOwner' AS reason
    ORDER BY count DESC
    """,

    # 11) Generic All Privileges on Tier Zero Objects
    "Generic All Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.name AS principal, o.name AS target_object, 'GenericAll -> T0 object' AS reason
    ORDER BY principal, target_object
    """,

    # 12) Ownership Privileges on Tier Zero Objects
    "Ownership Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:WriteOwner]-(p)
    RETURN DISTINCT p.name AS principal, o.name AS target_object, 'WriteOwner -> T0 object' AS reason
    ORDER BY principal, target_object
    """,

    # 13) Account Does Not Require Kerberos Pre-Authentication
    "Account Does Not Require Kerberos Pre-Authentication": """
    MATCH (u:User)
    WHERE COALESCE(u.dontreqpreauth,false) = true OR COALESCE(u.require_preauth,true) = false
    RETURN DISTINCT u.name AS user, 'dontreqpreauth=true' AS reason
    ORDER BY user
    """,

    # 14) DES Enabled Kerberos Accounts (bitmask & alt fields)
    "DES Enabled Kerberos Accounts": """
    // BH commonly stores supported_enctypes as integer bitmask; DES = bits 0x1|0x2
    MATCH (u:User)
    WHERE
  // any DES bit set: (value % 4) != 0  (since DES bits are 0x1 and 0x2)
    (toInteger(coalesce(u.supported_enctypes,0)) % 4) <> 0
    OR toString(coalesce(u.supported_enctypes,'')) CONTAINS 'DES'
    OR toString(coalesce(u.supportedEncryptionTypes,'')) CONTAINS 'DES'
    RETURN DISTINCT
    u.name AS user,
    u.supported_enctypes AS supported_enctypes,
    'DES present' AS reason
    ORDER BY user;
    """,

    # 15) Unconstrained Delegation (computers)
    "Unconstrained Delegation Configured on Domains": """
    MATCH (c:Computer)
    WHERE COALESCE(c.unconstraineddelegation,false) = true
       OR COALESCE(c.unconstrained_delegation,false) = true
    RETURN DISTINCT c.name AS computer, 'unconstrained delegation' AS reason
    ORDER BY computer
    """,

    # 16) Trust Without SID Filtering
    "Trust Without SID Filtering": """
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE COALESCE(t.sidFiltering,true) = false OR COALESCE(t.sid_filtering,true) = false
    RETURN a.name AS source_domain, b.name AS target_domain, 'sidFiltering=false' AS reason
    ORDER BY source_domain, target_domain
    """,

    # 17) NT4 Compatible Trust Discovered (TreatAsExternal heuristic)
    "NT4 Compatible Trust Discoverd": """
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE
  // bit 0x10 set?  Use modulo: keep lower 5 bits, check >= 16
    (toInteger(coalesce(t.trustattributes,0)) % 32) >= 16
    OR toString(coalesce(t.trusttype,'')) CONTAINS 'NT4'
    RETURN
    a.name AS source_domain,
    b.name AS target_domain,
    t.trusttype AS trust_type,
    t.trustattributes AS trust_attributes,
    'TreatAsExternal/NT4 indicator' AS reason
    ORDER BY source_domain, target_domain;
    """,

    # 18) Group Schema Admins not Empty
    "Group Schema Admins is not Empty": """
    MATCH (g:Group) WHERE g.name =~ '(?i)^schema admins@.*'
    OPTIONAL MATCH (g)<-[:MemberOf]-(m:User)
    RETURN g.name AS group, collect(DISTINCT m.name) AS members, size(collect(DISTINCT m)) AS count
    ORDER BY group
    """,

    # 19) Non-Admin Users Can Add up to 10 Computers to a Domain
    "Non-Admin Users Can Add up to 10 Computers to a Domain": """
    MATCH (d:Domain)
    WHERE toInteger(COALESCE(d.machineaccountquota,0)) > 0
    RETURN d.name AS domain, toInteger(d.machineaccountquota) AS machineaccountquota, 'MAQ > 0' AS reason
    ORDER BY domain
    """,

    # 20) User Account with Reversible Password  (if present in your BH ingest; else returns 0 rows)
    "User Account with Reversible Password": """
    // Only returns results if your BH importer stores a dedicated reversible flag or UAC hint
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--inspect", action="store_true", help="Print labels/relationship types/property keys")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    with driver.session() as s:
        if args.inspect:
            inspect_schema(s)

        # Run supported queries
        for finding, cypher in QUERIES.items():
            rows = run_query(s, finding, cypher)
            # Choose a few sensible columns to print for each query:
            # We infer keys from the first row to keep this generic.
            if rows:
                keys = list(rows[0].keys())
                print_rows(finding, keys, rows)
            else:
                print_rows(finding, ["info"], [])  # will print "(no results)"

        # Print skipped findings (for completeness)
        print("\n=== Skipped (not available via standard BloodHound data) ===")
        for name, reason in SKIP.items():
            print(f"- {name}: {reason}")

    driver.close()

if __name__ == "__main__":
    main()
