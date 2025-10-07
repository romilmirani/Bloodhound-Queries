#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BloodHound/Neo4j: query affected assets for common PingCastle-style findings.
- Keeps finding names EXACTLY as provided.
- Runs Cypher only for findings BloodHound can detect; clearly skips the rest.
- Exports one CSV per finding into ./results and prints a summary.

Usage:
  pip install neo4j pandas
  python bh_findings_query_full.py --uri bolt://127.0.0.1:7687 --user neo4j --password 'pass'
"""

import os
import argparse
import pandas as pd
from neo4j import GraphDatabase

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Findings FROM YOUR SHEETS (names must match exactly).
# For each, either:
#   - provide a Cypher query (supported by BloodHound), OR
#   - set value to None + a reason in NOT_SUPPORTED dict.
# Return columns should include (as applicable): objectid, name, labels, reason, plus any extras.
# ---------------------------------------------------------------------------

SUPPORTED_QUERIES = {
    # ----- T0/DCSync / Privileged membership / ACL-derived -----
    "Non Tier Zero Principals with DCSync Privileges": """
    MATCH (n)-[:CanDCSync]->(d:Domain)
    WHERE coalesce(n.highvalue,false)=false  // 'Tier Zero' heuristic; remove if you don't label T0
    RETURN DISTINCT n.objectid AS objectid, n.name AS name, labels(n) AS labels,
           d.name AS domain, 'CanDCSync' AS reason
    """,

    "Large Default Groups in Local Administrator Groups": """
    // Groups that are local admin to many computers (AdminTo edges)
    MATCH (g:Group)-[:AdminTo]->(c:Computer)
    WITH g, count(DISTINCT c) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'AdminTo on computers' AS reason
    """,

    "Generic All Privileges on Tier Zero Groups": """
    // GenericAll against high value groups (Tier Zero)
    MATCH (g:Group {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.objectid AS objectid, p.name AS name, labels(p) AS labels,
           g.name AS target, 'GenericAll -> highvalue group' AS reason
    """,

    "Large Default Groups with Generic Write Privileges": """
    // GenericWrite edges from groups to any object (approx. 'large' by count)
    MATCH (g:Group)-[:GenericWrite]->(o)
    WITH g, count(DISTINCT o) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'GenericWrite to many objects' AS reason
    """,

    "Large Default Groups with Generic All Privileges": """
    MATCH (g:Group)-[:GenericAll]->(o)
    WITH g, count(DISTINCT o) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'GenericAll to many objects' AS reason
    """,

    "Large Default Groups with Add Self Privileges": """
    // 'AddMember' is the BloodHound edge for adding members
    MATCH (g:Group)-[:AddMember]->(o:Group)
    WITH g, count(DISTINCT o) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'AddMember to groups' AS reason
    """,

    "Large Default Groups with Force Change Password Privileges": """
    MATCH (g:Group)-[:ForceChangePassword]->(u:User)
    WITH g, count(DISTINCT u) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'ForceChangePassword on users' AS reason
    """,

    "Large Default Groups with Write DACL Privilege": """
    MATCH (g:Group)-[:WriteDacl]->(o)
    WITH g, count(DISTINCT o) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'WriteDacl on many objects' AS reason
    """,

    "Large Default Groups with Write Owner Privilege": """
    MATCH (g:Group)-[:WriteOwner]->(o)
    WITH g, count(DISTINCT o) AS cnt
    WHERE cnt > 0
    RETURN g.objectid AS objectid, g.name AS name, labels(g) AS labels,
           cnt AS affected_count, 'WriteOwner on many objects' AS reason
    """,

    "Generic All Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:GenericAll]-(p)
    RETURN DISTINCT p.objectid AS objectid, p.name AS name, labels(p) AS labels,
           o.name AS target, 'GenericAll -> highvalue object' AS reason
    """,

    "Ownership Privileges on Tier Zero Objects": """
    MATCH (o {highvalue:true})<-[:WriteOwner]-(p)
    RETURN DISTINCT p.objectid AS objectid, p.name AS name, labels(p) AS labels,
           o.name AS target, 'WriteOwner -> highvalue object' AS reason
    """,

    # ----- Account flags / properties -----
    "Account Does Not Require Kerberos Pre-Authentication": """
    MATCH (u:User)
    WHERE coalesce(u.dontreqpreauth,false)=true OR coalesce(u.require_preauth,true)=false
    RETURN u.objectid AS objectid, u.name AS name, labels(u) AS labels,
           'dontreqpreauth=true' AS reason
    """,

    "DES Enabled Kerberos Accounts": """
    MATCH (u:User)
    WHERE toString(coalesce(u.supported_enctypes,'')) CONTAINS 'DES'
          OR toString(coalesce(u.supportedEncryptionTypes,'')) CONTAINS 'DES'
    RETURN u.objectid AS objectid, u.name AS name, labels(u) AS labels,
           'DES present in supported_enctypes' AS reason
    """,

    "Privileged Accounts not in \"Protected Users\" Group": """
    // admincount = 1 is a common proxy for privileged users
    MATCH (u:User)
    WHERE coalesce(u.admincount,0)=1 AND NOT (u)-[:MemberOf]->(:Group {name:'Protected Users'})
    RETURN u.objectid AS objectid, u.name AS name, labels(u) AS labels,
           'admincount=1; not member of Protected Users' AS reason
    """,

    "User Account with Reversible Password": """
    MATCH (u:User)
    WHERE (coalesce(u.useraccountcontrol,0) & 0x0080) = 0x0080
          OR coalesce(u.reversible_encryption,false)=true
    RETURN u.objectid AS objectid, u.name AS name, labels(u) AS labels,
           'reversible password allowed' AS reason
    """,

    # ----- Delegation / Trusts / Domain config -----
    "Unconstrained Delegation Configured on Domains": """
    MATCH (c:Computer)
    WHERE coalesce(c.unconstraineddelegation,false)=true
          OR coalesce(c.unconstrained_delegation,false)=true
    RETURN c.objectid AS objectid, c.name AS name, labels(c) AS labels,
           'unconstrained delegation' AS reason
    """,

    "Trust Without SID Filtering": """
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE coalesce(t.sidFiltering,true)=false OR coalesce(t.sid_filtering,true)=false
    RETURN a.name AS source_domain, b.name AS target_domain, t.trusttype AS trust_type,
           'sidFiltering=false' AS reason
    """,

    "NT4 Compatible Trust Discovered": """
    // Heuristic: trust type/attributes indicating NT4 compatibility (may vary by importer)
    MATCH (a:Domain)-[t:Trusted]->(b:Domain)
    WHERE toString(coalesce(t.trusttype,'')) CONTAINS 'NT4'
          OR toString(coalesce(t.trustattributes,'')) CONTAINS 'NT4'
    RETURN a.name AS source_domain, b.name AS target_domain, t.trusttype AS trust_type,
           t.trustattributes AS trust_attributes, 'NT4-compatible indicator' AS reason
    """,

    "Group Schema Admins is not Empty": """
    MATCH (g:Group {name:'Schema Admins'})<-[:MemberOf]-(u:User)
    RETURN DISTINCT u.objectid AS objectid, u.name AS name, labels(u) AS labels,
           'Member of Schema Admins' AS reason
    """,

    "Non-Admin Users Can Add up to 10 Computers to a Domain": """
    // ms-DS-MachineAccountQuota > 0 on a domain allows any authenticated user to add computers
    MATCH (d:Domain)
    WHERE toInteger(coalesce(d.machineaccountquota,0)) > 0
    RETURN d.name AS domain, toInteger(d.machineaccountquota) AS machine_account_quota,
           'MAQ > 0 (any user can add computers)' AS reason
    """,
}

# Findings present in your list that BloodHound CANNOT reliably provide via standard ingesters.
NOT_SUPPORTED = {
    "Large Default Groups with Write Account Restrictions Privileges": "ACL detail not exposed consistently by BloodHound.",
    "Large Default Groups with RDP Access": "RDP access requires host/service enumeration; not standard BloodHound.",
    "Generic All Privileges on Tier Zero Objects (duplicate variant)": "Handled above; keep one.",
    "Large Default Groups with All Extended Privileges": "Needs granular ACL expansion; not standard BH edge.",
    "Authenticated Users Can Create DNS Records": "DNS/ADCS rights not in standard BH dataset.",
    "Certificate Template Can Be Requested by \"Any Purpose\"": "Requires AD CS template enumeration (Certipy/certsync).",
    "The LAN Manager Authentication Level allows the use of NTLM v1 or LM": "Host policy; not BH.",
    "Excessive ACE and DACL Introduced from Server 2016 Installation": "Quantification not available in BH graph.",
    "Inactive Domain Controller (DC) Accounts": "Inactivity timestamps not populated in BH.",
    "No GPO Discovered to Disable LLMNR": "GPO content not parsed by BH.",
    "No Password Policy on User Account over 8 Characters": "Password policy not in BH.",
    "Password Discovered in GPO": "Requires parsing GPO XML/Preferences; not BH.",
    "Presence of Admin Accounts which do not have the Flag \"This Account is Sensitive...\"": "Property not tracked by BH.",
    "SMBv1 Active on DCs": "Service enumeration; not BH.",
    "SMB Signing Not Enforced on Domain Controller": "Host policy; not BH.",
    "Unix UserPassword Set to Accounts": "Non-AD attribute not present in BH imports.",
    "Vulnerable Schema Class - PossSuperiorComputer": "Schema class ACL nuance not modeled.",
    "WSUS Configured with HTTP": "Host/service enumeration; not BH.",
    "Certificate Utilized for Authentication can have SAN Modified": "AD CS template setting; not BH.",
    "Spooler Service Enabled on Domain Controller": "Service enumeration (RPC); not BH.",
    "Inactive Trusts Discovered": "Needs lastLogon/lastUpdate on trust; typically absent.",
    "Kerberos Accounts Password Change over 40 Days": "Password age timestamps not included in BH.",
    "Last AD Backup greater than 7 days": "Operational data; not BH.",
    "No Password Policy for Service Account": "Policy detail not in BH.",
}

# ---------------------------------------------------------------------------

def inspect_schema(session):
    print("\n--- DB Labels ---")
    print([x[0] for x in session.run("CALL db.labels()").values()])

    print("\n--- Relationship Types ---")
    print([x[0] for x in session.run("CALL db.relationshipTypes()").values()])

    print("\n--- Property Keys (sample) ---")
    print([x[0] for x in session.run("CALL db.propertyKeys()").values()][:200])

def run_and_save(session, finding_name, cypher):
    print(f"\n[+] {finding_name}")
    try:
        res = session.run(cypher)
        rows = list(res)
    except Exception as e:
        print(f"    ERROR running Cypher: {e}")
        return 0

    if not rows:
        print("    No results.")
        return 0

    cols = res.keys()
    data = []
    for r in rows:
        data.append({c: r.get(c) for c in cols})
    df = pd.DataFrame(data)

    # create a safe filename but DO NOT alter the finding name itself in content
    fname = finding_name.lower().replace(" ", "_").replace("\"","").replace("'","").replace("/","_")
    out = os.path.join(RESULTS_DIR, f"{fname}.csv")
    df.to_csv(out, index=False)
    print(f"    Saved {len(df)} rows -> {out}")
    return len(df)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--inspect", action="store_true", help="Print labels/relationships/property keys first")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    total = 0
    with driver.session() as s:
        if args.inspect:
            inspect_schema(s)

        print("\n=== Running BloodHound-backed findings ===")
        for finding, cypher in SUPPORTED_QUERIES.items():
            total += run_and_save(s, finding, cypher)

        print("\n=== Findings not supported by BloodHound (kept for completeness) ===")
        for finding, reason in NOT_SUPPORTED.items():
            print(f"[-] {finding}: skipped ({reason})")

    driver.close()
    print(f"\nDone. Rows exported: {total}")

if __name__ == "__main__":
    main()
