#!/usr/bin/env python3
"""
Simple SMBv1 status checker for Domain Controllers.

Usage:
    python3 check_smb1.py domains.txt

domains.txt: one domain per line (blank lines and lines starting with # are ignored).
"""

import subprocess
import socket
import sys
import re
from pathlib import Path

TIMEOUT = 3  # seconds for socket connect


def read_domains(path):
    p = Path(path)
    if not p.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    domains = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line)
    return domains


def find_dcs_by_srv(domain):
    """Use SRV lookup to find DCs: host -t SRV _ldap._tcp.dc._msdcs.<domain>"""
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        out = subprocess.check_output(["host", "-t", "SRV", srv_name],
                                      stderr=subprocess.STDOUT, text=True, timeout=8)
    except subprocess.CalledProcessError as e:
        out = e.output or ""
    except FileNotFoundError:
        return []
    hosts = []
    for line in out.splitlines():
        m = re.search(r"\bSRV record .*? (\S+)\.?$", line)
        if m:
            hosts.append(m.group(1).rstrip("."))
    return hosts


def tcp_connectable(host, port=445, timeout=TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run_nmap_smb_protocols(host):
    """Run nmap smb-protocols; return (success:bool, output:str)"""
    cmd = ["nmap", "-Pn", "-p", "445", "--script", "smb-protocols", host]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=30)
        return True, out
    except FileNotFoundError:
        return False, "nmap not found. Please install nmap and ensure it's in PATH."
    except subprocess.CalledProcessError as e:
        # nmap may return non-zero but still yield script output
        return True, (e.output or "")
    except Exception as e:
        return False, f"nmap error: {e}"


def smb1_status_from_nmap(output):
    """
    Best-effort parse of smb-protocols output to determine SMBv1 support.
    Looks for:
      - explicit 'SMBv1: disabled/enabled/not supported'
      - dialect list containing '1.0' / 'NT LM 0.12'
    Returns: 'ENABLED' | 'DISABLED' | 'UNKNOWN'
    """
    txt = output.lower()

    # Explicit lines some versions print
    if "smbv1" in txt:
        if "smbv1" in txt and ("disabled" in txt or "not supported" in txt or "negotiated: 2." in txt):
            return "DISABLED"
        if "smbv1" in txt and ("enabled" in txt or "supported" in txt):
            return "ENABLED"

    # Dialect hints commonly shown by smb-protocols
    # SMB1 dialects include "PC NETWORK PROGRAM 1.0", "LANMAN 1.0/2.0", "NT LM 0.12"
    if re.search(r"(pc network program 1\.0|lanman|nt lm 0\.12)", txt):
        return "ENABLED"

    # If it lists only SMB2/SMB3 dialects like 2.0.2, 2.1, 3.0, 3.02, 3.1.1
    if re.search(r"enabled dialects?:.*(2\.0|2\.1|3\.0|3\.02|3\.1\.1)", txt) and "1.0" not in txt and "nt lm 0.12" not in txt:
        return "DISABLED"

    return "UNKNOWN"


def check_domain(domain):
    print(f"\nDomain: {domain}")
    dcs = find_dcs_by_srv(domain)
    if not dcs:
        print("  No SRV DC records found (or 'host' unavailable). Will try domain name directly.")
        dcs = [domain]

    for dc in dcs:
        print(f"  DC candidate: {dc}")
        if not tcp_connectable(dc, 445):
            print(f"    [ERROR] {dc}: not reachable on TCP/445 (connectivity check failed)")
            continue

        ok, out = run_nmap_smb_protocols(dc)
        if not ok:
            print(f"    [ERROR] running nmap on {dc}: {out}")
            continue

        status = smb1_status_from_nmap(out)
        if status == "ENABLED":
            print(f"    [WARN] SMBv1 appears ENABLED on {dc}")
        elif status == "DISABLED":
            print(f"    [OK]  SMBv1 appears DISABLED on {dc}")
        else:
            print(f"    [UNKNOWN] Could not reliably determine SMBv1 status on {dc}")
            # print a short snippet to assist manual review
            snippet = "\n".join(line for line in out.splitlines() if line.strip())
            for line in snippet.splitlines()[:10]:
                print("      ", line)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 check_smb1.py domains.txt", file=sys.stderr)
        sys.exit(2)

    domains = read_domains(sys.argv[1])
    if not domains:
        print("No domains found in input file.", file=sys.stderr)
        sys.exit(1)

    for domain in domains:
        check_domain(domain)


if __name__ == "__main__":
    main()
