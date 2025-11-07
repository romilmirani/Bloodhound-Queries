#!/usr/bin/env python3
"""
Simple SMB signing checker for Domain Controllers.

Usage:
    python3 check_smb_signing.py domains.txt

domains.txt should contain one domain per line (blank lines and lines
starting with # are ignored).
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
    """
    Try SRV lookup to find DCs:
      host -t SRV _ldap._tcp.dc._msdcs.<domain>
    Returns list of hostnames (may be empty).
    """
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        out = subprocess.check_output(["host", "-t", "SRV", srv_name],
                                      stderr=subprocess.STDOUT,
                                      text=True,
                                      timeout=8)
    except subprocess.CalledProcessError as e:
        # host returns non-zero when no records; capture its output in e.output if exists
        out = e.output or ""
    except FileNotFoundError:
        # host command not available
        return []
    # parse host output like:
    # _ldap._tcp.dc._msdcs.example.com has SRV record 0 100 389 dc1.example.com.
    hosts = []
    for line in out.splitlines():
        m = re.search(r"\bSRV record .*? (\S+)\.?$", line)
        if m:
            hostname = m.group(1).rstrip(".")
            hosts.append(hostname)
    return hosts


def tcp_connectable(host, port=445, timeout=TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def run_nmap_smb_security(dc_host):
    """
    Runs nmap smb-security-mode script against host:445 and returns
    (success:boolean, output:str)
    """
    cmd = ["nmap", "-Pn", "-p", "445", "--script", "smb-security-mode", dc_host]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=30)
        return True, out
    except FileNotFoundError:
        return False, "nmap not found. Please install nmap and ensure it's in PATH."
    except subprocess.CalledProcessError as e:
        # nmap may return non-zero but still produce output
        return True, (e.output or "")
    except Exception as e:
        return False, f"nmap error: {e}"


def interpret_nmap_output(nmap_out):
    """
    Try to infer SMB signing enforcement from nmap smb-security-mode output.
    This is conservative: looks for keywords. If uncertain, returns 'unknown'.
    """
    txt = nmap_out.lower()
    # common phrases from the script include "Message signing: required/enabled" etc.
    if "message signing" in txt:
        # Look for 'required' or 'enabled' => enforced
        if re.search(r"message signing:.*required", txt) or re.search(r"message signing:.*enabled", txt):
            return "ENFORCED"
        # Look for 'disabled' or 'not required' => not enforced
        if re.search(r"message signing:.*disabled", txt) or re.search(r"message signing:.*not required", txt):
            return "NOT ENFORCED"
    # fallback: search for 'signing required' / 'signing enabled' / 'signing disabled'
    if "signing required" in txt or "signing enabled" in txt:
        return "ENFORCED"
    if "signing disabled" in txt or "signing not required" in txt:
        return "NOT ENFORCED"
    return "UNKNOWN"


def check_domain(domain):
    print(f"\nDomain: {domain}")
    dcs = find_dcs_by_srv(domain)
    if not dcs:
        # fallback: try the domain itself as host
        print("  No SRV DC records found (or 'host' unavailable). Will try domain name directly.")
        dcs = [domain]

    for dc in dcs:
        print(f"  DC candidate: {dc}")
        # connectivity check
        ok = tcp_connectable(dc, 445)
        if not ok:
            print(f"    [ERROR] {dc}: not reachable on TCP/445 (connectivity check failed)")
            continue

        # run nmap script
        success, out = run_nmap_smb_security(dc)
        if not success:
            print(f"    [ERROR] running nmap on {dc}: {out}")
            continue

        # interpret output
        result = interpret_nmap_output(out)
        if result == "ENFORCED":
            print(f"    [OK]  SMB signing appears ENFORCED on {dc}")
        elif result == "NOT ENFORCED":
            print(f"    [WARN] SMB signing appears NOT ENFORCED on {dc}")
        else:
            print(f"    [UNKNOWN] Could not reliably determine SMB signing status on {dc}")
            # show a short snippet of nmap output to help manual triage
            snippet = "\n".join(line for line in out.splitlines() if line.strip())[:1000]
            if snippet:
                print("    nmap output (short):")
                for l in snippet.splitlines()[:10]:
                    print("     ", l)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 check_smb_signing.py domains.txt", file=sys.stderr)
        sys.exit(2)

    domains_file = sys.argv[1]
    domains = read_domains(domains_file)
    if not domains:
        print("No domains found in input file.", file=sys.stderr)
        sys.exit(1)

    for domain in domains:
        check_domain(domain)


if __name__ == "__main__":
    main()
