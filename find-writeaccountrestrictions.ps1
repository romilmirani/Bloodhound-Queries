<#
  Find-WriteAccountRestrictions.ps1
  ---------------------------------
  Enumerate AD objects whose ACLs contain the
  "User-Account-Restrictions" (Write account restrictions) right.

  Requirements:
    - PowerView loaded (Get-DomainObject, Get-DomainObjectAcl)
#>

[CmdletBinding()]
param(
    [string]$Domain,
    [string]$Server,
    [string]$OutCsv = ".\WriteAccountRestrictions_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

# Prompt for domain if not given
if (-not $Domain) {
    $Domain = Read-Host "Enter target domain FQDN (e.g. corp.local)"
}

Write-Host "`n[*] Domain : $Domain" -ForegroundColor Cyan
if ($Server) { Write-Host "[*] Server : $Server" -ForegroundColor Cyan }

# Make sure PowerView functions exist
foreach ($fn in 'Get-DomainObject','Get-DomainObjectAcl') {
    if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
        Write-Error "PowerView function '$fn' not found. Import PowerView.ps1 first."
        return
    }
}

# 1. Get the list of objects to inspect (computers by default)
Write-Host "`n[*] Enumerating computer objects from domain..." -ForegroundColor Cyan
$objects = Get-DomainObject -Domain $Domain -LDAPFilter '(objectClass=computer)'

if (-not $objects) {
    Write-Warning "No computer objects returned. Adjust the LDAP filter if needed."
    return
}

# 2. Pull ACLs and look for User-Account-Restrictions entries
$findings = @()

foreach ($obj in $objects) {
    $dn = $obj.distinguishedname

    try {
        $acls = if ($Server) {
            Get-DomainObjectAcl -Domain $Domain -Identity $dn -Server $Server -ResolveGUIDs -ErrorAction SilentlyContinue
        } else {
            Get-DomainObjectAcl -Domain $Domain -Identity $dn -ResolveGUIDs -ErrorAction SilentlyContinue
        }

        if (-not $acls) { continue }

        foreach ($ace in $acls) {
            # Keep only ACEs for "User-Account-Restrictions" with some Write right
            if ($ace.ObjectAceType -ne 'User-Account-Restrictions') { continue }
            if ($ace.ActiveDirectoryRights -notmatch 'Write') { continue }

            # Translate SID to name (if possible)
            $principal = $null
            try {
                $principal = ([System.Security.Principal.SecurityIdentifier]$ace.SecurityIdentifier
                             ).Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                $principal = $ace.SecurityIdentifier
            }

            $findings += [pscustomobject]@{
                ObjectDN            = $ace.ObjectDN
                PrincipalSID        = $ace.SecurityIdentifier
                Principal           = $principal
                ActiveDirectoryRights = $ace.ActiveDirectoryRights
                AceType             = $ace.AceType
                IsInherited         = $ace.IsInherited
                ObjectAceType       = $ace.ObjectAceType
            }
        }
    }
    catch {
        Write-Warning "Failed to read ACL for $dn : $($_.Exception.Message)"
    }
}

# 3. Output
if ($findings.Count -gt 0) {
    $findings |
        Sort-Object ObjectDN, Principal |
        Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8

    Write-Host "`n[!] Found $($findings.Count) ACE(s) with 'User-Account-Restrictions' rights." -ForegroundColor Yellow
    Write-Host "[+] CSV saved to: $OutCsv" -ForegroundColor Green

    # Quick on-screen view
    $findings |
        Select-Object ObjectDN, Principal, ActiveDirectoryRights, AceType, IsInherited |
        Sort-Object ObjectDN, Principal |
        Format-Table -AutoSize
}
else {
    Write-Host "`n[+] No ACEs with 'User-Account-Restrictions' found on inspected objects." -ForegroundColor Green
}