<#
  Find-LargeDefaults-WriteAccountRestrictions.ps1
  --------------------------------------------------
  Usage:
    .\Find-LargeDefaults-WriteAccountRestrictions.ps1
    .\Find-LargeDefaults-WriteAccountRestrictions.ps1 -Target corp.local -OutCsv C:\Temp\WAR.csv
#>

param(
  [string]$Target,
  [string]$OutCsv = ".\LargeDefaults_WriteAccountRestrictions_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

# Ensure PowerView is loaded
if (-not (Get-Command Get-DomainObjectAcl -ErrorAction SilentlyContinue)) {
  Write-Error "PowerView not loaded. Please Import-Module PowerView.ps1 first."
  exit
}

# Prompt if not provided
if (-not $Target) {
  $Target = Read-Host "Enter domain FQDN (e.g., corp.local) or DC IP/hostname"
}

Write-Host "`n[*] Scanning domain: $Target" -ForegroundColor Cyan

# Large default groups to look for
$LargeDefaults = @(
  'Domain Users',
  'Authenticated Users',
  'Everyone',
  'Users',
  'Guests',
  'Domain Computers'
)
$pattern = ($LargeDefaults | ForEach-Object { [Regex]::Escape($_) }) -join '|'
$regex = [regex]::new($pattern, 'IgnoreCase')

$domainName = try { (Get-Domain -Domain $Target).Name } catch { $Target }
$acl = Get-DomainObjectAcl -Domain $domainName -ResolveGUIDs

$matches = $acl | Where-Object {
  ($_.ActiveDirectoryRights -match 'WriteProperty') -and
  ($_.ObjectAceType -match 'Account Restrictions') -and
  ($_.InheritedObjectType -match 'User') -and
  ($regex.IsMatch($_.IdentityReference))
} | Select-Object IdentityReference, ActiveDirectoryRights, ObjectAceType, InheritedObjectType, IsInherited

# Output results
if (-not $matches -or $matches.Count -eq 0) {
  Write-Host "`n[+] No large default groups with Write Account Restrictions rights found on $Target." -ForegroundColor Green
  # Write empty CSV with headers for consistency
  $empty = [pscustomobject]@{
    IdentityReference=''; ActiveDirectoryRights=''; ObjectAceType=''; InheritedObjectType=''; IsInherited=''
  }
  $empty | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "[*] Empty CSV created at: $OutCsv" -ForegroundColor Gray
} else {
  Write-Host "`n[!] Found $($matches.Count) matching ACE(s)!" -ForegroundColor Yellow
  $matches | Format-Table -AutoSize
  $matches | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
  Write-Host "[*] Results saved to: $OutCsv" -ForegroundColor Green
}
