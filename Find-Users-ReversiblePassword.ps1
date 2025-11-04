<#
  Find-Users-ReversiblePassword.ps1
  ---------------------------------
  Usage:
    .\Find-Users-ReversiblePassword.ps1
    .\Find-Users-ReversiblePassword.ps1 -Server dc01.corp.local
    .\Find-Users-ReversiblePassword.ps1 -Server corp.local -OutCsv C:\Temp\reversible_users.csv
#>

param(
  [string]$Server,
  [string]$OutCsv = ".\ReversiblePassword_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

if (-not $Server) {
  $Server = Read-Host "Enter domain FQDN or DC hostname/IP"
}

# ensure AD module is present
if (-not (Get-Module ActiveDirectory)) {
  try { Import-Module ActiveDirectory -ErrorAction Stop }
  catch { Write-Error "ActiveDirectory module not available (install RSAT)."; exit 1 }
}

# Bit for ENCRYPTED_TEXT_PASSWORD_ALLOWED
$UAC_ENCRYPTED_TEXT_ALLOWED = 0x80   # decimal 128

Write-Host "[*] Querying $Server for users with ENCRYPTED_TEXT_PASSWORD_ALLOWED (uac bit 0x80)..." -ForegroundColor Cyan

# LDAPFilter to test bit
$ldapFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=$($UAC_ENCRYPTED_TEXT_ALLOWED)))"

# Query AD
$users = Get-ADUser -Server $Server -LDAPFilter $ldapFilter -Properties samAccountName, name, enabled, userAccountControl, pwdLastSet, whenCreated, msDS-ResultantPSO, distinguishedName -ErrorAction SilentlyContinue

if (-not $users -or $users.Count -eq 0) {
  Write-Host "[+] No user accounts found with reversible password allowed." -ForegroundColor Green
  # emit blank CSV with headers so automation expects a file
  [pscustomobject]@{SamAccountName='';Name='';Enabled='';UserAccountControl='';PwdLastSet='';WhenCreated='';ResultantPSO='';DistinguishedName=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "CSV saved: $OutCsv"
  exit 0
}

# Build output rows
$rows = $users | ForEach-Object {
  [pscustomobject]@{
    SamAccountName      = $_.SamAccountName
    Name                = $_.Name
    Enabled             = $_.Enabled
    UserAccountControl  = $_.UserAccountControl
    PasswordNeverExpires= (($_.UserAccountControl -band 0x10000) -ne 0)  # helpful extra
    PwdLastSet          = if ($_.pwdLastSet) { [DateTime]::FromFileTime([int64]$_.pwdLastSet) } else { $null }
    WhenCreated         = $_.whenCreated
    ResultantPSO        = $_.'msDS-ResultantPSO'
    DistinguishedName   = $_.DistinguishedName
  }
}

# Save and show summary
$rows | Sort-Object SamAccountName | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ("[+] Found {0} user(s) with reversible password allowed. CSV: {1}" -f $rows.Count, $OutCsv) -ForegroundColor Yellow
$rows | Select SamAccountName,Name,Enabled,PasswordNeverExpires,PwdLastSet | Format-Table -AutoSize