<#
  Usage:
    Import-Module .\PowerView.ps1
    .\Find-AU-CanCreateDNS.ps1
    .\Find-AU-CanCreateDNS.ps1 -OutCsv C:\Temp\AU_DNS_Create.csv
#>

[CmdletBinding()]
param(
  [string]$Domain,
  [string]$DomainController,
  [string]$OutCsv = ".\AuthenticatedUsers_DNS_Create_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

foreach ($fn in 'Get-DomainObject','Get-DomainObjectAcl','ConvertFrom-SID') {
  if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
    Write-Error "PowerView function '$fn' not found. Import PowerView.ps1 first."
    exit 1
  }
}

$AuthUsersSID = 'S-1-5-11'
$rightsRegex  = 'CreateChild|GenericAll'

$common = @{}
if ($Domain)           { $common.Domain = $Domain }
if ($DomainController) { $common.DomainController = $DomainController }

Write-Host "[*] Enumerating all AD-integrated DNS zones..." -ForegroundColor Cyan
$zones = Get-DomainObject @common -LDAPFilter '(objectClass=dnsZone)' -ErrorAction SilentlyContinue

if (-not $zones) {
  Write-Host "[+] No dnsZone objects found." -ForegroundColor Yellow
  [pscustomobject]@{Zone='';ZoneDN='';Partition='';Principal='';SecurityIdentifier='';ActiveDirectoryRights='';IsInherited=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "Empty CSV saved: $OutCsv"
  exit
}

function Get-PartitionTag([string]$dn) {
  if ($dn -match 'DC=DomainDnsZones,') { return 'DomainDnsZones' }
  if ($dn -match 'DC=ForestDnsZones,') { return 'ForestDnsZones' }
  if ($dn -match 'CN=System,')         { return 'DomainNC/System' }
  return 'Unknown'
}

$findings = foreach ($z in $zones) {
  $zoneDN = $z.distinguishedName
  $zoneNm = $z.name
  $part   = Get-PartitionTag $zoneDN
  $acls   = Get-DomainObjectAcl -SearchBase $zoneDN -ErrorAction SilentlyContinue
  if (-not $acls) { continue }

  $hits = $acls | Where-Object {
    ($_.SecurityIdentifier -match $AuthUsersSID) -and
    ($_.ActiveDirectoryRights -match $rightsRegex)
  }

  foreach ($h in $hits) {
    [pscustomobject]@{
      Zone                 = $zoneNm
      ZoneDN               = $zoneDN
      Partition            = $part
      Principal            = (ConvertFrom-SID $h.SecurityIdentifier)
      SecurityIdentifier   = $h.SecurityIdentifier
      ActiveDirectoryRights= $h.ActiveDirectoryRights
      IsInherited          = $h.IsInherited
    }
  }
}

if ($findings -and $findings.Count -gt 0) {
  Write-Host "`n[!] Found $($findings.Count) affected permission entries." -ForegroundColor Yellow
  $findings | Sort-Object Partition,Zone |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "Results exported to: $OutCsv" -ForegroundColor Green
  $findings | Format-Table -AutoSize Zone,Partition,Principal,ActiveDirectoryRights,IsInherited
} else {
  Write-Host "[+] No zones grant 'Authenticated Users' CreateChild/GenericWrite/GenericAll." -ForegroundColor Green
  [pscustomobject]@{Zone='';ZoneDN='';Partition='';Principal='';SecurityIdentifier='';ActiveDirectoryRights='';IsInherited=''} |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  Write-Host "Empty CSV with headers saved to: $OutCsv"
}

Get-DomainObject -LDAPFilter '(objectClass=dnsZone)' | % { $z=$_; Get-DomainObjectAcl -SearchBase $z.distinguishedName | ?{ $_.SecurityIdentifier -match 'S-1-5-11' -and ($_.ActiveDirectoryRights -match 'CreateChild|GenericWrite|GenericAll') } | select @{n='Zone';e={$z.name}},SecurityIdentifier,ActiveDirectoryRights,IsInherited }
