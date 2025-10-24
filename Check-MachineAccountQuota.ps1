<#
  Check-MachineAccountQuota.ps1
  -----------------------------

  Usage:
    .\Check-MachineAccountQuota.ps1 -Server corp.local
    .\Check-MachineAccountQuota.ps1 -Server 10.0.0.10 -OutCsv C:\Temp\maq.csv
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Server,                                     # Domain FQDN, DC hostname, or IP

  [string]$OutCsv = ".\MachineAccountQuota_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

function Ensure-ADModule {
  if (-not (Get-Module -Name ActiveDirectory)) {
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch {
      Write-Error "ActiveDirectory module not available. Install RSAT and try again."
      exit 1
    }
  }
}

Ensure-ADModule

try {
  $domainDN = (Get-ADDomain -Server $Server -ErrorAction Stop).DistinguishedName
} catch {
  Write-Error "Failed to resolve domain via '$Server': $($_.Exception.Message)"
  exit 1
}

try {
  $obj = Get-ADObject -Identity $domainDN -Server $Server -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
} catch {
  Write-Error "Failed to query ms-DS-MachineAccountQuota: $($_.Exception.Message)"
  exit 1
}

$maq = $obj.'ms-DS-MachineAccountQuota'
if ($null -eq $maq) { $maq = '(not set)' }

# Console output
Write-Host "`nDomain DN: $domainDN" -ForegroundColor Cyan
Write-Host ("ms-DS-MachineAccountQuota: {0}" -f $maq) -ForegroundColor Yellow

# Export to CSV
$result = [pscustomobject]@{
  DomainDN                 = $domainDN
  ServerQueried            = $Server
  'ms-DS-MachineAccountQuota' = $maq
  Timestamp                = (Get-Date).ToString('o')
}
$result | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n[*] Result saved to: $OutCsv" -ForegroundColor Green
