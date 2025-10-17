<#
  Find-Trusts-SIDFiltering.ps1
  ----------------------------
  Usage examples:
    .\Find-Trusts-SIDFiltering.ps1 -Server corp.local
    .\Find-Trusts-SIDFiltering.ps1 -Server 10.0.0.10 -OutCsv .\trusts_sidfilter.csv
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Server,                                  # Domain FQDN, DC hostname, or DC IP

  [string]$Target,                                  

  [string]$OutCsv = ".\Trusts_SIDFiltering_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
)

function Ensure-ADModule {
  if (-not (Get-Module -Name ActiveDirectory)) {
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch { Write-Error "ActiveDirectory module not available. Install RSAT and try again."; exit 1 }
  }
}

# Try to read a boolean-like property safely
function Read-FirstPresentProperty {
  param($obj, [string[]]$Names)
  foreach ($n in $Names) {
    if ($obj.PSObject.Properties.Match($n)) {
      return $obj.$n
    }
  }
  return $null
}

function Normalize-BoolStatus {
  param($val)
  if ($null -eq $val) { return $null }
  $s = "$val".ToLowerInvariant()
  if ($s -in @('true','1','yes'))  { return 'Enabled' }
  if ($s -in @('false','0','no'))  { return 'Disabled' }
  return $null
}


Ensure-ADModule

Write-Host "[*] Querying trusts from: $Server" -ForegroundColor Cyan
if ($Target) { Write-Host "[*] Filter: Target -eq '$Target'" -ForegroundColor DarkGray }

# Build filter
$filter = if ($Target) { "Target -eq '$Target'" } else { '*' }

try {
  $trusts = Get-ADTrust -Server $Server -Filter $filter -Properties * -ErrorAction Stop
} catch {
  Write-Error "Failed to query trusts from $Server: $($_.Exception.Message)"; exit 1
}

if (-not $trusts) {
  Write-Host "[+] No trusts returned." -ForegroundColor Green
  exit 0
}

$SidFilterPropNames = @(
  'SidFilteringQuarantined',     # Common on newer builds
  'SIDFilteringQuarantined',
  'IsSidFilteringQuarantined',
  'SidFilteringEnabled',         # Some environments use an 'Enabled' phrasing
  'IsSidFilteringEnabled',
  'Quarantined'                  # Rare/legacy field names
)

$rows = foreach ($t in $trusts) {
  $sidFilterRaw   = Read-FirstPresentProperty -obj $t -Names $SidFilterPropNames
  $sidFilterState = Normalize-BoolStatus $sidFilterRaw

  $name           = $t.Name
  $partner        = $t.TrustPartner
  $target         = $t.Target
  $type           = $t.TrustType         # e.g., Forest, External, TreeRoot, etc.
  $direction      = $t.TrustDirection    # Inbound/Outbound/Bidirectional
  $attrs          = $t.TrustAttributes
  $attrsHex       = Hex $attrs
  $isForestTrans  = $t.IsForestTransitive -or $t.ForestTransitive

  $reason =
    if ($null -ne $sidFilterState) {
      "Explicit property present ($($SidFilterPropNames -join '/')) = $sidFilterRaw"
    } else {
      # No explicit property available on this object
      "No explicit SID-filtering flag exposed by this DC/API. Status set to 'Unknown'."
    }

  [pscustomobject]@{
    Name               = $name
    TrustPartner       = $partner
    Target             = $target
    TrustType          = $type
    TrustDirection     = $direction
    TrustAttributes    = $attrs
    TrustAttributesHex = $attrsHex
    ForestTransitive   = [bool]$isForestTrans
    SidFilteringStatus = ($sidFilterState ?? 'Unknown')
    SidFilteringDetail = $reason
    ServerQueried      = $Server
  }
}

$rows = $rows | Sort-Object -Property SidFilteringStatus, TrustType, Name

$rows | Select-Object Name,TrustPartner,TrustType,TrustDirection,ForestTransitive,SidFilteringStatus |
  Format-Table -Auto

$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n[*] CSV exported to: $OutCsv" -ForegroundColor Green

$unknown = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Unknown' }).Count
$disabled = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Disabled' }).Count
$enabled = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Enabled' }).Count
Write-Host ("[=] SID Filtering — Enabled: {0}  Disabled: {1}  Unknown: {2}" -f $enabled, $disabled, $unknown) -ForegroundColor Yellow


Get-ADTrust -Filter * -Server <domain-or-dc> -Properties * |
Select Name,TrustPartner,TrustType,TrustDirection,TrustAttributes,ForestTransitive,
@{n='SIDFiltering';e={$_.SidFilteringQuarantined}} |
Export-Csv ".\Trust_SIDFiltering.csv" -NoTypeInformation -Encoding UTF8
