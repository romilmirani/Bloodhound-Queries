<#
  Find-Trusts-SIDFiltering.ps1
  ----------------------------
  Usage:
    .\Find-Trusts-SIDFiltering.ps1 -Server 10.0.0.10 -OutCsv .\trusts_sidfilter.csv
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Server,                                  # Domain FQDN, DC hostname, or DC IP

  [string]$Target,                                  # Optional: only trusts whose Target equals this value

  [string]$OutCsv = ".\Trusts_SIDFiltering_{0}.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
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

# Return first present property value from a list of candidate names
function Read-FirstPresentProperty {
  param($obj, [string[]]$Names)
  foreach ($n in $Names) {
    if ($obj.PSObject.Properties[$n]) { return $obj.$n }
  }
  return $null
}

# Normalize various true/false/1/0 values to 'Enabled'/'Disabled'
function Normalize-BoolStatus {
  param($val)
  if ($null -eq $val) { return $null }
  $s = "$val".ToLower()
  switch ($s) {
    'true' { return 'Enabled' }
    '1'    { return 'Enabled' }
    'yes'  { return 'Enabled' }
    'false' { return 'Disabled' }
    '0'    { return 'Disabled' }
    'no'   { return 'Disabled' }
    default { return $null }
  }
}

function To-Hex {
  param($i)
  if ($i -is [int]) { return ('0x{0:X}' -f $i) } else { return $i }
}

Ensure-ADModule

Write-Host "[*] Querying trusts from: $Server" -ForegroundColor Cyan
if ($Target) { Write-Host "[*] Filter: Target -eq '$Target'" -ForegroundColor DarkGray }

# Build Get-ADTrust filter
$filter = if ($Target) { "Target -eq '$Target'" } else { "*" }

# Pull trusts (all props so we can find any SID-filter flag the DC exposes)
try {
  $trusts = Get-ADTrust -Server $Server -Filter $filter -Properties * -ErrorAction Stop
} catch {
  Write-Error "Failed to query trusts from $Server: $($_.Exception.Message)"
  exit 1
}

if (-not $trusts) {
  Write-Host "[+] No trusts returned." -ForegroundColor Green
  exit 0
}

# Common property names seen across AD builds
$SidFilterPropNames = @(
  'SidFilteringQuarantined',
  'SIDFilteringQuarantined',
  'IsSidFilteringQuarantined',
  'SidFilteringEnabled',
  'IsSidFilteringEnabled',
  'Quarantined'
)

# Build output rows
$rows = @()
foreach ($t in $trusts) {
  $sidFilterRaw   = Read-FirstPresentProperty -obj $t -Names $SidFilterPropNames
  $sidFilterState = Normalize-BoolStatus $sidFilterRaw

  if ($null -ne $sidFilterState) {
    $SidFilteringStatus = $sidFilterState
    $SidFilteringDetail = "Explicit property found ($($SidFilterPropNames -join '/')) = $sidFilterRaw"
  } else {
    $SidFilteringStatus = 'Unknown'
    $SidFilteringDetail = "No explicit SID-filtering flag exposed by this DC/API."
  }

  $forestTrans = $false
  if ($t.PSObject.Properties['IsForestTransitive']) { $forestTrans = [bool]$t.IsForestTransitive }
  elseif ($t.PSObject.Properties['ForestTransitive']) { $forestTrans = [bool]$t.ForestTransitive }

  $rows += [pscustomobject]@{
    Name               = $t.Name
    TrustPartner       = $t.TrustPartner
    Target             = $t.Target
    TrustType          = $t.TrustType
    TrustDirection     = $t.TrustDirection
    TrustAttributes    = $t.TrustAttributes
    TrustAttributesHex = To-Hex $t.TrustAttributes
    ForestTransitive   = $forestTrans
    SidFilteringStatus = $SidFilteringStatus
    SidFilteringDetail = $SidFilteringDetail
    ServerQueried      = $Server
  }
}

# Sort and show compact view
$rows = $rows | Sort-Object -Property SidFilteringStatus, TrustType, Name
$rows | Select-Object Name,TrustPartner,TrustType,TrustDirection,ForestTransitive,SidFilteringStatus | Format-Table -AutoSize

# Export CSV
$rows | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n[*] CSV exported to: $OutCsv" -ForegroundColor Green

# Summary line
$enabled  = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Enabled' }).Count
$disabled = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Disabled' }).Count
$unknown  = ($rows | Where-Object { $_.SidFilteringStatus -eq 'Unknown' }).Count
Write-Host ("[=] SID Filtering - Enabled: {0}  Disabled: {1}  Unknown: {2}" -f $enabled, $disabled, $unknown) -ForegroundColor Yellow
