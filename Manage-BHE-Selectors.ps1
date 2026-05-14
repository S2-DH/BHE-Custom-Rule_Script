#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive BHE Asset Group Tag Selector / Rule Manager.
    Lists ALL selectors across all asset group tags, then lets you choose what to delete.

.DESCRIPTION
    Correct endpoints (confirmed against local BHE instance):
      GET    /api/v2/asset-group-tags
      GET    /api/v2/asset-group-tags/{tagId}/selectors?limit=0
      DELETE /api/v2/asset-group-tags/{tagId}/selectors/{selectorId}

    Uses 3-step chained HMAC-SHA256 (matches BHE-API-Console.ps1)
    Reads credentials from .env file in same folder as script.

    Colour coding:
      Red   = SDH-2B-DELETED pattern
      Green = _SDH-KEEP pattern
      Gray  = Default/system selectors (is_default=true, protected)
      White = Other custom selectors

    Selection modes:
      Single  : 5
      List    : 1,3,7,12
      Range   : 1-15
      Pattern : pattern:SDH-2B-DELETED
      Tag     : tag:Tier Zero
      done    : proceed to deletion
      list    : redisplay all selectors
      quit    : exit without deleting

.PARAMETER EnvFile
    Path to .env file. Defaults to .\.env in same folder as script.

.EXAMPLE
    .\Manage-BHE-Selectors.ps1
    .\Manage-BHE-Selectors.ps1 -EnvFile "C:\creds\bhe.env"
#>

param(
    [string]$EnvFile  = "",
    [string]$BHEUrl   = "",
    [string]$TokenID  = "",
    [string]$TokenKey = "",
    [switch]$Audit,
    [switch]$NoFilter,
    [string]$DeleteFromCsv = "",
    [string]$DisableFromCsv = "",
    [string]$EnableFromCsv  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# Load .env
# ─────────────────────────────────────────────
if (-not $EnvFile) { $EnvFile = Join-Path $PSScriptRoot ".env" }

if (Test-Path $EnvFile) {
    Write-Host "  [*] Loading credentials from: $EnvFile" -ForegroundColor DarkGray
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and $line -notmatch '^\s*#') {
            if ($line -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?([^"]*)"?\s*$') {
                switch ($Matches[1]) {
                    'BHE_API_ID'  { if (-not $TokenID)  { $script:TokenID  = $Matches[2].Trim() } }
                    'BHE_API_KEY' { if (-not $TokenKey) { $script:TokenKey = $Matches[2].Trim() } }
                    'BHE_URL'     { if (-not $BHEUrl)   { $script:BHEUrl   = $Matches[2].Trim().TrimEnd('/') } }
                }
            }
        }
    }
} else {
    Write-Host "  [!] No .env file found at: $EnvFile" -ForegroundColor Yellow
}

$missing = @()
if (-not $TokenID)  { $missing += "BHE_API_ID" }
if (-not $TokenKey) { $missing += "BHE_API_KEY" }
if (-not $BHEUrl)   { $missing += "BHE_URL" }
if (@($missing).Count -gt 0) {
    Write-Error "Missing required values: $($missing -join ', '). Check your .env file."
}

# ─────────────────────────────────────────────
# 3-Step Chained HMAC-SHA256
# ─────────────────────────────────────────────
function Get-BHESignature {
    param([string]$Method, [string]$FullUrl, [string]$Body = "")
    $uriObj    = [System.Uri]$FullUrl
    $endpoint  = $uriObj.PathAndQuery
    $timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss+00:00")
    $dateKey   = $timestamp.Substring(0, 13)

    $hmac1     = New-Object System.Security.Cryptography.HMACSHA256
    $hmac1.Key = [System.Text.Encoding]::UTF8.GetBytes($TokenKey)
    $hash1     = $hmac1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Method$endpoint"))

    $hmac2     = New-Object System.Security.Cryptography.HMACSHA256
    $hmac2.Key = $hash1
    $hash2     = $hmac2.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dateKey))

    $hmac3     = New-Object System.Security.Cryptography.HMACSHA256
    $hmac3.Key = $hash2
    $hash3     = $hmac3.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Body))

    return @{
        "Authorization" = "bhesignature $TokenID"
        "RequestDate"   = $timestamp
        "Signature"     = [System.Convert]::ToBase64String($hash3)
        "Content-Type"  = "application/json"
    }
}

function Invoke-BHEGet {
    param([string]$Path)
    $url     = "$BHEUrl$Path"
    $headers = Get-BHESignature -Method "GET" -FullUrl $url
    try {
        return Invoke-RestMethod -Uri $url -Method GET -Headers $headers -ErrorAction Stop
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { "err" }
        Write-Warning "GET $Path failed (HTTP $code): $($_.Exception.Message)"
        return $null
    }
}

function Invoke-BHEDelete {
    param([string]$Path)
    $url     = "$BHEUrl$Path"
    $headers = Get-BHESignature -Method "DELETE" -FullUrl $url
    try {
        Invoke-RestMethod -Uri $url -Method DELETE -Headers $headers -ErrorAction Stop | Out-Null
        return $true
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { "err" }
        Write-Warning "DELETE $Path failed (HTTP $code): $($_.Exception.Message)"
        return $false
    }
}


function Invoke-BHEPATCH {
    param([string]$Path, [string]$Body)
    $url     = "$BHEUrl$Path"
    $headers = Get-BHESignature -Method "PATCH" -FullUrl $url -Body $Body
    try {
        Invoke-RestMethod -Uri $url -Method PATCH -Headers $headers -Body $Body -ErrorAction Stop | Out-Null
        return $true
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { "err" }
        Write-Warning "PATCH $Path failed (HTTP $code): $($_.Exception.Message)"
        return $false
    }
}

# ─────────────────────────────────────────────
# Fetch all tags and their selectors
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "     BHE Selector / Rule Manager"         -ForegroundColor Cyan
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "  BHE URL : $BHEUrl"                      -ForegroundColor DarkGray
Write-Host ""
Write-Host "  [*] Fetching asset group tags..." -ForegroundColor Cyan

$tagsResp = Invoke-BHEGet -Path "/api/v2/asset-group-tags"
if (-not $tagsResp -or -not $tagsResp.data) {
    Write-Error "Failed to retrieve asset group tags. Run Test-BHE-Connection.ps1 to diagnose."
}

$tags = $tagsResp.data.tags
if (-not $tags) { $tags = $tagsResp.data }
Write-Host "      Found $(@($tags).Count) tag(s)" -ForegroundColor Green

# ─────────────────────────────────────────────
# Build flat selector list
# ─────────────────────────────────────────────
$allSelectors = [System.Collections.Generic.List[PSCustomObject]]::new()
$idx          = 1

foreach ($tag in $tags) {
    $tagId   = $tag.id
    $tagName = $tag.name

    Write-Host "      [*] $tagName (id: $tagId)" -ForegroundColor DarkGray

    $selResp   = Invoke-BHEGet -Path "/api/v2/asset-group-tags/$tagId/selectors?limit=0"
    $selectors = $null

    if ($selResp -and $selResp.data) {
        $selectors = $selResp.data.selectors
        if (-not $selectors) { $selectors = $selResp.data }
    }

    if ($selectors) {
        $customCount  = 0
        $defaultCount = 0
        foreach ($sel in $selectors) {
            $seedSummary = ""
            if ($sel.PSObject.Properties["seeds"] -and $sel.seeds) {
                $seedSummary = ($sel.seeds | ForEach-Object {
                    $typeLabel = if ($_.type -eq 1) { "ObjectID" } elseif ($_.type -eq 2) { "Cypher" } else { "Type$($_.type)" }
                    $rawVal    = if ($_.PSObject.Properties["value"] -and $_.value) { ($_.value -replace '\s+',' ') } else { "" }
                    $preview   = $rawVal.Substring(0, [Math]::Min(60, $rawVal.Length))
                    "${typeLabel}: ${preview}..."
                }) -join " | "
            }

            $selId   = if ($sel.PSObject.Properties["id"])          { $sel.id }              else { 0 }
            $selName = if ($sel.PSObject.Properties["name"])        { $sel.name }            else { "(unnamed)" }
            $selDef  = if ($sel.PSObject.Properties["is_default"])  { [bool]$sel.is_default } else { $false }
            $selBy   = if ($sel.PSObject.Properties["created_by"])  { $sel.created_by }      else { "" }
            $selDis  = if ($sel.PSObject.Properties["disabled_at"]) { $sel.disabled_at }     else { $null }

            $allSelectors.Add([PSCustomObject]@{
                Index      = $idx
                TagID      = $tagId
                TagName    = $tagName
                SelectorID = $selId
                Name       = $selName
                IsDefault  = $selDef
                CreatedBy  = $selBy
                DisabledAt = $selDis
                Seeds      = $seedSummary
            })

            if ($selDef) { $defaultCount++ } else { $customCount++ }
            $idx++
        }
        Write-Host "          $customCount custom, $defaultCount default/system" -ForegroundColor DarkGray
    }
}

if (@($allSelectors).Count -eq 0) {
    Write-Host "  No selectors found." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# Display function
# ─────────────────────────────────────────────
function Show-AllSelectors {
    param($selectors)
    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "    ALL SELECTORS / RULES"               -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan

    $lastTag = ""
    foreach ($sel in $selectors | Sort-Object TagName, IsDefault, Name) {

        if ($sel.TagName -ne $lastTag) {
            Write-Host ""
            Write-Host "  [ Tag: $($sel.TagName) (id: $($sel.TagID)) ]" -ForegroundColor Magenta
            Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
            $lastTag = $sel.TagName
        }

        $idxLabel  = "[{0:D3}]" -f $sel.Index
        $defLabel  = if ($sel.IsDefault)   { " [DEFAULT]"  } else { "" }
        $disLabel  = if ($sel.DisabledAt)  { " [DISABLED]" } else { "" }

        $colour = switch -Regex ($sel.Name) {
            "SDH-2B-DELETED"  { "Red"     ; break }
            "_SDH-KEEP"       { "Green"   ; break }
            default {
                if ($sel.IsDefault) { "DarkGray" }
                else                { "White" }
            }
        }

        Write-Host ("  {0} {1}{2}{3}" -f $idxLabel, $sel.Name, $defLabel, $disLabel) -ForegroundColor $colour
        if ($sel.Seeds -and -not $sel.IsDefault) {
            Write-Host ("         $($sel.Seeds)") -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "  Colour key:" -ForegroundColor DarkGray
    Write-Host "    Red   = SDH-2B-DELETED pattern"              -ForegroundColor Red
    Write-Host "    Green = _SDH-KEEP pattern"                   -ForegroundColor Green
    Write-Host "    Gray  = Default/system (protected)"          -ForegroundColor DarkGray
    Write-Host "    White = Custom selectors"                    -ForegroundColor White

    $customTotal = @($selectors | Where-Object { -not $_.IsDefault }).Count
    Write-Host ""
    Write-Host "  Total: $(@($selectors).Count) selectors ($customTotal custom, $(@($selectors).Count - $customTotal) default)" -ForegroundColor Cyan
    Write-Host ""
}

Show-AllSelectors -selectors $allSelectors

# ---------------------------------------------
# AUDIT MODE - export CSV and exit, no deletion
# ---------------------------------------------
if ($Audit) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # ── Helper: export with row count ──────────────────────────────────────
    function Export-SelectorCsv {
        param($Data, $Path, $Label)
        $rows = @($Data)
        $rows | Select-Object Index, TagName, TagID, SelectorID, Name, IsDefault, CreatedBy, DisabledAt, Seeds |
            Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host ("  [{0,4}]  {1}" -f $rows.Count, $Label) -ForegroundColor White
        Write-Host ("          $Path") -ForegroundColor DarkGray
    }

    # ── CSV 1a: KEEP - Custom rules with underscore prefix (TagID=1, not default, name starts with _)
    $csv1Path = Join-Path $PSScriptRoot "BHE_Audit_1a_KEEP_Custom_Underscore_$timestamp.csv"
    $csv1Data = $allSelectors | Where-Object {
        $_.TagID -eq 1 -and
        -not $_.IsDefault -and
        $_.Name -match '^\s*_'
    }

    # ── CSV 1b: KEEP - Connector/integration rules (Jamf, Okta, GitHub, specific named objects)
    $csv1bPath = Join-Path $PSScriptRoot "BHE_Audit_1b_KEEP_Connector_Rules_$timestamp.csv"
    $csv1bData = $allSelectors | Where-Object {
        $_.TagID -eq 1 -and
        -not $_.IsDefault -and
        $_.Name -notmatch '^\s*_' -and
        (
            $_.Name -match '^Jamf:'   -or
            $_.Name -match '^Okta:'   -or
            $_.Name -match '^GitHub:' -or
            $_.Name -match '^Entra '  -or
            $_.Name -eq 'OKTAT1'      -or
            $_.Name -match '^ADMIN@'
        )
    }

    # ── CSV 2: KEEP - System/Default rules (IsDefault=TRUE, created by BloodHound)
    $csv2Path = Join-Path $PSScriptRoot "BHE_Audit_2_KEEP_System_Default_$timestamp.csv"
    $csv2Data = $allSelectors | Where-Object { $_.IsDefault -eq $true }

    # ── CSV 3: REVIEW - Non-Tier-Zero tags (TagID != 1)
    $csv3Path = Join-Path $PSScriptRoot "BHE_Audit_3_REVIEW_NonTierZero_Tags_$timestamp.csv"
    $csv3Data = $allSelectors | Where-Object { $_.TagID -ne 1 }

    # ── CSV 4: DELETE CANDIDATES
    # Default: TagID=1, IsDefault=FALSE, no underscore/connector prefix
    # -NoFilter: ALL non-default custom rules regardless of name - for manual review
    $csv4Path = Join-Path $PSScriptRoot "BHE_Audit_4_DELETE_Candidates_$timestamp.csv"

    if ($NoFilter) {
        $csv4Data = $allSelectors | Where-Object {
            -not $_.IsDefault -and
            $_.SelectorID -ne 0
        }
        Write-Host "  [!] NoFilter mode - ALL custom non-default rules in CSV 4 for manual review" -ForegroundColor Yellow
    } else {
        $csv4Data = $allSelectors | Where-Object {
            $_.TagID -eq 1 -and
            -not $_.IsDefault -and
            $_.SelectorID -ne 0 -and
            $_.Name -notmatch '^\s*_'  -and
            $_.Name -notmatch '^Jamf:' -and
            $_.Name -notmatch '^Okta:' -and
            $_.Name -notmatch '^GitHub:' -and
            $_.Name -notmatch '^Entra ' -and
            $_.Name -ne 'OKTAT1' -and
            $_.Name -notmatch '^ADMIN@'
        }
    }

    # Add a Delete column to the candidates file for review
    $csv4Rows = @($csv4Data) | ForEach-Object {
        [PSCustomObject]@{
            Delete     = ""
            Index      = $_.Index
            TagName    = $_.TagName
            TagID      = $_.TagID
            SelectorID = $_.SelectorID
            Name       = $_.Name
            IsDefault  = $_.IsDefault
            CreatedBy  = $_.CreatedBy
            DisabledAt = $_.DisabledAt
            Seeds      = $_.Seeds
        }
    }
    $csv4Rows | Export-Csv -Path $csv4Path -NoTypeInformation -Encoding UTF8

    # Export CSVs 1-3 via helper
    Export-SelectorCsv -Data $csv1Data  -Path $csv1Path  -Label "KEEP - Custom underscore rules (Tier Zero)"
    Export-SelectorCsv -Data $csv1bData -Path $csv1bPath -Label "KEEP - Connector rules (Jamf/Okta/GitHub/Entra)"
    Export-SelectorCsv -Data $csv2Data  -Path $csv2Path  -Label "KEEP - System/Default rules (BloodHound)"
    Export-SelectorCsv -Data $csv3Data  -Path $csv3Path  -Label "REVIEW - Non-Tier-Zero tags (Owned, Tier1, etc.)"
    Write-Host ("  [{0,4}]  DELETE CANDIDATES - Tier Zero, custom, no underscore, no connector prefix" -f @($csv4Data).Count) -ForegroundColor Red
    Write-Host ("          $csv4Path") -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "    AUDIT EXPORT COMPLETE"               -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Review CSV 4 (DELETE_Candidates) with your team"                              -ForegroundColor DarkGray
    Write-Host "    2. Mark Delete=YES on confirmed rows, leave blank to skip"                       -ForegroundColor DarkGray
    Write-Host "    3. Run: .\Manage-BHE-Selectors.ps1 -DeleteFromCsv '<path to CSV 4>'"            -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Note: CSV 3 (Non-Tier-Zero) should be reviewed separately before any deletion."   -ForegroundColor Yellow
    Write-Host ""
    exit
}


# ─────────────────────────────────────────────
# ---------------------------------------------
# CSV DELETION MODE
# ---------------------------------------------
if ($DeleteFromCsv) {
    if (-not (Test-Path $DeleteFromCsv)) {
        Write-Error "CSV file not found: $DeleteFromCsv"
    }

    $csvRows    = Import-Csv -Path $DeleteFromCsv
    $toDeleteCS = @($csvRows | Where-Object { $_.Delete -eq "YES" })

    if ($toDeleteCS.Count -eq 0) {
        Write-Host "  No rows marked Delete=YES in: $DeleteFromCsv" -ForegroundColor Yellow
        Write-Host "  Open the CSV, add YES in the Delete column for rows to remove, save and retry." -ForegroundColor DarkGray
        exit
    }

    # ── STEP 1: Show full deletion list ────────────────────────────────────
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "    DELETION CANDIDATE LIST"                                -ForegroundColor Red
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "  CSV File  : $DeleteFromCsv"                               -ForegroundColor DarkGray
    Write-Host "  Marked    : $($toDeleteCS.Count) rule(s) for deletion"    -ForegroundColor Red
    Write-Host ""
    Write-Host ("  {0,-6} {1,-55} {2,-10} {3}" -f "Row","Name","TagID","SelectorID") -ForegroundColor Cyan
    Write-Host ("  {0,-6} {1,-55} {2,-10} {3}" -f "---","----","-----","-----------") -ForegroundColor DarkGray

    $rowNum = 1
    foreach ($row in $toDeleteCS) {
        Write-Host ("  {0,-6} {1,-55} {2,-10} {3}" -f $rowNum, $row.Name, $row.TagID, $row.SelectorID) -ForegroundColor Yellow
        $rowNum++
    }

    Write-Host ""
    Write-Host "  Rules NOT included (safe):" -ForegroundColor Green
    Write-Host "    - BHE_Audit_1_KEEP  : Custom underscore rules"    -ForegroundColor DarkGray
    Write-Host "    - BHE_Audit_2_KEEP  : System/Default rules"       -ForegroundColor DarkGray
    Write-Host "    - BHE_Audit_3_REVIEW: Non-Tier-Zero tag rules"    -ForegroundColor DarkGray
    Write-Host ""

    $step1 = Read-Host "  List looks correct? Type CONFIRMED to continue, anything else to exit"
    if ($step1 -ne "CONFIRMED") { Write-Host "  Exited - nothing deleted." -ForegroundColor Yellow; exit }

    # ── STEP 2: Test deletion on first rule ────────────────────────────────
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "    STEP 2 - TEST DELETION (first rule only)"               -ForegroundColor Cyan
    Write-Host "  ========================================================" -ForegroundColor Cyan

    $testRow = $toDeleteCS[0]
    Write-Host "  Test rule : $($testRow.Name)" -ForegroundColor Yellow
    Write-Host "  TagID     : $($testRow.TagID)"     -ForegroundColor DarkGray
    Write-Host "  SelectorID: $($testRow.SelectorID)" -ForegroundColor DarkGray
    Write-Host ""

    $step2 = Read-Host "  Delete this one rule as a test? Type YES to proceed, anything else to skip test"
    if ($step2 -eq "YES") {
        $testPath   = "/api/v2/asset-group-tags/$($testRow.TagID)/selectors/$($testRow.SelectorID)"
        $testResult = Invoke-BHEDelete -Path $testPath
        if ($testResult) {
            Write-Host ""
            Write-Host "  [+] TEST PASSED - rule deleted successfully:" -ForegroundColor Green
            Write-Host "      $($testRow.Name)"                         -ForegroundColor Green
            Write-Host ""
            Write-Host "  Verify in BHE UI that the rule is gone, then return here." -ForegroundColor Yellow
            Write-Host ""
            $verified = Read-Host "  Verified in BHE? Type YES to proceed with full deletion, NO to stop here"
            if ($verified -ne "YES") {
                Write-Host "  Stopped after test. $($toDeleteCS.Count - 1) rules remaining." -ForegroundColor Yellow
                exit
            }
            # Remove test row from remaining list
            $toDeleteCS = @($toDeleteCS | Select-Object -Skip 1)
        } else {
            Write-Host ""
            Write-Host "  [!] TEST FAILED - could not delete: $($testRow.Name)" -ForegroundColor Red
            Write-Host "      Check API credentials and BHE connectivity before proceeding." -ForegroundColor Red
            Write-Host ""
            $proceed = Read-Host "  Test failed. Type OVERRIDE to proceed anyway, anything else to exit"
            if ($proceed -ne "OVERRIDE") { Write-Host "  Exited." -ForegroundColor Yellow; exit }
        }
    } else {
        Write-Host "  Test skipped." -ForegroundColor DarkGray
    }

    # ── STEP 3: Full deletion ──────────────────────────────────────────────
    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "    STEP 3 - FULL DELETION"                                 -ForegroundColor Red
    Write-Host "  ========================================================" -ForegroundColor Red
    Write-Host "  About to delete $($toDeleteCS.Count) remaining rule(s)."  -ForegroundColor Red
    Write-Host ""

    $step3 = Read-Host "  SAFE TO DELETE - type YES to proceed"
    if ($step3 -ne "YES") { Write-Host "  Cancelled - nothing further deleted." -ForegroundColor Yellow; exit }

    Write-Host ""
    Write-Host "  [*] Deleting..." -ForegroundColor Cyan
    Write-Host ""

    $deleted = 0
    $failed  = 0
    $failLog = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $toDeleteCS) {
        $path   = "/api/v2/asset-group-tags/$($row.TagID)/selectors/$($row.SelectorID)"
        $result = Invoke-BHEDelete -Path $path
        if ($result) {
            Write-Host "  [+] Deleted : $($row.Name)" -ForegroundColor Green
            $deleted++
        } else {
            Write-Host "  [!] Failed  : $($row.Name)" -ForegroundColor Red
            $failLog.Add($row.Name)
            $failed++
        }
    }

    Write-Host ""
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "    DELETION COMPLETE"                                       -ForegroundColor Cyan
    Write-Host "  ========================================================" -ForegroundColor Cyan
    Write-Host "  Deleted : $deleted" -ForegroundColor Green
    Write-Host "  Failed  : $failed"  -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "DarkGray" })

    if ($failLog.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed rules:" -ForegroundColor Red
        foreach ($f in $failLog) { Write-Host "    - $f" -ForegroundColor Red }
    }

    Write-Host ""
    exit
}


# ─────────────────────────────────────────────
# DISABLE FROM CSV
# ─────────────────────────────────────────────
if ($DisableFromCsv) {
    if (-not (Test-Path $DisableFromCsv)) { Write-Error "CSV file not found: $DisableFromCsv" }

    $csvRows   = Import-Csv -Path $DisableFromCsv
    $toDisable = @($csvRows | Where-Object { $_.Delete -eq "YES" })

    if ($toDisable.Count -eq 0) {
        Write-Host "  No rows marked Delete=YES in: $DisableFromCsv" -ForegroundColor Yellow
        exit
    }

    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Yellow
    Write-Host "    DISABLE CONFIRMATION"                -ForegroundColor Yellow
    Write-Host "  ======================================" -ForegroundColor Yellow
    Write-Host "  $($toDisable.Count) selector(s) will be DISABLED (not deleted - can be re-enabled):" -ForegroundColor Yellow
    Write-Host ""
    foreach ($row in $toDisable) {
        Write-Host ("  {0,-55} Tag: {1}  ID: {2}" -f $row.Name, $row.TagID, $row.SelectorID) -ForegroundColor Yellow
    }
    Write-Host ""

    $confirm = Read-Host "  Type YES to confirm disable"
    if ($confirm -ne "YES") { Write-Host "  Cancelled." -ForegroundColor Yellow; exit }

    Write-Host ""
    Write-Host "  [*] Disabling..." -ForegroundColor Cyan

    $disabled = 0
    $failed   = 0
    $failLog  = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $toDisable) {
        $path = "/api/v2/asset-group-tags/$($row.TagID)/selectors/$($row.SelectorID)"
        $body = '{"disabled":true,"id":' + $row.SelectorID + '}'
        $result = Invoke-BHEPATCH -Path $path -Body $body
        if ($result) {
            Write-Host "  [+] Disabled : $($row.Name)" -ForegroundColor Green
            $disabled++
        } else {
            Write-Host "  [!] Failed   : $($row.Name)" -ForegroundColor Red
            $failLog.Add($row.Name)
            $failed++
        }
    }

    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "    Disable Complete"                    -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "  Disabled : $disabled" -ForegroundColor Green
    Write-Host "  Failed   : $failed"   -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "DarkGray" })
    if ($failLog.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed rules:" -ForegroundColor Red
        foreach ($f in $failLog) { Write-Host "    - $f" -ForegroundColor Red }
    }
    Write-Host ""
    Write-Host "  Note: Run BHE analysis after disabling for objects to lose Tier Zero status." -ForegroundColor Yellow
    Write-Host "  To re-enable: use -EnableFromCsv with the same CSV file." -ForegroundColor DarkGray
    Write-Host ""
    exit
}

# ─────────────────────────────────────────────
# ENABLE FROM CSV
# ─────────────────────────────────────────────
if ($EnableFromCsv) {
    if (-not (Test-Path $EnableFromCsv)) { Write-Error "CSV file not found: $EnableFromCsv" }

    $csvRows  = Import-Csv -Path $EnableFromCsv
    $toEnable = @($csvRows | Where-Object { $_.Delete -eq "YES" })

    if ($toEnable.Count -eq 0) {
        Write-Host "  No rows marked Delete=YES in: $EnableFromCsv" -ForegroundColor Yellow
        Write-Host "  Mark YES on the rows you want re-enabled." -ForegroundColor DarkGray
        exit
    }

    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "    ENABLE CONFIRMATION"                 -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "  $($toEnable.Count) selector(s) will be RE-ENABLED:" -ForegroundColor Cyan
    Write-Host ""
    foreach ($row in $toEnable) {
        Write-Host ("  {0,-55} Tag: {1}  ID: {2}" -f $row.Name, $row.TagID, $row.SelectorID) -ForegroundColor White
    }
    Write-Host ""

    $confirm = Read-Host "  Type YES to confirm enable"
    if ($confirm -ne "YES") { Write-Host "  Cancelled." -ForegroundColor Yellow; exit }

    Write-Host ""
    Write-Host "  [*] Enabling..." -ForegroundColor Cyan

    $enabled = 0
    $failed  = 0
    $failLog = [System.Collections.Generic.List[string]]::new()

    foreach ($row in $toEnable) {
        $path   = "/api/v2/asset-group-tags/$($row.TagID)/selectors/$($row.SelectorID)"
        $body   = '{"disabled":false,"id":' + $row.SelectorID + '}'
        $result = Invoke-BHEPATCH -Path $path -Body $body
        if ($result) {
            Write-Host "  [+] Enabled  : $($row.Name)" -ForegroundColor Green
            $enabled++
        } else {
            Write-Host "  [!] Failed   : $($row.Name)" -ForegroundColor Red
            $failLog.Add($row.Name)
            $failed++
        }
    }

    Write-Host ""
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "    Enable Complete"                     -ForegroundColor Cyan
    Write-Host "  ======================================" -ForegroundColor Cyan
    Write-Host "  Enabled  : $enabled" -ForegroundColor Green
    Write-Host "  Failed   : $failed"  -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "DarkGray" })
    if ($failLog.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed rules:" -ForegroundColor Red
        foreach ($f in $failLog) { Write-Host "    - $f" -ForegroundColor Red }
    }
    Write-Host ""
    Write-Host "  Note: Run BHE analysis after enabling for objects to regain Tier Zero status." -ForegroundColor Yellow
    Write-Host ""
    exit
}

# Selection loop
# ─────────────────────────────────────────────
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "    SELECT RULES TO DELETE"               -ForegroundColor Cyan
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "  Single   : 5"                           -ForegroundColor Yellow
Write-Host "  List     : 1,3,7,12"                    -ForegroundColor Yellow
Write-Host "  Range    : 1-15"                        -ForegroundColor Yellow
Write-Host "  Pattern  : pattern:SDH-2B-DELETED"      -ForegroundColor Yellow
Write-Host "  Tag      : tag:Tier Zero"               -ForegroundColor Yellow
Write-Host "  Refresh  : list"                        -ForegroundColor Yellow
Write-Host "  Proceed  : done"                        -ForegroundColor Yellow
Write-Host "  Exit     : quit"                        -ForegroundColor Yellow
Write-Host ""

$toDelete = [System.Collections.Generic.List[PSCustomObject]]::new()

:selectionLoop while ($true) {

    $userInput = Read-Host "  Select"

    switch -Regex ($userInput.Trim()) {

        '^quit$' {
            Write-Host "  Exiting - nothing deleted." -ForegroundColor Yellow
            exit
        }

        '^list$' {
            Show-AllSelectors -selectors $allSelectors
        }

        '^done$' {
            break selectionLoop
        }

        '^pattern:(.+)$' {
            $pat     = $Matches[1].Trim()
            $matched = @($allSelectors | Where-Object { $_.Name -match $pat -and -not $_.IsDefault })
            if (@($matched).Count -gt 0) {
                foreach ($m in $matched) {
                    if (-not ($toDelete | Where-Object { $_.SelectorID -eq $m.SelectorID })) {
                        $toDelete.Add($m)
                        Write-Host "    [+] Queued: [$($m.Index)] $($m.Name)" -ForegroundColor Red
                    }
                }
                Write-Host "    $(@($matched).Count) selector(s) matched pattern '$pat'" -ForegroundColor DarkGray
            } else {
                Write-Host "    No custom selectors matched '$pat'" -ForegroundColor Yellow
            }
        }

        '^tag:(.+)$' {
            $tagPat  = $Matches[1].Trim()
            $matched = @($allSelectors | Where-Object { $_.TagName -match $tagPat -and -not $_.IsDefault })
            if (@($matched).Count -gt 0) {
                foreach ($m in $matched) {
                    if (-not ($toDelete | Where-Object { $_.SelectorID -eq $m.SelectorID })) {
                        $toDelete.Add($m)
                        Write-Host "    [+] Queued: [$($m.Index)] $($m.Name)" -ForegroundColor Red
                    }
                }
                Write-Host "    $(@($matched).Count) custom selector(s) added from tag '$tagPat'" -ForegroundColor DarkGray
            } else {
                Write-Host "    No custom selectors found in tag '$tagPat'" -ForegroundColor Yellow
            }
        }

        '^(\d+)-(\d+)$' {
            $from  = [int]$Matches[1]
            $to    = [int]$Matches[2]
            $items = @($allSelectors | Where-Object { $_.Index -ge $from -and $_.Index -le $to })
            foreach ($item in $items) {
                if ($item.IsDefault) {
                    Write-Host "    [SKIP] [$($item.Index)] $($item.Name) - default/system selector" -ForegroundColor DarkGray
                } elseif (-not ($toDelete | Where-Object { $_.SelectorID -eq $item.SelectorID })) {
                    $toDelete.Add($item)
                    Write-Host "    [+] Queued: [$($item.Index)] $($item.Name)" -ForegroundColor Red
                }
            }
        }

        '^[\d,\s]+$' {
            $nums = $userInput.Trim() -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
            foreach ($n in $nums) {
                $item = $allSelectors | Where-Object { $_.Index -eq [int]$n }
                if (-not $item) {
                    Write-Host "    [!] No selector with index $n" -ForegroundColor Yellow
                } elseif ($item.IsDefault) {
                    Write-Host "    [SKIP] [$($item.Index)] $($item.Name) - default/system selector" -ForegroundColor DarkGray
                } elseif (-not ($toDelete | Where-Object { $_.SelectorID -eq $item.SelectorID })) {
                    $toDelete.Add($item)
                    Write-Host "    [+] Queued: [$($item.Index)] $($item.Name)" -ForegroundColor Red
                }
            }
        }

        default {
            Write-Host "    [?] Unrecognised. Type 'list' to redisplay or 'quit' to exit." -ForegroundColor Yellow
        }
    }

    Write-Host "    --- $(@($toDelete).Count) queued for deletion ---" -ForegroundColor DarkGray
}

# ─────────────────────────────────────────────
# Confirmation
# ─────────────────────────────────────────────
if (@($toDelete).Count -eq 0) {
    Write-Host "  Nothing selected. Exiting." -ForegroundColor Yellow
    exit
}

Write-Host ""
Write-Host "  ======================================" -ForegroundColor Red
Write-Host "    DELETION CONFIRMATION"               -ForegroundColor Red
Write-Host "  ======================================" -ForegroundColor Red
Write-Host "  The following $(@($toDelete).Count) selector(s) will be PERMANENTLY DELETED:" -ForegroundColor Red
Write-Host ""
foreach ($sel in $toDelete | Sort-Object TagName, Name) {
    Write-Host ("  [{0:D3}] {1}" -f $sel.Index, $sel.Name) -ForegroundColor Yellow
    Write-Host ("        Tag: {0} | SelectorID: {1}" -f $sel.TagName, $sel.SelectorID) -ForegroundColor DarkGray
}
Write-Host ""

$confirm = Read-Host "  Type YES to confirm deletion, anything else to cancel"
if ($confirm -ne "YES") {
    Write-Host "  Cancelled - nothing deleted." -ForegroundColor Yellow
    exit
}

# ─────────────────────────────────────────────
# Delete
# ─────────────────────────────────────────────
Write-Host ""
Write-Host "  [*] Deleting..." -ForegroundColor Cyan

$deleted = 0
$failed  = 0

foreach ($sel in $toDelete) {
    $path   = "/api/v2/asset-group-tags/$($sel.TagID)/selectors/$($sel.SelectorID)"
    $result = Invoke-BHEDelete -Path $path
    if ($result) {
        Write-Host "  [+] Deleted : $($sel.Name)" -ForegroundColor Green
        $deleted++
    } else {
        Write-Host "  [!] Failed  : $($sel.Name)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "    Deletion Complete"                    -ForegroundColor Cyan
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "  Deleted : $deleted" -ForegroundColor Green
Write-Host "  Failed  : $failed"  -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "DarkGray" })
Write-Host ""
