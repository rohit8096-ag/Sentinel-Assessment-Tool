#Requires -Version 5.1

<#
.SYNOPSIS
    Azure Sentinel MITRE ATT&CK Coverage Analyzer
    
.DESCRIPTION
    Comprehensive analysis of Sentinel analytical rules with MITRE ATT&CK coverage,
    table optimization insights, and Defender custom detection integration.
    
    Generates an interactive HTML report with:
    - MITRE coverage analysis across all 211 techniques
    - Table optimization and data ingestion metrics
    - Defender for Endpoint custom detection rules
    - Full MITRE ATT&CK Navigator visualization
    
.PARAMETER WorkspaceId
    Log Analytics Workspace ID (GUID). If provided, skips workspace lookup.
    
.PARAMETER SubscriptionId
    Azure Subscription ID (optional if WorkspaceId provided)
    
.PARAMETER ResourceGroup
    Resource Group name (optional if WorkspaceId provided)
    
.PARAMETER WorkspaceName
    Workspace name (optional if WorkspaceId provided)
    
.PARAMETER TenantId
    Azure AD Tenant ID for Graph API authentication
    
.PARAMETER ClientId
    App Registration Client ID for Defender API access
    
.PARAMETER ClientSecret
    App Registration Client Secret (SecureString)
    
.PARAMETER ExportHtml
    Generate HTML report (saved to Downloads folder)
    
.EXAMPLE
    Get-SentinelAnalyticalRulesReport -WorkspaceId "guid" -TenantId "guid" -ClientId "guid" -ClientSecret $secret -ExportHtml
    
    Direct workspace access with Defender integration
    
.EXAMPLE
    Get-SentinelAnalyticalRulesReport -SubscriptionId "sub-id" -ResourceGroup "rg" -WorkspaceName "workspace" -ExportHtml
    
    Workspace lookup via Management API (may encounter 401 errors)
    
.NOTES
    File Name  : SentinelMITREAnalyzer.psm1
    Author     : Security Team
    Version    : 2.0
    Date       : 2026-03-10
    Requires   : Azure CLI or Az.Accounts PowerShell module
    
#>

# Module configuration
$script:Version = "2.0"
$script:Author = "Rohit Ashok"
$script:MgmtEndpoint = "https://management.azure.com"
$script:TotalMitreTechniques = 211

# MITRE tactic order (matches ATT&CK framework)
$script:TacticOrder = @(
    "InitialAccess","Execution","Persistence","PrivilegeEscalation",
    "DefenseEvasion","CredentialAccess","Discovery","LateralMovement",
    "Collection","CommandAndControl","Exfiltration","Impact",
    "Reconnaissance","ResourceDevelopment"
)

# Display names for tactics
$script:TacticNames = @{
    "InitialAccess"="Initial Access"
    "Execution"="Execution"
    "Persistence"="Persistence"
    "PrivilegeEscalation"="Privilege Escalation"
    "DefenseEvasion"="Defense Evasion"
    "CredentialAccess"="Credential Access"
    "Discovery"="Discovery"
    "LateralMovement"="Lateral Movement"
    "Collection"="Collection"
    "CommandAndControl"="Command & Control"
    "Exfiltration"="Exfiltration"
    "Impact"="Impact"
    "Reconnaissance"="Reconnaissance"
    "ResourceDevelopment"="Resource Development"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-UserDownloadsPath {
    if ($IsWindows -or $null -eq $IsWindows) {
        return Join-Path $env:USERPROFILE "Downloads"
    }
    return Join-Path $env:HOME "Downloads"
}

function Get-TechniqueBase {
    param([string]$TechId)
    if ($TechId -match '^(T\d+)') {
        return $Matches[1]
    }
    return $TechId
}

function Extract-MitreData {
    param($RuleObject)
    
    $props = $RuleObject.properties
    $tactics = @()
    $techniques = @()
    
    if ($props.tactics) {
        $tactics = $props.tactics
    }
    
    if ($props.techniques) {
        $techniques = $props.techniques
    } elseif ($props.mitreTechniques) {
        $techniques = $props.mitreTechniques
    }
    
    return @{
        Tactics = $tactics
        Techniques = $techniques
    }
}

# Table Optimization Functions
function Invoke-KqlQuery {
    param(
        [string]$WorkspaceId,
        [string]$Query,
        [string]$Token
    )
    
    $uri = "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query"
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    # Properly format the request body
    $bodyObject = @{
        query = $Query
    }
    
    $body = $bodyObject | ConvertTo-Json -Compress
    
    # DEBUG: Show what we're sending
    Write-Host "      DEBUG: URI = $uri" -ForegroundColor DarkGray
    Write-Host "      DEBUG: Query = $($Query -replace "`n", ' ' | Select-Object -First 100)..." -ForegroundColor DarkGray
    Write-Host "      DEBUG: Token length = $($Token.Length)" -ForegroundColor DarkGray
    
    try {
        # Use -Verbose to capture detailed error info
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body -ErrorAction Stop
        
        if (-not $response.tables -or $response.tables.Count -eq 0) {
            Write-Host "      ⚠ No tables in response" -ForegroundColor Yellow
            return @()
        }
        
        $table = $response.tables[0]
        
        if (-not $table.rows -or $table.rows.Count -eq 0) {
            Write-Host "      ⚠ No rows in table" -ForegroundColor Yellow
            return @()
        }
        
        $columns = $table.columns | ForEach-Object { $_.name }
        
        $rows = foreach ($row in $table.rows) {
            $obj = [ordered]@{}
            for ($i = 0; $i -lt $columns.Count; $i++) {
                $obj[$columns[$i]] = $row[$i]
            }
            [PSCustomObject]$obj
        }
        
        Write-Host "      ✓ Query returned $($rows.Count) rows" -ForegroundColor Green
        return $rows
        
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Host "      ✗ Query failed: $errorMsg" -ForegroundColor Red
        
        # Show the full exception
        Write-Host "      Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor Gray
        
        # Try to get detailed error from response
        if ($_.ErrorDetails) {
            Write-Host "      Error Details: $($_.ErrorDetails.Message)" -ForegroundColor Gray
        }
        
        if ($_.Exception.Response) {
            Write-Host "      Response Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Gray
            
            # Try different methods to read response
            try {
                $result = $_.Exception.Response.Content.ReadAsStringAsync().Result
                Write-Host "      Response Body: $result" -ForegroundColor Gray
            } catch {
                Write-Host "      Could not read response body" -ForegroundColor DarkGray
            }
        }
        
        # Re-throw so we can catch it upstream
        throw
    }
}

function Get-IngestedTables {
    param(
        [string]$WorkspaceId,
        [string]$Token,
        [int]$LookbackDays = 30
    )
    
    # Simplified KQL query - more reliable
    $kql = @"
Usage
| where TimeGenerated > ago($($LookbackDays)d)
| where DataType != "Operation" and DataType != "Watchlist"
| summarize LastSeen = max(TimeGenerated), TotalGB = round(sum(Quantity)/1024, 4) by DataType
| order by DataType asc
"@
    
    Write-Host "      → Querying Usage table (last $LookbackDays days)..." -ForegroundColor Gray
    Write-Host "      → Workspace ID: $WorkspaceId" -ForegroundColor Gray
    
    $result = Invoke-KqlQuery -WorkspaceId $WorkspaceId -Query $kql -Token $Token
    
    if ($result -and $result.Count -gt 0) {
        Write-Host "      ✓ Retrieved $($result.Count) tables from Usage" -ForegroundColor Green
        
        # Show sample for debugging
        if ($result.Count -ge 3) {
            Write-Host "      Sample: $($result[0].DataType) ($($result[0].TotalGB) GB)" -ForegroundColor Gray
        }
        
        return $result
    } else {
        Write-Host "      ⚠ No data returned from Usage table query" -ForegroundColor Yellow
        return @()
    }
}

function Get-RuleTableMappings {
    param(
        [array]$Rules,
        [hashtable]$TableLookup
    )
    
    $mappings = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    foreach ($rule in $Rules) {
        if ($rule.kind -ne "Scheduled") { continue }
        
        $queryLower = $rule.properties.query.ToLower()
        $matched = @()
        
        foreach ($tblKey in $TableLookup.Keys) {
            if ($queryLower -match "(?<![a-z0-9_])$([regex]::Escape($tblKey))(?![a-z0-9_])") {
                $matched += $TableLookup[$tblKey].DataType
            }
        }
        
        $mappings.Add([PSCustomObject]@{
            RuleName = $rule.properties.displayName
            Enabled = $rule.properties.enabled
            Severity = $rule.properties.severity
            Tactics = ($rule.properties.tactics -join ", ")
            Tables = if ($matched.Count -gt 0) { $matched } else { @("(no match)") }
            TableSizes = if ($matched.Count -gt 0) { 
                $matched | ForEach-Object { $TableLookup[$_.ToLower()].TotalGB }
            } else { @() }
        })
    }
    
    return $mappings
}

# Authentication handler with improved error handling
function Get-AzureToken {
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Authentication Check" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    $tokens = @{
        Management = $null
        LogAnalytics = $null
    }
    $issues = @()

    # Check for Azure CLI first (more reliable for multi-scope auth)
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCmd) { $azCmd = Get-Command az.cmd -ErrorAction SilentlyContinue }
    
    if ($azCmd) {
        Write-Host "  [Method 1] Checking Azure CLI..." -ForegroundColor White
        
        try {
            $accountInfo = & $azCmd.Source account show --output json 2>&1
            if ($LASTEXITCODE -eq 0) {
                $acct = $accountInfo | ConvertFrom-Json
                Write-Host "      ✓ CLI installed" -ForegroundColor Green
                Write-Host "      ✓ Logged in as: $($acct.user.name)" -ForegroundColor Green
                
                # Get Management token
                $tokenInfo = & $azCmd.Source account get-access-token --resource "https://management.azure.com" --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $tokenData = $tokenInfo | ConvertFrom-Json
                    if ($tokenData.accessToken.Length -gt 100) {
                        $tokens.Management = $tokenData.accessToken
                        Write-Host "      ✓ Management token obtained" -ForegroundColor Green
                        
                        # Get Log Analytics token
                        $laTokenInfo = & $azCmd.Source account get-access-token --resource "https://api.loganalytics.io" --output json 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            $laTokenData = $laTokenInfo | ConvertFrom-Json
                            $tokens.LogAnalytics = $laTokenData.accessToken
                            Write-Host "      ✓ Log Analytics token obtained" -ForegroundColor Green
                        } else {
                            Write-Host "      ⚠ Log Analytics token unavailable (Table Optimization will be skipped)" -ForegroundColor Yellow
                        }
                        
                        Write-Host ""
                        return $tokens
                    }
                }
            }
        } catch {
            $issues += "CLI error: $($_.Exception.Message)"
        }
    }

    # Try Az PowerShell as fallback
    Write-Host "  [Method 2] Checking Az PowerShell..." -ForegroundColor White
    
    $azMod = Get-Module -Name Az.Accounts -ListAvailable
    if ($azMod) {
        Write-Host "      ✓ Az module found (v$($azMod[0].Version))" -ForegroundColor Green
        
        try {
            Import-Module Az.Accounts -ErrorAction Stop
            $context = Get-AzContext -ErrorAction Stop
            
            if ($context) {
                Write-Host "      ✓ Logged in as: $($context.Account.Id)" -ForegroundColor Green
                Write-Host "      ✓ Subscription: $($context.Subscription.Name)" -ForegroundColor Green
                
                # Get Management token
                try {
                    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
                    $token = $tokenObj.Token
                    
                    if ($token -is [System.Security.SecureString]) {
                        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
                        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
                    }
                    
                    if ($token.Length -gt 100) {
                        $tokens.Management = $token
                        Write-Host "      ✓ Management token obtained" -ForegroundColor Green
                    }
                } catch {
                    $issues += "Failed to get Management token: $($_.Exception.Message)"
                }
                
                # Get Log Analytics token
                try {
                    $laTokenObj = Get-AzAccessToken -ResourceUrl "https://api.loganalytics.io/" -ErrorAction Stop
                    $laToken = $laTokenObj.Token
                    
                    if ($laToken -is [System.Security.SecureString]) {
                        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($laToken)
                        $laToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
                    }
                    
                    if ($laToken.Length -gt 100) {
                        $tokens.LogAnalytics = $laToken
                        Write-Host "      ✓ Log Analytics token obtained" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "      ⚠ Log Analytics token unavailable" -ForegroundColor Yellow
                    Write-Host "      Note: Table Optimization will be skipped" -ForegroundColor Gray
                    Write-Host "      Fix: Reconnect with: Connect-AzAccount -AuthScope https://api.loganalytics.io/" -ForegroundColor Gray
                }
                
                if ($tokens.Management) {
                    Write-Host ""
                    return $tokens
                }
            } else {
                $issues += "No Az context"
            }
        } catch {
            $issues += "Az module error: $($_.Exception.Message)"
        }
    } else {
        $issues += "Az module not installed"
    }

    # Authentication failed
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  Authentication Failed" -ForegroundColor Red
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Issues detected:" -ForegroundColor Yellow
    foreach ($issue in $issues) {
        Write-Host "    • $issue" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Fix: Run one of these commands first:" -ForegroundColor Yellow
    Write-Host "    az login  (recommended)" -ForegroundColor White
    Write-Host "    Connect-AzAccount -AuthScope https://api.loganalytics.io/" -ForegroundColor White
    Write-Host ""
    
    throw "Authentication required"
}

# Graph API Authentication
function Get-GraphApiToken {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$ClientId,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    
    Write-Host "  [Graph API] Authenticating..." -ForegroundColor White
    Write-Host "      Tenant ID: $($TenantId.Substring(0, 8))..." -ForegroundColor Gray
    Write-Host "      Client ID: $($ClientId.Substring(0, 8))..." -ForegroundColor Gray
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    # Properly URL-encode the request body
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        Write-Host "      ✓ Graph API token obtained" -ForegroundColor Green
        return $response.access_token
    } catch {
        Write-Host "      ✗ Failed to get Graph API token" -ForegroundColor Red
        
        # Get detailed error
        $errorDetails = $null
        if ($_.ErrorDetails) {
            try {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                Write-Host "      Error Code: $($errorDetails.error)" -ForegroundColor Yellow
                Write-Host "      Error Description: $($errorDetails.error_description)" -ForegroundColor Yellow
            } catch {
                Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Common issues
        Write-Host "" -ForegroundColor Yellow
        Write-Host "      Common causes:" -ForegroundColor Yellow
        Write-Host "        1. Invalid Tenant ID (check Azure AD overview)" -ForegroundColor White
        Write-Host "        2. Invalid Client ID (check App Registration)" -ForegroundColor White
        Write-Host "        3. Invalid or expired Client Secret" -ForegroundColor White
        Write-Host "        4. Special characters in secret not properly handled" -ForegroundColor White
        
        throw "Graph API authentication failed"
    }
}

# Fetch Defender Custom Detection Rules
function Get-DefenderCustomRules {
    param(
        [Parameter(Mandatory)]
        [string]$GraphToken
    )
    
    Write-Host "  → Fetching Defender custom detection rules..." -ForegroundColor White
    
    $headers = @{
        "Authorization" = "Bearer $GraphToken"
        "Content-Type"  = "application/json"
    }
    
    # Microsoft Defender Advanced Hunting Custom Detection Rules endpoint
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
        
        $rules = $response.value
        Write-Host "      ✓ Retrieved $($rules.Count) Defender custom rules" -ForegroundColor Green
        
        return $rules
    } catch {
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode.value__ } catch {}
        
        switch ($statusCode) {
            401 { Write-Host "      ✗ Unauthorized - Check TenantId, ClientId, and ClientSecret" -ForegroundColor Red }
            403 { Write-Host "      ✗ Forbidden - App needs 'SecurityEvents.Read.All' permission in Microsoft Graph" -ForegroundColor Red }
            404 { Write-Host "      ✗ Endpoint not found - Ensure Defender for Endpoint is enabled" -ForegroundColor Red }
            default { Write-Host "      ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red }
        }
        
        return @()
    }
}

# API helper
function Call-SentinelAPI {
    param(
        [string]$Uri,
        [string]$Token
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    
    $results = @()
    $nextUrl = $Uri
    
    while ($nextUrl) {
        try {
            $response = Invoke-RestMethod -Uri $nextUrl -Headers $headers -Method Get -ErrorAction Stop
            
            if ($response.value) {
                $results += $response.value
            }
            
            $nextUrl = $response.nextLink
        } catch {
            $status = $null
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            
            switch ($status) {
                401 { throw "Unauthorized - token may have expired" }
                403 { throw "Forbidden - need 'Microsoft Sentinel Reader' role" }
                404 { throw "Not found - check subscription/resource group/workspace names" }
                default { throw $_.Exception.Message }
            }
        }
    }
    
    return $results
}

# HTML report generator with tabs
function Build-HtmlReport {
    param(
        [array]$AllRules,
        [array]$EnabledRules,
        [array]$DisabledRules,
        [hashtable]$TacticData,
        [object]$TableData,
        [object]$DefenderData,
        [string]$WorkspaceName,
        [string]$OutputFile
    )

    Write-Host "  → Generating HTML report with tabs..." -ForegroundColor Cyan

    $total = $AllRules.Count
    $enabled = $EnabledRules.Count
    $disabled = $DisabledRules.Count
    $enabledPct = if ($total) { [math]::Round(($enabled / $total) * 100, 1) } else { 0 }

    # Calculate unique techniques (base techniques only, no sub-techniques)
    $uniqueTechs = [System.Collections.Generic.HashSet[string]]::new()
    $allTechniquesList = @()
    
    foreach ($rule in $EnabledRules) {
        $mitreInfo = Extract-MitreData $rule
        foreach ($tech in $mitreInfo.Techniques) {
            if ($tech) {
                $allTechniquesList += $tech
                $base = Get-TechniqueBase $tech
                [void]$uniqueTechs.Add($base)
            }
        }
    }
    
    $techCount = $uniqueTechs.Count
    $totalTechniqueReferences = $allTechniquesList.Count
    
    Write-Host "  → Debug: Total technique references across all rules: $totalTechniqueReferences" -ForegroundColor Gray
    Write-Host "  → Debug: Unique base techniques: $techCount" -ForegroundColor Gray
    
    # Calculate unique tactics coverage as well
    $uniqueTactics = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($rule in $EnabledRules) {
        $mitreInfo = Extract-MitreData $rule
        foreach ($tactic in $mitreInfo.Tactics) {
            if ($tactic) {
                [void]$uniqueTactics.Add($tactic)
            }
        }
    }
    $tacticCount = $uniqueTactics.Count
    $totalTactics = 14  # Total MITRE tactics
    $tacticCoverage = [math]::Round(($tacticCount / $totalTactics) * 100, 1)
    
    # Calculate coverage percentage
    $coverageRaw = if ($script:TotalMitreTechniques -gt 0) { 
        ($techCount / [double]$script:TotalMitreTechniques) * 100.0 
    } else { 0 }
    $coverage = [math]::Round($coverageRaw, 1)
    
    Write-Host "  → Debug: Coverage calculation: $techCount / $script:TotalMitreTechniques = $coverageRaw% (rounded to $coverage%)" -ForegroundColor Gray
    
    # Determine coverage metric to display
    if ($techCount -lt 10) {
        Write-Host "  → Using Tactic-based coverage (technique count too low)" -ForegroundColor Yellow
        $coverage = $tacticCoverage
        $coverageMetric = "Tactic"
    } else {
        Write-Host "  → Using Technique-based coverage" -ForegroundColor Green
        $coverageMetric = "Technique"
    }

    # Coverage grade
    $grade = if ($coverage -ge 80) { "A - Excellent" }
        elseif ($coverage -ge 60) { "B - Good" }
        elseif ($coverage -ge 40) { "C - Moderate" }
        elseif ($coverage -ge 20) { "D - Limited" }
        else { "F - Needs Improvement" }

    # Radar chart data
    $radarLabels = @()
    $radarValues = @()
    foreach ($tactic in $script:TacticOrder) {
        if ($TacticData[$tactic]) {
            $label = $script:TacticNames[$tactic]
            $radarLabels += """$label"""
            $radarValues += $TacticData[$tactic].EnabledCount
        }
    }

    # MITRE: Enabled rules per tactic table
    $tacticRows = ""
    foreach ($tactic in $script:TacticOrder) {
        if ($TacticData[$tactic]) {
            $label = $script:TacticNames[$tactic]
            $enCount = $TacticData[$tactic].EnabledCount
            $totCount = $TacticData[$tactic].Total
            $barWidth = if ($totCount) { [math]::Round(($enCount / $totCount) * 100) } else { 0 }
            
            $tacticRows += @"
<tr>
    <td><strong>$label</strong></td>
    <td>$enCount</td>
    <td>$totCount</td>
    <td>
        <div style='background:#e9ecef;border-radius:4px;height:20px;width:100%'>
            <div style='background:#3b82f6;height:20px;width:${barWidth}%;border-radius:4px'></div>
        </div>
    </td>
</tr>
"@
        }
    }

    # Rule Source Breakdown
    $gallery = $EnabledRules | Where-Object {
        $_.properties.templateVersion -or $_.properties.templateId -or
        $_.kind -in @('MicrosoftSecurityIncidentCreation','Fusion','ThreatIntelligence')
    }
    $custom = $EnabledRules | Where-Object {
        -not ($_.properties.templateVersion -or $_.properties.templateId) -and
        $_.kind -notin @('MicrosoftSecurityIncidentCreation','Fusion','ThreatIntelligence')
    }
    $galleryCount = $gallery.Count
    $customCount = $custom.Count
    $galleryPct = if ($enabled -gt 0) { [math]::Round(($galleryCount / $enabled) * 100, 1) } else { 0 }
    $customPct = if ($enabled -gt 0) { [math]::Round(($customCount / $enabled) * 100, 1) } else { 0 }

    # Disabled Rules
    $disabledRulesRows = ""
    $disabledTop50 = $DisabledRules | Select-Object -First 50
    foreach ($rule in $disabledTop50) {
        $tactics = if ($rule.properties.tactics) { ($rule.properties.tactics -join ", ") } else { "None" }
        $desc = if ($rule.properties.description) { 
            $rule.properties.description.Substring(0, [Math]::Min(100, $rule.properties.description.Length)) 
        } else { "No description" }
        $sevColor = switch ($rule.properties.severity) {
            "High" { "#dc3545" }
            "Medium" { "#ffc107" }
            "Low" { "#17a2b8" }
            default { "#6c757d" }
        }
        
        $disabledRulesRows += "<tr><td>$($rule.properties.displayName)</td>" +
            "<td><span class='badge' style='background:$sevColor'>$($rule.properties.severity)</span></td>" +
            "<td style='font-size:0.9em'>$tactics</td>" +
            "<td style='font-size:0.85em;color:#64748b'>$desc...</td></tr>`n"
    }

    # Rules Without MITRE Mapping
    $rulesWithoutMitreRows = ""
    $rulesWithoutMitre = $EnabledRules | Where-Object {
        $mitreInfo = Extract-MitreData $_
        $mitreInfo.Tactics.Count -eq 0
    } | Select-Object -First 30
    
    foreach ($rule in $rulesWithoutMitre) {
        $desc = if ($rule.properties.description) { 
            $rule.properties.description.Substring(0, [Math]::Min(80, $rule.properties.description.Length)) 
        } else { "No description" }
        $sevColor = switch ($rule.properties.severity) {
            "High" { "#dc3545" }
            "Medium" { "#ffc107" }
            "Low" { "#17a2b8" }
            default { "#6c757d" }
        }
        
        $rulesWithoutMitreRows += "<tr><td>$($rule.properties.displayName)</td>" +
            "<td><span class='badge' style='background:$sevColor'>$($rule.properties.severity)</span></td>" +
            "<td style='font-size:0.85em;color:#64748b'>$desc...</td></tr>`n"
    }

    # Coverage Gaps - Top 5 Least Covered Tactics
    $coverageGapsRows = ""
    $coverageGaps = $TacticData.GetEnumerator() | 
        Where-Object { 
            $_.Value.Total -gt 0 -and 
            $script:TacticNames.ContainsKey($_.Key) 
        } |
        ForEach-Object {
            $pct = if ($_.Value.Total -gt 0) { [math]::Round(($_.Value.EnabledCount / $_.Value.Total) * 100, 1) } else { 0 }
            [PSCustomObject]@{
                Tactic = $script:TacticNames[$_.Key]
                Enabled = $_.Value.EnabledCount
                Total = $_.Value.Total
                CoveragePct = $pct
            }
        } |
        Where-Object { $_.Tactic } |  # Filter out any null/empty tactics
        Sort-Object CoveragePct |
        Select-Object -First 5
    
    foreach ($gap in $coverageGaps) {
        $barColor = if ($gap.CoveragePct -lt 50) { "#ef4444" } 
            elseif ($gap.CoveragePct -lt 75) { "#ffc107" } 
            else { "#22c55e" }
        
        $coverageGapsRows += "<tr><td><strong>$($gap.Tactic)</strong></td>" +
            "<td>$($gap.Enabled) of $($gap.Total)</td>" +
            "<td>$($gap.CoveragePct)%</td>" +
            "<td><div style='background:#e9ecef;border-radius:4px;height:20px;width:100%'>" +
            "<div style='background:$barColor;height:20px;width:$($gap.CoveragePct)%;border-radius:4px'></div></div></td></tr>`n"
    }

    # Defender Custom Rules HTML
    $defenderHtml = ""
    
    if ($DefenderData -and $DefenderData.AllRules.Count -gt 0) {
        $defTotal = $DefenderData.AllRules.Count
        $defEnabled = $DefenderData.EnabledRules.Count
        $defDisabled = $DefenderData.DisabledRules.Count
        
        # Tactic-wise count with chart data
        $defTacticRows = ""
        $defenderChartLabels = ""
        $defenderChartValues = ""
        $defenderChartColors = ""
        
        if ($defenderData.TacticCounts.Count -gt 0) {
            # Sort tactics by value descending
            $sortedTactics = $defenderData.TacticCounts.GetEnumerator() | Sort-Object Value -Descending
            
            # Build table rows
            $sortedTactics | ForEach-Object {
                $defTacticRows += "<tr><td><strong>$($_.Key)</strong></td><td>$($_.Value)</td></tr>`n"
            }
            
            # Build chart data
            $tacticLabels = @()
            $tacticValues = @()
            $tacticColors = @()
            
            $colorPalette = @(
                'rgba(59, 130, 246, 0.8)',   # Blue
                'rgba(16, 185, 129, 0.8)',   # Green
                'rgba(245, 158, 11, 0.8)',   # Amber
                'rgba(239, 68, 68, 0.8)',    # Red
                'rgba(139, 92, 246, 0.8)',   # Purple
                'rgba(236, 72, 153, 0.8)',   # Pink
                'rgba(14, 165, 233, 0.8)',   # Sky
                'rgba(34, 197, 94, 0.8)',    # Emerald
                'rgba(249, 115, 22, 0.8)',   # Orange
                'rgba(168, 85, 247, 0.8)',   # Violet
                'rgba(6, 182, 212, 0.8)',    # Cyan
                'rgba(234, 179, 8, 0.8)',    # Yellow
                'rgba(156, 163, 175, 0.8)',  # Gray
                'rgba(220, 38, 38, 0.8)',    # Deep Red
                'rgba(37, 99, 235, 0.8)'     # Deep Blue
            )
            
            $colorIndex = 0
            $sortedTactics | ForEach-Object {
                # Special handling for "No Mapping Found"
                if ($_.Key -eq "No Mapping Found") {
                    $tacticLabels += """$($_.Key)"""
                    $tacticValues += $_.Value
                    $tacticColors += "'rgba(156, 163, 175, 0.8)'"  # Gray for unmapped
                } else {
                    $tacticLabels += """$($_.Key)"""
                    $tacticValues += $_.Value
                    $tacticColors += "'$($colorPalette[$colorIndex % $colorPalette.Length])'"
                    $colorIndex++
                }
            }
            
            $defenderChartLabels = $tacticLabels -join ","
            $defenderChartValues = $tacticValues -join ","
            $defenderChartColors = $tacticColors -join ","
            
        } else {
            $defTacticRows = @"
<tr>
    <td colspan='2' style='text-align:center;padding:30px'>
        <div style='color:#64748b'>
            <strong style='font-size:1.1em;display:block;margin-bottom:10px'>No MITRE Tactics Mapped</strong>
            <p style='margin:5px 0'>Your $defEnabled enabled rules don't have MITRE ATT&CK framework mappings.</p>
            <p style='margin:5px 0;font-size:0.9em'>This is common for custom detection rules created without explicit MITRE tagging.</p>
        </div>
    </td>
</tr>
"@
        }
        
        # Disabled rules with last modified
        $defDisabledRows = ""
        foreach ($rule in $DefenderData.DisabledRules | Sort-Object lastModifiedDateTime -Descending) {
            $ruleName = $rule.displayName
            $lastMod = if ($rule.lastModifiedDateTime) { 
                try {
                    ([DateTime]$rule.lastModifiedDateTime).ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $rule.lastModifiedDateTime
                }
            } else { "Unknown" }
            
            # Defender stores MITRE data in detectionAction.alertTemplate
            $category = "None"
            $techniques = ""
            
            if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                if ($rule.detectionAction.alertTemplate.category) {
                    $category = $rule.detectionAction.alertTemplate.category
                }
                
                if ($rule.detectionAction.alertTemplate.mitreTechniques -and 
                    $rule.detectionAction.alertTemplate.mitreTechniques.Count -gt 0) {
                    $techniques = " (" + ($rule.detectionAction.alertTemplate.mitreTechniques -join ", ") + ")"
                }
            }
            
            $defDisabledRows += "<tr><td>$ruleName</td><td>$category$techniques</td><td style='font-size:0.85em;color:#64748b'>$lastMod</td></tr>`n"
        }
        
        $defenderHtml = @"
            <div class="section">
                <h2>📊 Overview</h2>
                <p class="section-desc">Summary of Microsoft Defender custom detection rules.</p>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Rules</h3>
                        <div class="value">$defTotal</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#22c55e">
                        <h3>Enabled</h3>
                        <div class="value" style="color:#22c55e">$defEnabled</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#ef4444">
                        <h3>Disabled</h3>
                        <div class="value" style="color:#ef4444">$defDisabled</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🎯 Rules by MITRE Tactic</h2>
                <p class="section-desc">Distribution of enabled custom detection rules across MITRE ATT&CK tactics.</p>
                
                <div class="chart-wrapper" style="max-width:800px; height:400px; margin:0 auto 30px">
                    <canvas id="defenderTacticChart"></canvas>
                </div>
                
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>MITRE Tactic</th>
                                <th>Rule Count</th>
                            </tr>
                        </thead>
                        <tbody>$defTacticRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>🚫 Disabled Rules</h2>
                <p class="section-desc">Custom detection rules that are currently disabled, sorted by last modification date.</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>MITRE Tactic</th>
                                <th>Last Modified</th>
                            </tr>
                        </thead>
                        <tbody>$defDisabledRows</tbody>
                    </table>
                </div>
                <div class="info-box">
                    <p><strong>📌 Note:</strong> Review disabled rules periodically. MITRE tactic will show "None" if the rule wasn't tagged with MITRE ATT&CK framework.</p>
                </div>
            </div>
"@
    } else {
        $defenderHtml = @"
            <div class="section">
                <h2>🛡️ Defender Custom Detection Rules</h2>
                <div class="alert-box">
                    <p><strong>⚠️ No Defender Data Available</strong></p>
                    <p>To enable this feature, provide the following parameters when running the analyzer:</p>
                    <ul style="margin: 10px 0 0 20px; line-height: 1.8;">
                        <li><strong>-TenantId</strong>: Your Azure AD Tenant ID</li>
                        <li><strong>-ClientId</strong>: App Registration Client ID</li>
                        <li><strong>-ClientSecret</strong>: App Registration Client Secret</li>
                    </ul>
                    <p style="margin-top: 15px;"><strong>Required API Permissions:</strong></p>
                    <p style="margin: 5px 0 0 20px;">Microsoft Graph → Application permissions → SecurityEvents.Read.All</p>
                </div>
            </div>
"@
    }

    # Table Optimization HTML
    $tableOptHtml = ""
    
    if ($TableData -and $TableData.IngestedTables.Count -gt 0) {
        $tablesAnalyzed = $TableData.IngestedTables.Count
        $tablesWithRules = ($TableData.RuleMappings | 
            Where-Object { $_.Enabled -and $_.Tables[0] -ne "(no match)" } |
            ForEach-Object { $_.Tables } | 
            Select-Object -Unique).Count
        $unusedTables = $tablesAnalyzed - $tablesWithRules
        $totalIngestion = [math]::Round(($TableData.IngestedTables | Measure-Object -Property TotalGB -Sum).Sum, 1)
        
        # Log Ingestion Overview - Top tables by data volume
        $ingestionData = $TableData.IngestedTables | 
            Sort-Object TotalGB -Descending | 
            Select-Object -First 15
        
        $ingestionLabels = ($ingestionData | ForEach-Object { """$($_.DataType)""" }) -join ","
        # Ensure values are properly formatted numbers
        $ingestionValues = ($ingestionData | ForEach-Object { [string]$_.TotalGB }) -join ","
        
        Write-Host "  → Debug: Chart data sample: $($ingestionData[0].DataType) = $($ingestionData[0].TotalGB) GB" -ForegroundColor Gray
        
        $ingestionTableRows = ""
        foreach ($tbl in $ingestionData) {
            $pctOfTotal = if ($totalIngestion -gt 0) { [math]::Round(($tbl.TotalGB / $totalIngestion) * 100, 1) } else { 0 }
            $ingestionTableRows += "<tr><td><strong>$($tbl.DataType)</strong></td>" +
                "<td>$($tbl.TotalGB) GB</td>" +
                "<td>$pctOfTotal%</td>" +
                "<td><div style='background:#e9ecef;border-radius:4px;height:20px;width:100%'>" +
                "<div style='background:#3b82f6;height:20px;width:$pctOfTotal%;border-radius:4px'></div></div></td></tr>`n"
        }
        
        # Use Cases Per Table - Coverage based on rule count
        $useCasesRows = ""
        $maxRules = 50  # Define what "excellent coverage" means
        $summary = $TableData.RuleMappings |
            Where-Object { $_.Enabled -and $_.Tables[0] -ne "(no match)" } |
            ForEach-Object {
                foreach ($tbl in $_.Tables) {
                    [PSCustomObject]@{
                        Table = $tbl
                        Rule = $_.RuleName
                    }
                }
            } |
            Group-Object Table |
            ForEach-Object {
                $tblInfo = $TableData.TableLookup[$_.Name.ToLower()]
                $ruleCount = @($_.Group.Rule | Select-Object -Unique).Count
                $sizeGB = if ($tblInfo) { $tblInfo.TotalGB } else { 0 }
                $tblCoverage = [math]::Min([math]::Round(($ruleCount / $maxRules) * 100), 100)
                
                [PSCustomObject]@{
                    Table = $_.Name
                    Rules = $ruleCount
                    SizeGB = $sizeGB
                    Coverage = $tblCoverage
                }
            } |
            Sort-Object Rules -Descending
        
        foreach ($row in $summary) {
            $coverageColor = if ($row.Coverage -ge 80) { "#22c55e" }
                elseif ($row.Coverage -ge 50) { "#3b82f6" }
                elseif ($row.Coverage -ge 20) { "#ffc107" }
                else { "#ef4444" }
            
            $useCasesRows += "<tr><td><strong>$($row.Table)</strong></td><td>$($row.Rules)</td><td>$($row.SizeGB)</td>" +
                "<td><div style='background:#e9ecef;border-radius:4px;height:22px;width:100%;position:relative'>" +
                "<div style='background:$coverageColor;height:100%;width:$($row.Coverage)%;border-radius:4px'></div>" +
                "<span style='position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);font-size:0.75em;font-weight:600;color:#1e3a8a'>$($row.Coverage)%</span>" +
                "</div></td></tr>`n"
        }
        
        # Severity Breakdown
        $severityRows = ""
        $sevBreakdown = $TableData.RuleMappings |
            Where-Object { $_.Enabled -and $_.Tables[0] -ne "(no match)" } |
            ForEach-Object {
                foreach ($tbl in $_.Tables) {
                    [PSCustomObject]@{
                        Table = $tbl
                        Severity = $_.Severity
                    }
                }
            } |
            Group-Object Table |
            ForEach-Object {
                $grp = $_.Group
                [PSCustomObject]@{
                    Table = $_.Name
                    High = @($grp | Where-Object Severity -eq "High").Count
                    Medium = @($grp | Where-Object Severity -eq "Medium").Count
                    Low = @($grp | Where-Object Severity -eq "Low").Count
                    Info = @($grp | Where-Object Severity -eq "Informational").Count
                }
            } |
            Sort-Object {$_.High + $_.Medium} -Descending
        
        foreach ($row in $sevBreakdown) {
            $severityRows += "<tr><td><strong>$($row.Table)</strong></td>" +
                "<td><span class='badge' style='background:#dc3545'>$($row.High)</span></td>" +
                "<td><span class='badge' style='background:#ffc107'>$($row.Medium)</span></td>" +
                "<td><span class='badge' style='background:#17a2b8'>$($row.Low)</span></td>" +
                "<td><span class='badge' style='background:#6c757d'>$($row.Info)</span></td></tr>`n"
        }
        
        # Rule → Table Mappings - ALL rules, sorted by name
        $mappingRows = ""
        $allMappings = $TableData.RuleMappings |
            Where-Object { $_.Tables[0] -ne "(no match)" } |
            Sort-Object RuleName |  # Sort alphabetically by rule name
            ForEach-Object {
                $tablePills = ($_.Tables | ForEach-Object { "<span class='table-pill'>$_</span>" }) -join " "
                $statusColor = if ($_.Enabled) { "#28a745" } else { "#dc3545" }
                $statusIcon = if ($_.Enabled) { "✓" } else { "✗" }
                $sevColor = switch ($_.Severity) {
                    "High" { "#dc3545" }
                    "Medium" { "#ffc107" }
                    "Low" { "#17a2b8" }
                    default { "#6c757d" }
                }
                
                [PSCustomObject]@{
                    RuleName = $_.RuleName
                    TablePills = $tablePills
                    StatusColor = $statusColor
                    StatusIcon = $statusIcon
                    Severity = $_.Severity
                    SevColor = $sevColor
                }
            }
        
        foreach ($row in $allMappings) {
            $mappingRows += "<tr><td>$($row.RuleName)</td><td>$($row.TablePills)</td>" +
                "<td style='color:$($row.StatusColor); font-weight:bold'>$($row.StatusIcon)</td>" +
                "<td><span class='badge' style='background:$($row.SevColor)'>$($row.Severity)</span></td></tr>`n"
        }
        
        # Unmatched rules
        $unmatchedCount = ($TableData.RuleMappings | Where-Object { $_.Enabled -and $_.Tables[0] -eq "(no match)" }).Count
        $unmatchedAlert = if ($unmatchedCount -gt 0) {
            "<div class='alert-box'><p><strong>⚠️ Data Connector Health Alert:</strong> Found $unmatchedCount enabled rules querying tables that are not currently ingesting data.</p></div>"
        } else { "" }
        
        # Custom Tables (_CL) with No Rules
        $customTablesRows = ""
        $customTables = $TableData.IngestedTables | Where-Object { $_.DataType -like "*_CL" }
        $customTablesWithNoRules = $customTables | Where-Object {
            $tblName = $_.DataType
            $hasRules = $TableData.RuleMappings | Where-Object { 
                $_.Tables -contains $tblName -and $_.Enabled 
            }
            -not $hasRules
        } | Sort-Object TotalGB  # Sort by size ascending (smallest first)
        
        $totalCustomTableGB = [math]::Round(($customTablesWithNoRules | Measure-Object -Property TotalGB -Sum).Sum, 4)
        $customTableCount = $customTablesWithNoRules.Count
        
        foreach ($tbl in $customTablesWithNoRules) {
            # Show 4 decimal places to avoid showing 0 for small values
            $sizeDisplay = "{0:N4}" -f $tbl.TotalGB
            
            $pctOfTotal = if ($totalCustomTableGB -gt 0) { 
                [math]::Round(($tbl.TotalGB / $totalCustomTableGB) * 100, 2) 
            } else { 0 }
            
            $lastSeenDate = if ($tbl.LastSeen) { 
                try { ([DateTime]$tbl.LastSeen).ToString("yyyy-MM-dd HH:mm") } catch { "Unknown" }
            } else { "Unknown" }
            
            $customTablesRows += "<tr><td><strong>$($tbl.DataType)</strong></td>" +
                "<td>$sizeDisplay GB</td>" +
                "<td>$pctOfTotal%</td>" +
                "<td style='font-size:0.85em;color:#64748b'>$lastSeenDate</td></tr>`n"
        }
        
        $tableOptHtml = @"
            <div class="section">
                <h2>📊 Table Optimization Overview</h2>
                <p class="section-desc">Shows which Log Analytics tables are used by your detection rules. Helps identify <strong>unused tables</strong> consuming ingestion costs.</p>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Tables Analyzed</h3>
                        <div class="value">$tablesAnalyzed</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#22c55e">
                        <h3>Tables with Rules</h3>
                        <div class="value" style="color:#22c55e">$tablesWithRules</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#ef4444">
                        <h3>Unused Tables</h3>
                        <div class="value" style="color:#ef4444">$unusedTables</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#3b82f6">
                        <h3>Total Ingestion</h3>
                        <div class="value" style="color:#3b82f6">${totalIngestion} GB</div>
                    </div>
                </div>
                <div class="info-box">
                    <p><strong>💡 Optimization Insights:</strong> Tables with high GB but low rule coverage may be candidates for retention optimization. Tables with zero rules indicate unused data sources.</p>
                </div>
            </div>

            <div class="section">
                <h2>📈 Log Ingestion Overview</h2>
                <p class="section-desc">Top 15 tables by data volume ingested in the last 30 days. This helps identify high-volume data sources.</p>
                
                <div class="chart-wrapper" style="max-width:100%; height:400px">
                    <canvas id="ingestionChart"></canvas>
                </div>
                
                <div style="margin:15px 0; padding:10px; background:#f8fafc; border-radius:6px; display:flex; gap:20px; justify-content:center; flex-wrap:wrap">
                    <div style="display:flex; align-items:center; gap:8px">
                        <div style="width:20px; height:20px; background:rgba(239,68,68,0.8); border:2px solid rgb(239,68,68); border-radius:3px"></div>
                        <span style="font-size:0.9em; color:#64748b">Very Large (&gt;5000 GB)</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px">
                        <div style="width:20px; height:20px; background:rgba(249,115,22,0.8); border:2px solid rgb(249,115,22); border-radius:3px"></div>
                        <span style="font-size:0.9em; color:#64748b">Large (1000-5000 GB)</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px">
                        <div style="width:20px; height:20px; background:rgba(59,130,246,0.8); border:2px solid rgb(59,130,246); border-radius:3px"></div>
                        <span style="font-size:0.9em; color:#64748b">Medium (100-1000 GB)</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px">
                        <div style="width:20px; height:20px; background:rgba(34,197,94,0.8); border:2px solid rgb(34,197,94); border-radius:3px"></div>
                        <span style="font-size:0.9em; color:#64748b">Small (&lt;100 GB)</span>
                    </div>
                </div>
                
                <div class="table-container" style="margin-top:20px">
                    <table>
                        <thead>
                            <tr>
                                <th>Table Name</th>
                                <th>Data Ingested</th>
                                <th>% of Total</th>
                                <th>Visual</th>
                            </tr>
                        </thead>
                        <tbody>$ingestionTableRows</tbody>
                    </table>
                </div>
                
                <div class="info-box">
                    <p><strong>💰 Cost Insights:</strong> High-volume tables contribute most to ingestion costs. Consider data retention policies, sampling, or filtering for optimization.</p>
                </div>
            </div>

            <div class="section">
                <h3>🎯 Use Cases Per Table (Enabled Rules)</h3>
                <p class="section-desc">Detection coverage per table. Coverage is based on number of rules (50+ rules = 100% coverage). Scroll to see all tables.</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Table Name</th>
                                <th>Enabled Rules</th>
                                <th>Table Size (GB)</th>
                                <th>Coverage</th>
                            </tr>
                        </thead>
                        <tbody>$useCasesRows</tbody>
                    </table>
                </div>
                <div class="info-box">
                    <p><strong>📊 Coverage Legend:</strong> 
                    <span style='color:#22c55e;font-weight:bold'>●</span> Excellent (80%+) | 
                    <span style='color:#3b82f6;font-weight:bold'>●</span> Good (50-79%) | 
                    <span style='color:#ffc107;font-weight:bold'>●</span> Moderate (20-49%) | 
                    <span style='color:#ef4444;font-weight:bold'>●</span> Low (<20%)</p>
                </div>
            </div>

            <div class="section">
                <h3>⚡ Severity Breakdown by Table</h3>
                <p class="section-desc">Distribution of rule severity levels for each table (scroll for more).</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Table Name</th>
                                <th>High</th>
                                <th>Medium</th>
                                <th>Low</th>
                                <th>Informational</th>
                            </tr>
                        </thead>
                        <tbody>$severityRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h3>🔗 Rule → Table Mappings</h3>
                <p class="section-desc">Shows which tables each detection rule queries. All $($allMappings.Count) rules displayed, sorted alphabetically by name.</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Tables Used</th>
                                <th>Status</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>$mappingRows</tbody>
                    </table>
                </div>
                $unmatchedAlert
            </div>

            <div class="section">
                <h3>🔧 Custom Tables (_CL) Without Detection Rules</h3>
                <p class="section-desc">Custom log tables (ending with _CL) that have no associated detection rules. Consider creating rules or evaluating retention costs.</p>
                <div class="stats-grid" style="grid-template-columns: 1fr 1fr;">
                    <div class="stat-card" style="border-left-color:#8b5cf6">
                        <h3>Custom Tables (No Rules)</h3>
                        <div class="value" style="color:#8b5cf6">$customTableCount</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#ef4444">
                        <h3>Total Data Ingestion</h3>
                        <div class="value" style="color:#ef4444">$totalCustomTableGB GB</div>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Table Name</th>
                                <th>Size</th>
                                <th>% of Custom Tables</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>$customTablesRows</tbody>
                    </table>
                </div>
                <div class="alert-box">
                    <p><strong>💰 Cost Optimization Opportunity:</strong> These custom tables are ingesting $totalCustomTableGB GB of data without any detection rules. Consider:<br>
                    1. Creating detection rules for valuable data sources<br>
                    2. Reducing retention period for unused data<br>
                    3. Stopping ingestion for unnecessary tables</p>
                </div>
            </div>
"@
    } else {
        $tableOptHtml = @"
            <div class="section">
                <div class="alert-box">
                    <p><strong>⚠️ Table Optimization Unavailable:</strong> Log Analytics API token could not be obtained or no data was returned from the Usage table.</p>
                </div>
                <div class="info-box">
                    <p><strong>To enable this feature:</strong><br>
                    1. Ensure you have 'Log Analytics Reader' or 'Contributor' role on the workspace<br>
                    2. Re-authenticate with proper scope:<br>
                    &nbsp;&nbsp;&nbsp;<code>Disconnect-AzAccount</code><br>
                    &nbsp;&nbsp;&nbsp;<code>Connect-AzAccount -AuthScope https://api.loganalytics.io/</code><br>
                    3. OR use Azure CLI: <code>az login</code><br>
                    4. Re-run the analyzer</p>
                </div>
            </div>
"@
    }

    $timestamp = Get-Date -Format "MMMM dd, yyyy - HH:mm:ss"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Analytical Analyzer - $WorkspaceName</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; font-weight: 700; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        
        .tab-navigation {
            display: flex;
            background: #f8fafc;
            border-bottom: 3px solid #e2e8f0;
            padding: 0;
        }
        .tab-button {
            flex: 1;
            padding: 20px;
            background: none;
            border: none;
            font-size: 1.1em;
            font-weight: 600;
            color: #64748b;
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
            position: relative;
            top: 3px;
        }
        .tab-button:hover {
            background: #f1f5f9;
            color: #1e3a8a;
        }
        .tab-button.active {
            color: #1e3a8a;
            background: white;
            border-bottom: 3px solid #3b82f6;
        }
        .tab-button .tab-icon {
            font-size: 1.3em;
            margin-right: 8px;
        }
        
        .tab-content {
            display: none;
            padding: 40px;
            animation: fadeIn 0.3s ease;
        }
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #1e3a8a;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3b82f6;
        }
        .section h3 {
            color: #1e3a8a;
            font-size: 1.3em;
            margin-top: 30px;
            margin-bottom: 15px;
        }
        .section-desc {
            color: #64748b;
            font-size: 0.95em;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat-card {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3b82f6;
        }
        .stat-card h3 {
            font-size: 0.85em;
            color: #64748b;
            margin: 0 0 8px 0;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 2em;
            font-weight: 700;
            color: #1e3a8a;
        }
        
        .chart-wrapper {
            max-width: 650px;
            height: 450px;
            margin: 25px auto;
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .table-container {
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-top: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        thead {
            background: #1e3a8a;
            color: white;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        tbody tr:hover { background: #f8fafc; }
        tbody tr:nth-child(even) { background: #f9fafb; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        
        .info-box {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .info-box p {
            color: #92400e;
            font-size: 0.9em;
            line-height: 1.6;
            margin: 0;
        }
        
        .alert-box {
            background: #fee2e2;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .alert-box p {
            color: #7f1d1d;
            font-size: 0.9em;
            line-height: 1.6;
            margin: 0;
        }
        
        .table-pill {
            display: inline-block;
            background: #dbeafe;
            color: #1e3a8a;
            padding: 3px 10px;
            border-radius: 12px;
            margin: 2px;
            font-size: 0.85em;
            font-weight: 500;
        }
        
        .summary-panel {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 28px;
            border-radius: 8px;
            margin-top: 25px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 15px;
        }
        .summary-row {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8fafc;
            color: #64748b;
            font-size: 0.9em;
        }
        
        .table-container::-webkit-scrollbar {
            width: 8px;
        }
        .table-container::-webkit-scrollbar-track {
            background: #f1f5f9;
        }
        .table-container::-webkit-scrollbar-thumb {
            background: #cbd5e1;
            border-radius: 4px;
        }
        .table-container::-webkit-scrollbar-thumb:hover {
            background: #94a3b8;
        }
        
        /* MITRE Navigator Styles */
        .mitre-navigator {
            display: flex;
            gap: 4px;
            min-width: fit-content;
        }
        .tactic-column {
            min-width: 180px;
            flex-shrink: 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            border: 2px solid #e2e8f0;
        }
        .tactic-header {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: white;
            padding: 16px 12px;
            text-align: center;
            font-weight: 600;
            border-bottom: 3px solid #1e3a8a;
        }
        .tactic-header h4 {
            margin: 0 0 6px 0;
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.3px;
        }
        .tactic-header small {
            font-size: 12px;
            opacity: 0.95;
        }
        .technique-cell {
            padding: 10px 12px;
            margin: 3px;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid rgba(0,0,0,0.1);
            background: white;
        }
        .technique-cell:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.15);
            z-index: 100;
            border-color: #3b82f6;
        }
        .tech-id {
            font-weight: 700;
            font-size: 13px;
            display: block;
            margin-bottom: 4px;
        }
        .tech-name {
            font-size: 11px;
            display: block;
            line-height: 1.3;
            margin-bottom: 6px;
            opacity: 0.85;
        }
        .tech-count {
            display: inline-block;
            font-weight: 600;
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 12px;
            background: rgba(0,0,0,0.05);
        }
        .no-coverage {
            background: #ffe0e0 !important;
        }
        .limited-coverage {
            background: #d4edda !important;
        }
        .good-coverage {
            background: #28a745 !important;
            color: white !important;
        }
        .good-coverage .tech-name,
        .good-coverage .tech-count {
            color: white !important;
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header" style="display:flex; align-items:center; justify-content:center">
            <div style="text-align:center">
                <h1>Microsoft Sentinel Security Analytics Report</h1>
                <p>Comprehensive Security Analysis for <strong>$WorkspaceName</strong></p>
                <p style="font-size:0.9em; margin-top:10px">Generated: $timestamp</p>
            </div>
        </div>
        <div class="tab-navigation">
            <button class="tab-button active" onclick="switchTab(event, 'mitre-tab')">
                <span class="tab-icon">🎯</span>Sentinel Analytical Rule Analysis
            </button>
            <button class="tab-button" onclick="switchTab(event, 'table-tab')">
                <span class="tab-icon">📊</span>Table Optimization
            </button>
            <button class="tab-button" onclick="switchTab(event, 'defender-tab')">
                <span class="tab-icon">🛡️</span>Defender Custom Rules
            </button>
            <button class="tab-button" onclick="switchTab(event, 'heatmap-tab')">
                <span class="tab-icon">🔥</span>Overall MITRE HeatMap
            </button>
        </div>

        <!-- Tab 1: MITRE Analysis -->
        <div id="mitre-tab" class="tab-content active">
            <div class="section">
                <h2>📊 Overview</h2>
                <p class="section-desc">Summary of your Sentinel analytical rules. Coverage shows <strong>unique MITRE techniques</strong> detected by enabled rules (out of 211 total).</p>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Rules</h3>
                        <div class="value">$total</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#22c55e">
                        <h3>Enabled</h3>
                        <div class="value" style="color:#22c55e">$enabled</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#ef4444">
                        <h3>Disabled</h3>
                        <div class="value" style="color:#ef4444">$disabled</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#f59e0b">
                        <h3>Coverage</h3>
                        <div class="value" style="color:#f59e0b">$coverage%</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📡 MITRE ATT&CK Tactics Coverage</h2>
                <p class="section-desc">Radar chart showing <strong>enabled Sentinel rules</strong> per tactic. Larger areas = more rules covering that tactic.</p>
                <div class="chart-wrapper">
                    <canvas id="radarChart"></canvas>
                </div>
            </div>

            <div class="section">
                <h2>🎯 Enabled Rules by Tactic</h2>
                <p class="section-desc">Number of active detection rules covering each MITRE ATT&CK tactic (scroll for all).</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>MITRE Tactic</th>
                                <th>Enabled</th>
                                <th>Total</th>
                                <th>Distribution</th>
                            </tr>
                        </thead>
                        <tbody>$tacticRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>📋 Rule Source Breakdown</h2>
                <p class="section-desc">Distribution of enabled rules by source: Gallery (Microsoft-provided) vs Custom (Organization-specific).</p>
                <div class="stats-grid">
                    <div class="stat-card" style="border-left-color:#3b82f6">
                        <h3>Gallery/Built-in Rules</h3>
                        <div class="value" style="color:#3b82f6">$galleryCount</div>
                        <p style="margin-top:8px;font-size:0.85em;color:#64748b">$galleryPct% of enabled rules</p>
                    </div>
                    <div class="stat-card" style="border-left-color:#8b5cf6">
                        <h3>Custom Rules</h3>
                        <div class="value" style="color:#8b5cf6">$customCount</div>
                        <p style="margin-top:8px;font-size:0.85em;color:#64748b">$customPct% of enabled rules</p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🚫 Disabled Rules</h2>
                <p class="section-desc">Currently disabled analytical rules (showing top 50 of $disabled total).</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Severity</th>
                                <th>MITRE Tactics</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>$disabledRulesRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>⚠️ Rules Without MITRE Mapping</h2>
                <p class="section-desc">Enabled rules without MITRE tactics (top 30 of $($rulesWithoutMitre.Count) total).</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Severity</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>$rulesWithoutMitreRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <h2>📉 Coverage Gaps - Top 5 Least Covered Tactics</h2>
                <p class="section-desc">Tactics with lowest coverage - priority improvement areas.</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>MITRE Tactic</th>
                                <th>Coverage</th>
                                <th>Percentage</th>
                                <th>Visual</th>
                            </tr>
                        </thead>
                        <tbody>$coverageGapsRows</tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <div class="summary-panel">
                    <h2 style="color:white; border:none; margin:0 0 15px 0">📋 Executive Summary</h2>
                    <div class="summary-grid">
                        <div class="summary-row">
                            <span>Enabled Rules</span>
                            <span style="color:#22c55e; font-weight:700">$enabled</span>
                        </div>
                        <div class="summary-row">
                            <span>Disabled Rules</span>
                            <span style="color:#ef4444; font-weight:700">$disabled</span>
                        </div>
                        <div class="summary-row">
                            <span>Total MITRE Techniques</span>
                            <span style="font-weight:700">211</span>
                        </div>
                        <div class="summary-row">
                            <span>Techniques Covered</span>
                            <span style="color:#f59e0b; font-weight:700">$techCount</span>
                        </div>
                        <div class="summary-row">
                            <span>Tactics Covered</span>
                            <span style="color:#3b82f6; font-weight:700">$tacticCount of $totalTactics</span>
                        </div>
                        <div class="summary-row">
                            <span>Coverage Percentage ($coverageMetric-based)</span>
                            <span style="color:#3b82f6; font-weight:700">$coverage%</span>
                        </div>
                        <div class="summary-row">
                            <span>Coverage Grade</span>
                            <span style="font-weight:700">$grade</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab 2: Table Optimization -->
        <div id="table-tab" class="tab-content">
            $tableOptHtml
        </div>

        <!-- Tab 3: Defender Custom Rules -->
        <div id="defender-tab" class="tab-content">
            $defenderHtml
        </div>

        <!-- Tab 4: Overall MITRE HeatMap -->
        <div id="heatmap-tab" class="tab-content">
            <div class="section">
                <h2>🔥 Overall MITRE Coverage HeatMap</h2>
                <p class="section-desc">Complete MITRE ATT&CK coverage combining <strong>all detection sources</strong>. Coverage percentage shows <strong>unique techniques detected</strong> out of 211 total techniques.</p>
                
                <div style="background:#eff6ff; border-left:4px solid #3b82f6; padding:15px; margin-bottom:25px; border-radius:8px">
                    <p style="margin:0; color:#1e3a8a"><strong>ℹ️ Included Sources:</strong> This HeatMap combines coverage from:</p>
                    <ul style="margin:10px 0 0 20px; color:#1e3a8a">
                        <li><strong>Microsoft Sentinel</strong> - Your analytical rules ($total rules)</li>
                        <li><strong>Defender Custom Rules</strong> - Your custom detections</li>
                        <li><strong>Defender for Endpoint (MDE)</strong> - Included by default (277 rules)</li>
                        <li><strong>Defender for Identity (MDI)</strong> - Included by default (63 rules)</li>
                        <li><strong>Defender for Cloud Apps (MDA)</strong> - Included by default (22 rules)</li>
                        <li><strong>Defender for Office 365 (MDO)</strong> - Included by default (30 rules)</li>
                        <li><strong>Entra ID Protection</strong> - Included by default (21 rules)</li>
                    </ul>
                </div>

                <div class="stats-grid" style="margin-bottom:30px">
                    <div class="stat-card">
                        <h3 style="color:#3b82f6">$enabled</h3>
                        <p>Sentinel Rules (Enabled)</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color:#10b981" id="defender-rules-count">0</h3>
                        <p>Defender Custom Rules</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color:#8b5cf6" id="detection-sources-count">7</h3>
                        <p>Detection Sources</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color:#ec4899" id="overall-coverage">Calculating...</h3>
                        <p>Overall MITRE Coverage</p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🗺️ MITRE ATT&CK Navigator View</h2>
                <p class="section-desc">Visual heatmap of all 211 MITRE techniques. Shows <strong>combined detection coverage</strong> from Sentinel + Defender + all products. Color indicates <strong>how many rules</strong> detect each technique.</p>
                
                <div style="background:#fff3cd; border-left:4px solid #ffc107; padding:15px; margin-bottom:20px; border-radius:8px">
                    <p style="margin:0; color:#856404"><strong>📌 Color Legend:</strong> 
                    <span style="background:#ffe0e0; padding:2px 8px; margin:0 5px; border-radius:3px">No Coverage (0 rules)</span>
                    <span style="background:#d4edda; padding:2px 8px; margin:0 5px; border-radius:3px">Limited (1 rule)</span>
                    <span style="background:#28a745; color:white; padding:2px 8px; margin:0 5px; border-radius:3px">Good Coverage (2+ rules)</span>
                    </p>
                </div>

                <div id="mitre-navigator-container" style="background:#f8f9fa; padding:15px; border-radius:8px; overflow-x:auto; border:1px solid #dee2e6">
                    <div id="mitre-navigator" class="mitre-navigator">
                        <!-- Navigator populated by JavaScript below -->
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📊 Coverage Matrix by Tactic</h2>
                <p class="section-desc">Shows <strong>unique MITRE techniques</strong> covered per tactic by each product. Numbers indicate <strong>technique count</strong>, not rule count (multiple rules may detect the same technique).</p>
                
                <div style="overflow-x:auto; margin-top:20px">
                    <table style="width:100%; border-collapse:collapse">
                        <thead>
                            <tr style="background:#1e3a8a; color:white">
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:left">Tactic</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">Sentinel</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">Defender Custom</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">MDE</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">MDI</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">MDA</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">MDO</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center">Entra ID</th>
                                <th style="padding:12px; border:1px solid #cbd5e1; text-align:center; background:#059669; color:white; font-weight:bold">TOTAL</th>
                            </tr>
                        </thead>
                        <tbody id="heatmap-body">
                            <!-- Data populated by JavaScript -->
                        </tbody>
                    </table>
                </div>
                
                <div style="margin-top:20px; padding:15px; background:#f8fafc; border-radius:8px">
                    <p style="margin:0 0 10px 0; font-weight:600; color:#475569">Color Legend:</p>
                    <div style="display:flex; gap:15px; flex-wrap:wrap">
                        <div style="display:flex; align-items:center; gap:8px">
                            <div style="width:20px; height:20px; background:#d1fae5; border:1px solid #cbd5e1"></div>
                            <span style="font-size:0.9em; color:#475569">≥50 rules (Strong)</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px">
                            <div style="width:20px; height:20px; background:#fef3c7; border:1px solid #cbd5e1"></div>
                            <span style="font-size:0.9em; color:#475569">20-49 rules (Moderate)</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px">
                            <div style="width:20px; height:20px; background:#fed7aa; border:1px solid #cbd5e1"></div>
                            <span style="font-size:0.9em; color:#475569">10-19 rules (Limited)</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px">
                            <div style="width:20px; height:20px; background:#fee2e2; border:1px solid #cbd5e1"></div>
                            <span style="font-size:0.9em; color:#475569">1-9 rules (Minimal)</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px">
                            <div style="width:20px; height:20px; background:#f3f4f6; border:1px solid #cbd5e1"></div>
                            <span style="font-size:0.9em; color:#475569">0 rules (None)</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>📋 Detection Source Summary</h2>
                <p class="section-desc">Lists all detection products and their <strong>total rule counts</strong>. Shows which sources are active in your environment vs. included by default.</p>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Detection Source</th>
                                <th>Rule Count</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr><td><strong>Microsoft Sentinel</strong></td><td>$total</td><td><span style="color:#10b981">✓ Active</span></td></tr>
                            <tr><td><strong>Defender Custom Rules</strong></td><td id="defender-count">0</td><td><span style="color:#10b981">✓ Active</span></td></tr>
                            <tr><td><strong>Defender for Endpoint (MDE)</strong></td><td>277</td><td><span style="color:#64748b">Default</span></td></tr>
                            <tr><td><strong>Defender for Identity (MDI)</strong></td><td>63</td><td><span style="color:#64748b">Default</span></td></tr>
                            <tr><td><strong>Defender for Cloud Apps (MDA)</strong></td><td>22</td><td><span style="color:#64748b">Default</span></td></tr>
                            <tr><td><strong>Defender for Office 365 (MDO)</strong></td><td>30</td><td><span style="color:#64748b">Default</span></td></tr>
                            <tr><td><strong>Entra ID Protection</strong></td><td>21</td><td><span style="color:#64748b">Default</span></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="footer">
            Sentinel Analytical Analyzer v$script:Version | Designed by <strong>$script:Author</strong>
        </div>
    </div>

    <script>
        function switchTab(event, tabId) {
            const tabContents = document.getElementsByClassName('tab-content');
            for (let i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            const tabButtons = document.getElementsByClassName('tab-button');
            for (let i = 0; i < tabButtons.length; i++) {
                tabButtons[i].classList.remove('active');
            }
            
            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active');
        }
        
        const ctx = document.getElementById('radarChart').getContext('2d');
        new Chart(ctx, {
            type: 'radar',
            data: {
                labels: [$($radarLabels -join ',')],
                datasets: [{
                    label: 'Enabled Rules',
                    data: [$($radarValues -join ',')],
                    fill: true,
                    backgroundColor: 'rgba(59, 130, 246, 0.25)',
                    borderColor: 'rgb(59, 130, 246)',
                    pointBackgroundColor: 'rgb(59, 130, 246)',
                    pointBorderColor: '#fff',
                    pointRadius: 5,
                    pointHoverRadius: 7,
                    borderWidth: 2.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'MITRE ATT&CK Tactics - Enabled Detection Coverage',
                        font: { size: 16, weight: 'bold' },
                        color: '#1e3a8a',
                        padding: 15
                    },
                    legend: { display: false }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: { stepSize: 5 },
                        pointLabels: {
                            font: { size: 12, weight: '600' },
                            color: '#475569'
                        }
                    }
                }
            }
        });
        
        // Ingestion Bar Chart
        const ingestionCtx = document.getElementById('ingestionChart');
        if (ingestionCtx) {
            new Chart(ingestionCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: [$ingestionLabels],
                    datasets: [{
                        label: 'Data Ingested (GB)',
                        data: [$ingestionValues],
                        backgroundColor: function(context) {
                            const value = context.raw;
                            // Color gradient based on size
                            if (value > 5000) return 'rgba(239, 68, 68, 0.8)';  // Red for very large
                            if (value > 1000) return 'rgba(249, 115, 22, 0.8)'; // Orange for large
                            if (value > 100) return 'rgba(59, 130, 246, 0.8)';  // Blue for medium
                            return 'rgba(34, 197, 94, 0.8)';                    // Green for small
                        },
                        borderColor: function(context) {
                            const value = context.raw;
                            if (value > 5000) return 'rgb(239, 68, 68)';
                            if (value > 1000) return 'rgb(249, 115, 22)';
                            if (value > 100) return 'rgb(59, 130, 246)';
                            return 'rgb(34, 197, 94)';
                        },
                        borderWidth: 2
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Top 15 Tables by Data Ingestion (Last 30 Days)',
                            font: { size: 16, weight: 'bold' },
                            color: '#1e3a8a',
                            padding: 15
                        },
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return context.parsed.x.toFixed(2) + ' GB';
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Data Ingested (GB)',
                                font: { weight: 'bold' }
                            },
                            ticks: {
                                callback: function(value) {
                                    return value.toFixed(2) + ' GB';
                                }
                            }
                        },
                        y: {
                            ticks: {
                                font: { size: 11 }
                            }
                        }
                    }
                }
            });
        }
        
        // Defender MITRE Tactics Chart
        const defenderTacticCtx = document.getElementById('defenderTacticChart');
        if (defenderTacticCtx) {
            const hasData = [$defenderChartValues].some(v => v > 0);
            if (hasData) {
                new Chart(defenderTacticCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: [$defenderChartLabels],
                        datasets: [{
                            label: 'Rules',
                            data: [$defenderChartValues],
                            backgroundColor: [$defenderChartColors],
                            borderColor: '#ffffff',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Defender Custom Rules by MITRE ATT&CK Tactic',
                                font: { size: 16, weight: 'bold' },
                                color: '#1e3a8a',
                                padding: 15
                            },
                            legend: {
                                display: true,
                                position: 'right',
                                labels: {
                                    padding: 12,
                                    font: { size: 11 },
                                    generateLabels: function(chart) {
                                        const data = chart.data;
                                        return data.labels.map((label, i) => ({
                                            text: label + ' (' + data.datasets[0].data[i] + ')',
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            hidden: false,
                                            index: i
                                        }));
                                    }
                                }
                            },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                        const value = context.parsed;
                                        const percentage = ((value / total) * 100).toFixed(1);
                                        return context.label + ': ' + value + ' rules (' + percentage + '%)';
                                    }
                                }
                            }
                        }
                    }
                });
            } else {
                // Show message when no data
                defenderTacticCtx.parentElement.innerHTML = 
                    '<div style="text-align:center;padding:40px;color:#64748b">' +
                    '<strong>No MITRE Tactic Data Available</strong><br>' +
                    '<span style="font-size:0.9em">Rules do not have MITRE ATT&CK mappings</span>' +
                    '</div>';
            }
        }
        
        // === HEATMAP TAB JAVASCRIPT ===
        
        // Helper: Get color based on count
        function getCellColor(count) {
            if (count === 0) return '#f3f4f6';
            if (count < 10) return '#fee2e2';
            if (count < 20) return '#fed7aa';
            if (count < 50) return '#fef3c7';
            return '#d1fae5';
        }
        
        // Helper: Extract base technique (remove sub-technique)
        function getBaseTechnique(techId) {
            if (!techId) return null;
            const match = techId.match(/^T\d+/);
            return match ? match[0] : null;
        }
        
        // Build technique coverage map from Sentinel rules
        const techniqueCoverage = {};
        const allTechniques = [];
        
        $($allTechniquesList | ForEach-Object {
            $baseTech = if ($_ -match '^(T\d+)') { $Matches[1] } else { $_ }
            "allTechniques.push('$baseTech');"
        })
        
        // Count occurrences of each base technique
        allTechniques.forEach(function(tech) {
            if (tech) {
                if (!techniqueCoverage[tech]) {
                    techniqueCoverage[tech] = 0;
                }
                techniqueCoverage[tech]++;
            }
        });
        
        // MITRE ATT&CK Enterprise Matrix - All 211 Techniques
        const mitreMatrix = {
            'Reconnaissance': [{id:'T1595',name:'Active Scanning'},{id:'T1592',name:'Gather Victim Host Information'},{id:'T1589',name:'Gather Victim Identity Information'},{id:'T1590',name:'Gather Victim Network Information'},{id:'T1591',name:'Gather Victim Org Information'},{id:'T1598',name:'Phishing for Information'},{id:'T1597',name:'Search Closed Sources'},{id:'T1596',name:'Search Open Technical Databases'},{id:'T1593',name:'Search Open Websites/Domains'},{id:'T1594',name:'Search Victim-Owned Websites'}],
            'Resource Development': [{id:'T1583',name:'Acquire Infrastructure'},{id:'T1586',name:'Compromise Accounts'},{id:'T1584',name:'Compromise Infrastructure'},{id:'T1587',name:'Develop Capabilities'},{id:'T1585',name:'Establish Accounts'},{id:'T1588',name:'Obtain Capabilities'},{id:'T1608',name:'Stage Capabilities'},{id:'T1650',name:'Acquire Access'}],
            'Initial Access': [{id:'T1189',name:'Drive-by Compromise'},{id:'T1190',name:'Exploit Public-Facing Application'},{id:'T1133',name:'External Remote Services'},{id:'T1200',name:'Hardware Additions'},{id:'T1566',name:'Phishing'},{id:'T1091',name:'Replication Through Removable Media'},{id:'T1195',name:'Supply Chain Compromise'},{id:'T1199',name:'Trusted Relationship'},{id:'T1078',name:'Valid Accounts'}],
            'Execution': [{id:'T1059',name:'Command and Scripting Interpreter'},{id:'T1609',name:'Container Administration Command'},{id:'T1610',name:'Deploy Container'},{id:'T1203',name:'Exploitation for Client Execution'},{id:'T1559',name:'Inter-Process Communication'},{id:'T1106',name:'Native API'},{id:'T1053',name:'Scheduled Task/Job'},{id:'T1129',name:'Shared Modules'},{id:'T1204',name:'User Execution'},{id:'T1047',name:'Windows Management Instrumentation'},{id:'T1072',name:'Software Deployment Tools'},{id:'T1569',name:'System Services'},{id:'T1651',name:'Cloud Administration Command'},{id:'T1648',name:'Serverless Execution'}],
            'Persistence': [{id:'T1098',name:'Account Manipulation'},{id:'T1197',name:'BITS Jobs'},{id:'T1547',name:'Boot or Logon Autostart Execution'},{id:'T1037',name:'Boot or Logon Initialization Scripts'},{id:'T1176',name:'Browser Extensions'},{id:'T1554',name:'Compromise Client Software Binary'},{id:'T1136',name:'Create Account'},{id:'T1543',name:'Create or Modify System Process'},{id:'T1546',name:'Event Triggered Execution'},{id:'T1574',name:'Hijack Execution Flow'},{id:'T1525',name:'Implant Internal Image'},{id:'T1556',name:'Modify Authentication Process'},{id:'T1137',name:'Office Application Startup'},{id:'T1542',name:'Pre-OS Boot'},{id:'T1053',name:'Scheduled Task/Job'},{id:'T1505',name:'Server Software Component'},{id:'T1205',name:'Traffic Signaling'},{id:'T1078',name:'Valid Accounts'},{id:'T1601',name:'Modify System Image'},{id:'T1600',name:'Weaken Encryption'}],
            'Privilege Escalation': [{id:'T1548',name:'Abuse Elevation Control Mechanism'},{id:'T1134',name:'Access Token Manipulation'},{id:'T1547',name:'Boot or Logon Autostart Execution'},{id:'T1037',name:'Boot or Logon Initialization Scripts'},{id:'T1543',name:'Create or Modify System Process'},{id:'T1484',name:'Domain or Tenant Policy Modification'},{id:'T1611',name:'Escape to Host'},{id:'T1546',name:'Event Triggered Execution'},{id:'T1068',name:'Exploitation for Privilege Escalation'},{id:'T1574',name:'Hijack Execution Flow'},{id:'T1055',name:'Process Injection'},{id:'T1053',name:'Scheduled Task/Job'},{id:'T1078',name:'Valid Accounts'},{id:'T1098',name:'Account Manipulation'}],
            'Defense Evasion': [{id:'T1548',name:'Abuse Elevation Control Mechanism'},{id:'T1134',name:'Access Token Manipulation'},{id:'T1197',name:'BITS Jobs'},{id:'T1612',name:'Build Image on Host'},{id:'T1622',name:'Debugger Evasion'},{id:'T1140',name:'Deobfuscate/Decode Files or Information'},{id:'T1610',name:'Deploy Container'},{id:'T1006',name:'Direct Volume Access'},{id:'T1484',name:'Domain or Tenant Policy Modification'},{id:'T1480',name:'Execution Guardrails'},{id:'T1211',name:'Exploitation for Defense Evasion'},{id:'T1222',name:'File and Directory Permissions Modification'},{id:'T1564',name:'Hide Artifacts'},{id:'T1574',name:'Hijack Execution Flow'},{id:'T1562',name:'Impair Defenses'},{id:'T1070',name:'Indicator Removal'},{id:'T1202',name:'Indirect Command Execution'},{id:'T1036',name:'Masquerading'},{id:'T1556',name:'Modify Authentication Process'},{id:'T1578',name:'Modify Cloud Compute Infrastructure'},{id:'T1112',name:'Modify Registry'},{id:'T1601',name:'Modify System Image'},{id:'T1599',name:'Network Boundary Bridging'},{id:'T1027',name:'Obfuscated Files or Information'},{id:'T1647',name:'Plist File Modification'},{id:'T1542',name:'Pre-OS Boot'},{id:'T1055',name:'Process Injection'},{id:'T1620',name:'Reflective Code Loading'},{id:'T1207',name:'Rogue Domain Controller'},{id:'T1014',name:'Rootkit'},{id:'T1553',name:'Subvert Trust Controls'},{id:'T1218',name:'System Binary Proxy Execution'},{id:'T1216',name:'System Script Proxy Execution'},{id:'T1221',name:'Template Injection'},{id:'T1205',name:'Traffic Signaling'},{id:'T1535',name:'Unused/Unsupported Cloud Regions'},{id:'T1550',name:'Use Alternate Authentication Material'},{id:'T1078',name:'Valid Accounts'},{id:'T1497',name:'Virtualization/Sandbox Evasion'},{id:'T1600',name:'Weaken Encryption'},{id:'T1220',name:'XSL Script Processing'}],
            'Credential Access': [{id:'T1110',name:'Brute Force'},{id:'T1555',name:'Credentials from Password Stores'},{id:'T1212',name:'Exploitation for Credential Access'},{id:'T1187',name:'Forced Authentication'},{id:'T1606',name:'Forge Web Credentials'},{id:'T1056',name:'Input Capture'},{id:'T1557',name:'Adversary-in-the-Middle'},{id:'T1556',name:'Modify Authentication Process'},{id:'T1111',name:'Multi-Factor Authentication Interception'},{id:'T1621',name:'Multi-Factor Authentication Request Generation'},{id:'T1040',name:'Network Sniffing'},{id:'T1003',name:'OS Credential Dumping'},{id:'T1528',name:'Steal Application Access Token'},{id:'T1558',name:'Steal or Forge Kerberos Tickets'},{id:'T1539',name:'Steal Web Session Cookie'},{id:'T1552',name:'Unsecured Credentials'},{id:'T1649',name:'Steal or Forge Authentication Certificates'}],
            'Discovery': [{id:'T1087',name:'Account Discovery'},{id:'T1010',name:'Application Window Discovery'},{id:'T1217',name:'Browser Information Discovery'},{id:'T1580',name:'Cloud Infrastructure Discovery'},{id:'T1538',name:'Cloud Service Dashboard'},{id:'T1526',name:'Cloud Service Discovery'},{id:'T1613',name:'Container and Resource Discovery'},{id:'T1482',name:'Domain Trust Discovery'},{id:'T1083',name:'File and Directory Discovery'},{id:'T1615',name:'Group Policy Discovery'},{id:'T1046',name:'Network Service Discovery'},{id:'T1135',name:'Network Share Discovery'},{id:'T1040',name:'Network Sniffing'},{id:'T1201',name:'Password Policy Discovery'},{id:'T1120',name:'Peripheral Device Discovery'},{id:'T1069',name:'Permission Groups Discovery'},{id:'T1057',name:'Process Discovery'},{id:'T1012',name:'Query Registry'},{id:'T1018',name:'Remote System Discovery'},{id:'T1518',name:'Software Discovery'},{id:'T1082',name:'System Information Discovery'},{id:'T1614',name:'System Location Discovery'},{id:'T1016',name:'System Network Configuration Discovery'},{id:'T1049',name:'System Network Connections Discovery'},{id:'T1033',name:'System Owner/User Discovery'},{id:'T1007',name:'System Service Discovery'},{id:'T1124',name:'System Time Discovery'},{id:'T1497',name:'Virtualization/Sandbox Evasion'},{id:'T1652',name:'Device Driver Discovery'}],
            'Lateral Movement': [{id:'T1210',name:'Exploitation of Remote Services'},{id:'T1534',name:'Internal Spearphishing'},{id:'T1570',name:'Lateral Tool Transfer'},{id:'T1563',name:'Remote Service Session Hijacking'},{id:'T1021',name:'Remote Services'},{id:'T1091',name:'Replication Through Removable Media'},{id:'T1072',name:'Software Deployment Tools'},{id:'T1080',name:'Taint Shared Content'},{id:'T1550',name:'Use Alternate Authentication Material'}],
            'Collection': [{id:'T1557',name:'Adversary-in-the-Middle'},{id:'T1560',name:'Archive Collected Data'},{id:'T1123',name:'Audio Capture'},{id:'T1119',name:'Automated Collection'},{id:'T1185',name:'Browser Session Hijacking'},{id:'T1115',name:'Clipboard Data'},{id:'T1530',name:'Data from Cloud Storage'},{id:'T1602',name:'Data from Configuration Repository'},{id:'T1213',name:'Data from Information Repositories'},{id:'T1005',name:'Data from Local System'},{id:'T1039',name:'Data from Network Shared Drive'},{id:'T1025',name:'Data from Removable Media'},{id:'T1074',name:'Data Staged'},{id:'T1114',name:'Email Collection'},{id:'T1056',name:'Input Capture'},{id:'T1113',name:'Screen Capture'},{id:'T1125',name:'Video Capture'}],
            'Command and Control': [{id:'T1071',name:'Application Layer Protocol'},{id:'T1092',name:'Communication Through Removable Media'},{id:'T1132',name:'Data Encoding'},{id:'T1001',name:'Data Obfuscation'},{id:'T1568',name:'Dynamic Resolution'},{id:'T1573',name:'Encrypted Channel'},{id:'T1008',name:'Fallback Channels'},{id:'T1105',name:'Ingress Tool Transfer'},{id:'T1104',name:'Multi-Stage Channels'},{id:'T1095',name:'Non-Application Layer Protocol'},{id:'T1571',name:'Non-Standard Port'},{id:'T1572',name:'Protocol Tunneling'},{id:'T1090',name:'Proxy'},{id:'T1219',name:'Remote Access Software'},{id:'T1205',name:'Traffic Signaling'},{id:'T1102',name:'Web Service'}],
            'Exfiltration': [{id:'T1020',name:'Automated Exfiltration'},{id:'T1030',name:'Data Transfer Size Limits'},{id:'T1048',name:'Exfiltration Over Alternative Protocol'},{id:'T1041',name:'Exfiltration Over C2 Channel'},{id:'T1011',name:'Exfiltration Over Other Network Medium'},{id:'T1052',name:'Exfiltration Over Physical Medium'},{id:'T1567',name:'Exfiltration Over Web Service'},{id:'T1029',name:'Scheduled Transfer'},{id:'T1537',name:'Transfer Data to Cloud Account'}],
            'Impact': [{id:'T1531',name:'Account Access Removal'},{id:'T1485',name:'Data Destruction'},{id:'T1486',name:'Data Encrypted for Impact'},{id:'T1491',name:'Defacement'},{id:'T1561',name:'Disk Wipe'},{id:'T1499',name:'Endpoint Denial of Service'},{id:'T1495',name:'Firmware Corruption'},{id:'T1490',name:'Inhibit System Recovery'},{id:'T1498',name:'Network Denial of Service'},{id:'T1496',name:'Resource Hijacking'},{id:'T1489',name:'Service Stop'},{id:'T1529',name:'System Shutdown/Reboot'}]
        };
        
        // Build MITRE Navigator
        const navigatorContainer = document.getElementById('mitre-navigator');
        if (navigatorContainer && Object.keys(techniqueCoverage).length > 0) {
            Object.keys(mitreMatrix).forEach(function(tactic) {
                const techniques = mitreMatrix[tactic];
                const column = document.createElement('div');
                column.className = 'tactic-column';
                
                const header = document.createElement('div');
                header.className = 'tactic-header';
                header.innerHTML = '<h4>' + tactic + '</h4><small>' + techniques.length + ' techniques</small>';
                column.appendChild(header);
                
                techniques.forEach(function(tech) {
                    const count = techniqueCoverage[tech.id] || 0;
                    const cell = document.createElement('div');
                    cell.className = 'technique-cell';
                    
                    if (count === 0) {
                        cell.classList.add('no-coverage');
                    } else if (count === 1) {
                        cell.classList.add('limited-coverage');
                    } else {
                        cell.classList.add('good-coverage');
                    }
                    
                    cell.title = tech.id + ': ' + tech.name + ' (' + count + ' detection rule' + (count !== 1 ? 's' : '') + ')';
                    cell.innerHTML = 
                        '<span class="tech-id">' + tech.id + '</span>' +
                        '<span class="tech-name">' + tech.name + '</span>' +
                        '<span class="tech-count">' + count + ' rule' + (count !== 1 ? 's' : '') + '</span>';
                    
                    column.appendChild(cell);
                });
                
                navigatorContainer.appendChild(column);
            });
        } else if (navigatorContainer) {
            navigatorContainer.innerHTML = '<p style="text-align:center; color:#64748b; padding:40px">No MITRE technique data available.</p>';
        }
        
        // Build tactic coverage map
        const tacticCounts = {};
        const defenderCounts = {};
        
        // Populate from PowerShell data
        $($script:TacticOrder | ForEach-Object { 
            $tactic = $_
            $sentinelCount = if ($TacticData -and $TacticData.ContainsKey($tactic)) { $TacticData[$tactic].EnabledCount } else { 0 }
            "tacticCounts['$tactic'] = $sentinelCount;"
        })
        
        // Add defender counts if available
        $(if ($DefenderData -and $DefenderData.TacticCounts) {
            $DefenderData.TacticCounts.GetEnumerator() | Where-Object { $_.Key -ne "No Mapping Found" } | ForEach-Object {
                "defenderCounts['$($_.Key)'] = $($_.Value);"
            }
        })
        
        // Update defender count with null-safe access
        $(if ($DefenderData -and $DefenderData.EnabledRules) {
            $defCount = $DefenderData.EnabledRules.Count
            if ($null -eq $defCount) { $defCount = 0 }
            "document.getElementById('defender-count').textContent = '$defCount';"
            "document.getElementById('defender-rules-count').textContent = '$defCount';"
        } else {
            "document.getElementById('defender-count').textContent = '0';"
            "document.getElementById('defender-rules-count').textContent = '0';"
        })
        
        // Calculate detection sources count
        // Base sources: Sentinel (1) + MDE + MDI + MDA + MDO + Entra (5) = 6
        // + Defender Custom (1 if available) = 7 total
        $(if ($DefenderData -and $DefenderData.EnabledRules -and $DefenderData.EnabledRules.Count -gt 0) {
            "document.getElementById('detection-sources-count').textContent = '7';"
        } else {
            "document.getElementById('detection-sources-count').textContent = '6';"
        })
        
        // Calculate OVERALL coverage from ALL sources (Sentinel + Defender + Products)
        var allSourceTechniques = new Set();
        
        // Add Sentinel techniques
        $($allTechniquesList | ForEach-Object { 
            $baseTech = if ($_ -match '^(T\d+)') { $Matches[1] } else { $_ }
            "allSourceTechniques.add('$baseTech');"
        })
        
        // Add Defender custom rule techniques
        $(if ($DefenderData -and $DefenderData.Techniques) {
            $DefenderData.Techniques | ForEach-Object {
                $baseTech = if ($_ -match '^(T\d+)') { $Matches[1] } else { $_ }
                "allSourceTechniques.add('$baseTech');"
            }
        })
        
        // Add default product techniques (MDE, MDI, MDA, MDO, Entra)
        // Based on actual deployment data from your environment
        // Note: MDC (Defender for Cloud) removed - not in your deployment
        var defaultProductTechs = [
            'T1003', 'T1005', 'T1016', 'T1018', 'T1020', 'T1021', 'T1027', 'T1036',
            'T1046', 'T1047', 'T1048', 'T1053', 'T1055', 'T1057', 'T1059', 'T1068',
            'T1069', 'T1070', 'T1071', 'T1078', 'T1082', 'T1083', 'T1087', 'T1090',
            'T1091', 'T1098', 'T1102', 'T1105', 'T1110', 'T1111', 'T1112', 'T1113',
            'T1114', 'T1134', 'T1136', 'T1140', 'T1189', 'T1190', 'T1202', 'T1203',
            'T1204', 'T1207', 'T1210', 'T1213', 'T1218', 'T1222', 'T1485', 'T1486',
            'T1489', 'T1490', 'T1496', 'T1499', 'T1505', 'T1528', 'T1537', 'T1539',
            'T1543', 'T1546', 'T1547', 'T1548', 'T1550', 'T1552', 'T1555', 'T1556',
            'T1557', 'T1558', 'T1559', 'T1562', 'T1563', 'T1564', 'T1566', 'T1567',
            'T1569', 'T1570', 'T1574', 'T1599', 'T1606', 'T1614', 'T1621'
        ];
        defaultProductTechs.forEach(function(tech) { allSourceTechniques.add(tech); });
        
        // Calculate overall coverage percentage
        var overallCoveragePct = Math.round((allSourceTechniques.size / 211) * 100);
        document.getElementById('overall-coverage').textContent = overallCoveragePct + '%';
        
        // Tactic heatmap data - actual technique counts from your environment
        // MDC removed (you don't have Defender for Cloud)
        // MDA updated with your actual Defender for Cloud Apps coverage
        const heatmapData = {
            'InitialAccess': { sentinel: tacticCounts['InitialAccess'] || 0, defender: defenderCounts['InitialAccess'] || 0, mde: 5, mdi: 2, mda: 2, mdo: 2, entra: 1 },
            'Execution': { sentinel: tacticCounts['Execution'] || 0, defender: defenderCounts['Execution'] || 0, mde: 9, mdi: 2, mda: 2, mdo: 1, entra: 0 },
            'Persistence': { sentinel: tacticCounts['Persistence'] || 0, defender: defenderCounts['Persistence'] || 0, mde: 9, mdi: 5, mda: 2, mdo: 1, entra: 0 },
            'PrivilegeEscalation': { sentinel: tacticCounts['PrivilegeEscalation'] || 0, defender: defenderCounts['PrivilegeEscalation'] || 0, mde: 4, mdi: 2, mda: 1, mdo: 1, entra: 1 },
            'DefenseEvasion': { sentinel: tacticCounts['DefenseEvasion'] || 0, defender: defenderCounts['DefenseEvasion'] || 0, mde: 14, mdi: 3, mda: 2, mdo: 0, entra: 2 },
            'CredentialAccess': { sentinel: tacticCounts['CredentialAccess'] || 0, defender: defenderCounts['CredentialAccess'] || 0, mde: 8, mdi: 10, mda: 3, mdo: 1, entra: 3 },
            'Discovery': { sentinel: tacticCounts['Discovery'] || 0, defender: defenderCounts['Discovery'] || 0, mde: 9, mdi: 3, mda: 0, mdo: 0, entra: 0 },
            'LateralMovement': { sentinel: tacticCounts['LateralMovement'] || 0, defender: defenderCounts['LateralMovement'] || 0, mde: 5, mdi: 4, mda: 0, mdo: 0, entra: 0 },
            'Collection': { sentinel: tacticCounts['Collection'] || 0, defender: defenderCounts['Collection'] || 0, mde: 3, mdi: 1, mda: 1, mdo: 1, entra: 2 },
            'CommandAndControl': { sentinel: tacticCounts['CommandAndControl'] || 0, defender: defenderCounts['CommandAndControl'] || 0, mde: 3, mdi: 0, mda: 0, mdo: 0, entra: 1 },
            'Exfiltration': { sentinel: tacticCounts['Exfiltration'] || 0, defender: defenderCounts['Exfiltration'] || 0, mde: 3, mdi: 0, mda: 3, mdo: 1, entra: 0 },
            'Impact': { sentinel: tacticCounts['Impact'] || 0, defender: defenderCounts['Impact'] || 0, mde: 5, mdi: 0, mda: 3, mdo: 1, entra: 0 },
            'Reconnaissance': { sentinel: tacticCounts['Reconnaissance'] || 0, defender: defenderCounts['Reconnaissance'] || 0, mde: 0, mdi: 0, mda: 0, mdo: 0, entra: 0 },
            'ResourceDevelopment': { sentinel: tacticCounts['ResourceDevelopment'] || 0, defender: defenderCounts['ResourceDevelopment'] || 0, mde: 1, mdi: 0, mda: 0, mdo: 0, entra: 0 }
        };
        
        // Tactic names
        const tacticNames = {
            'InitialAccess': 'Initial Access',
            'Execution': 'Execution',
            'Persistence': 'Persistence',
            'PrivilegeEscalation': 'Privilege Escalation',
            'DefenseEvasion': 'Defense Evasion',
            'CredentialAccess': 'Credential Access',
            'Discovery': 'Discovery',
            'LateralMovement': 'Lateral Movement',
            'Collection': 'Collection',
            'CommandAndControl': 'Command and Control',
            'Exfiltration': 'Exfiltration',
            'Impact': 'Impact',
            'Reconnaissance': 'Reconnaissance',
            'ResourceDevelopment': 'Resource Development'
        };
        
        // Populate tactic heatmap table
        const heatmapBody = document.getElementById('heatmap-body');
        if (heatmapBody) {
            Object.keys(heatmapData).forEach(function(tacticKey) {
                const data = heatmapData[tacticKey];
                const total = data.sentinel + data.defender + data.mde + data.mdi + data.mda + data.mdo + data.entra;
                const tacticName = tacticNames[tacticKey] || tacticKey;
                
                const row = document.createElement('tr');
                row.innerHTML = 
                    '<td style="padding:10px; border:1px solid #cbd5e1; font-weight:600; color:#1e293b">' + tacticName + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.sentinel) + '">' + data.sentinel + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.defender) + '">' + data.defender + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.mde) + '">' + data.mde + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.mdi) + '">' + data.mdi + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.mda) + '">' + data.mda + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.mdo) + '">' + data.mdo + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:' + getCellColor(data.entra) + '">' + data.entra + '</td>' +
                    '<td style="padding:10px; border:1px solid #cbd5e1; text-align:center; background:#10b981; color:white; font-weight:bold">' + total + '</td>';
                heatmapBody.appendChild(row);
            });
        }
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        Write-Host "  ✓ Report saved: $OutputFile" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  ✗ Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main function
function Get-SentinelAnalyticalRulesReport {
    [CmdletBinding()]
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroup,
        [string]$WorkspaceName,
        [string]$WorkspaceId,  # Optional: Provide directly to skip lookup
        [switch]$ExportHtml,
        [switch]$ExportPdf,
        
        # Microsoft Defender Graph API Parameters (Optional)
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )

    Clear-Host
    Write-Host ""
    Write-Host "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     " -ForegroundColor Cyan
    Write-Host "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     " -ForegroundColor Cyan
    Write-Host "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     " -ForegroundColor Cyan
    Write-Host "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     " -ForegroundColor Cyan
    Write-Host "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗" -ForegroundColor Cyan
    Write-Host "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "          ANALYTICAL ANALYZER" -ForegroundColor White
    Write-Host "          Developed by Rohit Ashok" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host ""

    # Collect inputs
    if (-not $SubscriptionId) {
        Write-Host "  Subscription ID : " -NoNewline -ForegroundColor Yellow
        $SubscriptionId = Read-Host
    }
    if (-not $ResourceGroup) {
        Write-Host "  Resource Group  : " -NoNewline -ForegroundColor Yellow
        $ResourceGroup = Read-Host
    }
    if (-not $WorkspaceName) {
        Write-Host "  Workspace Name  : " -NoNewline -ForegroundColor Yellow
        $WorkspaceName = Read-Host
    }

    # Authenticate
    try {
        $tokens = Get-AzureToken
    } catch {
        return $null
    }

    # Fetch rules
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Fetching Data" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  → Connecting to Sentinel workspace..." -ForegroundColor White
    
    # Validate required parameters
    if (-not $SubscriptionId -or -not $ResourceGroup -or -not $WorkspaceName) {
        Write-Host "  ✗ Error: Missing required parameters!" -ForegroundColor Red
        Write-Host "     SubscriptionId: $SubscriptionId" -ForegroundColor Gray
        Write-Host "     ResourceGroup: $ResourceGroup" -ForegroundColor Gray
        Write-Host "     WorkspaceName: $WorkspaceName" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "  Please provide all required parameters:" -ForegroundColor Yellow
        Write-Host "     -SubscriptionId 'your-sub-id'" -ForegroundColor Yellow
        Write-Host "     -ResourceGroup 'your-rg-name'" -ForegroundColor Yellow
        Write-Host "     -WorkspaceName 'your-workspace-name'" -ForegroundColor Yellow
        return $null
    }

    $apiVersions = @("2024-09-01", "2024-03-01", "2023-12-01-preview")
    $baseUrl = "$script:MgmtEndpoint/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
               "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
               "/providers/Microsoft.SecurityInsights/alertRules"

    Write-Host "     Subscription: $SubscriptionId" -ForegroundColor Gray
    Write-Host "     Resource Group: $ResourceGroup" -ForegroundColor Gray
    Write-Host "     Workspace: $WorkspaceName" -ForegroundColor Gray
    Write-Host ""

    $rules = $null
    $lastError = $null
    foreach ($ver in $apiVersions) {
        try {
            $url = "$baseUrl`?api-version=$ver"
            Write-Host "     Trying API version $ver..." -ForegroundColor Gray
            $rules = Call-SentinelAPI -Uri $url -Token $tokens.Management
            Write-Host "     ✓ Connected successfully" -ForegroundColor Green
            break
        } catch {
            $lastError = $_
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            if ($statusCode -eq 404) {
                Write-Host "     × API version $ver not supported" -ForegroundColor DarkGray
                continue
            } elseif ($statusCode -eq 403) {
                Write-Host "  ✗ Error: Access Denied (403)" -ForegroundColor Red
                Write-Host "     You don't have permission to access this workspace" -ForegroundColor Yellow
                Write-Host "     Required role: 'Microsoft Sentinel Reader' or 'Reader'" -ForegroundColor Yellow
                return $null
            } elseif ($statusCode -eq 401) {
                Write-Host "  ✗ Error: Unauthorized (401)" -ForegroundColor Red
                Write-Host "     Authentication failed. Try running: az login" -ForegroundColor Yellow
                return $null
            } else {
                Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "     Status Code: $statusCode" -ForegroundColor Gray
                Write-Host "     URL: $url" -ForegroundColor DarkGray
                return $null
            }
        }
    }

    if (-not $rules) {
        Write-Host "  ✗ Failed to connect to workspace" -ForegroundColor Red
        if ($lastError) {
            Write-Host "     Last error: $($lastError.Exception.Message)" -ForegroundColor Gray
        }
        Write-Host "" -ForegroundColor Yellow
        Write-Host "  Troubleshooting:" -ForegroundColor Yellow
        Write-Host "     1. Verify workspace name is correct (case-sensitive)" -ForegroundColor Yellow
        Write-Host "     2. Verify resource group name is correct (case-sensitive)" -ForegroundColor Yellow
        Write-Host "     3. Check you have 'Reader' role on the workspace" -ForegroundColor Yellow
        Write-Host "     4. Verify you're logged into the correct subscription:" -ForegroundColor Yellow
        Write-Host "        az account show" -ForegroundColor Gray
        return $null
    }

    Write-Host "  ✓ Retrieved $($rules.Count) analytical rules" -ForegroundColor Green

    # Process MITRE data
    Write-Host "  → Processing MITRE mappings..." -ForegroundColor White

    # Note: Using arrays here - could optimize with ArrayList for large datasets (500+ rules)
    # but current performance is acceptable for typical Sentinel deployments
    $enabled = @()
    $disabled = @()
    $tacticData = @{}

    foreach ($rule in $rules) {
        # Quick enabled/disabled split
        if ($rule.properties.enabled) {
            $enabled += $rule
        } else {
            $disabled += $rule
        }

        $mitreInfo = Extract-MitreData $rule
        foreach ($tactic in $mitreInfo.Tactics) {
            if (-not $tactic) { continue }
            
            $key = $tactic -replace '\s', ''  # Remove spaces for consistency
            if (-not $tacticData[$key]) {
                $tacticData[$key] = @{
                    Total = 0
                    EnabledCount = 0
                }
            }
            
            $tacticData[$key].Total++
            if ($rule.properties.enabled) {
                $tacticData[$key].EnabledCount++
            }
        }
    }

    Write-Host "  ✓ MITRE analysis complete" -ForegroundColor Green

    # Table Optimization
    $tableData = $null
    
    if ($tokens.LogAnalytics) {
        Write-Host "  → Analyzing table usage..." -ForegroundColor White
        
        try {
            # Use provided WorkspaceId or look it up
            if ($WorkspaceId) {
                Write-Host "      → Using provided Workspace ID: $WorkspaceId" -ForegroundColor Gray
                $workspaceIdToUse = $WorkspaceId
            } else {
                Write-Host "      → Looking up Workspace ID..." -ForegroundColor Gray
                $wsUri = "$script:MgmtEndpoint/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                         "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName?api-version=2022-10-01"
                
                $wsInfo = Invoke-RestMethod -Uri $wsUri -Headers @{"Authorization"="Bearer $($tokens.Management)"} -Method Get
                $workspaceIdToUse = $wsInfo.properties.customerId
                Write-Host "      → Workspace ID: $workspaceIdToUse" -ForegroundColor Gray
            }
            
            $ingestedTables = Get-IngestedTables -WorkspaceId $workspaceIdToUse -Token $tokens.LogAnalytics -LookbackDays 30
            
            if ($ingestedTables -and $ingestedTables.Count -gt 0) {
                $tableLookup = @{}
                foreach ($tbl in $ingestedTables) {
                    $tableLookup[$tbl.DataType.ToLower()] = $tbl
                }
                
                $ruleMappings = Get-RuleTableMappings -Rules $rules -TableLookup $tableLookup
                
                $tableData = @{
                    IngestedTables = $ingestedTables
                    RuleMappings = $ruleMappings
                    TableLookup = $tableLookup
                }
                
                Write-Host "  ✓ Table optimization analysis complete" -ForegroundColor Green
            } else {
                Write-Host "  ⚠ No table data available (Usage table may be empty)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ⚠ Table analysis failed: $($_.Exception.Message)" -ForegroundColor Yellow
            
            # Show more details for troubleshooting
            if ($_.Exception.Response) {
                Write-Host "      HTTP Status: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Gray
                
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $responseBody = $reader.ReadToEnd()
                    $reader.Close()
                    
                    if ($responseBody) {
                        Write-Host "      Error Details: $responseBody" -ForegroundColor Gray
                    }
                } catch {}
            }
            
            Write-Host "      Note: MITRE analysis completed successfully - report will still be generated" -ForegroundColor Gray
        }
    } else {
        Write-Host "  ⚠ Skipping table analysis (Log Analytics token unavailable)" -ForegroundColor Yellow
    }

    # Defender Custom Rules (Optional)
    $defenderData = $null
    
    if ($TenantId -and $ClientId -and $ClientSecret) {
        Write-Host ""
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Defender Custom Detection Rules" -ForegroundColor Cyan
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        try {
            $graphToken = Get-GraphApiToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
            $defenderRules = Get-DefenderCustomRules -GraphToken $graphToken
            
            if ($defenderRules -and $defenderRules.Count -gt 0) {
                # Process Defender rules
                $defenderEnabled = $defenderRules | Where-Object { $_.isEnabled -eq $true }
                $defenderDisabled = $defenderRules | Where-Object { $_.isEnabled -eq $false }
                
                Write-Host "      → Processing $($defenderEnabled.Count) enabled rules..." -ForegroundColor Gray
                
                # Group by MITRE tactics and extract techniques
                # MITRE data is nested: rule.detectionAction.alertTemplate.category
                $defenderTactics = @{}
                $defenderTechniques = @()  # Collect all techniques
                $rulesProcessed = 0
                $rulesWithCategory = 0
                
                foreach ($rule in $defenderEnabled) {
                    $rulesProcessed++
                    
                    # Defender stores MITRE data in detectionAction.alertTemplate
                    $category = $null
                    if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                        $category = $rule.detectionAction.alertTemplate.category
                        
                        # Extract MITRE techniques
                        if ($rule.detectionAction.alertTemplate.mitreTechniques) {
                            $defenderTechniques += $rule.detectionAction.alertTemplate.mitreTechniques
                        }
                    }
                    
                    # If category is null or empty, mark as "No Mapping Found"
                    if (-not $category) {
                        $category = "No Mapping Found"
                    } else {
                        $rulesWithCategory++
                    }
                    
                    if (-not $defenderTactics.ContainsKey($category)) {
                        $defenderTactics[$category] = 0
                    }
                    $defenderTactics[$category]++
                }
                
                # Get unique techniques
                $uniqueDefenderTechniques = $defenderTechniques | Select-Object -Unique
                
                # Debug output
                Write-Host "      → Processed $rulesProcessed rules" -ForegroundColor Gray
                Write-Host "      → Rules with MITRE category: $rulesWithCategory" -ForegroundColor Gray
                Write-Host "      → Found $($defenderTactics.Count) unique MITRE tactics (including unmapped)" -ForegroundColor Gray
                Write-Host "      → Found $($uniqueDefenderTechniques.Count) unique MITRE techniques" -ForegroundColor Gray
                
                if ($defenderTactics.Count -gt 0) {
                    Write-Host "        Tactics found:" -ForegroundColor Gray
                    $defenderTactics.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object {
                        Write-Host "          $($_.Key): $($_.Value)" -ForegroundColor Green
                    }
                }
                
                $defenderData = @{
                    AllRules = $defenderRules
                    EnabledRules = $defenderEnabled
                    DisabledRules = $defenderDisabled
                    TacticCounts = $defenderTactics
                    Techniques = $uniqueDefenderTechniques  # Add techniques array
                }
                
                Write-Host "  ✓ Defender analysis complete" -ForegroundColor Green
            } else {
                Write-Host "  ⚠ No Defender custom rules found" -ForegroundColor Yellow
                # TODO: Add support for MDO/MDI custom rules
            }
        } catch {
            Write-Host "  ⚠ Defender analysis failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "     Check App Registration permissions (SecurityEvents.Read.All required)" -ForegroundColor Gray
        }
    }

    # Generate report
    if ($ExportHtml -or $ExportPdf) {
        Write-Host ""
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Report Generation" -ForegroundColor Cyan
        Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        $downloadsPath = Get-UserDownloadsPath
        $htmlFile = Join-Path $downloadsPath "Sentinel Analytical Analyzer.html"

        Build-HtmlReport -AllRules $rules -EnabledRules $enabled -DisabledRules $disabled `
                         -TacticData $tacticData -TableData $tableData -DefenderData $defenderData `
                         -WorkspaceName $WorkspaceName -OutputFile $htmlFile
    }

    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ ANALYSIS COMPLETE" -ForegroundColor Green
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""

    return @{
        Rules = $rules
        Enabled = $enabled
        Disabled = $disabled
        TacticStats = $tacticData
        TableData = $tableData
        HtmlPath = if ($ExportHtml -or $ExportPdf) { $htmlFile } else { $null }
    }
}

Export-ModuleMember -Function 'Get-SentinelAnalyticalRulesReport'
