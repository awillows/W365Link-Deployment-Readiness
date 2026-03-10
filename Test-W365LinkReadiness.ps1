<#
.SYNOPSIS
    Windows 365 Link - Deployment Readiness Assessment
    
.DESCRIPTION
    Checks Microsoft Graph for Windows 365 Link deployment prerequisites and generates
    a professional HTML report with findings, risk levels, and remediation links.

    Checks performed:
      1. Licensing (Windows 365, Intune, Entra ID Premium)
      2. Entra ID Device Join settings
      3. Intune Automatic Enrollment (MDM User Scope)
      4. Enrollment Restrictions (personal device blocks)
      5. SSO on Cloud PC Provisioning Policies
      6. Conditional Access policies (two-stage auth model)
      7. Authentication Methods (FIDO2)
      8. Intune Filters for Windows 365 Link (operatingSystemSKU = WCPC)

.PARAMETER UserUPN
    Optional. A target user UPN to check licenses and group membership against.
    If omitted, the script checks tenant-wide settings only.

.PARAMETER OutputPath
    Optional. Path for the HTML report. Defaults to .\W365Link-ReadinessReport.html

.PARAMETER OpenReport
    Switch. Opens the report in the default browser after generation.

.PARAMETER IncludeProvisioningPolicies
    Optional. Array of provisioning policy names to include in the SSO check.
    Only these policies will be evaluated — all others are excluded.
    Cannot be used together with -ExcludeProvisioningPolicies.

.PARAMETER ExcludeProvisioningPolicies
    Optional. Array of provisioning policy names to exclude from the SSO check.
    These policies will be shown separately and will not affect the readiness score.
    Useful for policies assigned to Cloud PCs that won't be used with Link devices.
    Cannot be used together with -IncludeProvisioningPolicies.

.EXAMPLE
    .\Test-W365LinkReadiness.ps1 -UserUPN "admin@contoso.com" -OpenReport

.EXAMPLE
    .\Test-W365LinkReadiness.ps1 -ExcludeProvisioningPolicies "Hybrid/ Test policy","BYON TEST" -OpenReport
    Runs the assessment but excludes the named policies from the SSO check.

.EXAMPLE
    .\Test-W365LinkReadiness.ps1 -IncludeProvisioningPolicies "AADJ Standard","Frontline" -OpenReport
    Only evaluates SSO status on the named policies — all others are ignored.

.NOTES
    Requires: Microsoft.Graph PowerShell module
    Permissions needed (delegated):
      - DeviceManagementServiceConfig.Read.All
      - DeviceManagementConfiguration.Read.All
      - Policy.Read.All
      - Directory.Read.All
      - CloudPC.Read.All
      - Policy.ReadWrite.ConditionalAccess (read-only usage)
    
    Author: Windows 365 Link Supportability Team
    Version: 1.0 - March 2026
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$UserUPN,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\W365Link-ReadinessReport.html",

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport,

    [Parameter(Mandatory = $false)]
    [string[]]$IncludeProvisioningPolicies,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeProvisioningPolicies
)

#Requires -Version 5.1

# Validate mutually exclusive parameters
if ($IncludeProvisioningPolicies -and $ExcludeProvisioningPolicies) {
    Write-Error "-IncludeProvisioningPolicies and -ExcludeProvisioningPolicies cannot be used together. Use one or the other."
    return
}

# ============================================================================
# REGION: Configuration & Constants
# ============================================================================
$ErrorActionPreference = "Continue"
$script:Checks = [System.Collections.ArrayList]::new()
$script:TenantInfo = @{}
$script:Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Well-known App IDs for Conditional Access
$W365AppId      = "0af06dc6-e4b5-4f28-818e-e78e62d137a5"  # Windows 365
$AVDAppId       = "9cdead84-a844-4324-93f2-b2e6bb768d07"  # Azure Virtual Desktop
$WCLAppId       = "270efc09-cd0d-444b-a71f-39af4910ec45"  # Windows Cloud Login

# License SKU part names we look for
$W365SkuParts = @(
    "CPC_E_",    # Windows 365 Enterprise
    "CPC_B_",    # Windows 365 Business
    "CPC_F_",    # Windows 365 Frontline
    "WIN365"     # Catch-all
)
$IntuneSkuParts = @(
    "INTUNE_A",
    "Intune_EDU",
    "INTUNE_SMB",
    "Microsoft_Intune_Suite",  # Intune Suite add-on
    "SPE_E3",    # M365 E3 includes Intune
    "SPE_E5",    # M365 E5 includes Intune
    "Microsoft_365_E5",  # M365 E5 (no Teams) variant
    "Microsoft_365_E3",  # M365 E3 (no Teams) variant
    "SPB",       # M365 Business Premium
    "Microsoft_365_Business_Premium",
    "EMSPREMIUM" # EMS E5
)
$EntraPremiumSkuParts = @(
    "AAD_PREMIUM",
    "EMSPREMIUM",
    "SPE_E3",
    "SPE_E5",
    "Microsoft_365_E5",  # M365 E5 (no Teams) variant
    "Microsoft_365_E3",  # M365 E3 (no Teams) variant
    "SPB",
    "Microsoft_365_Business_Premium",
    "EMS"
)

# ============================================================================
# REGION: Helper Functions
# ============================================================================
function Add-CheckResult {
    param(
        [string]$Category,
        [string]$CheckName,
        [ValidateSet("Pass","Warning","Fail","Info","Error")]
        [string]$Status,
        [string]$Detail,
        [string]$Remediation = "",
        [string]$LearnMoreUrl = "",
        [string]$RiskLevel = ""  # "Critical", "High", "Medium", "Low"
    )

    $null = $script:Checks.Add([PSCustomObject]@{
        Category     = $Category
        CheckName    = $CheckName
        Status       = $Status
        Detail       = $Detail
        Remediation  = $Remediation
        LearnMoreUrl = $LearnMoreUrl
        RiskLevel    = $RiskLevel
    })
}

function Invoke-MgGraphSafe {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [string]$ApiVersion = "v1.0"
    )
    try {
        $fullUri = "https://graph.microsoft.com/$ApiVersion/$($Uri.TrimStart('/'))"
        $response = Invoke-MgGraphRequest -Method $Method -Uri $fullUri -OutputType PSObject -ErrorAction Stop
        return $response
    }
    catch {
        $statusCode = $null
        # Try standard HttpResponseMessage
        if ($_.Exception.Response) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        # Fallback: .NET 5+ HttpRequestException exposes StatusCode directly
        if (-not $statusCode -and $_.Exception.PSObject.Properties['StatusCode']) {
            try { $statusCode = [int]$_.Exception.StatusCode } catch {}
        }
        # Fallback: parse well-known status names from the error message
        if (-not $statusCode) {
            $msg = $_.Exception.Message
            if     ($msg -match 'NotFound')     { $statusCode = 404 }
            elseif ($msg -match 'Forbidden')    { $statusCode = 403 }
            elseif ($msg -match 'Unauthorized') { $statusCode = 401 }
            elseif ($msg -match 'BadRequest')   { $statusCode = 400 }
            elseif ($msg -match 'Conflict')     { $statusCode = 409 }
        }
        Write-Warning "Graph call failed: $Uri — $($_.Exception.Message)"
        return [PSCustomObject]@{ "_error" = $_.Exception.Message; "_statusCode" = $statusCode }
    }
}

function Test-GraphModule {
    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication")) {
        Write-Host "`n[!] Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
        }
        catch {
            Write-Error "Failed to install Microsoft.Graph module. Please install manually: Install-Module Microsoft.Graph -Scope CurrentUser"
            return $false
        }
    }
    return $true
}

function Connect-ToGraph {
    $scopes = @(
        "DeviceManagementServiceConfig.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "Policy.Read.All",
        "Directory.Read.All",
        "CloudPC.Read.All"
    )
    
    Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Write-Host "    Required scopes: $($scopes -join ', ')" -ForegroundColor Gray
    
    try {
        $context = Get-MgContext
        if ($null -eq $context) {
            Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
            $context = Get-MgContext
        }
        else {
            # Check if we have the scopes we need
            $missingScopes = $scopes | Where-Object { $context.Scopes -notcontains $_ }
            if ($missingScopes.Count -gt 0) {
                Write-Host "    Reconnecting with additional scopes..." -ForegroundColor Yellow
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
                $context = Get-MgContext
            }
        }
        
        Write-Host "    Connected as: $($context.Account)" -ForegroundColor Green
        Write-Host "    Tenant ID:    $($context.TenantId)" -ForegroundColor Green
        
        $script:TenantInfo["Account"] = $context.Account
        $script:TenantInfo["TenantId"] = $context.TenantId
        return $true
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# REGION: Check Functions
# ============================================================================

# --- CHECK 1: Licensing ---
function Test-Licensing {
    Write-Host "`n[1/8] Checking licensing..." -ForegroundColor Cyan
    $category = "Licensing"

    # Get all subscribed SKUs in the tenant
    $skuResponse = Invoke-MgGraphSafe -Uri "/subscribedSkus"
    
    if ($skuResponse._error) {
        Add-CheckResult -Category $category -CheckName "Retrieve tenant licenses" `
            -Status "Error" -Detail "Could not query licenses: $($skuResponse._error)" `
            -RiskLevel "Critical"
        return
    }

    $skus = if ($skuResponse.value) { $skuResponse.value } else { @($skuResponse) | Where-Object { $_.skuPartNumber } }
    
    # Check Windows 365
    $w365Skus = $skus | Where-Object { 
        $sku = $_.skuPartNumber
        ($W365SkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($w365Skus) {
        $skuNames = ($w365Skus | ForEach-Object { "$($_.skuPartNumber) ($($_.consumedUnits)/$($_.prepaidUnits.enabled) used)" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Windows 365 license" `
            -Status "Pass" -Detail "Found: $skuNames" -RiskLevel "Low"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Windows 365 license" `
            -Status "Fail" -Detail "No Windows 365 (Enterprise, Frontline, or Business) license found in tenant." `
            -Remediation "Purchase and assign a Windows 365 license." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -RiskLevel "Critical"
    }

    # Check Intune
    $intuneSkus = $skus | Where-Object {
        $sku = $_.skuPartNumber
        ($IntuneSkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($intuneSkus) {
        $skuNames = ($intuneSkus | ForEach-Object { "$($_.skuPartNumber)" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Microsoft Intune license" `
            -Status "Pass" -Detail "Intune capability found via: $skuNames" -RiskLevel "Low"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Microsoft Intune license" `
            -Status "Fail" -Detail "No license providing Intune found. Link requires Intune for device management." `
            -Remediation "Assign a license that includes Intune (standalone, M365 E3/E5, Business Premium, etc.)." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
            -RiskLevel "Critical"
    }

    # Check Entra ID Premium
    $entraSkus = $skus | Where-Object {
        $sku = $_.skuPartNumber
        ($EntraPremiumSkuParts | Where-Object { $sku -like "*$_*" }).Count -gt 0
    }
    if ($entraSkus) {
        $skuNames = ($entraSkus | ForEach-Object { "$($_.skuPartNumber)" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Entra ID Premium license" `
            -Status "Pass" -Detail "Entra Premium capability found via: $skuNames" -RiskLevel "Low"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Entra ID Premium license" `
            -Status "Fail" -Detail "No Entra ID Premium license found. Without it, automatic MDM enrollment silently fails — devices join Entra but never appear in Intune." `
            -Remediation "Assign Entra ID Premium P1 or P2 (standalone, M365 E3/E5, EMS, Business Premium, etc.)." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -RiskLevel "Critical"
    }

    # If a target user was specified, check their individual licenses
    if ($UserUPN) {
        Write-Host "    Checking user-level licenses for $UserUPN..." -ForegroundColor Gray
        $userLicenses = Invoke-MgGraphSafe -Uri "/users/$UserUPN/licenseDetails"
        if (-not $userLicenses._error) {
            $userSkus = if ($userLicenses.value) { $userLicenses.value } else { @() }
            $userSkuNames = ($userSkus | ForEach-Object { $_.skuPartNumber }) -join ", "
            
            if ($userSkuNames) {
                Add-CheckResult -Category $category -CheckName "User licenses ($UserUPN)" `
                    -Status "Info" -Detail "Assigned SKUs: $userSkuNames" -RiskLevel "Low"
            }
            else {
                Add-CheckResult -Category $category -CheckName "User licenses ($UserUPN)" `
                    -Status "Warning" -Detail "No licenses found assigned to $UserUPN. Ensure W365, Intune, and Entra Premium are assigned." `
                    -Remediation "Assign required licenses to this user in M365 Admin Center." `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements" `
                    -RiskLevel "High"
            }
        }
    }
}

# --- CHECK 2: Entra ID Device Join ---
function Test-EntraDeviceJoin {
    Write-Host "[2/8] Checking Entra ID device join settings..." -ForegroundColor Cyan
    $category = "Entra ID Device Join"

    # Get device registration policy  
    $regPolicy = Invoke-MgGraphSafe -Uri "/policies/deviceRegistrationPolicy"
    
    if ($regPolicy._error) {
        # Fallback: try beta
        $regPolicy = Invoke-MgGraphSafe -Uri "/policies/deviceRegistrationPolicy" -ApiVersion "beta"
    }

    if ($regPolicy._error) {
        Add-CheckResult -Category $category -CheckName "Device registration policy" `
            -Status "Error" -Detail "Could not retrieve device registration policy: $($regPolicy._error). You may need Policy.Read.All permissions." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
            -RiskLevel "Medium"
        return
    }

    # Check azureADJoin setting
    $joinSetting = $regPolicy.azureADJoin
    if ($joinSetting) {
        # Determine join scope — the API uses two different shapes:
        #   Beta/legacy:  appliesTo = "all" | "selected" | "none" (or "0"/"1"/"2")
        #   v1.0 (2024+): allowedToJoin with @odata.type polymorphic membership
        $appliesTo = $joinSetting.appliesTo

        # If appliesTo is missing/empty, derive it from the allowedToJoin OData type
        if ([string]::IsNullOrWhiteSpace($appliesTo) -and $joinSetting.allowedToJoin) {
            $odataType = $joinSetting.allowedToJoin.'@odata.type'
            if ($odataType -like '*allDeviceRegistrationMembership*')        { $appliesTo = "all" }
            elseif ($odataType -like '*enumeratedDeviceRegistrationMembership*') { $appliesTo = "selected" }
            elseif ($odataType -like '*noDeviceRegistrationMembership*')     { $appliesTo = "none" }
        }

        # Normalise legacy numeric values
        if ($appliesTo -eq "0") { $appliesTo = "none" }
        elseif ($appliesTo -eq "1") { $appliesTo = "all" }
        elseif ($appliesTo -eq "2") { $appliesTo = "selected" }

        $allowedToJoin = $joinSetting.isAllowed

        if ($appliesTo -eq "none" -or $allowedToJoin -eq $false) {
            Add-CheckResult -Category $category -CheckName "Users may join devices to Entra" `
                -Status "Fail" -Detail "Device join is set to NONE. No users can join Windows 365 Link devices to Entra ID." `
                -Remediation "Set 'Users may join devices to Microsoft Entra' to All or Selected in Entra admin center > Identity > Devices > Device Settings." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -RiskLevel "Critical"
        }
        elseif ($appliesTo -eq "all") {
            Add-CheckResult -Category $category -CheckName "Users may join devices to Entra" `
                -Status "Pass" -Detail "All users are allowed to join devices to Entra ID." -RiskLevel "Low"
        }
        elseif ($appliesTo -eq "selected") {
            # Collect allowed groups/users from whichever shape the API returned
            $groupIds = @()
            $userIds  = @()
            if ($joinSetting.allowedToJoin) {
                if ($joinSetting.allowedToJoin.groups) { $groupIds = $joinSetting.allowedToJoin.groups }
                if ($joinSetting.allowedToJoin.users)  { $userIds  = $joinSetting.allowedToJoin.users }
            }
            if (-not $groupIds -and $joinSetting.allowedGroups) { $groupIds = $joinSetting.allowedGroups }
            $groupCount = ($groupIds | Measure-Object).Count
            $userCount  = ($userIds  | Measure-Object).Count
            $scopeDetail = @()
            if ($groupCount -gt 0) { $scopeDetail += "$groupCount group(s)" }
            if ($userCount  -gt 0) { $scopeDetail += "$userCount user(s)" }
            $scopeText = if ($scopeDetail.Count -gt 0) { $scopeDetail -join " and " } else { "unknown membership — verify in portal" }
            Add-CheckResult -Category $category -CheckName "Users may join devices to Entra" `
                -Status "Warning" -Detail "Device join is set to SELECTED ($scopeText). Ensure all Windows 365 Link users are included in the allowed scope." `
                -Remediation "Verify target groups/users in Entra admin center > Identity > Devices > Device Settings > 'Users may join devices to Microsoft Entra'." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -RiskLevel "Medium"
        }
        else {
            # Truly unknown — dump what we got for diagnostics
            $raw = $joinSetting | ConvertTo-Json -Depth 4 -Compress -ErrorAction SilentlyContinue
            Add-CheckResult -Category $category -CheckName "Users may join devices to Entra" `
                -Status "Warning" -Detail "Could not determine device join scope from the policy response. Raw azureADJoin value: $raw. Please verify manually in Entra admin center > Identity > Devices > Device Settings." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -RiskLevel "Medium"
        }
    }
    else {
        Add-CheckResult -Category $category -CheckName "Users may join devices to Entra" `
            -Status "Warning" -Detail "The azureADJoin setting was not found in the device registration policy response. This can happen if Graph permissions are insufficient. Verify manually: Entra admin center > Identity > Devices > Device Settings > 'Users may join devices to Microsoft Entra'." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
            -RiskLevel "Medium"
    }

    # Check device limit
    $maxDevices = $regPolicy.userDeviceQuota
    if ($null -ne $maxDevices) {
        if ([int]$maxDevices -lt 20) {
            Add-CheckResult -Category $category -CheckName "Max devices per user" `
                -Status "Warning" -Detail "Limit is $maxDevices. If using a DEM account for bulk onboarding, this limit may be reached quickly." `
                -Remediation "Consider increasing the limit in Entra admin center > Identity > Devices > Device Settings." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/join-microsoft-entra" `
                -RiskLevel "Medium"
        }
        else {
            Add-CheckResult -Category $category -CheckName "Max devices per user" `
                -Status "Pass" -Detail "Limit is $maxDevices per user." -RiskLevel "Low"
        }
    }
}

# --- CHECK 3: Intune Automatic Enrollment (MDM User Scope) ---
function Test-MDMUserScope {
    Write-Host "[3/8] Checking MDM User Scope (auto-enrollment)..." -ForegroundColor Cyan
    $category = "Intune Auto-Enrollment"

    # The mobilityManagementPolicies endpoint is beta only
    $mdmPolicies = Invoke-MgGraphSafe -Uri "/policies/mobileDeviceManagementPolicies" -ApiVersion "beta"
    
    if ($mdmPolicies._error) {
        Add-CheckResult -Category $category -CheckName "MDM User Scope" `
            -Status "Error" -Detail "Could not query MDM policies (beta API): $($mdmPolicies._error). Verify manually in Entra admin center > Settings > Mobility." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -RiskLevel "High"
        return
    }

    $policies = if ($mdmPolicies.value) { $mdmPolicies.value } else { @($mdmPolicies) | Where-Object { $_.id } }
    
    # Look for Microsoft Intune
    $intunePolicy = $policies | Where-Object { 
        $_.displayName -like "*Intune*" -or 
        $_.discoveryUrl -like "*enrollment.manage.microsoft.com*"
    }

    if (-not $intunePolicy) {
        Add-CheckResult -Category $category -CheckName "Microsoft Intune MDM application" `
            -Status "Fail" -Detail "No Microsoft Intune MDM application found on the Mobility page. Devices will NOT auto-enroll." `
            -Remediation "Navigate to Entra admin center > Settings > Mobility > Microsoft Intune and set MDM user scope to All or Some." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -RiskLevel "Critical"
        return
    }

    $scope = $intunePolicy.appliesTo
    switch ($scope) {
        "none" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Fail" -Detail "MDM user scope is set to NONE. Devices will join Entra but will NOT enroll in Intune. This is a silent failure — no error is shown." `
                -Remediation "Set MDM user scope to 'All' or 'Some' in Entra admin center > Settings > Mobility > Microsoft Intune." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -RiskLevel "Critical"
        }
        "all" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Pass" -Detail "MDM user scope is set to ALL. All users will auto-enroll." -RiskLevel "Low"
        }
        "selected" {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Warning" -Detail "MDM user scope is set to SELECTED. Ensure all Link device users are in the selected groups." `
                -Remediation "Verify the groups in Entra admin center > Settings > Mobility > Microsoft Intune." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -RiskLevel "Medium"
        }
        default {
            Add-CheckResult -Category $category -CheckName "MDM User Scope" `
                -Status "Info" -Detail "MDM user scope value: '$scope'. Review manually." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
                -RiskLevel "Medium"
        }
    }

    # Check for conflicting MDM apps
    $otherMdmApps = $policies | Where-Object { 
        ($_.displayName -notlike "*Intune*") -and 
        ($_.discoveryUrl -notlike "*enrollment.manage.microsoft.com*") -and
        ($_.appliesTo -ne "none")
    }
    if ($otherMdmApps) {
        $names = ($otherMdmApps | ForEach-Object { $_.displayName }) -join ", "
        Add-CheckResult -Category $category -CheckName "Conflicting MDM applications" `
            -Status "Warning" -Detail "Other MDM apps with active scope found: $names. This can cause enrollment to go to the wrong MDM." `
            -Remediation "Ensure only Microsoft Intune has MDM user scope enabled. Set other applications to None." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/intune-automatic-enrollment" `
            -RiskLevel "High"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Conflicting MDM applications" `
            -Status "Pass" -Detail "No conflicting MDM applications with active scope found." -RiskLevel "Low"
    }
}

# --- CHECK 4: Enrollment Restrictions ---
function Test-EnrollmentRestrictions {
    Write-Host "[4/8] Checking enrollment restrictions..." -ForegroundColor Cyan
    $category = "Enrollment Restrictions"

    $enrollConfigs = Invoke-MgGraphSafe -Uri "/deviceManagement/deviceEnrollmentConfigurations"
    
    if ($enrollConfigs._error) {
        Add-CheckResult -Category $category -CheckName "Platform restrictions" `
            -Status "Error" -Detail "Could not query enrollment configurations: $($enrollConfigs._error)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
            -RiskLevel "High"
        return
    }

    $configs = if ($enrollConfigs.value) { $enrollConfigs.value } else { @() }
    
    # Look for platform restriction configs
    $platformRestrictions = $configs | Where-Object { 
        $_.'@odata.type' -like "*platformRestriction*" 
    }

    $personalBlocked = $false
    $blockingPolicies = @()

    foreach ($restriction in $platformRestrictions) {
        # Check windowsRestriction or the generic structure
        $winRestriction = $restriction.windowsRestriction
        if (-not $winRestriction) {
            $winRestriction = $restriction.platformRestriction
            # If it's a per-platform config, check if it targets Windows
            if ($restriction.platformType -and $restriction.platformType -ne "windows") {
                continue
            }
        }

        if ($winRestriction -and $winRestriction.personalDeviceEnrollmentBlocked -eq $true) {
            $personalBlocked = $true
            $blockingPolicies += "$($restriction.displayName) (Priority: $($restriction.priority))"
        }
    }
    
    # Also check the default restriction
    $defaultRestriction = $configs | Where-Object {
        $_.'@odata.type' -like "*platformRestrictions*" -and $_.displayName -like "*default*"
    }
    foreach ($def in $defaultRestriction) {
        if ($def.windowsRestriction -and $def.windowsRestriction.personalDeviceEnrollmentBlocked -eq $true) {
            $personalBlocked = $true
            $blockingPolicies += "$($def.displayName) [DEFAULT]"
        }
    }

    if ($personalBlocked) {
        $policyList = $blockingPolicies -join "; "
        Add-CheckResult -Category $category -CheckName "Windows personal device enrollment" `
            -Status "Fail" `
            -Detail "Personal/unknown Windows device enrollment is BLOCKED by: $policyList. Windows 365 Link devices initially appear as 'Unknown' during enrollment and will be blocked." `
            -Remediation "Use one of three bypass methods: (1) Upload corporate identifiers with serial numbers, (2) Create a higher-priority policy with an Intune filter for WCPC SKU, or (3) Use a Device Enrollment Manager account." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
            -RiskLevel "Critical"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Windows personal device enrollment" `
            -Status "Pass" -Detail "No platform restriction blocking personal Windows devices found. Link devices should enroll successfully." -RiskLevel "Low"
    }

    # Check for corporate identifiers
    $corpIds = Invoke-MgGraphSafe -Uri "/deviceManagement/importedDeviceIdentities" -ApiVersion "beta"
    if (-not $corpIds._error) {
        $ids = if ($corpIds.value) { $corpIds.value } else { @() }
        $linkIds = $ids | Where-Object { $_.description -like "*Link*" -or $_.importedDeviceIdentifier -like "*Windows 365 Link*" }
        $totalCount = ($ids | Measure-Object).Count
        
        if ($totalCount -gt 0) {
            Add-CheckResult -Category $category -CheckName "Corporate device identifiers" `
                -Status "Info" -Detail "$totalCount corporate identifier(s) found in tenant." -RiskLevel "Low"
        }
        elseif ($personalBlocked) {
            Add-CheckResult -Category $category -CheckName "Corporate device identifiers" `
                -Status "Warning" -Detail "No corporate identifiers uploaded, but personal devices are blocked. Link devices will fail enrollment unless you use DEM or SKU filter." `
                -Remediation "Upload CSV with: Microsoft Corporation,Windows 365 Link,<SerialNumber>" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/enrollment-restrictions" `
                -RiskLevel "High"
        }
    }
}

# --- CHECK 5: SSO on Cloud PC Provisioning Policies ---
function Test-CloudPCSSO {
    Write-Host "[5/8] Checking Cloud PC SSO configuration..." -ForegroundColor Cyan
    $category = "SSO Configuration"

    $provPolicies = Invoke-MgGraphSafe -Uri "/deviceManagement/virtualEndpoint/provisioningPolicies" -ApiVersion "beta"
    
    if ($provPolicies._error) {
        Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
            -Status "Error" -Detail "Could not query provisioning policies: $($provPolicies._error). Ensure CloudPC.Read.All permission is granted." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -RiskLevel "High"
        return
    }

    $allPolicies = if ($provPolicies.value) { $provPolicies.value } else { @() }
    
    if ($allPolicies.Count -eq 0) {
        Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
            -Status "Warning" -Detail "No provisioning policies found. Either no Cloud PCs are configured or permissions are insufficient." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -RiskLevel "Medium"
        return
    }

    # Apply include/exclude filtering
    $policies = $allPolicies
    $excludedPolicies = @()
    $filterNote = ""

    if ($IncludeProvisioningPolicies -and $IncludeProvisioningPolicies.Count -gt 0) {
        $excludedPolicies = $allPolicies | Where-Object { $_.displayName -notin $IncludeProvisioningPolicies }
        $policies = $allPolicies | Where-Object { $_.displayName -in $IncludeProvisioningPolicies }
        $filterNote = "<div style='margin-top:6px;padding:8px 12px;background:#deecf9;border-radius:4px;font-size:12px;color:#0078d4'><strong>Filter applied:</strong> Only evaluating $($policies.Count) of $($allPolicies.Count) policies (include list). $($excludedPolicies.Count) policy(ies) excluded from scoring.</div>"
        if ($policies.Count -eq 0) {
            Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
                -Status "Warning" -Detail "None of the $($allPolicies.Count) provisioning policies matched the -IncludeProvisioningPolicies list. Check the policy names and try again." `
                -RiskLevel "Medium"
            return
        }
    }
    elseif ($ExcludeProvisioningPolicies -and $ExcludeProvisioningPolicies.Count -gt 0) {
        $excludedPolicies = $allPolicies | Where-Object { $_.displayName -in $ExcludeProvisioningPolicies }
        $policies = $allPolicies | Where-Object { $_.displayName -notin $ExcludeProvisioningPolicies }
        $filterNote = "<div style='margin-top:6px;padding:8px 12px;background:#deecf9;border-radius:4px;font-size:12px;color:#0078d4'><strong>Filter applied:</strong> Evaluating $($policies.Count) of $($allPolicies.Count) policies. $($excludedPolicies.Count) policy(ies) excluded from scoring.</div>"
        if ($policies.Count -eq 0) {
            Add-CheckResult -Category $category -CheckName "Cloud PC provisioning policies" `
                -Status "Warning" -Detail "All $($allPolicies.Count) provisioning policies were excluded. Nothing left to evaluate." `
                -RiskLevel "Medium"
            return
        }
    }

    $ssoDisabledPolicies = @()
    $ssoEnabledPolicies = @()

    foreach ($policy in $policies) {
        # The microsoftManagedDesktop or domainJoinConfigurations may contain SSO info
        # Check the cloudPcDomainJoinType and singleSignOnStatus
        $ssoEnabled = $false
        
        # Check various property names where SSO might be stored
        if ($policy.microsoftManagedDesktop -and $policy.microsoftManagedDesktop.type) {
            # Check managed desktop settings
        }
        
        # In beta, SSO can be in windowsSetting or domainJoinConfigurations
        if ($null -ne $policy.enableSingleSignOn) {
            $ssoEnabled = $policy.enableSingleSignOn
        }
        elseif ($null -ne $policy.windowsSetting -and $null -ne $policy.windowsSetting.enableSingleSignOn) {
            $ssoEnabled = $policy.windowsSetting.enableSingleSignOn
        }
        elseif ($null -ne $policy.domainJoinConfigurations) {
            foreach ($djc in $policy.domainJoinConfigurations) {
                if ($djc.type -eq "azureADJoin" -and $djc.enableSingleSignOn -eq $true) {
                    $ssoEnabled = $true
                }
            }
        }
        # Also check the direct property
        if ($policy.PSObject.Properties.Name -contains "singleSignOnStatus") {
            $ssoEnabled = ($policy.singleSignOnStatus -eq "enabled")
        }

        if ($ssoEnabled) {
            $ssoEnabledPolicies += $policy.displayName
        }
        else {
            $ssoDisabledPolicies += $policy.displayName
        }
    }

    # Build a combined HTML table for all provisioning policies
    $evaluatedCount = $ssoEnabledPolicies.Count + $ssoDisabledPolicies.Count
    $tableRows = ""
    foreach ($name in ($ssoEnabledPolicies | Sort-Object)) {
        $tableRows += "<tr><td style='padding:4px 12px;border-bottom:1px solid #eee'><span style='color:#107c10;font-weight:700'>&#x2705;</span> $name</td><td style='padding:4px 12px;border-bottom:1px solid #eee;color:#107c10;font-weight:600'>Enabled</td></tr>"
    }
    foreach ($name in ($ssoDisabledPolicies | Sort-Object)) {
        $tableRows += "<tr><td style='padding:4px 12px;border-bottom:1px solid #eee'><span style='color:#d13438;font-weight:700'>&#x274C;</span> $name</td><td style='padding:4px 12px;border-bottom:1px solid #eee;color:#d13438;font-weight:600'>Disabled</td></tr>"
    }

    # Add excluded policies to the table (greyed out, not scored)
    $excludedNames = @()
    if ($excludedPolicies.Count -gt 0) {
        foreach ($ep in ($excludedPolicies | Sort-Object { $_.displayName })) {
            $excludedNames += $ep.displayName
            $tableRows += "<tr><td style='padding:4px 12px;border-bottom:1px solid #eee;color:#999'><span style='color:#999'>&#x2796;</span> $($ep.displayName)</td><td style='padding:4px 12px;border-bottom:1px solid #eee;color:#999;font-style:italic'>Excluded</td></tr>"
        }
    }

    $policyTable = "<table style='border-collapse:collapse;width:100%;margin-top:8px;font-size:13px'><thead><tr style='background:#f5f5f5'><th style='padding:6px 12px;text-align:left;border-bottom:2px solid #ddd'>Provisioning Policy</th><th style='padding:6px 12px;text-align:left;border-bottom:2px solid #ddd'>SSO Status</th></tr></thead><tbody>$tableRows</tbody></table>$filterNote"

    if ($ssoDisabledPolicies.Count -gt 0) {
        $summaryText = "$($ssoEnabledPolicies.Count) of $evaluatedCount evaluated provisioning policies have SSO enabled. Windows 365 Link CANNOT connect to Cloud PCs without SSO enabled — users will see: 'Your Cloud PC does not support Entra ID single sign-on.'$policyTable"
        Add-CheckResult -Category $category -CheckName "SSO on provisioning policies ($($ssoEnabledPolicies.Count)/$evaluatedCount enabled)" `
            -Status "Fail" `
            -Detail $summaryText `
            -Remediation "Edit each disabled provisioning policy in Intune > Devices > Windows 365 > Provisioning policies > Enable single sign-on. Existing Cloud PCs will use SSO on their next connection — no reprovisioning required." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/enterprise/configure-single-sign-on" `
            -RiskLevel "Critical"
    }
    else {
        $summaryText = "All $evaluatedCount evaluated provisioning policies have SSO enabled.$(if ($excludedPolicies.Count -gt 0) { " ($($excludedPolicies.Count) excluded from scoring.)" })$policyTable"
        Add-CheckResult -Category $category -CheckName "SSO on provisioning policies ($evaluatedCount/$evaluatedCount enabled)" `
            -Status "Pass" -Detail $summaryText -RiskLevel "Low"
    }

    # Check for SSO consent suppression (service principals + targetDeviceGroups)
    Write-Host "    Checking SSO consent suppression..." -ForegroundColor Gray
    
    $ssoSPs = @(
        @{ Name = "Windows Cloud Login"; AppId = $WCLAppId }
    )

    foreach ($ssoSP in $ssoSPs) {
        $spResponse = Invoke-MgGraphSafe -Uri "/servicePrincipals?`$filter=appId eq '$($ssoSP.AppId)'"
        if ($spResponse._error) {
            Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) service principal" `
                -Status "Error" -Detail "Could not query service principal: $($spResponse._error)" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                -RiskLevel "Medium"
            continue
        }

        $spList = if ($spResponse.value) { $spResponse.value } else { @() }
        if ($spList.Count -eq 0) {
            Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) service principal" `
                -Status "Warning" -Detail "'$($ssoSP.Name)' service principal not found in tenant. SSO consent suppression cannot be configured without it." `
                -Remediation "Register the '$($ssoSP.Name)' enterprise app in Entra admin center > Enterprise Applications, or run: New-MgServicePrincipal -AppId '$($ssoSP.AppId)'" `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                -RiskLevel "High"
            continue
        }

        # Extract SP object ID
        $sp = $spList[0]
        $spId = $sp.id
        
        if (-not $spId) {
            Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) consent suppression" `
                -Status "Warning" -Detail "Service principal found but could not extract its object ID. Check consent suppression manually in Entra admin center." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                -RiskLevel "High"
            continue
        }

        # Check remoteDesktopSecurityConfiguration/targetDeviceGroups (beta)
        $targetGroups = Invoke-MgGraphSafe -Uri "/servicePrincipals/$spId/remoteDesktopSecurityConfiguration/targetDeviceGroups" -ApiVersion "beta"
        
        if ($targetGroups._error) {
            # If 404, RDP security config doesn't exist yet (not configured)
            if ($targetGroups._statusCode -eq 404) {
                Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) consent suppression" `
                    -Status "Fail" -Detail "Remote Desktop security configuration not found on '$($ssoSP.Name)'. SSO consent suppression is NOT configured. Users on Link will see: 'Failed to open a Microsoft Entra ID credential prompt' — recurring every 30 days." `
                    -Remediation "Configure consent suppression: Entra admin center > Enterprise Apps > '$($ssoSP.Name)' > Properties > set 'Assignment required' to Yes > add your Cloud PC dynamic device group under 'Users and groups'." `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                    -RiskLevel "Critical"
            }
            else {
                Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) consent suppression" `
                    -Status "Warning" -Detail "Could not query targetDeviceGroups: $($targetGroups._error). Check manually in Entra admin center." `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                    -RiskLevel "High"
            }
        }
        else {
            $groups = if ($targetGroups.value) { $targetGroups.value } else { @() }
            if ($groups.Count -gt 0) {
                $groupNames = ($groups | ForEach-Object { $_.displayName }) -join ", "
                Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) consent suppression" `
                    -Status "Pass" -Detail "Consent suppression is configured with $($groups.Count) target device group(s): $groupNames" -RiskLevel "Low"
            }
            else {
                Add-CheckResult -Category $category -CheckName "$($ssoSP.Name) consent suppression" `
                    -Status "Fail" -Detail "Remote Desktop security configuration exists on '$($ssoSP.Name)' but NO target device groups are assigned. Consent suppression is incomplete — users will still be prompted." `
                    -Remediation "Add your Cloud PC dynamic device group: Entra admin center > Enterprise Apps > '$($ssoSP.Name)' > Users and groups > Add the group containing Cloud PC device objects." `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/requirements#suppress-single-sign-on-consent-prompts-for-windows-365-link" `
                    -RiskLevel "Critical"
            }
        }
    }
}

# --- CHECK 6: Conditional Access ---
function Test-ConditionalAccess {
    Write-Host "[6/8] Checking Conditional Access policies..." -ForegroundColor Cyan
    $category = "Conditional Access"

    $caPolicies = Invoke-MgGraphSafe -Uri "/identity/conditionalAccess/policies"
    
    if ($caPolicies._error) {
        Add-CheckResult -Category $category -CheckName "Conditional Access policies" `
            -Status "Error" -Detail "Could not query CA policies: $($caPolicies._error). Requires Policy.Read.All permission." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
            -RiskLevel "High"
        return
    }

    $policies = if ($caPolicies.value) { $caPolicies.value } else { @() }
    $enabledPolicies = $policies | Where-Object { $_.state -eq "enabled" -or $_.state -eq "enabledForReportingButNotEnforced" }

    # Find policies targeting W365 resources (connection stage)
    $w365ResourcePolicies = @()
    foreach ($pol in $enabledPolicies) {
        $targetApps = @()
        if ($pol.conditions.applications.includeApplications) {
            $targetApps = $pol.conditions.applications.includeApplications
        }
        
        $targetsW365 = $false
        if ($targetApps -contains "All" -or $targetApps -contains $W365AppId -or $targetApps -contains $AVDAppId -or $targetApps -contains $WCLAppId) {
            $targetsW365 = $true
        }
        if ($targetApps -contains "AllApps") { $targetsW365 = $true }

        if ($targetsW365) {
            $w365ResourcePolicies += $pol
        }
    }

    # Find policies targeting user action "Register or join devices"
    $userActionPolicies = @()
    foreach ($pol in $enabledPolicies) {
        $userActions = @()
        if ($pol.conditions.applications.includeUserActions) {
            $userActions = $pol.conditions.applications.includeUserActions
        }
        if ($userActions -contains "urn:user:registerdevice" -or $userActions -contains "urn:user:registersecurityinfo") {
            $userActionPolicies += $pol
        }
    }

    # Report findings
    if ($w365ResourcePolicies.Count -gt 0) {
        $policyNames = ($w365ResourcePolicies | ForEach-Object { "$($_.displayName) [$($_.state)]" }) -join ", "
        Add-CheckResult -Category $category -CheckName "CA policies on Windows 365 resources" `
            -Status "Info" -Detail "Found $($w365ResourcePolicies.Count) policy(ies) targeting W365/AVD resources: $policyNames" `
            -RiskLevel "Medium"

        # Check if MFA is required on any of them
        $mfaRequired = $w365ResourcePolicies | Where-Object {
            ($_.grantControls.builtInControls -contains "mfa") -or
            ($_.grantControls.authenticationStrength) -or
            ($_.sessionControls.signInFrequency)
        }

        if ($mfaRequired -and $userActionPolicies.Count -eq 0) {
            $mfaPolicyNames = ($mfaRequired | ForEach-Object { $_.displayName }) -join ", "
            Add-CheckResult -Category $category -CheckName "Missing user-action CA policy" `
                -Status "Warning" `
                -Detail "MFA/auth controls found on resource policies ($mfaPolicyNames) but no matching 'Register or join devices' user-action policy exists. Since build 26100.7462, this is no longer mandatory — but Microsoft still highly recommends creating this policy as a best practice." `
                -Remediation "Create a CA policy targeting user action 'Register or join devices' with the same Grant controls. Use Report-only mode first. On devices before build 26100.7462, this is required to avoid connection errors." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                -RiskLevel "Medium"
        }
        elseif ($mfaRequired -and $userActionPolicies.Count -gt 0) {
            Add-CheckResult -Category $category -CheckName "User-action CA policy" `
                -Status "Pass" -Detail "A 'Register or join devices' user-action policy exists alongside resource-targeting policies. Verify Grant controls match." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                -RiskLevel "Low"
        }
    }
    else {
        Add-CheckResult -Category $category -CheckName "CA policies on Windows 365 resources" `
            -Status "Info" -Detail "No enabled CA policies specifically targeting Windows 365, AVD, or Windows Cloud Login resources found. If 'All resources' policies require MFA, ensure a user-action policy also exists." `
            -RiskLevel "Low"
    }

    if ($userActionPolicies.Count -gt 0) {
        $uaPolicyNames = ($userActionPolicies | ForEach-Object { "$($_.displayName)" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Register/join devices user-action policy" `
            -Status "Pass" -Detail "Found $($userActionPolicies.Count) user-action policy(ies): $uaPolicyNames" -RiskLevel "Low"
        
        # Check for unsupported controls on user-action policies
        foreach ($uaPol in $userActionPolicies) {
            $unsupported = @()
            if ($uaPol.grantControls.builtInControls -contains "compliantDevice") {
                $unsupported += "Require device compliance"
            }
            if ($uaPol.grantControls.customAuthenticationFactors) {
                $unsupported += "Custom controls"
            }
            if ($uaPol.sessionControls.signInFrequency.isEnabled -eq $true) {
                $unsupported += "Sign-in frequency"
            }
            
            if ($unsupported.Count -gt 0) {
                $issues = $unsupported -join ", "
                Add-CheckResult -Category $category -CheckName "Unsupported controls on '$($uaPol.displayName)'" `
                    -Status "Fail" -Detail "This user-action policy uses controls that are NOT supported for 'Register or join devices': $issues. These will cause failures." `
                    -Remediation "Remove unsupported controls from this policy. Device compliance, custom controls, and sign-in frequency cannot be used with user actions." `
                    -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/conditional-access-policies" `
                    -RiskLevel "Critical"
            }
        }
    }
    else {
        # Only warn if there are resource policies that might require MFA
        if ($w365ResourcePolicies.Count -eq 0) {
            Add-CheckResult -Category $category -CheckName "Register/join devices user-action policy" `
                -Status "Info" -Detail "No user-action policy found, but no W365 resource policies detected either. If you add CA policies later, remember to create a matching user-action policy." `
                -RiskLevel "Low"
        }
    }
}

# --- CHECK 7: Authentication Methods ---
function Test-AuthenticationMethods {
    Write-Host "[7/8] Checking authentication methods (FIDO2)..." -ForegroundColor Cyan
    $category = "Authentication Methods"

    $authMethods = Invoke-MgGraphSafe -Uri "/policies/authenticationMethodsPolicy"
    
    if ($authMethods._error) {
        Add-CheckResult -Category $category -CheckName "Authentication methods policy" `
            -Status "Error" -Detail "Could not query authentication methods: $($authMethods._error)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -RiskLevel "Medium"
        return
    }

    $configs = $authMethods.authenticationMethodConfigurations
    if (-not $configs) {
        Add-CheckResult -Category $category -CheckName "FIDO2 security key" `
            -Status "Info" -Detail "Could not parse authentication method configurations. Check manually." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -RiskLevel "Medium"
        return
    }

    $fido2Config = $configs | Where-Object { $_.id -eq "fido2" -or $_.'@odata.type' -like "*fido2*" }
    
    if ($fido2Config) {
        $fido2State = $fido2Config.state
        if ($fido2State -eq "enabled") {
            Add-CheckResult -Category $category -CheckName "FIDO2 security key" `
                -Status "Pass" -Detail "FIDO2 security key sign-in is enabled. Users will see both globe and security key icons on the Link sign-in screen." -RiskLevel "Low"
        }
        else {
            Add-CheckResult -Category $category -CheckName "FIDO2 security key" `
                -Status "Warning" -Detail "FIDO2 security key sign-in is '$fido2State'. Microsoft strongly recommends enabling FIDO2 for the best security and user experience on Windows 365 Link." `
                -Remediation "Enable FIDO2 in Entra admin center > Protection > Authentication methods > FIDO2 security key." `
                -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
                -RiskLevel "Medium"
        }
    }
    else {
        Add-CheckResult -Category $category -CheckName "FIDO2 security key" `
            -Status "Warning" -Detail "FIDO2 configuration not found in authentication methods policy. Only web sign-in will be available." `
            -Remediation "Enable FIDO2 in Entra admin center > Protection > Authentication methods > FIDO2 security key." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -RiskLevel "Medium"
    }

    # Check for CBA (warn if enabled — not supported on Link)
    $cbaConfig = $configs | Where-Object { $_.id -eq "x509Certificate" -or $_.'@odata.type' -like "*x509*" }
    if ($cbaConfig -and $cbaConfig.state -eq "enabled") {
        Add-CheckResult -Category $category -CheckName "Certificate-based auth (CBA)" `
            -Status "Warning" -Detail "CBA is enabled in the tenant. Note: CBA is NOT supported for web sign-in on Windows 365 Link. Users relying on CBA will need an alternative method." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/sign-in-methods" `
            -RiskLevel "Medium"
    }
}

# --- CHECK 8: Intune Filters ---
function Test-IntuneFilters {
    Write-Host "[8/8] Checking Intune filters for Windows 365 Link..." -ForegroundColor Cyan
    $category = "Intune Filters"

    $filters = Invoke-MgGraphSafe -Uri "/deviceManagement/assignmentFilters" -ApiVersion "beta"
    
    if ($filters._error) {
        Add-CheckResult -Category $category -CheckName "Intune device filters" `
            -Status "Error" -Detail "Could not query Intune filters: $($filters._error)" `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/create-intune-filter" `
            -RiskLevel "Medium"
        return
    }

    $filterList = if ($filters.value) { $filters.value } else { @() }
    
    # Look for a filter targeting WCPC / Windows CPC / operatingSystemSKU
    $linkFilters = $filterList | Where-Object {
        $_.rule -like "*WCPC*" -or
        $_.rule -like "*operatingSystemSKU*" -or
        $_.rule -like "*Windows CPC*" -or
        $_.rule -like "*210*" -or
        $_.displayName -like "*Link*" -or
        $_.displayName -like "*365 Link*" -or
        $_.displayName -like "*W365*Link*"
    }

    if ($linkFilters) {
        $filterNames = ($linkFilters | ForEach-Object { "$($_.displayName) (Platform: $($_.platform))" }) -join ", "
        Add-CheckResult -Category $category -CheckName "Windows 365 Link device filter" `
            -Status "Pass" -Detail "Found filter(s) that appear to target Link devices: $filterNames" -RiskLevel "Low"
    }
    else {
        Add-CheckResult -Category $category -CheckName "Windows 365 Link device filter" `
            -Status "Warning" -Detail "No Intune filter found targeting Windows 365 Link devices (operatingSystemSKU = WCPC). A filter is recommended for policy targeting and enrollment restriction bypass." `
            -Remediation "Create filter: Intune > Tenant admin > Filters > Create > Platform: Windows 10 and later > Property: operatingSystemSKU, Equals, WCPC." `
            -LearnMoreUrl "https://learn.microsoft.com/en-us/windows-365/link/create-intune-filter" `
            -RiskLevel "Medium"
    }
}

# ============================================================================
# REGION: HTML Report Generator
# ============================================================================
function New-HtmlReport {
    $totalChecks = $script:Checks.Count
    $passCount   = ($script:Checks | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount   = ($script:Checks | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount   = ($script:Checks | Where-Object { $_.Status -eq "Warning" }).Count
    $infoCount   = ($script:Checks | Where-Object { $_.Status -eq "Info" }).Count
    $errorCount  = ($script:Checks | Where-Object { $_.Status -eq "Error" }).Count

    $criticalCount = ($script:Checks | Where-Object { $_.RiskLevel -eq "Critical" -and $_.Status -in @("Fail","Warning") }).Count

    # Readiness score (only count pass vs actionable)
    $actionable = $passCount + $failCount + $warnCount
    $readinessScore = if ($actionable -gt 0) { [math]::Round(($passCount / $actionable) * 100) } else { 0 }
    
    # Ring color
    $ringColor = if ($readinessScore -ge 90) { "#107c10" }
                 elseif ($readinessScore -ge 60) { "#0078d4" }
                 elseif ($readinessScore -ge 30) { "#e87400" }
                 else { "#d13438" }

    $ringCircumference = 2 * [math]::PI * 54  # ~339
    $ringOffset = $ringCircumference - ($ringCircumference * $readinessScore / 100)

    # Build category sections
    $categories = $script:Checks | Select-Object -ExpandProperty Category -Unique
    $categorySectionsHtml = ""

    foreach ($cat in $categories) {
        $catChecks = $script:Checks | Where-Object { $_.Category -eq $cat }
        $catPass = ($catChecks | Where-Object { $_.Status -eq "Pass" }).Count
        $catTotal = $catChecks.Count
        
        $catIcon = switch -Wildcard ($cat) {
            "*Licens*"       { "&#x1F4CB;" }
            "*Entra*Join*"   { "&#x1F513;" }
            "*Auto-Enroll*"  { "&#x2699;&#xFE0F;" }
            "*Restriction*"  { "&#x1F6AB;" }
            "*SSO*"          { "&#x1F511;" }
            "*Conditional*"  { "&#x1F6E1;&#xFE0F;" }
            "*Auth*"         { "&#x1F510;" }
            "*Filter*"       { "&#x1F50D;" }
            default          { "&#x2714;" }
        }

        $rowsHtml = ""
        foreach ($check in $catChecks) {
            $statusBadge = switch ($check.Status) {
                "Pass"    { '<span class="badge badge-pass">PASS</span>' }
                "Fail"    { '<span class="badge badge-fail">FAIL</span>' }
                "Warning" { '<span class="badge badge-warn">WARNING</span>' }
                "Info"    { '<span class="badge badge-info">INFO</span>' }
                "Error"   { '<span class="badge badge-error">ERROR</span>' }
            }

            $riskBadge = ""
            if ($check.RiskLevel -and $check.Status -in @("Fail","Warning")) {
                $riskBadge = switch ($check.RiskLevel) {
                    "Critical" { '<span class="risk risk-critical">Critical Risk</span>' }
                    "High"     { '<span class="risk risk-high">High Risk</span>' }
                    "Medium"   { '<span class="risk risk-medium">Medium Risk</span>' }
                    "Low"      { '<span class="risk risk-low">Low Risk</span>' }
                }
            }

            $remediationHtml = ""
            if ($check.Remediation) {
                $remediationHtml = "<div class='remediation'><strong>&#x1F527; Remediation:</strong> $($check.Remediation)</div>"
            }

            $learnMoreHtml = ""
            if ($check.LearnMoreUrl) {
                $learnMoreHtml = "<a class='learn-more' href='$($check.LearnMoreUrl)' target='_blank'>&#x1F4D6; Learn More &rarr;</a>"
            }

            $rowClass = switch ($check.Status) {
                "Fail"    { "row-fail" }
                "Warning" { "row-warn" }
                "Error"   { "row-error" }
                default   { "" }
            }

            $rowsHtml += @"
            <div class="check-row $rowClass">
                <div class="check-header">
                    <div class="check-title">$statusBadge <span class="check-name">$($check.CheckName)</span> $riskBadge</div>
                </div>
                <div class="check-detail">$($check.Detail)</div>
                $remediationHtml
                $learnMoreHtml
            </div>
"@
        }

        $catStatusClass = if (($catChecks | Where-Object { $_.Status -eq "Fail" }).Count -gt 0) { "cat-fail" }
                          elseif (($catChecks | Where-Object { $_.Status -eq "Warning" }).Count -gt 0) { "cat-warn" }
                          else { "cat-pass" }

        $categorySectionsHtml += @"
        <div class="category-section">
            <div class="category-header $catStatusClass">
                <span class="cat-icon">$catIcon</span>
                <span class="cat-title">$cat</span>
                <span class="cat-count">$catPass / $catTotal passed</span>
            </div>
            <div class="category-body">
                $rowsHtml
            </div>
        </div>
"@
    }

    # Full HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows 365 Link — Deployment Readiness Report</title>
    <style>
        :root {
            --brand: #0078d4;
            --brand-dark: #005a9e;
            --brand-light: #deecf9;
            --pass: #107c10;
            --pass-bg: #dff6dd;
            --warn: #e87400;
            --warn-bg: #fff4ce;
            --fail: #d13438;
            --fail-bg: #fde7e9;
            --info: #0078d4;
            --info-bg: #deecf9;
            --error: #881798;
            --error-bg: #f3e8f9;
            --text: #1b1b1b;
            --text2: #505050;
            --text3: #707070;
            --bg: #f5f5f5;
            --card: #ffffff;
            --border: #e1e1e1;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            font-size: 14px; line-height: 1.6; color: var(--text); background: var(--bg);
        }

        /* Header */
        .report-header {
            background: linear-gradient(135deg, #1b1b1b 0%, #2d2d2d 100%);
            color: #fff; padding: 32px 48px;
        }
        .report-header .ms-brand {
            display: flex; align-items: center; gap: 10px; margin-bottom: 20px;
        }
        .ms-logo { display: inline-grid; grid-template-columns: 1fr 1fr; gap: 2px; width: 18px; height: 18px; }
        .ms-logo span { background: #fff; display: block; }
        .report-header h1 { font-size: 26px; font-weight: 600; margin-bottom: 4px; }
        .report-header .subtitle { font-size: 14px; opacity: 0.7; }
        .report-meta { display: flex; gap: 32px; margin-top: 16px; font-size: 13px; opacity: 0.8; }
        .report-meta .meta-item { display: flex; align-items: center; gap: 6px; }

        /* Summary strip */
        .summary-strip {
            display: flex; align-items: center; gap: 32px;
            background: var(--card); border-bottom: 1px solid var(--border);
            padding: 24px 48px; flex-wrap: wrap;
        }
        .score-ring { position: relative; width: 120px; height: 120px; flex-shrink: 0; }
        .score-ring svg { transform: rotate(-90deg); }
        .score-ring .ring-bg { fill: none; stroke: #e0e0e0; stroke-width: 8; }
        .score-ring .ring-fill { fill: none; stroke-width: 8; stroke-linecap: round;
            stroke-dasharray: $([math]::Round($ringCircumference, 1));
            stroke-dashoffset: $([math]::Round($ringOffset, 1));
            stroke: $ringColor; transition: stroke-dashoffset 0.8s ease;
        }
        .score-ring .score-text {
            position: absolute; inset: 0; display: flex; flex-direction: column;
            align-items: center; justify-content: center;
        }
        .score-ring .score-num { font-size: 32px; font-weight: 700; color: var(--text); }
        .score-ring .score-label { font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }

        .summary-stats { display: flex; gap: 16px; flex-wrap: wrap; }
        .stat-card {
            padding: 12px 20px; border-radius: 8px; text-align: center;
            min-width: 90px; border: 1px solid var(--border); background: var(--card);
        }
        .stat-card .stat-num { font-size: 28px; font-weight: 700; }
        .stat-card .stat-label { font-size: 11px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-pass .stat-num { color: var(--pass); }
        .stat-fail .stat-num { color: var(--fail); }
        .stat-warn .stat-num { color: var(--warn); }
        .stat-info .stat-num { color: var(--info); }
        .stat-error .stat-num { color: var(--error); }

        .summary-message {
            flex: 1; min-width: 200px; padding: 16px 24px;
            border-radius: 8px; font-size: 14px; line-height: 1.7;
        }
        .summary-message.critical { background: var(--fail-bg); border-left: 4px solid var(--fail); }
        .summary-message.warning { background: var(--warn-bg); border-left: 4px solid var(--warn); }
        .summary-message.good { background: var(--pass-bg); border-left: 4px solid var(--pass); }

        /* Content */
        .content { max-width: 1000px; margin: 0 auto; padding: 32px 48px 64px; }

        /* Category sections */
        .category-section {
            background: var(--card); border: 1px solid var(--border); border-radius: 8px;
            margin-bottom: 16px; overflow: hidden;
        }
        .category-header {
            padding: 14px 20px; display: flex; align-items: center; gap: 10px;
            font-weight: 600; font-size: 15px; border-bottom: 1px solid var(--border);
            cursor: pointer; user-select: none; transition: background 0.15s;
        }
        .category-header:hover { background: #f8f8f8; }
        .category-header.cat-fail { border-left: 4px solid var(--fail); }
        .category-header.cat-warn { border-left: 4px solid var(--warn); }
        .category-header.cat-pass { border-left: 4px solid var(--pass); }
        .cat-icon { font-size: 18px; }
        .cat-title { flex: 1; }
        .cat-count { font-size: 12px; color: var(--text3); font-weight: 400; }
        .category-body { padding: 0; }

        /* Check rows */
        .check-row { padding: 14px 20px; border-bottom: 1px solid #f0f0f0; }
        .check-row:last-child { border-bottom: none; }
        .check-row.row-fail { background: #fff8f8; }
        .check-row.row-warn { background: #fffdf5; }
        .check-row.row-error { background: #fdf5ff; }
        .check-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
        .check-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .check-name { font-weight: 600; font-size: 14px; }
        .check-detail { font-size: 13px; color: var(--text2); line-height: 1.7; margin-left: 4px; }
        .remediation {
            margin-top: 8px; padding: 10px 14px; border-radius: 6px;
            background: #f6f6f6; font-size: 13px; line-height: 1.6;
            border: 1px solid var(--border);
        }
        .learn-more {
            display: inline-block; margin-top: 8px; font-size: 13px;
            color: var(--brand); text-decoration: none; font-weight: 600;
        }
        .learn-more:hover { text-decoration: underline; }

        /* Badges */
        .badge {
            display: inline-block; padding: 2px 8px; border-radius: 3px;
            font-size: 11px; font-weight: 700; letter-spacing: 0.3px;
        }
        .badge-pass { background: var(--pass-bg); color: var(--pass); }
        .badge-fail { background: var(--fail-bg); color: var(--fail); }
        .badge-warn { background: var(--warn-bg); color: var(--warn); }
        .badge-info { background: var(--info-bg); color: var(--info); }
        .badge-error { background: var(--error-bg); color: var(--error); }
        .risk {
            display: inline-block; padding: 2px 8px; border-radius: 3px;
            font-size: 10px; font-weight: 700; letter-spacing: 0.3px; text-transform: uppercase;
        }
        .risk-critical { background: #d13438; color: #fff; }
        .risk-high { background: #e87400; color: #fff; }
        .risk-medium { background: var(--warn-bg); color: #7a6400; }
        .risk-low { background: #f0f0f0; color: var(--text3); }

        /* Footer */
        .report-footer {
            text-align: center; padding: 24px; font-size: 12px; color: var(--text3);
            border-top: 1px solid var(--border); margin-top: 32px;
        }
        .report-footer a { color: var(--brand); text-decoration: none; }
        .report-footer a:hover { text-decoration: underline; }

        /* Print */
        @media print {
            .report-header { background: #1b1b1b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            body { background: #fff; }
            .content { padding: 16px; }
        }
    </style>
</head>
<body>

<div class="report-header">
    <div class="ms-brand">
        <div class="ms-logo"><span></span><span></span><span></span><span></span></div>
        <span style="font-size:14px;font-weight:600;opacity:0.9">Microsoft</span>
    </div>
    <h1>Windows 365 Link — Deployment Readiness Report</h1>
    <div class="subtitle">Automated prerequisite assessment for Windows 365 Link device deployment</div>
    <div class="report-meta">
        <div class="meta-item">&#x1F4C5; $($script:Timestamp)</div>
        <div class="meta-item">&#x1F3E2; Tenant: $($script:TenantInfo['TenantId'])</div>
        <div class="meta-item">&#x1F464; Run by: $($script:TenantInfo['Account'])</div>
        $(if ($UserUPN) { "<div class='meta-item'>&#x1F4CB; Target user: $UserUPN</div>" })
    </div>
</div>

<div class="summary-strip">
    <div class="score-ring">
        <svg width="120" height="120" viewBox="0 0 120 120">
            <circle class="ring-bg" cx="60" cy="60" r="54"/>
            <circle class="ring-fill" cx="60" cy="60" r="54"/>
        </svg>
        <div class="score-text">
            <div class="score-num">$readinessScore%</div>
            <div class="score-label">Ready</div>
        </div>
    </div>

    <div class="summary-stats">
        <div class="stat-card stat-pass"><div class="stat-num">$passCount</div><div class="stat-label">Passed</div></div>
        <div class="stat-card stat-fail"><div class="stat-num">$failCount</div><div class="stat-label">Failed</div></div>
        <div class="stat-card stat-warn"><div class="stat-num">$warnCount</div><div class="stat-label">Warnings</div></div>
        <div class="stat-card stat-info"><div class="stat-num">$infoCount</div><div class="stat-label">Info</div></div>
        $(if ($errorCount -gt 0) { "<div class='stat-card stat-error'><div class='stat-num'>$errorCount</div><div class='stat-label'>Errors</div></div>" })
    </div>

    $(
        if ($criticalCount -gt 0) {
            "<div class='summary-message critical'><strong>&#x1F6D1; $criticalCount critical issue(s) found.</strong><br>These could affect Windows 365 Link deployment. Address all critical items before proceeding.</div>"
        }
        elseif ($failCount -gt 0 -or $warnCount -gt 0) {
            "<div class='summary-message warning'><strong>&#x26A0;&#xFE0F; $($failCount + $warnCount) issue(s) need attention.</strong><br>Review and address warnings and failures before deploying Link devices at scale.</div>"
        }
        else {
            "<div class='summary-message good'><strong>&#x2705; Environment looks ready for Windows 365 Link deployment.</strong><br>All automated checks passed. Consider a pilot deployment with a single device before going to scale.</div>"
        }
    )
</div>

<div class="content">
    <h2 style="font-size:20px; font-weight:600; margin-bottom:16px; color:var(--text);">Assessment Details</h2>
    $categorySectionsHtml
</div>

<div class="report-footer">
    <p>Generated by <strong>Test-W365LinkReadiness.ps1</strong> &mdash; Windows 365 Link Supportability Team</p>
    <p style="margin-top:8px;">
        <a href="https://learn.microsoft.com/en-us/windows-365/link/" target="_blank">Windows 365 Link Documentation</a> &bull;
        <a href="https://learn.microsoft.com/en-us/windows-365/link/deployment-overview" target="_blank">Deployment Overview</a> &bull;
        <a href="https://learn.microsoft.com/en-us/windows-365/link/troubleshooting" target="_blank">Troubleshooting</a> &bull;
        <a href="https://learn.microsoft.com/en-us/windows-365/link/known-issues" target="_blank">Known Issues</a>
    </p>
</div>

</body>
</html>
"@

    return $html
}

# ============================================================================
# REGION: Main Execution
# ============================================================================
function Start-ReadinessAssessment {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Windows 365 Link — Deployment Readiness Assessment" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  This script checks your Microsoft 365 environment against" -ForegroundColor Gray
    Write-Host "  known prerequisites for Windows 365 Link deployment." -ForegroundColor Gray
    Write-Host ""

    # Pre-flight
    if (-not (Test-GraphModule)) { return }
    if (-not (Connect-ToGraph)) { return }

    # Get tenant display name
    $org = Invoke-MgGraphSafe -Uri "/organization"
    if (-not $org._error -and $org.value) {
        $tenantName = $org.value[0].displayName
        $script:TenantInfo["TenantName"] = $tenantName
        Write-Host "    Tenant name:  $tenantName" -ForegroundColor Green
    }

    Write-Host "`n--- Running checks ---`n" -ForegroundColor Yellow

    # Execute all checks
    Test-Licensing
    Test-EntraDeviceJoin
    Test-MDMUserScope
    Test-EnrollmentRestrictions
    Test-CloudPCSSO
    Test-ConditionalAccess
    Test-AuthenticationMethods
    Test-IntuneFilters

    # Generate report
    Write-Host "`n[*] Generating HTML report..." -ForegroundColor Cyan
    $html = New-HtmlReport

    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $html | Out-File -FilePath $resolvedPath -Encoding utf8 -Force
    Write-Host "    Report saved to: $resolvedPath" -ForegroundColor Green

    # Summary
    $passCount = ($script:Checks | Where-Object { $_.Status -eq "Pass" }).Count
    $failCount = ($script:Checks | Where-Object { $_.Status -eq "Fail" }).Count
    $warnCount = ($script:Checks | Where-Object { $_.Status -eq "Warning" }).Count
    $totalChecks = $script:Checks.Count

    Write-Host ""
    Write-Host "--- Summary ---" -ForegroundColor Yellow
    Write-Host "  Total checks: $totalChecks" -ForegroundColor White
    Write-Host "  Passed:       $passCount" -ForegroundColor Green
    Write-Host "  Failed:       $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
    Write-Host "  Warnings:     $warnCount" -ForegroundColor $(if ($warnCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""

    if ($OpenReport) {
        Write-Host "[*] Opening report in browser..." -ForegroundColor Cyan
        Start-Process $resolvedPath
    }
    else {
        Write-Host "    Tip: Use -OpenReport to open in your default browser." -ForegroundColor Gray
    }

    Write-Host ""
}

# Run
Start-ReadinessAssessment
