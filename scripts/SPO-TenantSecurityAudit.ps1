#Requires -Version 5.1
<#
===============================================================================
  SharePoint Online Tenant-Wide Security Audit Script
  By: Luis Z Guzman Garcia (KillBillKill98)
  GitHub: https://github.com/KillBillKill98
===============================================================================

.SYNOPSIS
    Tenant-wide SharePoint Online security audit with HTML report output.

.DESCRIPTION
    Performs a comprehensive security audit of a SharePoint Online tenant covering:
      - Tenant sharing and access control settings
      - All site collections and sharing levels
      - External/guest users
      - Site admins and privileged accounts
      - PnP deep permission scan (optional)
      - Unified Audit Log events (sharing, permission changes, external access)
      - OneDrive settings
      - Virus/malware protection settings
      - Oversharing risk assessment (critical for Microsoft Copilot environments)
    Outputs timestamped CSV files and a branded HTML summary report.

.PARAMETER TenantName
    SharePoint tenant name (e.g., "contoso" for contoso.sharepoint.com)

.PARAMETER ClientName
    Client or organization name used as the report folder name.
    (e.g., "contoso-LLC" creates folder: contoso-LLC_SPO_Audit_20260217_150000)

.PARAMETER AdminUPN
    UPN of the admin account (e.g., admin@contoso.com).
    Required for Exchange/audit log connections.

.PARAMETER OutputPath
    Folder where reports are saved. Defaults to current directory.

.PARAMETER AuditDays
    Days to look back in the Unified Audit Log. Default: 30.

.PARAMETER SkipAuditLog
    Skip the Unified Audit Log search (faster).

.PARAMETER SkipPnP
    Skip the PnP deep permission scan (faster).

.EXAMPLE
    # Step 1 - pre-connect:
    Connect-SPOService -Url "https://contoso-admin.sharepoint.com"

    # Step 2 - run:
    .\SPO-TenantSecurityAudit.ps1 -TenantName "contoso" -ClientName "Contoso-LLC" -AdminUPN "admin@contoso.com"

.NOTES
    Author  : Luis Z Guzman Garcia (KillBillKill98)
    GitHub  : https://github.com/KillBillKill98
    Version : 2.0

    Run in Windows PowerShell 5.1 as Administrator.
    If blocked by execution policy run first:
        Unblock-File -Path ".\SPO-TenantSecurityAudit.ps1"
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Requires : Microsoft.Online.SharePoint.PowerShell, ExchangeOnlineManagement
    Optional : PnP.PowerShell v1.x (for Section 5 deep scan)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantName,

    [Parameter(Mandatory = $true)]
    [string]$ClientName,

    [Parameter(Mandatory = $false)]
    [string]$AdminUPN = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [int]$AuditDays = 30,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAuditLog,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPnP
)

# ============================================================
# CONFIGURATION
# ============================================================

$ScriptAuthor           = "Luis Z Guzman Garcia (KillBillKill98)"
$ScriptGitHub           = "https://github.com/KillBillKill98"
$ScriptVersion          = "2.0"
$Timestamp              = Get-Date -Format "yyyyMMdd_HHmmss"
$SafeClientName         = $ClientName -replace '[^a-zA-Z0-9_\-]', '_'
$ReportFolder           = Join-Path $OutputPath "${SafeClientName}_SPO_Audit_$Timestamp"
$AdminUrl               = "https://$TenantName-admin.sharepoint.com"
$script:PnPCreds        = $null
$script:SkipAuditLogInt = $false
$script:FilesGenerated  = New-Object System.Collections.ArrayList

# ============================================================
# HELPERS
# ============================================================

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "INFO"    { "Cyan"   }
        "SUCCESS" { "Green"  }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        default   { "White"  }
    }
    Write-Host ("[{0}][{1}] {2}" -f (Get-Date -Format "HH:mm:ss"), $Level, $Message) -ForegroundColor $color
}

function Initialize-OutputFolder {
    if (-not (Test-Path $ReportFolder)) {
        New-Item -ItemType Directory -Path $ReportFolder | Out-Null
    }
    Write-AuditLog "Output folder: $ReportFolder"
}

function Export-AuditData {
    param([object[]]$Data, [string]$FileName, [string]$Description)
    if ($Data -and $Data.Count -gt 0) {
        $path = Join-Path $ReportFolder "$FileName.csv"
        $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-AuditLog ("{0} -- {1} records -> {2}.csv" -f $Description, $Data.Count, $FileName) "SUCCESS"
        [void]$script:FilesGenerated.Add([PSCustomObject]@{
            File        = "$FileName.csv"
            Records     = $Data.Count
            Description = $Description
        })
    }
    else {
        Write-AuditLog "$Description -- No data found (file not created)." "WARN"
    }
}

function Get-SharingLabel {
    param([string]$Value)
    switch ($Value) {
        "Disabled"                        { "No external sharing" }
        "ExistingExternalUserSharingOnly" { "Existing guests only" }
        "ExternalUserSharingOnly"         { "New and existing guests" }
        "ExternalUserAndGuestSharing"     { "Anyone (including anonymous)" }
        default                           { $Value }
    }
}

function Get-RiskLevel {
    param([string]$Value)
    switch ($Value) {
        "ExternalUserAndGuestSharing"     { "High"   }
        "ExternalUserSharingOnly"         { "Medium" }
        "ExistingExternalUserSharingOnly" { "Low"    }
        "Disabled"                        { "Good"   }
        default                           { "Info"   }
    }
}

# ============================================================
# SECTION 1 - TENANT SETTINGS
# ============================================================

function Get-TenantSettings {
    Write-AuditLog "=== SECTION 1: Tenant-Level Settings ===" "INFO"
    try {
        $t = Get-SPOTenant -ErrorAction Stop
        $s = [PSCustomObject]@{
            SharingCapability                          = $t.SharingCapability
            SharingCapabilityLabel                     = Get-SharingLabel $t.SharingCapability.ToString()
            DefaultSharingLinkType                     = $t.DefaultSharingLinkType
            DefaultLinkPermission                      = $t.DefaultLinkPermission
            RequireAcceptingAccountMatchInvitedAccount = $t.RequireAcceptingAccountMatchInvitedAccount
            SharingAllowedDomainList                   = $t.SharingAllowedDomainList
            SharingBlockedDomainList                   = $t.SharingBlockedDomainList
            SharingDomainRestrictionMode               = $t.SharingDomainRestrictionMode
            ExternalUserExpirationRequired             = $t.ExternalUserExpirationRequired
            ExternalUserExpireInDays                   = $t.ExternalUserExpireInDays
            EmailAttestationRequired                   = $t.EmailAttestationRequired
            EmailAttestationReAuthDays                 = $t.EmailAttestationReAuthDays
            PreventExternalUsersFromResharing          = $t.PreventExternalUsersFromResharing
            FileAnonymousLinkType                      = $t.FileAnonymousLinkType
            FolderAnonymousLinkType                    = $t.FolderAnonymousLinkType
            ConditionalAccessPolicy                    = $t.ConditionalAccessPolicy
            AllowDownloadingNonWebViewableFiles        = $t.AllowDownloadingNonWebViewableFiles
            LegacyAuthProtocolsEnabled                 = $t.LegacyAuthProtocolsEnabled
            DisableCustomAppAuthentication             = $t.DisableCustomAppAuthentication
            OneDriveStorageQuota_MB                    = $t.OneDriveStorageQuota
            OneDriveForGuestsEnabled                   = $t.OneDriveForGuestsEnabled
            PublicCdnEnabled                           = $t.PublicCdnEnabled
            ODBMembersCanShare                         = $t.ODBMembersCanShare
            ODBAccessRequests                          = $t.ODBAccessRequests
            AuditedAt                                  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        Export-AuditData -Data @($s) -FileName "01_TenantSettings" -Description "Tenant settings"
        return $s
    }
    catch {
        Write-AuditLog "Failed to retrieve tenant settings: $_" "ERROR"
        return $null
    }
}

# ============================================================
# SECTION 2 - ALL SITE COLLECTIONS
# ============================================================

function Get-AllSiteCollections {
    Write-AuditLog "=== SECTION 2: All Site Collections ===" "INFO"
    try {
        Write-AuditLog "Retrieving all sites (may take a few minutes)..." "INFO"
        $sites = Get-SPOSite -Limit All -IncludePersonalSite $true -ErrorAction Stop

        $siteData = $sites | ForEach-Object {
            [PSCustomObject]@{
                Url                    = $_.Url
                Title                  = $_.Title
                Template               = $_.Template
                SharingCapability      = $_.SharingCapability
                SharingCapabilityLabel = Get-SharingLabel $_.SharingCapability.ToString()
                RiskLevel              = Get-RiskLevel $_.SharingCapability.ToString()
                StorageUsageCurrent_MB = $_.StorageUsageCurrent
                StorageQuota_MB        = $_.StorageQuota
                Owner                  = $_.Owner
                LockState              = $_.LockState
                LastContentModified    = $_.LastContentModifiedDate
                SensitivityLabel       = $_.SensitivityLabel
                IsHubSite              = $_.IsHubSite
            }
        }

        Export-AuditData -Data $siteData -FileName "02_SiteCollections" -Description "All site collections"

        $highRisk = $siteData | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }
        if ($highRisk -and $highRisk.Count -gt 0) {
            Export-AuditData -Data $highRisk -FileName "02a_HighRisk_AnonymousSharingSites" -Description "HIGH RISK - Sites with Anyone sharing"
        }
        return $siteData
    }
    catch {
        Write-AuditLog "Failed to retrieve site collections: $_" "ERROR"
        return @()
    }
}

# ============================================================
# SECTION 3 - EXTERNAL USERS
# ============================================================

function Get-ExternalUsers {
    Write-AuditLog "=== SECTION 3: External / Guest Users ===" "INFO"
    try {
        $allExtUsers = New-Object System.Collections.ArrayList
        $pageSize    = 50
        $position    = 0

        Write-AuditLog "Paginating external users (50 per page)..." "INFO"
        do {
            try {
                $page = Get-SPOExternalUser -PageSize $pageSize -Position $position -ErrorAction Stop
            }
            catch {
                Write-AuditLog "Stopped paginating at position $position : $_" "WARN"
                break
            }
            if ($page -and $page.Count -gt 0) {
                foreach ($u in $page) { [void]$allExtUsers.Add($u) }
            }
            $position += $pageSize
        } while ($page -and $page.Count -eq $pageSize)

        Write-AuditLog "Total external users retrieved: $($allExtUsers.Count)" "INFO"

        if ($allExtUsers.Count -eq 0) {
            Write-AuditLog "No external users found." "WARN"
            return @()
        }

        $userData = $allExtUsers | ForEach-Object {
            [PSCustomObject]@{
                DisplayName = $_.DisplayName
                Email       = $_.Email
                LoginName   = $_.LoginName
                InvitedAs   = $_.InvitedAs
                InvitedBy   = $_.InvitedBy
                AcceptedAs  = $_.AcceptedAs
                WhenCreated = $_.WhenCreated
                UniqueId    = $_.UniqueId
                IsSiteAdmin = $_.IsSiteAdmin
            }
        }

        Export-AuditData -Data $userData -FileName "03_ExternalUsers" -Description "External/guest users"

        $extAdmins = $userData | Where-Object { $_.IsSiteAdmin -eq $true }
        if ($extAdmins -and $extAdmins.Count -gt 0) {
            Export-AuditData -Data $extAdmins -FileName "03a_CRITICAL_ExternalSiteAdmins" -Description "CRITICAL - External users with Site Admin rights"
        }
        return $userData
    }
    catch {
        Write-AuditLog "Failed to retrieve external users: $_" "ERROR"
        return @()
    }
}

# ============================================================
# SECTION 4 - SITE ADMINS
# ============================================================

function Get-SiteAdmins {
    param([object[]]$Sites)
    Write-AuditLog "=== SECTION 4: Site Admins ===" "INFO"

    $adminData = New-Object System.Collections.ArrayList
    $counter   = 0

    $filteredSites = $Sites | Where-Object {
        $_.Template -notmatch "REDIRECT" -and
        $_.Url -notmatch "-my\.sharepoint\.com/personal"
    }

    Write-AuditLog "Scanning admins on $($filteredSites.Count) sites..." "INFO"

    foreach ($site in $filteredSites) {
        $counter++
        if ($counter % 25 -eq 0) {
            Write-AuditLog "  Progress: $counter / $($filteredSites.Count)" "INFO"
        }
        try {
            $users  = Get-SPOUser -Site $site.Url -Limit 500 -ErrorAction Stop
            $admins = $users | Where-Object { $_.IsSiteAdmin -eq $true }
            foreach ($admin in $admins) {
                [void]$adminData.Add([PSCustomObject]@{
                    SiteUrl     = $site.Url
                    SiteTitle   = $site.Title
                    DisplayName = $admin.DisplayName
                    LoginName   = $admin.LoginName
                    Email       = $admin.Email
                    IsSiteAdmin = $admin.IsSiteAdmin
                    IsGuest     = ($admin.LoginName -match "#ext#" -or $admin.LoginName -match "urn:spo:guest")
                })
            }
        }
        catch { }
    }

    Export-AuditData -Data $adminData -FileName "04_SiteAdmins" -Description "Site admins"

    $guestAdmins = $adminData | Where-Object { $_.IsGuest -eq $true }
    if ($guestAdmins -and $guestAdmins.Count -gt 0) {
        Export-AuditData -Data $guestAdmins -FileName "04a_CRITICAL_GuestSiteAdmins" -Description "CRITICAL - Guest accounts with Site Admin role"
    }
    return $adminData
}

# ============================================================
# SECTION 5 - PnP DEEP PERMISSION SCAN
# ============================================================

function Get-DeepPermissions {
    param([object[]]$Sites)
    Write-AuditLog "=== SECTION 5: Deep Permission Scan (PnP) ===" "INFO"

    $filteredSites = $Sites | Where-Object {
        $_.Template -notmatch "REDIRECT" -and
        $_.Url -notmatch "-my\.sharepoint\.com/personal"
    }

    if ($filteredSites.Count -eq 0) {
        Write-AuditLog "No eligible sites found for PnP scan." "WARN"
        return
    }

    # Prompt for credentials ONCE before the loop starts - no prompts during scanning
    Write-AuditLog "Enter SharePoint admin credentials for PnP scan." "INFO"
    Write-AuditLog "You will be prompted ONCE - credentials are reused for all $($filteredSites.Count) sites silently." "INFO"

    if (-not $script:PnPCreds) {
        $script:PnPCreds = Get-Credential -Message "PnP Scan - Enter SharePoint admin credentials (used once for all sites)"
    }

    # Verify credentials work on the first site before proceeding
    $testSite = $filteredSites | Select-Object -First 1
    try {
        Connect-PnPOnline -Url $testSite.Url -Credentials $script:PnPCreds `
            -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        Write-AuditLog "PnP credentials verified. Starting silent scan..." "SUCCESS"
    }
    catch {
        Write-AuditLog "PnP credential test failed - skipping deep scan: $_" "ERROR"
        Write-AuditLog "Tip: Make sure you're using the full UPN (e.g., admin@contoso.com) and correct password." "WARN"
        return
    }

    $permData = New-Object System.Collections.ArrayList
    $counter  = 0

    Write-AuditLog "Scanning $($filteredSites.Count) sites for broken inheritance and Everyone grants..." "INFO"

    foreach ($site in $filteredSites) {
        $counter++

        # Progress every 5 sites so the user knows it's still running
        if ($counter % 5 -eq 0 -or $counter -eq 1 -or $counter -eq $filteredSites.Count) {
            Write-AuditLog "  PnP Progress: $counter / $($filteredSites.Count) -- $($site.Title)" "INFO"
        }

        try {
            # Silently reconnect per site - suppress ALL output to prevent empty prompts
            Connect-PnPOnline -Url $site.Url -Credentials $script:PnPCreds `
                -ErrorAction Stop -WarningAction SilentlyContinue 2>$null | Out-Null

            # Lists and libraries with broken permission inheritance
            $uniqueLists = Get-PnPList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                Where-Object { $_.HasUniqueRoleAssignments -and -not $_.Hidden }

            foreach ($list in $uniqueLists) {
                [void]$permData.Add([PSCustomObject]@{
                    SiteUrl       = $site.Url
                    SiteTitle     = $site.Title
                    LibraryOrList = $list.Title
                    FindingType   = "Broken Inheritance"
                    ListUrl       = $list.RootFolder.ServerRelativeUrl
                    ItemCount     = $list.ItemCount
                    Note          = "Unique permissions set - review who has access"
                })
            }

            # Site groups with Everyone-type accounts
            $groups = Get-PnPGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            foreach ($group in $groups) {
                try {
                    $members = Get-PnPGroupMember -Group $group `
                        -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    $everyoneMembers = $members | Where-Object {
                        $_.LoginName -match "spo-grid-all-users" -or
                        $_.LoginName -match "c:0\(\.s\|true"     -or
                        $_.Title     -match "^Everyone"
                    }
                    foreach ($m in $everyoneMembers) {
                        [void]$permData.Add([PSCustomObject]@{
                            SiteUrl       = $site.Url
                            SiteTitle     = $site.Title
                            LibraryOrList = "Group: $($group.Title)"
                            FindingType   = "Everyone Account in Group"
                            ListUrl       = "N/A"
                            ItemCount     = "N/A"
                            Note          = "Member: $($m.Title) | $($m.LoginName) - REVIEW REQUIRED"
                        })
                    }
                }
                catch { }
            }
        }
        catch {
            # Site inaccessible - log it and continue silently
            Write-AuditLog "  Skipped (access denied): $($site.Url)" "WARN"
        }
    }

    Write-AuditLog "PnP scan complete." "SUCCESS"
    Export-AuditData -Data $permData -FileName "05_DeepPermissions_BrokenInheritance" -Description "Broken inheritance and Everyone grants"
    return $permData
}

# ============================================================
# SECTION 6 - UNIFIED AUDIT LOG
# ============================================================

function Get-AuditLogEvents {
    Write-AuditLog "=== SECTION 6: Unified Audit Log (last $AuditDays days) ===" "INFO"

    if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
        Write-AuditLog "Search-UnifiedAuditLog not available. Attempting reconnect..." "WARN"
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            $exoMod = Get-Module ExchangeOnlineManagement
            $exoVer = if ($exoMod) { $exoMod.Version.Major } else { 0 }
            try {
                if ($exoVer -ge 2) {
                    if ($AdminUPN) { Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false -ErrorAction Stop }
                    else           { Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop }
                }
                else {
                    if ($AdminUPN) { Connect-EXOPSSession -UserPrincipalName $AdminUPN -ErrorAction Stop }
                    else           { Connect-EXOPSSession -ErrorAction Stop }
                }
            }
            catch {
                if ($exoVer -ge 2) {
                    if ($AdminUPN) { Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ErrorAction Stop }
                    else           { Connect-ExchangeOnline -ErrorAction Stop }
                }
            }
        }
        catch {
            Write-AuditLog "Could not reconnect for audit log. Skipping Section 6: $_" "ERROR"
            return
        }
    }

    $startDate = (Get-Date).AddDays(-$AuditDays)
    $endDate   = Get-Date

    # Anonymous link events
    Write-AuditLog "Searching: anonymous link events..." "INFO"
    try {
        $raw = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
            -Operations "AnonymousLinkCreated","AnonymousLinkUsed","AnonymousLinkUpdated" `
            -ResultSize 5000 -ErrorAction Stop
        if ($raw -and $raw.Count -gt 0) {
            $data = $raw | ForEach-Object {
                $d = $_.AuditData | ConvertFrom-Json
                [PSCustomObject]@{
                    CreationTime   = $_.CreationDate
                    Operation      = $_.Operations
                    User           = $d.UserId
                    SiteUrl        = $d.SiteUrl
                    SourceFileName = $d.SourceFileName
                    ObjectId       = $d.ObjectId
                }
            }
            Export-AuditData -Data $data -FileName "06a_AnonymousLinkEvents" -Description "Anonymous link events"
        }
        else { Write-AuditLog "Anonymous link events -- None found in last $AuditDays days." "WARN" }
    }
    catch { Write-AuditLog "Anonymous link search failed: $_" "WARN" }

    # External sharing invitations
    Write-AuditLog "Searching: external sharing events..." "INFO"
    try {
        $raw = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
            -Operations "SharingInvitationCreated","AddedToSecureLink","SharingSet" `
            -ResultSize 5000 -ErrorAction Stop
        if ($raw -and $raw.Count -gt 0) {
            $data = $raw | ForEach-Object {
                $d = $_.AuditData | ConvertFrom-Json
                [PSCustomObject]@{
                    CreationTime      = $_.CreationDate
                    Operation         = $_.Operations
                    User              = $d.UserId
                    TargetUserOrGroup = $d.TargetUserOrGroupName
                    SiteUrl           = $d.SiteUrl
                    ObjectId          = $d.ObjectId
                }
            }
            Export-AuditData -Data $data -FileName "06b_SharingInvitationEvents" -Description "External sharing invitation events"
        }
        else { Write-AuditLog "Sharing invitation events -- None found in last $AuditDays days." "WARN" }
    }
    catch { Write-AuditLog "Sharing invitation search failed: $_" "WARN" }

    # Permission changes
    Write-AuditLog "Searching: permission change events..." "INFO"
    try {
        $raw = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
            -Operations "PermissionLevelAdded","PermissionLevelChanged","SiteCollectionAdminAdded","AddedToGroup" `
            -ResultSize 5000 -ErrorAction Stop
        if ($raw -and $raw.Count -gt 0) {
            $data = $raw | ForEach-Object {
                $d = $_.AuditData | ConvertFrom-Json
                [PSCustomObject]@{
                    CreationTime = $_.CreationDate
                    Operation    = $_.Operations
                    User         = $d.UserId
                    TargetUser   = $d.TargetUserOrGroupName
                    SiteUrl      = $d.SiteUrl
                    ObjectId     = $d.ObjectId
                }
            }
            Export-AuditData -Data $data -FileName "06c_PermissionChangeEvents" -Description "Permission change events"
        }
        else { Write-AuditLog "Permission change events -- None found in last $AuditDays days." "WARN" }
    }
    catch { Write-AuditLog "Permission change search failed: $_" "WARN" }

    # External user file access
    Write-AuditLog "Searching: file access by external users..." "INFO"
    try {
        $raw = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate `
            -Operations "FileAccessed","FileDownloaded" `
            -ResultSize 5000 -ErrorAction Stop
        if ($raw -and $raw.Count -gt 0) {
            $data = $raw | ForEach-Object {
                $d = $_.AuditData | ConvertFrom-Json
                if ($d.UserId -match "#ext#" -or $d.UserId -match "urn:spo:guest") {
                    [PSCustomObject]@{
                        CreationTime   = $_.CreationDate
                        Operation      = $_.Operations
                        ExternalUser   = $d.UserId
                        SiteUrl        = $d.SiteUrl
                        SourceFileName = $d.SourceFileName
                        ObjectId       = $d.ObjectId
                    }
                }
            } | Where-Object { $_ -ne $null }
            Export-AuditData -Data $data -FileName "06d_ExternalUserFileAccess" -Description "File access by external users"
        }
        else { Write-AuditLog "External file access events -- None found in last $AuditDays days." "WARN" }
    }
    catch { Write-AuditLog "External file access search failed: $_" "WARN" }
}

# ============================================================
# SECTION 7 - ONEDRIVE SETTINGS
# ============================================================

function Get-OneDriveSettings {
    Write-AuditLog "=== SECTION 7: OneDrive Settings ===" "INFO"
    try {
        $t = Get-SPOTenant -ErrorAction Stop
        $od = [PSCustomObject]@{
            OneDriveStorageQuota_MB               = $t.OneDriveStorageQuota
            OneDriveForGuestsEnabled              = $t.OneDriveForGuestsEnabled
            BlockMacSync                          = $t.BlockMacSync
            IsUnmanagedSyncAppForTenantRestricted = $t.IsUnmanagedSyncAppForTenantRestricted
            AllowedDomainListForSyncClient        = $t.AllowedDomainListForSyncClient
            ExcludedFileExtensionsForSyncClient   = $t.ExcludedFileExtensionsForSyncClient
            DisableAddToOneDrive                  = $t.DisableAddToOneDrive
            ODBMembersCanShare                    = $t.ODBMembersCanShare
            ODBAccessRequests                     = $t.ODBAccessRequests
        }
        Export-AuditData -Data @($od) -FileName "07_OneDriveSettings" -Description "OneDrive settings"
        return $od
    }
    catch {
        Write-AuditLog "Failed to retrieve OneDrive settings: $_" "ERROR"
        return $null
    }
}

# ============================================================
# SECTION 8 - VIRUS PROTECTION SETTINGS
# ============================================================

function Get-VirusProtectionSettings {
    Write-AuditLog "=== SECTION 8: Virus / Malware Protection Settings ===" "INFO"
    try {
        $t = Get-SPOTenant -ErrorAction Stop

        # DisallowInfectedFileDownload = True means infected files are BLOCKED (secure)
        # DisallowInfectedFileDownload = False means infected files CAN be downloaded (insecure)
        $virusBlocked   = $t.DisallowInfectedFileDownload
        $virusStatusMsg = if ($virusBlocked) { "ENABLED - Infected files are blocked from download" } else { "DISABLED - Infected files CAN be downloaded by users" }
        $virusRisk      = if ($virusBlocked) { "Good" } else { "High" }

        $virusData = [PSCustomObject]@{
            DisallowInfectedFileDownload = $t.DisallowInfectedFileDownload
            VirusProtectionStatus        = $virusStatusMsg
            RiskLevel                    = $virusRisk
            Recommendation               = if (-not $virusBlocked) {
                "Run: Set-SPOTenant -DisallowInfectedFileDownload `$true to block infected file downloads"
            } else {
                "No action required. Virus protection is active."
            }
        }

        Export-AuditData -Data @($virusData) -FileName "08_VirusProtectionSettings" -Description "Virus/malware protection settings"
        return $virusData
    }
    catch {
        Write-AuditLog "Failed to retrieve virus protection settings: $_" "ERROR"
        return $null
    }
}

# ============================================================
# SECTION 9 - OVERSHARING / COPILOT RISK ASSESSMENT
# ============================================================

function Get-OversharingRisk {
    param([object[]]$Sites, [object[]]$ExternalUsers)
    Write-AuditLog "=== SECTION 9: Oversharing / Microsoft Copilot Risk Assessment ===" "INFO"

    $oversharingData = New-Object System.Collections.ArrayList

    if ($Sites -and $Sites.Count -gt 0) {
        $anonSites    = $Sites | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }
        $guestSites   = $Sites | Where-Object { $_.SharingCapability -eq "ExternalUserSharingOnly" }
        $totalSites   = $Sites.Count
        $anonCount    = if ($anonSites)  { $anonSites.Count  } else { 0 }
        $guestCount   = if ($guestSites) { $guestSites.Count } else { 0 }
        $anonPercent  = [math]::Round(($anonCount  / $totalSites) * 100, 1)
        $guestPercent = [math]::Round(($guestCount / $totalSites) * 100, 1)

        [void]$oversharingData.Add([PSCustomObject]@{
            Category       = "Anonymous Sharing Exposure"
            AffectedCount  = $anonCount
            TotalSites     = $totalSites
            PercentAffected = "$anonPercent%"
            CopilotRisk    = "CRITICAL - Copilot can surface files from these sites to any user with a link"
            Remediation    = "Disable Anyone sharing tenant-wide and restrict per-site. Set default link to Specific people."
        })

        [void]$oversharingData.Add([PSCustomObject]@{
            Category        = "External Guest Sharing Exposure"
            AffectedCount   = $guestCount
            TotalSites      = $totalSites
            PercentAffected = "$guestPercent%"
            CopilotRisk     = "HIGH - Copilot may surface content to guest users with broad permissions"
            Remediation     = "Review guest access per site. Enable guest expiration. Use sensitivity labels."
        })
    }

    if ($ExternalUsers -and $ExternalUsers.Count -gt 0) {
        [void]$oversharingData.Add([PSCustomObject]@{
            Category        = "Guest User Count"
            AffectedCount   = $ExternalUsers.Count
            TotalSites      = "N/A"
            PercentAffected = "N/A"
            CopilotRisk     = "MEDIUM - Each guest can potentially access Copilot-indexed content they have permissions to"
            Remediation     = "Review all guest accounts. Remove stale or unrecognized guests. Enable access reviews in Entra ID."
        })
    }

    [void]$oversharingData.Add([PSCustomObject]@{
        Category        = "Broad Internal Permissions"
        AffectedCount   = "Manual review required"
        TotalSites      = "N/A"
        PercentAffected = "N/A"
        CopilotRisk     = "HIGH - Copilot respects SharePoint permissions. If Everyone or broad groups have access, Copilot will surface that content to all members."
        Remediation     = "Run PnP deep scan (-SkipPnP:false) to find Everyone group grants. Apply sensitivity labels to restrict Copilot indexing of sensitive content."
    })

    [void]$oversharingData.Add([PSCustomObject]@{
        Category        = "Sensitivity Labels Not Applied"
        AffectedCount   = "Manual review required"
        TotalSites      = "N/A"
        PercentAffected = "N/A"
        CopilotRisk     = "HIGH - Without sensitivity labels, Copilot treats all content equally and may surface confidential data in AI-generated responses."
        Remediation     = "Apply Microsoft Purview sensitivity labels to site collections. Enable mandatory labeling for new content. Configure label-based Copilot restrictions."
    })

    Export-AuditData -Data $oversharingData -FileName "09_OversharingCopilotRisk" -Description "Oversharing and Copilot risk assessment"
    return $oversharingData
}

# ============================================================
# SECTION 10 - RISK FINDINGS
# ============================================================

function Get-RiskFindings {
    param(
        [object]$TenantSettings,
        [object[]]$Sites,
        [object[]]$ExternalUsers,
        [object[]]$SiteAdmins,
        [object]$VirusProtection
    )
    Write-AuditLog "=== SECTION 10: Risk Findings Summary ===" "INFO"

    $findings = New-Object System.Collections.ArrayList

    function Add-Finding {
        param([string]$Cat, [string]$Risk, [string]$Finding, [string]$Detail, [string]$Fix)
        [void]$findings.Add([PSCustomObject]@{
            Category    = $Cat
            RiskLevel   = $Risk
            Finding     = $Finding
            Detail      = $Detail
            Remediation = $Fix
        })
    }

    if ($TenantSettings) {
        $sc = $TenantSettings.SharingCapability.ToString()
        if ($sc -eq "ExternalUserAndGuestSharing") {
            Add-Finding "External Sharing" "High" `
                "Tenant allows anonymous Anyone links" `
                "SharingCapability = ExternalUserAndGuestSharing" `
                "Set to New and existing guests or lower in SPO Admin > Policies > Sharing"
        }
        elseif ($sc -eq "ExternalUserSharingOnly") {
            Add-Finding "External Sharing" "Medium" `
                "Tenant allows sharing with new external guests" `
                "SharingCapability = ExternalUserSharingOnly" `
                "Review whether new guest invitations are necessary for all sites"
        }

        if ($TenantSettings.LegacyAuthProtocolsEnabled -eq $true) {
            Add-Finding "Authentication" "High" `
                "Legacy authentication protocols are enabled" `
                "LegacyAuthProtocolsEnabled = True" `
                "Disable legacy auth in SPO Admin > Access Control"
        }

        if ($TenantSettings.EmailAttestationRequired -eq $false) {
            Add-Finding "Guest Access" "Medium" `
                "Email attestation not required for anonymous link recipients" `
                "EmailAttestationRequired = False" `
                "Enable in SPO Admin > Sharing settings"
        }

        if ($TenantSettings.ExternalUserExpirationRequired -eq $false) {
            Add-Finding "Guest Access" "Medium" `
                "No expiration set for external/guest users" `
                "ExternalUserExpirationRequired = False" `
                "Enable guest expiration in SPO Admin > Sharing"
        }

        if ($TenantSettings.PreventExternalUsersFromResharing -eq $false) {
            Add-Finding "External Sharing" "Medium" `
                "External users can reshare content they do not own" `
                "PreventExternalUsersFromResharing = False" `
                "Enable Prevent external users from resharing in SPO Admin"
        }

        if ($TenantSettings.ConditionalAccessPolicy -eq "AllowFullAccess") {
            Add-Finding "Access Control" "High" `
                "No conditional access policy restricts SharePoint access" `
                "ConditionalAccessPolicy = AllowFullAccess" `
                "Apply limited web-only access for unmanaged devices at minimum"
        }

        if ($TenantSettings.DefaultSharingLinkType -eq "AnonymousAccess") {
            Add-Finding "External Sharing" "High" `
                "Default sharing link type is Anyone (anonymous)" `
                "DefaultSharingLinkType = AnonymousAccess" `
                "Change to Specific people or Only people in your organization"
        }

        if ($TenantSettings.OneDriveForGuestsEnabled -eq $true) {
            Add-Finding "OneDrive" "Medium" `
                "OneDrive sharing enabled for guest accounts" `
                "OneDriveForGuestsEnabled = True" `
                "Disable guest access to OneDrive if not required"
        }
    }

    # Virus protection finding
    if ($VirusProtection -and $VirusProtection.DisallowInfectedFileDownload -eq $false) {
        Add-Finding "Malware Protection" "High" `
            "SharePoint built-in virus protection is NOT blocking infected file downloads" `
            "DisallowInfectedFileDownload = False. Users can download files flagged as infected." `
            "Run: Set-SPOTenant -DisallowInfectedFileDownload `$true in SharePoint Online PowerShell"
    }
    elseif ($VirusProtection -and $VirusProtection.DisallowInfectedFileDownload -eq $true) {
        Add-Finding "Malware Protection" "Good" `
            "SharePoint built-in virus protection is active and blocking infected downloads" `
            "DisallowInfectedFileDownload = True" `
            "No action required."
    }

    if ($Sites -and $Sites.Count -gt 0) {
        $anonSites = $Sites | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }
        if ($anonSites -and $anonSites.Count -gt 0) {
            Add-Finding "Site Permissions" "High" `
                "$($anonSites.Count) of $($Sites.Count) sites allow anonymous Anyone sharing" `
                "These sites permit unauthenticated access and are a critical Copilot oversharing risk" `
                "Review each site in SPO Admin > Sites > Active Sites and restrict sharing"
        }
    }

    if ($ExternalUsers -and $ExternalUsers.Count -gt 0) {
        Add-Finding "Guest Access" "Info" `
            "$($ExternalUsers.Count) external/guest users exist in the tenant" `
            "Total guest count across all sites" `
            "Review regularly - remove inactive or unrecognized guests"

        $extAdmins = $ExternalUsers | Where-Object { $_.IsSiteAdmin -eq $true }
        if ($extAdmins -and $extAdmins.Count -gt 0) {
            Add-Finding "Guest Access" "High" `
                "CRITICAL: $($extAdmins.Count) external user(s) have Site Admin rights" `
                "External users should never be site collection administrators" `
                "Remove site admin rights from all external/guest users immediately"
        }
    }

    if ($SiteAdmins -and $SiteAdmins.Count -gt 0) {
        $guestAdmins = $SiteAdmins | Where-Object { $_.IsGuest -eq $true }
        if ($guestAdmins -and $guestAdmins.Count -gt 0) {
            Add-Finding "Privileged Access" "High" `
                "CRITICAL: $($guestAdmins.Count) guest account(s) have Site Admin role" `
                "Guest accounts should never hold administrative roles" `
                "Remove these accounts from site admin roles immediately"
        }
    }

    Export-AuditData -Data $findings -FileName "10_RiskFindings" -Description "Risk findings"
    return $findings
}

# ============================================================
# HTML REPORT
# ============================================================

function New-HtmlReport {
    param(
        [object]$TenantSettings,
        [object[]]$Sites,
        [object[]]$ExternalUsers,
        [object[]]$Findings,
        [object]$VirusProtection,
        [object[]]$OversharingRisk
    )
    Write-AuditLog "=== Generating HTML Report ===" "INFO"

    $highCount  = if ($Findings) { ($Findings | Where-Object { $_.RiskLevel -eq "High"   }).Count } else { 0 }
    $medCount   = if ($Findings) { ($Findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count } else { 0 }
    $goodCount  = if ($Findings) { ($Findings | Where-Object { $_.RiskLevel -eq "Good"   }).Count } else { 0 }
    $totalSites = if ($Sites)         { $Sites.Count }         else { "N/A" }
    $extCount   = if ($ExternalUsers) { $ExternalUsers.Count } else { "N/A" }
    $anonCount  = if ($Sites) { ($Sites | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }).Count } else { 0 }

    # Virus protection badge
    $virusBadge = "<span style='background:#FF4444;color:white;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:bold'>NOT PROTECTED</span>"
    $virusDetail = "Infected files can be downloaded. Run: Set-SPOTenant -DisallowInfectedFileDownload `$true"
    if ($VirusProtection -and $VirusProtection.DisallowInfectedFileDownload -eq $true) {
        $virusBadge  = "<span style='background:#00C851;color:white;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:bold'>PROTECTED</span>"
        $virusDetail = "DisallowInfectedFileDownload = True. Infected files are blocked from download."
    }

    # Risk findings rows
    $findingRows = ""
    if ($Findings) {
        $findingRows = ($Findings | ForEach-Object {
            $bg = switch ($_.RiskLevel) {
                "High"   { "#fff0f0" } "Medium" { "#fff8e1" }
                "Low"    { "#fffff0" } "Good"   { "#f0fff4" }
                default  { "#f0f8ff" }
            }
            $badge = switch ($_.RiskLevel) {
                "High"   { "<span style='background:#FF4444;color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold'>HIGH</span>" }
                "Medium" { "<span style='background:#FFA500;color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold'>MEDIUM</span>" }
                "Low"    { "<span style='background:#FFD700;color:black;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold'>LOW</span>" }
                "Good"   { "<span style='background:#00C851;color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold'>GOOD</span>" }
                default  { "<span style='background:#33B5E5;color:white;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold'>INFO</span>" }
            }
            "<tr style='background:$bg'><td>$($_.Category)</td><td>$badge</td><td><strong>$($_.Finding)</strong><br><small style='color:#666'>$($_.Detail)</small></td><td><em>$($_.Remediation)</em></td></tr>"
        }) -join ""
    }

    # Sharing breakdown rows
    $sharingRows = ""
    if ($Sites) {
        $sharingRows = ($Sites | Group-Object SharingCapability | ForEach-Object {
            $color = switch ($_.Name) {
                "ExternalUserAndGuestSharing"     { "#FF4444" }
                "ExternalUserSharingOnly"         { "#FFA500" }
                "ExistingExternalUserSharingOnly" { "#FFD700" }
                "Disabled"                        { "#00C851" }
                default                           { "#33B5E5" }
            }
            "<tr><td>$(Get-SharingLabel $_.Name)</td><td><span style='color:$color;font-weight:bold'>$($_.Count)</span></td></tr>"
        }) -join ""
    }

    # Oversharing rows
    $oversharingRows = ""
    if ($OversharingRisk) {
        $oversharingRows = ($OversharingRisk | ForEach-Object {
            $riskColor = switch -Wildcard ($_.CopilotRisk) {
                "CRITICAL*" { "#FF4444" }
                "HIGH*"     { "#FFA500" }
                "MEDIUM*"   { "#FFD700" }
                default     { "#33B5E5" }
            }
            "<tr>
                <td><strong>$($_.Category)</strong></td>
                <td style='color:$riskColor;font-weight:bold'>$($_.AffectedCount)</td>
                <td style='color:$riskColor;font-size:12px'>$($_.CopilotRisk)</td>
                <td style='font-size:12px'><em>$($_.Remediation)</em></td>
            </tr>"
        }) -join ""
    }

    # Tenant settings HTML
    $settingsHtml = ""
    if ($TenantSettings) {
        $sc      = $TenantSettings.SharingCapability.ToString()
        $scClass = switch ($sc) {
            "ExternalUserAndGuestSharing"     { "bad"  }
            "ExternalUserSharingOnly"         { "warn" }
            "ExistingExternalUserSharingOnly" { "warn" }
            "Disabled"                        { "good" }
            default                           { ""     }
        }
        $dlClass = if ($TenantSettings.DefaultSharingLinkType  -eq "AnonymousAccess") { "bad"  } else { "good" }
        $caClass = if ($TenantSettings.ConditionalAccessPolicy -eq "AllowFullAccess") { "bad"  } else { "good" }
        $laClass = if ($TenantSettings.LegacyAuthProtocolsEnabled)                    { "bad"  } else { "good" }
        $geClass = if (-not $TenantSettings.ExternalUserExpirationRequired)            { "warn" } else { "good" }
        $eaClass = if (-not $TenantSettings.EmailAttestationRequired)                 { "warn" } else { "good" }
        $prClass = if (-not $TenantSettings.PreventExternalUsersFromResharing)        { "warn" } else { "good" }
        $odClass = if ($TenantSettings.OneDriveForGuestsEnabled)                      { "warn" } else { "good" }
        $aDom    = if ($TenantSettings.SharingAllowedDomainList) { $TenantSettings.SharingAllowedDomainList } else { "Not configured" }
        $bDom    = if ($TenantSettings.SharingBlockedDomainList) { $TenantSettings.SharingBlockedDomainList } else { "Not configured" }

        $settingsHtml = @"
<div class="setting-row"><span class="key">Tenant Sharing Level</span><span class="val $scClass">$(Get-SharingLabel $sc)</span></div>
<div class="setting-row"><span class="key">Default Sharing Link Type</span><span class="val $dlClass">$($TenantSettings.DefaultSharingLinkType)</span></div>
<div class="setting-row"><span class="key">Default Link Permission</span><span class="val">$($TenantSettings.DefaultLinkPermission)</span></div>
<div class="setting-row"><span class="key">Conditional Access Policy</span><span class="val $caClass">$($TenantSettings.ConditionalAccessPolicy)</span></div>
<div class="setting-row"><span class="key">Legacy Auth Enabled</span><span class="val $laClass">$($TenantSettings.LegacyAuthProtocolsEnabled)</span></div>
<div class="setting-row"><span class="key">Guest Expiration Required</span><span class="val $geClass">$($TenantSettings.ExternalUserExpirationRequired)</span></div>
<div class="setting-row"><span class="key">Guest Expiration (Days)</span><span class="val">$($TenantSettings.ExternalUserExpireInDays)</span></div>
<div class="setting-row"><span class="key">Email Attestation Required</span><span class="val $eaClass">$($TenantSettings.EmailAttestationRequired)</span></div>
<div class="setting-row"><span class="key">Prevent External Resharing</span><span class="val $prClass">$($TenantSettings.PreventExternalUsersFromResharing)</span></div>
<div class="setting-row"><span class="key">OneDrive for Guests</span><span class="val $odClass">$($TenantSettings.OneDriveForGuestsEnabled)</span></div>
<div class="setting-row"><span class="key">Sharing Allowed Domains</span><span class="val">$aDom</span></div>
<div class="setting-row"><span class="key">Sharing Blocked Domains</span><span class="val">$bDom</span></div>
"@
    }

    # Files generated table
    $filesTableRows = ($script:FilesGenerated | ForEach-Object {
        "<tr><td>$($_.File)</td><td style='text-align:center'>$($_.Records)</td><td>$($_.Description)</td></tr>"
    }) -join ""

    $genDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $genShort = Get-Date -Format "yyyy-MM-dd HH:mm"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SharePoint Online Security Audit - $ClientName</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:Segoe UI,Arial,sans-serif; background:#f5f7fa; color:#333; }
  .header { background:linear-gradient(135deg,#0078d4,#004e8c); color:white; padding:40px; }
  .header h1 { font-size:28px; font-weight:300; }
  .header p  { opacity:0.85; margin-top:6px; font-size:14px; }
  .container { max-width:1200px; margin:30px auto; padding:0 20px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:30px; }
  .card { background:white; border-radius:8px; padding:20px; box-shadow:0 2px 8px rgba(0,0,0,.08); text-align:center; }
  .card .num { font-size:42px; font-weight:bold; }
  .card .lbl { font-size:13px; color:#666; margin-top:4px; }
  .card.red .num { color:#FF4444; } .card.org .num { color:#FFA500; }
  .card.grn .num { color:#00C851; } .card.blu .num { color:#0078d4; }
  section { background:white; border-radius:8px; padding:24px; box-shadow:0 2px 8px rgba(0,0,0,.08); margin-bottom:24px; }
  section h2 { font-size:18px; color:#0078d4; border-bottom:2px solid #e8f0fe; padding-bottom:10px; margin-bottom:16px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { background:#f0f4f8; text-align:left; padding:10px 12px; font-weight:600; color:#444; }
  td { padding:10px 12px; border-bottom:1px solid #f0f0f0; vertical-align:top; }
  .setting-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f5f5f5; font-size:13px; }
  .setting-row .key { color:#555; }
  .setting-row .val { font-weight:600; color:#222; }
  .val.bad { color:#FF4444; } .val.warn { color:#FFA500; } .val.good { color:#00C851; }
  .note { background:#fff8e1; border-left:4px solid #FFA500; padding:12px 16px; margin-bottom:16px; font-size:13px; border-radius:4px; }
  .copilot-box { background:linear-gradient(135deg,#f0f4ff,#e8f0fe); border-left:4px solid #0078d4; padding:16px 20px; margin-bottom:16px; border-radius:4px; font-size:13px; line-height:1.6; }
  .copilot-box strong { color:#004e8c; }
  .virus-box { display:flex; align-items:center; gap:16px; padding:16px; border-radius:8px; margin-bottom:12px; }
  .virus-box.protected { background:#f0fff4; border:1px solid #00C851; }
  .virus-box.unprotected { background:#fff0f0; border:1px solid #FF4444; }
  .footer { text-align:center; color:#999; font-size:12px; padding:30px; border-top:1px solid #eee; margin-top:20px; }
  .footer a { color:#0078d4; text-decoration:none; }
  .sig { font-style:italic; margin-top:6px; }
</style>
</head>
<body>

<div class="header">
  <h1>SharePoint Online Security Audit</h1>
  <p>Client: <strong>$ClientName</strong> | Tenant: <strong>$TenantName</strong> | Generated: $genDate | Audit period: Last $AuditDays days</p>
</div>

<div class="container">

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card red"><div class="num">$highCount</div><div class="lbl">High Risk Findings</div></div>
    <div class="card org"><div class="num">$medCount</div><div class="lbl">Medium Risk Findings</div></div>
    <div class="card blu"><div class="num">$totalSites</div><div class="lbl">Total Sites</div></div>
    <div class="card red"><div class="num">$anonCount</div><div class="lbl">Sites with Anyone Links</div></div>
    <div class="card org"><div class="num">$extCount</div><div class="lbl">External / Guest Users</div></div>
    <div class="card grn"><div class="num">$goodCount</div><div class="lbl">Good / Compliant</div></div>
  </div>

  <!-- Risk Findings -->
  <section>
    <h2>Risk Findings</h2>
    <table>
      <thead><tr><th>Category</th><th>Risk</th><th>Finding</th><th>Remediation</th></tr></thead>
      <tbody>$findingRows</tbody>
    </table>
  </section>

  <!-- Virus Protection -->
  <section>
    <h2>Virus / Malware Protection</h2>
    <div class="virus-box $(if ($VirusProtection -and $VirusProtection.DisallowInfectedFileDownload) { 'protected' } else { 'unprotected' })">
      <div>$virusBadge</div>
      <div>
        <strong>SharePoint Built-in Virus Protection</strong><br>
        <span style="font-size:13px;color:#555">$virusDetail</span>
      </div>
    </div>
    <p class="note" style="font-size:12px">
      SharePoint Online includes a built-in virus scanner that checks files on upload and download.
      When <strong>DisallowInfectedFileDownload = True</strong>, infected files are blocked from being downloaded by any user.
      This setting is disabled by default and most organizations never enable it.
      To enable: <code>Set-SPOTenant -DisallowInfectedFileDownload `$true</code>
    </p>
  </section>

  <!-- Oversharing / Copilot Risk -->
  <section>
    <h2>Oversharing Risk - Microsoft Copilot Warning</h2>
    <div class="copilot-box">
      <strong>Why oversharing is critical when using Microsoft 365 Copilot:</strong><br>
      Microsoft 365 Copilot respects SharePoint permissions when surfacing content in AI-generated responses.
      This means <strong>Copilot will expose any file a user has access to</strong> -- including files they may not
      have been aware existed. Broad permissions, Anyone links, and excessive guest access become
      <strong>amplified security risks</strong> in a Copilot environment because Copilot can proactively
      surface sensitive content that users would otherwise never find on their own.
      Organizations deploying Copilot <strong>must address oversharing before or during rollout</strong>
      to prevent AI-assisted data leakage.
    </div>
    <table>
      <thead><tr><th>Risk Category</th><th>Affected Count</th><th>Copilot Risk</th><th>Remediation</th></tr></thead>
      <tbody>$oversharingRows</tbody>
    </table>
  </section>

  <!-- Tenant Settings -->
  <section>
    <h2>Tenant Security Settings</h2>
    $settingsHtml
  </section>

  <!-- Site Sharing Breakdown -->
  <section>
    <h2>Site Sharing Level Breakdown</h2>
    <table>
      <thead><tr><th>Sharing Level</th><th>Number of Sites</th></tr></thead>
      <tbody>$sharingRows</tbody>
    </table>
  </section>

  <!-- Files Generated -->
  <section>
    <h2>Files Generated This Run</h2>
    <p class="note">Only files with data are listed. Sections with no findings (e.g., no external admins found) do not generate a file.</p>
    <table>
      <thead><tr><th>File</th><th style="text-align:center">Records</th><th>Contents</th></tr></thead>
      <tbody>$filesTableRows</tbody>
    </table>
  </section>

</div>

<div class="footer">
  SharePoint Online Security Audit | $ClientName | $genShort<br>
  <div class="sig">
    Created by <strong>Luis Z Guzman Garcia (KillBillKill98)</strong> |
    <a href="$ScriptGitHub" target="_blank">$ScriptGitHub</a> |
    Script Version $ScriptVersion
  </div>
</div>

</body>
</html>
"@

    $htmlPath = Join-Path $ReportFolder "SPO_SecurityAudit_Report.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-AuditLog "HTML report saved: $htmlPath" "SUCCESS"
}

# ============================================================
# MAIN
# ============================================================

function Main {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  SharePoint Online Tenant-Wide Security Audit"           -ForegroundColor Cyan
    Write-Host "  By: $ScriptAuthor"                                      -ForegroundColor Cyan
    Write-Host "  $ScriptGitHub"                                          -ForegroundColor Cyan
    Write-Host "  Version $ScriptVersion"                                 -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Client  : $ClientName"                                  -ForegroundColor Cyan
    Write-Host "  Tenant  : $TenantName"                                  -ForegroundColor Cyan
    if ($AdminUPN) {
        Write-Host "  Admin   : $AdminUPN"                                -ForegroundColor Cyan
    }
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""

    Initialize-OutputFolder

    # SPO Connection check
    Write-AuditLog "Checking SharePoint Online connection..." "INFO"
    try {
        Get-SPOTenant -ErrorAction Stop | Out-Null
        Write-AuditLog "Already connected to SPO." "SUCCESS"
    }
    catch {
        try {
            Connect-SPOService -Url $AdminUrl -ModernAuth $true -ErrorAction Stop
            Write-AuditLog "Connected to SPO." "SUCCESS"
        }
        catch {
            Write-AuditLog "SPO connection failed: $_" "ERROR"
            Write-AuditLog "Pre-connect first: Connect-SPOService -Url '$AdminUrl'" "WARN"
            return
        }
    }

    # Exchange Online connection
    if (-not $SkipAuditLog) {
        Write-AuditLog "Connecting to Exchange Online (required for audit log)..." "INFO"
        try {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop

            # Detect module version to use the correct connection cmdlet
            $exoModule  = Get-Module ExchangeOnlineManagement
            $exoVersion = if ($exoModule) { $exoModule.Version.Major } else { 0 }
            Write-AuditLog "ExchangeOnlineManagement module version: $($exoModule.Version)" "INFO"

            if ($exoVersion -ge 2) {
                # v2 / v3 - use Connect-ExchangeOnline
                Write-AuditLog "Using Connect-ExchangeOnline (module v2+)..." "INFO"
                try {
                    if ($AdminUPN) {
                        Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ShowBanner:$false -ErrorAction Stop
                    }
                    else {
                        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                    }
                }
                catch {
                    # Some v2 builds don't support -ShowBanner
                    if ($AdminUPN) {
                        Connect-ExchangeOnline -UserPrincipalName $AdminUPN -ErrorAction Stop
                    }
                    else {
                        Connect-ExchangeOnline -ErrorAction Stop
                    }
                }
            }
            else {
                # v1 - use the legacy Connect-EXOPSSession
                Write-AuditLog "Module v1 detected - using Connect-EXOPSSession (legacy)..." "WARN"
                Write-AuditLog "RECOMMENDATION: Update module with: Update-Module ExchangeOnlineManagement -Force" "WARN"
                if ($AdminUPN) {
                    Connect-EXOPSSession -UserPrincipalName $AdminUPN -ErrorAction Stop
                }
                else {
                    Connect-EXOPSSession -ErrorAction Stop
                }
            }
            Write-AuditLog "Exchange Online connected." "SUCCESS"

            # IPPS / Security & Compliance - needed for Search-UnifiedAuditLog
            Write-AuditLog "Connecting to Security and Compliance Center..." "INFO"
            try {
                if ($exoVersion -ge 2) {
                    if ($AdminUPN) {
                        Connect-IPPSSession -UserPrincipalName $AdminUPN -ErrorAction Stop
                    }
                    else {
                        Connect-IPPSSession -ErrorAction Stop
                    }
                }
                else {
                    # v1 legacy
                    if ($AdminUPN) {
                        Connect-IPPSSession -UserPrincipalName $AdminUPN -ErrorAction Stop
                    }
                    else {
                        Connect-IPPSSession -ErrorAction Stop
                    }
                }
                Write-AuditLog "Security and Compliance connected." "SUCCESS"
            }
            catch {
                Write-AuditLog "IPPS connection failed (audit log may still work via Exchange session): $_" "WARN"
            }
        }
        catch {
            Write-AuditLog "Exchange connection failed - audit log sections will be skipped." "WARN"
            Write-AuditLog "Error: $_" "WARN"
            Write-AuditLog "Fix: Run 'Update-Module ExchangeOnlineManagement -Force' then re-run this script." "WARN"
            $script:SkipAuditLogInt = $true
        }
    }

    # Run all sections
    $tenantSettings  = Get-TenantSettings
    $sites           = Get-AllSiteCollections
    $externalUsers   = Get-ExternalUsers
    $siteAdmins      = Get-SiteAdmins      -Sites $sites
    $virusProtection = Get-VirusProtectionSettings
    $oversharingRisk = Get-OversharingRisk -Sites $sites -ExternalUsers $externalUsers

    if (-not $SkipPnP) {
        $pnpAvailable = Get-Module PnP.PowerShell -ListAvailable
        if ($pnpAvailable) {
            Get-DeepPermissions -Sites $sites
        }
        else {
            Write-AuditLog "PnP.PowerShell not installed - skipping deep scan." "WARN"
            Write-AuditLog "Install: Install-Module PnP.PowerShell -RequiredVersion 1.12.0" "WARN"
        }
    }
    else {
        Write-AuditLog "Skipping PnP deep scan (-SkipPnP)." "WARN"
    }

    if (-not $script:SkipAuditLogInt -and -not $SkipAuditLog) {
        Get-AuditLogEvents
    }

    $null = Get-OneDriveSettings

    $findings = Get-RiskFindings `
        -TenantSettings  $tenantSettings `
        -Sites           $sites `
        -ExternalUsers   $externalUsers `
        -SiteAdmins      $siteAdmins `
        -VirusProtection $virusProtection

    New-HtmlReport `
        -TenantSettings  $tenantSettings `
        -Sites           $sites `
        -ExternalUsers   $externalUsers `
        -Findings        $findings `
        -VirusProtection $virusProtection `
        -OversharingRisk $oversharingRisk

    # Final summary
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Green
    Write-Host "  AUDIT COMPLETE"                                          -ForegroundColor Green
    Write-Host "  Client  : $ClientName"                                   -ForegroundColor Green
    Write-Host "  Output  : $ReportFolder"                                 -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green

    $high = if ($findings) { ($findings | Where-Object { $_.RiskLevel -eq "High"   }).Count } else { 0 }
    $med  = if ($findings) { ($findings | Where-Object { $_.RiskLevel -eq "Medium" }).Count } else { 0 }

    Write-Host ("  Files Generated      : {0}" -f $script:FilesGenerated.Count) -ForegroundColor Cyan
    Write-Host ("  High Risk Findings   : {0}" -f $high) -ForegroundColor $(if ($high -gt 0) { "Red"    } else { "Green" })
    Write-Host ("  Medium Risk Findings : {0}" -f $med)  -ForegroundColor $(if ($med  -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""
    Write-Host "  By: $ScriptAuthor" -ForegroundColor DarkCyan
    Write-Host "  $ScriptGitHub"     -ForegroundColor DarkCyan
    Write-Host ""

    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    try { Disconnect-SPOService -ErrorAction SilentlyContinue } catch { }
}

Main
