# Usage Guide — SPO-TenantSecurityAudit.ps1

> By **Luis Z Guzman Garcia (KillBillKill98)**
> [https://github.com/KillBillKill98](https://github.com/KillBillKill98)

---

## Requirements

| Requirement | Notes |
|---|---|
| Windows PowerShell 5.1 | Do NOT use PowerShell 7 — SPO module is unstable on PS7 |
| Global Admin or SharePoint Admin | Required to run SPO cmdlets |
| Compliance Admin or higher | Required for Unified Audit Log search |
| Microsoft.Online.SharePoint.PowerShell | Version 16.0.24810.12000 recommended |
| ExchangeOnlineManagement | For audit log sections |
| PnP.PowerShell v1.12.0 | Optional, for deep permission scan only |

---

## Step-by-Step Setup

### 1. Install Modules (run once)

Open **Windows PowerShell 5.1 as Administrator** and run:

```powershell
# Required
Install-Module Microsoft.Online.SharePoint.PowerShell -RequiredVersion 16.0.24810.12000 -Force -AllowClobber
Install-Module ExchangeOnlineManagement -Force -AllowClobber

# Optional (deep permission scan)
Install-Module PnP.PowerShell -RequiredVersion 1.12.0 -Force -AllowClobber
```

### 2. Unblock the Script

If downloaded from GitHub or stored in a OneDrive-synced folder:

```powershell
Unblock-File -Path ".\scripts\SPO-TenantSecurityAudit.ps1"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

### 3. Pre-Connect to SharePoint Online

```powershell
Connect-SPOService -Url "https://YOURTENANT-admin.sharepoint.com"
```

Wait for the browser login prompt to complete before proceeding.

### 4. Run the Audit

**Standard run (recommended):**
```powershell
.\scripts\SPO-TenantSecurityAudit.ps1 `
    -TenantName "safousa" `
    -ClientName "SAFO-LLC" `
    -AdminUPN   "admin@safousa.com" `
    -AuditDays  30
```

**Fast run (skip PnP deep scan, skip audit log):**
```powershell
.\scripts\SPO-TenantSecurityAudit.ps1 `
    -TenantName  "safousa" `
    -ClientName  "SAFO-LLC" `
    -AdminUPN    "admin@safousa.com" `
    -AuditDays   30 `
    -SkipPnP `
    -SkipAuditLog
```

---

## Parameters Reference

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-TenantName` | YES | — | SharePoint tenant slug (e.g., `safousa`) |
| `-ClientName` | YES | — | Client name for output folder (e.g., `SAFO-LLC`) |
| `-AdminUPN` | Recommended | `""` | Admin UPN for Exchange/IPPS connections |
| `-OutputPath` | No | Current dir | Where to save the output folder |
| `-AuditDays` | No | `30` | Days to look back in the Unified Audit Log |
| `-SkipAuditLog` | No | `$false` | Skip Unified Audit Log search |
| `-SkipPnP` | No | `$false` | Skip PnP deep permission scan |

---

## Output Files

All files are saved inside a timestamped client folder:

```
SAFO-LLC_SPO_Audit_20260217_150000/
├── SPO_SecurityAudit_Report.html            ← Start here — full HTML dashboard
├── 01_TenantSettings.csv                    ← Tenant sharing and access settings
├── 02_SiteCollections.csv                   ← All sites with risk ratings
├── 02a_HighRisk_AnonymousSharingSites.csv   ← Sites with Anyone links (HIGH RISK)
├── 03_ExternalUsers.csv                     ← All guest/external users
├── 03a_CRITICAL_ExternalSiteAdmins.csv      ← Guests with Site Admin rights
├── 04_SiteAdmins.csv                        ← All site admins
├── 04a_CRITICAL_GuestSiteAdmins.csv         ← Guest accounts as site admins
├── 05_DeepPermissions_BrokenInheritance.csv ← Broken inheritance (PnP scan)
├── 06a_AnonymousLinkEvents.csv              ← Anonymous link activity (audit log)
├── 06b_SharingInvitationEvents.csv          ← External sharing events
├── 06c_PermissionChangeEvents.csv           ← Permission change events
├── 06d_ExternalUserFileAccess.csv           ← Files accessed by external users
├── 07_OneDriveSettings.csv                  ← OneDrive tenant settings
├── 08_VirusProtectionSettings.csv           ← SharePoint malware protection status
├── 09_OversharingCopilotRisk.csv            ← Copilot oversharing risk assessment
└── 10_RiskFindings.csv                      ← All findings with remediation steps
```

> Files are only created when data exists. Sections with no findings (e.g., no external admins) will not produce a CSV.

---

## Virus Protection Explained

SharePoint Online includes a built-in virus scanner that scans files on upload and download.

| Setting | Value | Meaning |
|---|---|---|
| `DisallowInfectedFileDownload` | `True` | PROTECTED — infected files are blocked |
| `DisallowInfectedFileDownload` | `False` | NOT PROTECTED — infected files can be downloaded |

This setting is **disabled by default** and most organizations never enable it.

**To enable:**
```powershell
Connect-SPOService -Url "https://YOURTENANT-admin.sharepoint.com"
Set-SPOTenant -DisallowInfectedFileDownload $true
```

---

## Oversharing and Microsoft Copilot Risk

Microsoft 365 Copilot uses SharePoint permissions to determine what content it can surface in AI responses. This means:

- **Copilot will expose files users have access to** even if they did not know those files existed
- **Anyone links** (anonymous sharing) are a critical risk — Copilot can surface this content broadly
- **Broad group memberships** (Everyone, All Users) amplify the blast radius of oversharing
- **Sensitivity labels** are the primary control to restrict Copilot from indexing sensitive content

Organizations deploying Copilot should resolve oversharing findings **before rollout**.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `UnauthorizedAccess` on script load | Execution policy or file blocked | `Unblock-File` + `Set-ExecutionPolicy Bypass -Scope Process` |
| `400 Bad Request` on `Connect-SPOService` | Running in PS7 or token conflict | Use Windows PowerShell 5.1 only |
| `Search-UnifiedAuditLog not recognized` | IPPS connected but Exchange not | Use `-AdminUPN` parameter |
| `AADSTS700016` browser error | App not registered in tenant | Ignore if Exchange still connects — it uses a different app |
| `PnP module version conflict` | Wrong PnP version installed | `Install-Module PnP.PowerShell -RequiredVersion 1.12.0 -Force` |
| `Graph.Authentication locked` | Files locked by OneDrive sync | Close OneDrive, delete the 2.28.0 folder, reopen |
| Module stored in OneDrive path | File locking issues | Move modules to `C:\Program Files\PowerShell\Modules` |
