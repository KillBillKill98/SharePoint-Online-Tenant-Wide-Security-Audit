# SPO-TenantSecurityAudit

**SharePoint Online Tenant-Wide Security Audit Toolkit**

---

## Overview

A comprehensive PowerShell-based audit toolkit for SharePoint Online environments.
Designed for MSPs, IT administrators, and security engineers who need a fast,
repeatable, and client-ready security assessment of Microsoft 365 SharePoint tenants.

### What It Audits

| Section | Coverage |
|---|---|
| Tenant Settings | Sharing policies, conditional access, legacy auth, link defaults |
| Site Collections | All 70+ site types with per-site risk ratings |
| External / Guest Users | Paginated full inventory with admin flag detection |
| Site Admins | All admin accounts across all sites, guest admin detection |
| PnP Deep Scan | Broken inheritance, Everyone group grants (optional) |
| Audit Log | Anonymous links, sharing invitations, permission changes, external file access |
| OneDrive Settings | Sync restrictions, guest access, storage quotas |
| Virus Protection | Built-in SharePoint malware protection status (commonly missed) |
| Oversharing / Copilot | AI-amplified oversharing risk assessment for Copilot environments |
| Risk Findings | Prioritized findings with remediation steps |

---

## Repository Structure

```
/
├── scripts/        Audit execution scripts
├── reports/        Generated audit reports (output destination)
└── docs/           Documentation and usage guides
```

---

## Quick Start

### Prerequisites

Install required modules in **Windows PowerShell 5.1**:

```powershell
Install-Module Microsoft.Online.SharePoint.PowerShell -RequiredVersion 16.0.24810.12000 -Force
Install-Module ExchangeOnlineManagement -Force
Install-Module PnP.PowerShell -RequiredVersion 1.12.0 -Force  # Optional, for deep scan
```

### Running the Audit

```powershell
# Step 1 - Unblock the script (required when downloaded from the internet or OneDrive)
Unblock-File -Path ".\scripts\SPO-TenantSecurityAudit.ps1"

# Step 2 - Set execution policy for current session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Step 3 - Pre-connect to SharePoint Online
Connect-SPOService -Url "https://yourtenant-admin.sharepoint.com"

# Step 4 - Run the audit
.\scripts\SPO-TenantSecurityAudit.ps1 `
    -TenantName "yourtenant" `
    -ClientName "Client-Name" `
    -AdminUPN "admin@yourtenant.com" `
    -AuditDays 30
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-TenantName` | Yes | SharePoint tenant slug (e.g., `safousa`) |
| `-ClientName` | Yes | Client name used for output folder naming |
| `-AdminUPN` | Recommended | Admin UPN for Exchange/audit log connections |
| `-OutputPath` | No | Custom output folder (defaults to current directory) |
| `-AuditDays` | No | Audit log lookback in days (default: 30) |
| `-SkipAuditLog` | No | Skip Unified Audit Log search (faster) |
| `-SkipPnP` | No | Skip PnP deep permission scan (faster) |

### Output

Reports are saved to a timestamped folder named after the client:

```
Client-Name_SPO_Audit_20260217_150000/
├── SPO_SecurityAudit_Report.html       ← Open this first
├── 01_TenantSettings.csv
├── 02_SiteCollections.csv
├── 02a_HighRisk_AnonymousSharingSites.csv
├── 03_ExternalUsers.csv
├── 04_SiteAdmins.csv
├── 05_DeepPermissions_BrokenInheritance.csv
├── 06a_AnonymousLinkEvents.csv
├── 06b_SharingInvitationEvents.csv
├── 06c_PermissionChangeEvents.csv
├── 06d_ExternalUserFileAccess.csv
├── 07_OneDriveSettings.csv
├── 08_VirusProtectionSettings.csv
├── 09_OversharingCopilotRisk.csv
└── 10_RiskFindings.csv
```

---

## Common Issues

| Error | Fix |
|---|---|
| Script not digitally signed | `Unblock-File -Path ".\SPO-TenantSecurityAudit.ps1"` |
| Connect-SPOService 400 Bad Request | Use Windows PowerShell 5.1, not PS7 |
| Search-UnifiedAuditLog not found | Use `-AdminUPN` parameter to fix Exchange connection |
| PnP module version conflict | `Install-Module PnP.PowerShell -RequiredVersion 1.12.0 -Force` |
| Graph.Authentication version conflict | Close all PS windows, delete the conflicting version folder |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*By Luis Z Guzman Garcia (KillBillKill98) — [https://github.com/KillBillKill98](https://github.com/KillBillKill98)*
