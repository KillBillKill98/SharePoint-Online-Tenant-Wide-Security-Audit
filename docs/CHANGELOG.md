# Changelog

All notable changes to SPO-TenantSecurityAudit are documented here.

---

## [2.0] - 2026-02-17

### Added
- `-ClientName` parameter — output folder now named after the client
  (e.g., `SAFO-LLC_SPO_Audit_20260217_150000`)
- **Section 8: Virus / Malware Protection** — audits `DisallowInfectedFileDownload`
  setting which is disabled by default on all tenants and almost universally overlooked
- **Section 9: Oversharing / Microsoft Copilot Risk Assessment** — dedicated section
  assessing oversharing risks that are amplified in Microsoft 365 Copilot environments
- Author signature in script header and console output:
  `By: Luis Z Guzman Garcia (KillBillKill98)`
- GitHub URL in HTML report footer: `https://github.com/KillBillKill98`
- HTML report now shows **only files actually generated** (not a static list)
  with accurate record counts per file
- `$script:FilesGenerated` tracking list to power accurate HTML report
- Virus protection status badge in HTML report (green/red visual indicator)
- Copilot oversharing explainer box in HTML report
- `Connect-ExchangeOnline` now used in addition to `Connect-IPPSSession`
  to ensure `Search-UnifiedAuditLog` is available
- Audit log section self-heals — attempts reconnect if cmdlet not found

### Fixed
- `Get-SPOExternalUser -Limit` error — replaced with `-PageSize` / `-Position` pagination
- `Get-SPOUser -Limit All` replaced with `-Limit 500` for compatibility
- `Connect-PnPOnline -Interactive` replaced with cached credential approach
  (credentials prompted once, reused across all sites)
- Console output noise — file paths and objects no longer print mid-run
- `Connect-IPPSSession` AADSTS700016 error — now passes `-UserPrincipalName`
- Script encoding — all em dashes and box-drawing characters replaced with
  plain ASCII to prevent PS 5.1 parse errors
- `$script:SkipAuditLog` scoping bug that caused audit log to run even after
  Exchange connection failure

### Changed
- Output folder naming: `SPO_Audit_TIMESTAMP` → `CLIENTNAME_SPO_Audit_TIMESTAMP`
- Risk findings now include virus protection as a finding with Good/High rating
- Section numbering updated to accommodate new sections (8, 9, 10)

---

## [1.0] - 2026-02-17

### Added
- Initial release
- Sections: Tenant Settings, Site Collections, External Users, Site Admins,
  PnP Deep Scan, Unified Audit Log, OneDrive Settings, Risk Findings
- HTML dashboard report with risk badges and site sharing breakdown
- CSV exports for all sections
