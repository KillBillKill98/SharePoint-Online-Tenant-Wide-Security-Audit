# /reports

This folder is the destination for generated audit reports.

When you run `SPO-TenantSecurityAudit.ps1`, point `-OutputPath` to this directory
to keep all client report folders organized in one place.

## Example

```powershell
.\scripts\SPO-TenantSecurityAudit.ps1 `
    -TenantName "contoso" `
    -ClientName "Contoso-LLC" `
    -AdminUPN   "admin@contoso.com" `
    -OutputPath ".\reports"
```

This will create:
```
reports/
└── SAFO-LLC_SPO_Audit_20260217_150000/
    ├── SPO_SecurityAudit_Report.html
    ├── 01_TenantSettings.csv
    └── ...
```

> **Note:** Report folders containing client data should be added to `.gitignore`
> and never committed to a public repository.
