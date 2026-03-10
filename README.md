# Windows 365 Link — Deployment Readiness Assessment

A PowerShell-based automated assessment tool that checks your Microsoft 365 tenant against the known prerequisites for [Windows 365 Link](https://learn.microsoft.com/en-us/windows-365/link/) device deployment. It generates a professional HTML report with findings, risk levels, and actionable remediation guidance.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Why This Matters

Windows 365 Link is a purpose-built Cloud PC device that connects users to their Windows 365 Cloud PC. A smooth deployment relies on a combination of Entra ID, Intune, and Windows 365 settings working together. Running this assessment beforehand helps confirm everything is in place and highlights anything that may need attention.

Examples of what this tool can catch early:

- **Intune enrollment readiness** — Link devices need Entra ID Premium and MDM auto-enrollment to be configured. Without these, a device may join Entra ID but not appear in Intune.
- **SSO configuration** — enabling Single Sign-On on Cloud PC provisioning policies gives users a seamless connection experience without repeated authentication prompts.
- **Conditional Access compatibility** — Windows 365 Link uses a two-stage authentication model (local sign-in → Cloud PC connection), so it's worth confirming your Conditional Access policies are aligned.
- **Enrollment restriction alignment** — platform restrictions designed for BYOD scenarios may unintentionally apply to Link devices if not reviewed.

We recommend running this tool as part of your deployment planning — even if you're confident in your configuration — so you have a clear baseline before onboarding devices.

## Checks Performed

| # | Category | What It Checks |
|---|----------|---------------|
| 1 | **Licensing** | Windows 365, Microsoft Intune, and Entra ID Premium licenses exist in the tenant. Optionally checks a specific user's assigned licenses. |
| 2 | **Entra ID Device Join** | Device registration policy allows users to join devices to Entra ID (`All`, `Selected`, or `None`), plus the maximum device-per-user limit. |
| 3 | **Intune Auto-Enrollment** | MDM user scope is configured on the Microsoft Intune mobility application so devices auto-enroll after Entra join. |
| 4 | **Enrollment Restrictions** | Default and custom enrollment restriction profiles are compatible with Windows 365 Link device enrollment. |
| 5 | **Cloud PC SSO** | Single Sign-On is enabled on Cloud PC provisioning policies. Produces a combined table showing SSO status across all (or filtered) policies. |
| 6 | **Conditional Access** | Evaluates policies targeting Windows 365, Azure Virtual Desktop, and Windows Cloud Login apps to confirm compatibility with the two-stage authentication model. |
| 7 | **Authentication Methods** | Checks if FIDO2 security keys are enabled as an authentication method (relevant for passwordless scenarios). |
| 8 | **Intune Filters** | Looks for existing Intune assignment filters using the `operatingSystemSKU -eq "WCPC"` rule that can target Windows 365 Link devices specifically. |

## Prerequisites

- **PowerShell 5.1** or later (Windows PowerShell or PowerShell 7+)
- **Microsoft.Graph PowerShell module** — the script will attempt to install it automatically if missing
- An account with permissions to read the following Microsoft Graph scopes (delegated):
  - `DeviceManagementServiceConfig.Read.All`
  - `DeviceManagementConfiguration.Read.All`
  - `Policy.Read.All`
  - `Directory.Read.All`
  - `CloudPC.Read.All`
  - `Policy.ReadWrite.ConditionalAccess` (read-only usage)

> **Note:** The script uses *delegated* permissions and will prompt for interactive sign-in via `Connect-MgGraph`. No application registration is required.

## Installation

```powershell
# Clone the repository
git clone https://github.com/awillows/W365Link-Deployment-Readiness.git
cd W365Link-Deployment-Readiness
```

Or simply download `Test-W365LinkReadiness.ps1` directly.

## Usage

### Basic usage — check tenant and open the report

```powershell
.\Test-W365LinkReadiness.ps1 -OpenReport
```

### Check a specific user's licenses in addition to tenant settings

```powershell
.\Test-W365LinkReadiness.ps1 -UserUPN "user@contoso.com" -OpenReport
```

### Save the report to a custom path

```powershell
.\Test-W365LinkReadiness.ps1 -OutputPath "C:\Reports\W365Link-Report.html"
```

### Filter SSO check to specific provisioning policies

If your tenant has provisioning policies that aren't intended for Link devices, you can filter which policies are evaluated in the SSO readiness score:

```powershell
# Only evaluate these policies
.\Test-W365LinkReadiness.ps1 -IncludeProvisioningPolicies "Standard CPC","Frontline CPC" -OpenReport

# Evaluate all policies EXCEPT these
.\Test-W365LinkReadiness.ps1 -ExcludeProvisioningPolicies "Dev/Test Policy","Legacy BYOD" -OpenReport
```

> **Note:** `-IncludeProvisioningPolicies` and `-ExcludeProvisioningPolicies` are mutually exclusive — use one or the other.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-UserUPN` | String | No | A target user UPN to check individual license assignments against. |
| `-OutputPath` | String | No | File path for the HTML report. Defaults to `.\W365Link-ReadinessReport.html`. |
| `-OpenReport` | Switch | No | Opens the generated report in the default browser. |
| `-IncludeProvisioningPolicies` | String[] | No | Only evaluate SSO on these named provisioning policies. |
| `-ExcludeProvisioningPolicies` | String[] | No | Exclude these named provisioning policies from the SSO score. |

## Report Output

The generated HTML report includes:

- **Readiness score** — a percentage based on passed vs. failed/warning checks, displayed as a visual ring chart
- **Summary statistics** — pass, fail, warning, info, and error counts at a glance
- **Categorized findings** — each check grouped by category with color-coded status badges (PASS, FAIL, WARNING, INFO)
- **Risk levels** — Critical, High, Medium, or Low risk ratings on actionable findings
- **Remediation guidance** — specific steps to resolve each finding with links to official Microsoft documentation
- **Tenant context** — tenant ID, timestamp, and the account used to run the assessment

The report is a self-contained HTML file that can be shared with stakeholders, saved for your records, or used as part of your deployment documentation.

## Interactive Deployment Guide

The repository also includes an [interactive deployment guide](index.html) (`index.html`) — a standalone web page that walks through the Windows 365 Link deployment process step-by-step with expandable sections and visual guidance.

## Contributing

Contributions are welcome. If you encounter a check that produces inaccurate results or have ideas for additional prerequisite checks, please open an issue or submit a pull request.

## Disclaimer

This tool is provided as-is for informational purposes. It reads tenant configuration via Microsoft Graph using delegated permissions — it does **not** make any changes to your environment. Always validate findings against your organization's specific requirements and refer to [official Microsoft documentation](https://learn.microsoft.com/en-us/windows-365/link/) for the latest guidance.
