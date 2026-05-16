[BHE-Rule-Cleanup-README.md](https://github.com/user-attachments/files/27851507/BHE-Rule-Cleanup-README.md)
# Manage-BHE-Selectors.ps1

**BHE Asset Group Tag Rule Manager — Bulk Cleanup Tool**  
TAM Team | May 2026

---

## What it does

Connects to a BloodHound Enterprise tenant via the API and manages Asset Group Tag Rules (previously called Selectors). Designed for large-scale cleanup operations — typically removing hundreds of legacy rules — through a safe, audit-first, CSV-driven workflow.

The delete operation is permanent and irreversible, so the script is structured to make it impossible to accidentally skip the review and confirmation steps.

---

## Prerequisites

- PowerShell 5.1 or later
- A `.env` file in the same folder as the script (see below)
- API token with Asset Isolation **write** access in BHE

### `.env` format

```
BHE_API_ID="your-token-id-here"
BHE_API_KEY="your-token-key-here"
BHE_URL="https://your-tenant.bloodhoundenterprise.io"
```

Pass a custom path with `-EnvFile "C:\creds\bhe.env"` if needed.

---

## Modes

| Parameter | What it does |
|---|---|
| `-Audit` | Fetches all rules, exports five categorised CSVs, no changes made |
| `-Audit -NoFilter` | Same but includes all custom rules in CSV 4 regardless of naming |
| `-DisableFromCsv "<path>"` | Disables rules marked `Confirm=YES` in the CSV — reversible |
| `-EnableFromCsv "<path>"` | Re-enables rules marked `Confirm=YES` — run BHE analysis after |
| `-DeleteFromCsv "<path>"` | Permanently deletes rules marked `Confirm=YES` |
| *(no params)* | Interactive mode — displays all rules, select and delete ad-hoc |

---

## Recommended workflow

### 1. Run the audit

```powershell
.\Manage-BHE-Selectors.ps1 -Audit



```
<img width="964" height="694" alt="1 - Audit Results" src="https://github.com/user-attachments/assets/fc91d21b-8d64-489b-b99b-a385b8f41b99" />


Generates five CSV files in the script directory:

| File | Contents | Action |
|---|---|---|
| `BHE_Audit_1a_KEEP_Custom_Underscore` | Rules with `_` prefix (Tier Zero) | Leave alone |
| `BHE_Audit_1b_KEEP_Connector_Rules` | Jamf / Okta / GitHub / Entra rules | Leave alone |
| `BHE_Audit_2_KEEP_System_Default` | Built-in BloodHound system rules | Leave alone |
| `BHE_Audit_3_REVIEW_NonTierZero_Tags` | Rules on non-Tier-Zero tags | Review separately |
| `BHE_Audit_4_ACTION_REQUIRED` | Tier Zero custom rules — candidates for action | **Work from this one** |

<img width="820" height="366" alt="2 - Folder csv View" src="https://github.com/user-attachments/assets/ffde768a-278e-48bc-a7aa-8ab00aac36d0" />


### 2. Review CSV 4

Open `BHE_Audit_4_ACTION_REQUIRED_*.csv` in Excel.

<img width="1685" height="402" alt="4 - CSV4 - Important YES Column" src="https://github.com/user-attachments/assets/33b555e4-6ad5-486f-890c-28e9ce410742" />


- Review each row — the `Seeds` column shows what each rule targets (Object ID or Cypher query)
- Type `YES` in the **Confirm** column for any rule you want to action
- Leave blank to skip
- Save the file

> The same `Confirm=YES` column drives all three operations (disable, enable, delete).
> The action depends on which parameter you use in the command — not on separate columns.

### 3. Disable first (recommended)

```powershell
.\Manage-BHE-Selectors.ps1 -DisableFromCsv ".\BHE_Audit_4_ACTION_REQUIRED_20260516_070537.csv"
```

Disabling is reversible. Objects lose Tier Zero status after the next BHE analysis, letting you verify impact before committing to deletion. To undo:

```powershell
.\Manage-BHE-Selectors.ps1 -EnableFromCsv ".\BHE_Audit_4_ACTION_REQUIRED_20260516_070537.csv"
```

### 4. Delete

```powershell
.\Manage-BHE-Selectors.ps1 -DeleteFromCsv ".\BHE_Audit_4_ACTION_REQUIRED_20260516_070537.csv"
```

The delete mode has three confirmation checkpoints:

1. **Review** — displays all `Confirm=YES` rows, type `CONFIRMED` to continue

<img width="1685" height="497" alt="5 - Delete List" src="https://github.com/user-attachments/assets/70691181-be13-4f31-aed3-f4615a4db0c2" />

2. **Test** — deletes a single rule, prompts you to verify it's gone in the BHE UI before proceeding

<img width="596" height="208" alt="6 - Test Single Rule" src="https://github.com/user-attachments/assets/879db1be-c86e-486b-bc7c-34df55bd8334" />

**IMPORTANT: **Check BHE (Run Analysis / Check Rule was deleted and any Objects are no longer tagged as Tier Zero !)

<img width="559" height="579" alt="7 - Single Test Rule Deleted BHE UI" src="https://github.com/user-attachments/assets/8f57d908-0f6f-447a-9631-924b1150773b" />

3. **Full run** — type `YES` to process all remaining rows

<img width="518" height="417" alt="8 - Delete Remaining Rules" src="https://github.com/user-attachments/assets/2e178c29-799d-42b7-84f7-b1e517a36afe" />

**NOTE: **Failures are reported at the end — a single failure does not abort the batch.

4. BHE will require analysis to be run.

5. Review Rules in BHE to confirm they have all been deleted / disabled or Enabled (Depending on your use case / Method actioned)

<img width="688" height="512" alt="9 - ALL Rules Deleted" src="https://github.com/user-attachments/assets/24c26a5a-3204-4d1c-afd8-00e5192b2bde" />






---

## Authentication

Uses the standard BHE three-step chained HMAC-SHA256 signing pattern. The same auth logic is used across all BHE API tooling in this repo (`bhe-api.sh`, `BHE-API-Console.ps1`).

Each request signs `METHOD + ENDPOINT`, then the DateKey, then the request body — matching the BHE API signature spec exactly.

---

## CSV 4 filtering logic

By default, rules land in `BHE_Audit_4_ACTION_REQUIRED` if they are:
- On Tag ID 1 (Tier Zero)
- Not a default/system rule (`IsDefault = false`)
- Name does not start with `_`
- Name does not start with `Jamf:`, `Okta:`, `GitHub:`, `Entra `
- Name is not `OKTAT1` or match `ADMIN@...`

Use `-NoFilter` to bypass this and include everything for manual review.

---

## Error reference

| HTTP Code | Meaning | Action |
|---|---|---|
| 403 | Token lacks write permissions | Check API token role in BHE admin |
| 404 | Rule already deleted | Safe to ignore |
| 429 | Rate limiting | Re-run — already-processed rules won't reappear |
| Connection error | Network / VPN issue | Check connectivity to BHE tenant |

---

## Files in this folder

```
Manage-BHE-Selectors.ps1          Main script
.env                               Credentials (not committed to source control)
BHE_Audit_1a_KEEP_*               Generated by -Audit
BHE_Audit_1b_KEEP_*               Generated by -Audit
BHE_Audit_2_KEEP_*                Generated by -Audit
BHE_Audit_3_REVIEW_*              Generated by -Audit
BHE_Audit_4_ACTION_REQUIRED_*     Generated by -Audit — working file for actions
```

---

## Notes

- Never commit `.env` or CSV files containing rule data to source control
- CSV 3 (Non-Tier-Zero tags) should always be reviewed separately — do not action it without understanding what's in it
- When running against a customer environment, use a separate `.env` file and always run `-Audit` first — naming conventions will differ from the lab
- The `_` prefix and connector prefix filtering is tuned for the SDH lab environment
