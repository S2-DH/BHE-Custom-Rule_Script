[README.md](https://github.com/user-attachments/files/27760602/README.md)
# BHE Selector / Rule Manager
### `Manage-BHE-Selectors.ps1`

A PowerShell script to audit, disable, enable and delete BHE Asset Group Tag Selectors (rules) via the BHE API.

---

## Pre-requisites

- PowerShell 5.1+
- BHE API token (Administrator role)
- A `.env` file in the same folder as the script:

```
BHE_API_ID=<your-token-id>
BHE_API_KEY=<your-token-key>
BHE_URL=http://<your-bhe-instance>:8080
```

> Generate a token in BHE: **Settings > Manage API Tokens**

---

## Parameters

| Parameter | Description |
|---|---|
| `-Audit` | Read-only mode — exports 5 CSV files, no changes made |
| `-Audit -NoFilter` | Same as `-Audit` but all custom rules go into CSV 4 regardless of name |
| `-DeleteFromCsv "path"` | Deletes rows marked `YES` in the specified CSV |
| `-DisableFromCsv "path"` | Disables rows marked `YES` in the specified CSV |
| `-EnableFromCsv "path"` | Re-enables rows marked `YES` in the specified CSV |
| `-EnvFile "path"` | Override the default `.env` file location |
| `-BHEUrl` | Override BHE URL (instead of `.env`) |
| `-TokenID` | Override API Token ID (instead of `.env`) |
| `-TokenKey` | Override API Token Key (instead of `.env`) |

---

## Step 1 — Audit

Run the script in audit mode. This is **read-only** — no changes are made.

```powershell
.\Manage-BHE-Selectors.ps1 -Audit
```

The script connects to BHE, pulls all selectors across all asset group tags, and exports 5 CSV files to the script folder.

> **Screenshot: Script folder showing the 5 CSV files**
> `<img width="469" height="263" alt="image" src="https://github.com/user-attachments/assets/9297a334-1d06-4afa-b142-9c1957eb6f3a" />`

> **Screenshot: Script output showing CSV file contents summary**
> `<img width="878" height="168" alt="image" src="https://github.com/user-attachments/assets/531e3a4b-c779-4e1c-b643-a2e271a49d76" />`

---

## The 5 CSV Files

| File | Contents | Action |
|---|---|---|
| `BHE_Audit_1a_KEEP_Custom_Underscore` | Custom rules with `_` prefix | Keep |
| `BHE_Audit_1b_KEEP_Connector_Rules` | Connector rules (Jamf / Okta / GitHub / Entra) | Keep |
| `BHE_Audit_2_KEEP_System_Default` | BHE default rules (`IsDefault = TRUE`) | Keep — never delete |
| `BHE_Audit_3_REVIEW_NonTierZero_Tags` | Rules in non-Tier-Zero tags (Owned, Tier 1 etc.) | Review separately |
| `BHE_Audit_4_DELETE_Candidates` | Tier Zero custom rules — no `_` prefix, not a connector | **Review and action** |

> **Screenshot: All rules listed in the audit output**
> `<img width="4282" height="1130" alt="image" src="https://github.com/user-attachments/assets/f193951a-dbcf-4cbe-a224-8c8d32c6fe70" />`

---

## Step 2 — Review CSV 4

Open `BHE_Audit_4_DELETE_Candidates_<timestamp>.csv` in Excel.

- The `Delete` column is **blank by default**
- Add `YES` on every row you want deleted
- Leave blank to skip that rule
- If a rule in CSV 4 should be kept — either remove the row or leave `Delete` blank
- Save the file as CSV when done

> **Screenshot: CSV 4 with Delete column marked YES**
> `<img width="847" height="217" alt="image" src="https://github.com/user-attachments/assets/7f4dcc4f-06e4-4e30-a9ac-b9fba7f6b718" />`

---

## Step 3 — Delete Rules

Point the script at your completed CSV 4:

```powershell
.\Manage-BHE-Selectors.ps1 -DeleteFromCsv ".\BHE_Audit_4_DELETE_Candidates_<timestamp>.csv"
```

The deletion runs in **3 steps**:

**Step 1 — Review the deletion list**

> **Screenshot: Deletion Candidate List**
> `[INSERT SCREENSHOT - DELETION CANDIDATE LIST]`

The script displays every rule marked `YES` with its Tag ID and Selector ID.
Type `CONFIRMED` to proceed.

**Step 2 — Single rule test**

> **Screenshot: Single rule test deletion**
> `<img width="434" height="165" alt="image" src="https://github.com/user-attachments/assets/839ca6d7-e078-42b0-b3bf-9a7378e2ae10" />`

The script deletes the **first rule only** as a test. Verify in the BHE UI that the rule is gone, then type `YES` to proceed to the full run.

**Step 3 — Full deletion**

The script deletes all remaining rules, reporting `[+] Deleted` or `[!] Failed` per rule, with a summary at the end.

---

## After Deletion — Run Analysis

Objects in deleted rules retain their Tier Zero tag until BHE analysis recalculates membership.

**Via BHE UI:** Settings → Analysis → Run Analysis

**Via API:**
```powershell
$t = "$url/api/v2/analysis"
Invoke-RestMethod -Uri $t -Method PUT -Headers (Sign "PUT" $t)
```

**Check analysis status:**
Wait until `status = idle` 

---

## Disable / Enable Rules (Alternative to Deletion)

Disabling is reversible — rules can be re-enabled without a restore.

**Disable rules** (same CSV workflow as deletion):
```powershell
.\Manage-BHE-Selectors.ps1 -DisableFromCsv ".\BHE_Audit_4_DELETE_Candidates_<timestamp>.csv"
```

**Re-enable rules:**
```powershell
.\Manage-BHE-Selectors.ps1 -EnableFromCsv ".\BHE_Audit_4_DELETE_Candidates_<timestamp>.csv"
```

Both use the same CSV file with `YES` in the `Delete` column. Run analysis after either action for changes to take effect.

---

## Generic Use — No Naming Pattern

If there is no distinguishing naming pattern to filter on, run the audit with `-NoFilter`:

```powershell
.\Manage-BHE-Selectors.ps1 -Audit -NoFilter
```

This puts **all** custom non-default rules into CSV 4 for manual review. Open in Excel, mark `YES` on the rules to delete, and run the deletion script as normal.

---

## Interactive Mode

Running the script without parameters launches an interactive selector browser — displays all rules colour-coded and lets you select rules to delete by number, range or name pattern:

```powershell
.\Manage-BHE-Selectors.ps1
```

| Colour | Meaning |
|---|---|
| 🔴 Red | Matches `SDH-2B-DELETED` pattern |
| 🟢 Green | Matches `_SDH-KEEP` pattern |
| ⚫ Gray | Default / system rule (protected) |
| ⚪ White | Other custom rule |

Selection options at the prompt:

| Input | Action |
|---|---|
| `5` | Select single rule by index |
| `1,3,7` | Select multiple by index |
| `1-15` | Select a range |
| `pattern:TEXT` | Select all matching a name pattern |
| `tag:Tier Zero` | Select all custom rules in a tag |
| `list` | Redisplay all rules |
| `done` | Proceed to deletion |
| `quit` | Exit without deleting |
