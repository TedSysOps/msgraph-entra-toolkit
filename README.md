# Entra ID User Lookup Toolkit
### Help Desk Edition — Read-Only

---

## What This Tool Does

This script lets you look up Microsoft 365 / Entra ID user accounts directly
from a PowerShell terminal. It connects to Microsoft Graph and gives you a
menu-driven interface to find users and view their account details, licenses,
group memberships, and sign-in history.

**It is read-only. It cannot make any changes to user accounts.**

> **Guest accounts are out of scope for this tool.** Contractors and external
> users who need system access are provisioned as standard member accounts
> without a mailbox — this tool will find them normally. If you cannot locate
> a user and suspect they may be a guest/external account, escalate the ticket
> — guest accounts are managed by a separate team.

---

## Before You Run It

### Step 1 — Set PowerShell Execution Policy

PowerShell blocks unsigned scripts by default. You only need to do this
once per session (or set it permanently for your user account).

Open PowerShell 7 and run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

Type `Y` and press Enter to confirm. The `-Scope CurrentUser` flag means
this change applies **only to your account** — it does not affect other
users or system-wide policy. If a colleague or security tool asks why you
ran this, that is the answer: user-scoped, your account only, required to
run help desk scripts that are not code-signed.

### Step 2 — Make Sure You Have PowerShell 7

This script requires PowerShell 7 or newer. To check your version:

```powershell
$PSVersionTable.PSVersion
```

If the major version shown is less than 7, open **PowerShell 7** (not
Windows PowerShell 5). They are separate apps.

### Step 3 — Make Sure the Microsoft.Graph Module Is Installed

Run this to check:

```powershell
Get-Module Microsoft.Graph.Users -ListAvailable
```

If nothing comes back, install it (requires internet access):

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

---

## How to Run the Script

Open PowerShell 7, navigate to the folder, and run:

```powershell
cd "C:\path\to\ps-scripts"
.\ps7-userlookup-msgraph.ps1
```

Or run it with a full path:

```powershell
& "C:\path\to\ps-scripts\ps7-userlookup-msgraph.ps1"
```

---

## Signing In to Microsoft Graph

When the script starts, it will show `[DISCONNECTED]` in the header if you
are not already signed in. Press **C** from the main menu to connect.

A browser window (or device code prompt) will open asking you to sign in.
**Sign in with your admin account** — this is the account that has the
required Graph permissions, not your standard user account.

> **Important:** PowerShell must be launched as your regular user account
> (not Run as Administrator). This ensures the MFA prompt appears in your
> active desktop session. You sign in to *Graph* with your admin credentials,
> but the PowerShell process itself runs under your user session.

The script only requests read-only permissions (`User.Read.All`, `AuditLog.Read.All`).

Once connected, the header will show `[CONNECTED]` and your account email.
Your sign-in token persists for the session — you should not need to
reconnect unless it expires or you quit and reopen the script.

---

## Main Menu Options

```
-- SEARCH --
  1) Search by Name (First / Last)
  2) Search by UPN
  3) Search by Mail / Primary SMTP
  4) Search by Username (mailNickname)

-- RECENT USERS --
  R1) ... (last users you looked up)
  R)  View all recent users

-- CONNECTION --
  C) Connect / Reconnect to Graph
  D) Disconnect from Graph

-- SETTINGS --
  T) Change Theme

Available themes: **1 Classic**, **2 Steel**, **3 Amber**, **4 Monochrome**, **5 Matrix**, **6 Midnight**

  Q) Quit
```

### Search Options Explained

| Option | Use When You Have... | Example Input |
|--------|----------------------|---------------|
| 1 - Name | First name, last name, or both | `John` / `Smith` |
| 2 - UPN | The full login name | `jsmith@corp.local` |
| 3 - Mail/SMTP | Their email address | `jsmith@company.com` |
| 4 - Username | Their short account name | `jsmith` |

If a search returns multiple results, you will see a numbered list. Enter
the number to open that user's details.

---

## Viewing User Details

When you open a user, the screen shows:

- **Identity** — UPN, mail, username, employee ID, object ID
- **Email Aliases** — all addresses on the account, with primary marked
- **Organization** — title, department, company, office
- **Contact** — work phone, mobile
- **Account Details** — enabled/disabled, sync status, password last changed,
  last sign-in, licenses assigned

At the bottom you will see action keys:

| Key | Action |
|-----|--------|
| C | Copy the summary to clipboard |
| L | View full license details |
| G | View AD-synced group memberships |
| S | View last 30 sign-in attempts |
| Enter | Go back to the main menu |

---

## Sign-In History

The sign-in history screen (option S from a user card) shows the last 30
sign-in attempts with:

- Success or failure status
- Timestamp
- Application used
- Location and IP address
- Device info (OS and browser)
- Failure reason (if failed)

> **Note:** This screen requires the `AuditLog.Read.All` permission. If you
> see an error when opening sign-in history, disconnect and reconnect
> (press **D** then **C**) to re-authenticate with the correct scopes.

The user card also shows a **Last SignIn** and **Last NonInt** timestamp
under Account Details. These are two different things:

- **Last SignIn** — the most recent interactive login: a browser sign-in,
  app login, or anything the user actively initiated.
- **Last NonInt** — the most recent non-interactive sign-in: a background
  token refresh from an app like Outlook or Teams running silently. This
  updates frequently even when the user has not "logged in" recently.

This matters in practice: if a user says "I haven't logged in for weeks"
but their non-interactive timestamp is current, their apps are still active
and the account is in use. If both timestamps are old or N/A, the account
may be genuinely inactive.

Press **C** on the sign-in history screen to copy the history to clipboard.

---

## Group Memberships

The group screen (option G) shows only **AD-synced security groups**. Cloud-
only groups and Teams are excluded by design — this is intentional so the
list reflects on-premises access relevant to help desk work.

The groups displayed are Active Directory security groups synced from
on-premises. These groups control access to on-prem resources such as file
shares, printers, and local applications, as well as cloud services and
Microsoft 365 license assignments in our hybrid environment. Help desk staff
can manage access and verify membership directly through AD.

Groups that exist only in the cloud — including SharePoint Online
permissions, Teams membership, and cloud app assignments — are not shown
here. For cloud-only group membership, use the M365 Admin Portal or
escalate as needed.

Each group shows its type (Security, Distribution List, or M365 Group) and
the SAM account name where available.

---

## License Details

The license screen (option L) shows each assigned license with its friendly
name (e.g. "Microsoft 365 G5") and a breakdown of which service plans are
enabled, disabled, or pending. The script downloads a name mapping file from
Microsoft on first use and caches it locally for 72 hours.

---

## Persistent State

The script saves your theme preference and recently viewed users between
sessions. This data is stored at:

```
$env:USERPROFILE\UserLookupTool\state.json    (PowerShell)
%USERPROFILE%\UserLookupTool\state.json       (File Explorer / cmd)
```

Logs are stored at:

```
$env:USERPROFILE\UserLookupTool\logs\         (PowerShell)
%USERPROFILE%\UserLookupTool\logs\            (File Explorer / cmd)
```

The folder is created on first run and locked to your user account only —
other local users on a shared workstation cannot read your logs or state.

Logs rotate automatically — they cap at 10 MB each and the folder keeps
the 30 most recent log files.

---

## Troubleshooting

### "The script cannot be loaded because running scripts is disabled"

You need to set the execution policy. Run this in PowerShell 7:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

---

### "Connect-MgGraph is not recognized" or module errors

The Microsoft.Graph module is not installed. Run:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

If you get a permission error, add `-Force` or contact your IT admin to
install it for you.

---

### Sign-in prompt doesn't appear / browser doesn't open

- Make sure PowerShell is running as your **regular user account**, not as
  Administrator. The MFA prompt will only appear in your active desktop
  session — running as a different user (e.g. via runas) will break this.
- Try disconnecting and reconnecting: press **D** then **C** from the menu.
- If no browser window opens, PowerShell may prompt you to visit
  `https://microsoft.com/devicelogin` and enter a code. Follow those
  instructions.
- Make sure you are not blocking pop-ups or have a default browser set.

---

### Token expires / searches fail after leaving the script idle

Graph authentication tokens expire. If you leave the script open for an
extended period and searches start erroring, press **D** then **C** to
disconnect and reconnect.

---

### Idle timeout and auto-disconnect

The script automatically disconnects and exits after **15 minutes of no
input** at the main menu. Before exiting it displays a live countdown
warning — press any key within **60 seconds** to stay in the session.
If the countdown reaches zero, the script disconnects from Graph, saves
state, and closes. Your recent users and theme preference are preserved.

---

### "Insufficient privileges" or permission errors when searching

Your account may not have the `User.Read.All` scope. This is a Graph API
permission — contact whoever manages your tenant's app consent policies.
You may need an admin to grant consent.

---

### Search returns no results when the user should exist

Try a different search method. For example:
- Name search may fail if the display name is formatted differently than
  expected. Try their username (option 4) or UPN (option 2) instead.
- If you search by email and get nothing, try searching by username — some
  accounts have a different primary mail than their UPN.
- Guest/external accounts are not returned by this tool. If you suspect the
  user is a guest, escalate — guest accounts are managed separately.

---

### Sign-in history screen errors

The sign-in history screen requires the `AuditLog.Read.All` permission. If
you get an error on that screen, press **D** then **C** to disconnect and
reconnect — the script will request the correct scopes on reconnect.

---

### Last SignIn shows N/A for an account that has clearly been used

Two possible causes. First, the account may have been created before
sign-in activity logging was enabled in the tenant — there is no historical
data to show. Second, the session token may be missing the `AuditLog.Read.All`
scope. Try disconnecting and reconnecting (D then C). If the user card still
shows N/A but sign-in history (option S) shows records, escalate for a scope
review — the summary field and the detail log pull from different API endpoints.

---

### Sign-in history shows no records for a recent user

Entra sign-in logs are retained for 30 days on most license tiers (7 days
on some). If the user has not signed in recently or logs have aged out, the
screen will say no records were found. This is normal.

---

### License names show as a GUID instead of a friendly name

The script downloads a license name mapping CSV from Microsoft. If your
machine had no internet access when you first ran it, the download failed
and GUIDs are used as a fallback. Once you have internet access, the file
will download automatically on the next run (or when the 72-hour cache
expires).

---

### Recent users list shows an error when reloading a user

If a user account was deleted or moved after you last looked them up, the
stored object ID will no longer be valid. The error is expected in that case.
Do a fresh search instead.

---

### The script crashes with a red [FATAL] error on startup

Check the log file at `%USERPROFILE%\UserLookupTool\logs\` for the error
message. Common causes:
- PowerShell version below 7 (run `$PSVersionTable.PSVersion` to check)
- A required Graph module is missing or corrupted
- `state.json` is corrupted — you can delete it and the script will recreate
  it fresh with default settings

---

## Quick Reference Card

| Task | Steps |
|------|-------|
| Run the script | Open PS7, set execution policy, run the .ps1 file |
| Sign in | Press C from main menu, sign in via browser |
| Look up a user by email | Press 3, enter their email address |
| Look up a user by name | Press 1, enter first/last name |
| Check if account is enabled | Account status shown on user card header |
| Check last sign-in | Shown on user card under Account Details |
| Check licenses | Open user card, press L |
| Check group memberships | Open user card, press G |
| See failed sign-in attempts | Open user card, press S |
| Copy sign-in history to clipboard | Open user card, press S, then press C |
| Copy info to paste into a ticket | Press C on any screen that offers it |
| Change the color theme | Press T from main menu |
| Exit the script | Press Q |
| Keep session alive (idle warning) | Press any key when countdown appears |

---

*Script: ps7-userlookup-msgraph.ps1*
*Requires: PowerShell 7+, Microsoft.Graph module, User.Read.All + AuditLog.Read.All permissions*
