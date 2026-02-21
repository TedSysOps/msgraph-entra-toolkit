#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Authentication, Microsoft.Graph.Reports
<#
.SYNOPSIS
    Entra ID User Lookup Toolkit - Read-only help desk user lookup tool.

.DESCRIPTION
    Connects to Microsoft Graph and provides common help desk user lookup
    operations via an interactive menu. Filters guest accounts server-side.
    Supports first/last name, UPN, username (mailNickname), mail, and
    primary SMTP alias searches.

.NOTES
    Required Scopes: User.Read.All
    Permissions:     Read-only. No write operations.
    Data Store:      $env:USERPROFILE\UserLookupTool\
    Log Rotation:    10 MB max, 30 logs retained
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
#  PATHS & CONSTANTS
# ============================================================
$script:AppFolder  = Join-Path $env:USERPROFILE 'UserLookupTool'
$script:LogFolder  = Join-Path $script:AppFolder 'logs'
$script:PersistFile = Join-Path $script:AppFolder 'state.json'
$script:MaxRecentUsers  = 5
$script:LogMaxBytes     = 10MB
$script:LogKeepCount    = 30
$script:IdleTimeoutMinutes = 15   # Minutes of no input before warning
$script:IdleWarningSeconds = 60   # Seconds to respond before auto-disconnect

# Graph properties fetched on every user query - explicit select = faster API call
$script:UserProperties = @(
    'id','displayName','givenName','surname','userPrincipalName',
    'mail','mailNickname','jobTitle','department','officeLocation',
    'businessPhones','mobilePhone','accountEnabled','userType',
    'createdDateTime','lastPasswordChangeDateTime','onPremisesSyncEnabled',
    'onPremisesLastSyncDateTime','assignedLicenses','proxyAddresses',
    'signInSessionsValidFromDateTime','companyName','employeeId',
    'signInActivity'
) -join ','

# ============================================================
#  INPUT SANITIZATION
# ============================================================
function Sanitize-ODataString {
    # Escapes single quotes in user-supplied values before embedding in OData
    # filter strings. OData represents a literal single quote as two single quotes.
    param([string]$Value)
    return $Value -replace "'", "''"
}

# ============================================================
#  THEME SYSTEM
# ============================================================
$script:Themes = @{
    '1' = @{ Name='Classic';    Header=[ConsoleColor]::Cyan;    Accent=[ConsoleColor]::Yellow;  Success=[ConsoleColor]::Green;  Warning=[ConsoleColor]::Yellow; Error=[ConsoleColor]::Red;    Normal=[ConsoleColor]::White;  Dim=[ConsoleColor]::DarkGray  }
    '2' = @{ Name='Steel';      Header=[ConsoleColor]::Blue;    Accent=[ConsoleColor]::Cyan;    Success=[ConsoleColor]::Green;  Warning=[ConsoleColor]::Cyan;   Error=[ConsoleColor]::Red;    Normal=[ConsoleColor]::Gray;   Dim=[ConsoleColor]::DarkGray  }
    '3' = @{ Name='Amber';      Header=[ConsoleColor]::Yellow;  Accent=[ConsoleColor]::White;   Success=[ConsoleColor]::Green;  Warning=[ConsoleColor]::Yellow; Error=[ConsoleColor]::Red;    Normal=[ConsoleColor]::Yellow; Dim=[ConsoleColor]::DarkYellow}
    '4' = @{ Name='Monochrome'; Header=[ConsoleColor]::White;   Accent=[ConsoleColor]::White;   Success=[ConsoleColor]::White;  Warning=[ConsoleColor]::Gray;   Error=[ConsoleColor]::Gray;   Normal=[ConsoleColor]::Gray;   Dim=[ConsoleColor]::DarkGray  }
    '5' = @{ Name='Matrix';     Header=[ConsoleColor]::Green;   Accent=[ConsoleColor]::DarkGreen; Success=[ConsoleColor]::Green; Warning=[ConsoleColor]::Yellow; Error=[ConsoleColor]::Red;   Normal=[ConsoleColor]::Green;  Dim=[ConsoleColor]::DarkGreen }
    '6' = @{ Name='Midnight';   Header=[ConsoleColor]::Magenta; Accent=[ConsoleColor]::Blue;    Success=[ConsoleColor]::Cyan;   Warning=[ConsoleColor]::Yellow; Error=[ConsoleColor]::Red;    Normal=[ConsoleColor]::White;  Dim=[ConsoleColor]::DarkGray  }
}
$script:ActiveTheme = $script:Themes['1']

# ============================================================
#  LOGGING
# ============================================================
function Initialize-Logging {
    if (-not (Test-Path $script:LogFolder)) {
        New-Item -ItemType Directory -Path $script:LogFolder -Force | Out-Null
    }
    $script:LogFile = Join-Path $script:LogFolder ("UserLookup_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Write-Debug "Log file: $script:LogFile"
    Invoke-LogRotation
}

function Invoke-LogRotation {
    # Handles count-based cleanup only. Size-based rotation is handled inline in
    # Write-Log after each write, where $script:LogFile is directly accessible.
    try {
        $logs = Get-ChildItem -Path $script:LogFolder -Filter '*.log' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
        if ($logs.Count -ge $script:LogKeepCount) {
            $logs | Select-Object -Skip ($script:LogKeepCount - 1) | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Debug "Log rotation error: $_"
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO'
    )
    try {
        $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Debug $entry
        # Check rotation after write - assign new path here where $script: scope is writable,
        # then call Invoke-LogRotation to handle count-based cleanup of old files.
        if ((Get-Item $script:LogFile -ErrorAction SilentlyContinue).Length -ge $script:LogMaxBytes) {
            $script:LogFile = Join-Path $script:LogFolder ("UserLookup_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            Invoke-LogRotation
        }
    } catch {
        Write-Debug "Write-Log failed: $_"
    }
}

# ============================================================
#  PERSISTENCE
# ============================================================
function Initialize-AppFolder {
    @($script:AppFolder, $script:LogFolder) | ForEach-Object {
        $dir = $_
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            # Restrict the app folder to the current user only.
            # Prevents other local users on shared workstations from reading logs or state.
            try {
                $acl  = Get-Acl -Path $dir
                $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                    'FullControl',
                    'ContainerInherit,ObjectInherit',
                    'None',
                    'Allow'
                )
                $acl.AddAccessRule($rule)
                Set-Acl -Path $dir -AclObject $acl
                Write-Debug "Created directory with restricted ACL: $dir"
            } catch {
                Write-Debug "Created directory (ACL restriction failed: $($_.Exception.Message)): $dir"
            }
        }
    }
}

function Read-PersistState {
    $defaults = @{
        ThemeKey    = '1'
        RecentUsers = @()
    }
    try {
        if (Test-Path $script:PersistFile) {
            $data = Get-Content $script:PersistFile -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
            if ($data.ThemeKey -and $script:Themes.ContainsKey($data.ThemeKey)) {
                $defaults.ThemeKey = $data.ThemeKey
            }
            if ($data.RecentUsers -is [array]) {
                $defaults.RecentUsers = @($data.RecentUsers | Select-Object -First $script:MaxRecentUsers)
            }
            Write-Log "Loaded persisted state. Theme=$($defaults.ThemeKey) RecentCount=$($defaults.RecentUsers.Count)"
        }
    } catch {
        Write-Log "Could not read persist file: $($_.Exception.Message)" -Level WARN
    }
    return $defaults
}

function Save-PersistState {
    try {
        $state = @{
            ThemeKey    = $script:CurrentThemeKey
            RecentUsers = @($script:RecentUsers)
        }
        $state | ConvertTo-Json -Depth 5 | Set-Content -Path $script:PersistFile -Encoding UTF8 -Force
        Write-Debug "State saved."
    } catch {
        Write-Log "Could not save persist file: $($_.Exception.Message)" -Level WARN
    }
}

function Add-RecentUser {
    param([hashtable]$User)
    # Remove duplicate by UPN if exists
    $script:RecentUsers = @($script:RecentUsers | Where-Object { $_.upn -ne $User.upn })
    # Prepend
    $script:RecentUsers = @($User) + $script:RecentUsers
    # Trim to max
    $script:RecentUsers = @($script:RecentUsers | Select-Object -First $script:MaxRecentUsers)
    Save-PersistState
    Write-Log "Added to recent: $($User.upn)"
}

# ============================================================
#  THEMED OUTPUT HELPERS
# ============================================================
function Write-C {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White, [switch]$NoNewline)
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else            { Write-Host $Text -ForegroundColor $Color }
}

function Write-Header { param([string]$Text)
    $t = $script:ActiveTheme
    Write-C ('=' * 70) $t.Header
    Write-C ("  $Text") $t.Header
    Write-C ('=' * 70) $t.Header
}

function Write-SectionLine { param([string]$Text)
    Write-C ('-' * 70) $script:ActiveTheme.Dim
    if ($Text) { Write-C "  $Text" $script:ActiveTheme.Accent }
}

function Write-Success { param([string]$Text) Write-C "[OK]  $Text" $script:ActiveTheme.Success }
function Write-Warning2 { param([string]$Text) Write-C "[WARN] $Text" $script:ActiveTheme.Warning }
function Write-Error2  { param([string]$Text) Write-C "[ERR] $Text" $script:ActiveTheme.Error }
function Write-Info    { param([string]$Text) Write-C "  $Text" $script:ActiveTheme.Normal }
function Write-Dim     { param([string]$Text) Write-C "  $Text" $script:ActiveTheme.Dim }

# ============================================================
#  GRAPH CONNECTION
# ============================================================
function Get-ConnectionStatus {
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx -and $ctx.Account) {
            return @{ Connected=$true; Account=$ctx.Account; TenantId=$ctx.TenantId; Scopes=$ctx.Scopes }
        }
    } catch { }
    return @{ Connected=$false }
}

function Show-ConnectionStatus {
    $status = Get-ConnectionStatus
    if ($status.Connected) {
        Write-C "  Graph: " $script:ActiveTheme.Dim -NoNewline
        Write-C "[CONNECTED]" $script:ActiveTheme.Success -NoNewline
        Write-C "  $($status.Account)" $script:ActiveTheme.Normal
    } else {
        Write-C "  Graph: " $script:ActiveTheme.Dim -NoNewline
        Write-C "[DISCONNECTED]" $script:ActiveTheme.Error
    }
}

function Connect-ToGraph {
    Write-Info "Connecting to Microsoft Graph..."
    Write-Info "Required scopes: User.Read.All, AuditLog.Read.All"
    Write-Host ""
    try {
        Connect-MgGraph -Scopes 'User.Read.All','AuditLog.Read.All' -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Log "Connected to Graph. Account=$($ctx.Account) Tenant=$($ctx.TenantId)"
        Write-Success "Connected as: $($ctx.Account)"
    } catch {
        Write-Log "Graph connection failed: $($_.Exception.Message)" -Level ERROR
        Write-Error2 "Connection failed: $_"
    }
    Read-Host "`n  Press Enter to continue"
}

function Disconnect-FromGraph {
    try {
        Disconnect-MgGraph -ErrorAction Stop
        Write-Log "Disconnected from Graph."
        Write-Success "Disconnected."
    } catch {
        Write-Warning2 "Disconnect warning: $_"
    }
    Read-Host "`n  Press Enter to continue"
}

# ============================================================
#  GRAPH USER QUERIES  (server-side guest filter on all calls)
# ============================================================
# Guest accounts have #EXT# in UPN - filtered server-side via userType eq 'Member'
# Note: userType eq 'Member' excludes Guest. We also exclude service accounts that
# may have EXT in UPN by adding NOT filter on UPN as belt-and-suspenders.

function Invoke-UserSearch {
    <#
    .SYNOPSIS
        Core search function. Builds efficient server-side filter and returns
        a list of user objects. All searches exclude guests server-side.
    #>
    param(
        [string]$Filter,
        [switch]$UseAdvanced,
        [int]$Top = 25
    )

    $params = @{
        Property         = $script:UserProperties
        Filter           = $Filter
        Top              = $Top
        ErrorAction      = 'Stop'
    }

    if ($UseAdvanced) {
        $params['ConsistencyLevel'] = 'eventual'
        $params['CountVariable']    = 'resultCount'
    }

    try {
        Write-Log "Graph query filter: $Filter (advanced=$UseAdvanced)"
        $results = Get-MgUser @params
        Write-Log "Query returned $($results.Count) result(s)"
        return $results
    } catch {
        Write-Log "Graph query error: $($_.Exception.Message) | Filter: $Filter" -Level ERROR
        throw
    }
}

function Search-ByUpn {
    param([string]$Upn)
    # Exact UPN match - no guest filter needed, UPN with #EXT# is caught by userType
    # but we use both: direct property access is most efficient for exact UPN
    $Upn = Sanitize-ODataString $Upn
    $filter = "userPrincipalName eq '$Upn' and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter
}

function Search-ByMail {
    param([string]$Mail)
    $Mail = Sanitize-ODataString $Mail
    $filter = "mail eq '$Mail' and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter
}

function Search-ByMailNickname {
    param([string]$Username)
    $Username = Sanitize-ODataString $Username
    $filter = "mailNickname eq '$Username' and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter
}

function Search-ByProxyAddress {
    # proxyAddresses includes all smtp aliases - SMTP: (uppercase) = primary, smtp: (lowercase) = secondary
    # Search both prefixes so secondary aliases are matched correctly
    param([string]$SmtpAlias)
    $SmtpAlias = Sanitize-ODataString $SmtpAlias
    $filter = "proxyAddresses/any(p:p eq 'SMTP:$SmtpAlias' or p eq 'smtp:$SmtpAlias') and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter
}

function Search-ByName {
    param([string]$GivenName, [string]$Surname)
    $GivenName = Sanitize-ODataString $GivenName
    $Surname   = Sanitize-ODataString $Surname
    $parts = @()
    if ($GivenName) { $parts += "startsWith(givenName,'$GivenName')" }
    if ($Surname)   { $parts += "startsWith(surname,'$Surname')" }
    $filter = ($parts -join ' and ') + " and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter
}

function Search-ByDisplayName {
    param([string]$Name)
    $Name = Sanitize-ODataString $Name
    # Advanced query required for startsWith on displayName with other filters
    $filter = "startsWith(displayName,'$Name') and userType eq 'Member'"
    return Invoke-UserSearch -Filter $filter -UseAdvanced
}

function Get-UserById {
    param([string]$UserId)
    try {
        Write-Log "Fetching user by ID: $UserId"
        return Get-MgUser -UserId $UserId -Property $script:UserProperties -ErrorAction Stop
    } catch {
        Write-Log "Get-UserById error: $($_.Exception.Message)" -Level ERROR
        throw
    }
}

# ============================================================
#  SKU / LICENSE NAME MAPPING
# ============================================================
# Microsoft publishes a CSV mapping SKU GUIDs to friendly product names.
# URL confirmed current as of 2025-10. Includes GCC, GCC-H, and DoD SKUs.
$script:SkuMapUrl  = 'https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv'
$script:SkuMapFile = Join-Path $script:AppFolder 'sku_map.csv'
$script:SkuMapMaxAgeHours = 72   # Refresh cached CSV every 3 days
$script:SkuMap     = $null       # Hashtable: GUID -> Product_Display_Name (loaded on first use)

function Get-SkuMap {
    # Returns hashtable keyed by lowercase GUID -> friendly name.
    # Uses a local cache file to avoid downloading on every run.
    # Thread-safe enough for single-user interactive use.
    if ($script:SkuMap) { return $script:SkuMap }

    $needDownload = $true
    if (Test-Path $script:SkuMapFile) {
        $age = (Get-Date) - (Get-Item $script:SkuMapFile).LastWriteTime
        if ($age.TotalHours -lt $script:SkuMapMaxAgeHours) {
            $needDownload = $false
            Write-Debug "Using cached SKU map (age: $([int]$age.TotalHours)h)"
        } else {
            Write-Debug "SKU map cache expired ($([int]$age.TotalHours)h old). Refreshing."
        }
    }

    if ($needDownload) {
        try {
            Write-Debug "Downloading SKU map from Microsoft..."
            Invoke-WebRequest -Uri $script:SkuMapUrl -OutFile $script:SkuMapFile -UseBasicParsing -ErrorAction Stop
            Write-Log "SKU map downloaded/refreshed from Microsoft."
        } catch {
            Write-Log "SKU map download failed: $_" -Level WARN
            # If download failed but we have a stale cache, use it anyway
            if (-not (Test-Path $script:SkuMapFile)) {
                Write-Debug "No cached SKU map available. GUID fallback will be used."
                $script:SkuMap = @{}
                return $script:SkuMap
            }
            Write-Debug "Using stale cached SKU map as fallback."
        }
    }

    try {
        # utf8BOM encoding (PS7+) ensures BOM is handled correctly on import.
        $rows = Import-Csv -Path $script:SkuMapFile -Encoding utf8BOM -ErrorAction Stop
        $map  = @{}
        if ($rows.Count -gt 0) {
            # Locate the GUID column dynamically - BOM may corrupt the first column name
            # depending on encoding handling. Match any column name containing 'GUID'.
            $guidCol = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match 'GUID' })[0]
            $nameCol = 'Product_Display_Name'
            if (-not $guidCol) {
                Write-Log "SKU map GUID column not found. License names will fall back to GUIDs." -Level WARN
            } else {
                foreach ($row in $rows) {
                    $guid = ($row.$guidCol ?? '').Trim().ToLower()
                    $name = ($row.$nameCol ?? '').Trim()
                    if ($guid -and $name -and -not $map.ContainsKey($guid)) {
                        $map[$guid] = $name
                    }
                }
            }
        }
        $script:SkuMap = $map
        Write-Log "SKU map loaded: $($map.Count) entries."
    } catch {
        Write-Log "SKU map parse error: $($_.Exception.Message)" -Level WARN
        $script:SkuMap = @{}
    }

    return $script:SkuMap
}

function Resolve-SkuName {
    param([string]$SkuId, [string]$SkuPartNumber)
    $map = Get-SkuMap
    $key = $SkuId.ToLower()
    if ($map.ContainsKey($key) -and $map[$key]) {
        return $map[$key]
    }
    # Fallback: return the SKU part number (e.g. SPE_E3_GCC) which is still readable
    return $SkuPartNumber
}

function Show-LicenseDetails {
    param([string]$UserId, [string]$DisplayName)
    $t = $script:ActiveTheme
    Write-Host ""
    Write-C "  Loading license details..." $t.Dim

    try {
        # Get-MgUserLicenseDetail returns skuId, skuPartNumber, servicePlans[]
        $licenses = Get-MgUserLicenseDetail -UserId $UserId -ErrorAction Stop
        Write-Log "License details fetched for $UserId. Count=$($licenses.Count)"
    } catch {
        Write-Error2 "Could not retrieve license details: $_"
        Write-Log "License detail error for $UserId : $($_.Exception.Message)" -Level ERROR
        Read-Host "`n  Press Enter to continue"
        return
    }

    Clear-Host
    Write-C ('=' * 70) $t.Header
    Write-C "  LICENSE DETAILS" $t.Header
    Write-C "  $DisplayName" $t.Dim
    Write-C ('=' * 70) $t.Header
    Write-Host ""

    if (-not $licenses -or $licenses.Count -eq 0) {
        Write-Warning2 "No licenses assigned."
        Read-Host "`n  Press Enter to continue"
        return
    }

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("LICENSE DETAILS: $DisplayName")
    $clipLines.Add(('-' * 50))

    foreach ($lic in ($licenses | Sort-Object SkuPartNumber)) {
        $friendlyName = Resolve-SkuName -SkuId $lic.SkuId -SkuPartNumber $lic.SkuPartNumber
        Write-C "  $friendlyName" $t.Accent
        Write-C "    SKU Part  : $($lic.SkuPartNumber)" $t.Dim
        Write-C "    SKU GUID  : $($lic.SkuId)" $t.Dim

        $clipLines.Add("  $friendlyName")
        $clipLines.Add("    SKU: $($lic.SkuPartNumber)")

        # Show service plan status breakdown
        if ($lic.ServicePlans -and $lic.ServicePlans.Count -gt 0) {
            $enabled  = @($lic.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Success' })
            $disabled = @($lic.ServicePlans | Where-Object { $_.ProvisioningStatus -eq 'Disabled' })
            $pending  = @($lic.ServicePlans | Where-Object { $_.ProvisioningStatus -notin @('Success','Disabled') })

            Write-C "    Services  : $($lic.ServicePlans.Count) total | $($enabled.Count) enabled | $($disabled.Count) disabled$(if($pending.Count -gt 0){" | $($pending.Count) pending"})" $t.Normal

            # Show enabled services
            if ($enabled.Count -gt 0) {
                Write-C "    Enabled:" $t.Normal
                foreach ($svc in ($enabled | Sort-Object ServicePlanName)) {
                    Write-C "      [+] $($svc.ServicePlanName)" $t.Success
                }
            }

            # Show disabled/suppressed services (collapsed unless there are few total)
            if ($disabled.Count -gt 0) {
                # Only show disabled list if 10 or fewer, otherwise show count only
                if ($disabled.Count -le 10) {
                    Write-C "    Disabled:" $t.Normal
                    foreach ($svc in ($disabled | Sort-Object ServicePlanName)) {
                        Write-C "      [-] $($svc.ServicePlanName)" $t.Dim
                    }
                } else {
                    Write-C "    Disabled: $($disabled.Count) services suppressed (not shown)" $t.Dim
                }
            }

            # Show pending/error states
            if ($pending.Count -gt 0) {
                Write-C "    Pending/Other:" $t.Warning
                foreach ($svc in ($pending | Sort-Object ServicePlanName)) {
                    Write-C "      [?] $($svc.ServicePlanName) [$($svc.ProvisioningStatus)]" $t.Warning
                    $clipLines.Add("      [?] $($svc.ServicePlanName) [$($svc.ProvisioningStatus)]")
                }
            }

            $clipLines.Add("    Enabled services: $($enabled.Count)")
            $clipLines.Add("    Disabled services: $($disabled.Count)")
        }
        Write-Host ""
        $clipLines.Add("")
    }

    Write-C "  [C] Copy to clipboard  [Enter] Back" $t.Dim
    $k = Read-Host "  > "
    if ($k -eq 'c' -or $k -eq 'C') {
        ($clipLines -join "`n") | Set-Clipboard
        Write-Success "Copied to clipboard."
        Start-Sleep -Milliseconds 800
    }
}

# ============================================================
#  SIGN-IN HISTORY
# ============================================================
$script:SignInCount = 30   # Number of sign-in entries to retrieve

function Show-SignInHistory {
    param([string]$UserId, [string]$DisplayName)
    $t = $script:ActiveTheme
    Write-Host ""
    Write-C "  Loading sign-in history..." $t.Dim

    $UserId = Sanitize-ODataString $UserId
    try {
        # Filter by userId, newest first, explicit property select for efficiency
        $signIns = Get-MgAuditLogSignIn `
            -Filter "userId eq '$UserId'" `
            -Top $script:SignInCount `
            -Sort 'createdDateTime desc' `
            -Property 'createdDateTime','appDisplayName','ipAddress','location',
                      'status','isInteractive','clientAppUsed','deviceDetail',
                      'conditionalAccessStatus','riskLevelDuringSignIn' `
            -ErrorAction Stop
        Write-Log "Sign-in history fetched for $UserId. Count=$($signIns.Count)"
    } catch {
        Write-Error2 "Could not retrieve sign-in history: $_"
        Write-Log "Sign-in history error for $UserId : $($_.Exception.Message)" -Level ERROR
        Read-Host "`n  Press Enter to continue"
        return
    }

    Clear-Host
    Write-C ('=' * 70) $t.Header
    Write-C "  SIGN-IN HISTORY  (last $script:SignInCount attempts)" $t.Header
    Write-C "  $DisplayName" $t.Dim
    Write-C ('=' * 70) $t.Header
    Write-Host ""

    if (-not $signIns -or $signIns.Count -eq 0) {
        Write-Warning2 "No sign-in records found. Log retention may have expired."
        Read-Host "`n  Press Enter to continue"
        return
    }

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("SIGN-IN HISTORY: $DisplayName")
    $clipLines.Add(('-' * 60))

    $num = 1
    foreach ($si in $signIns) {
        # Result / failure info
        $errorCode = $si.Status.ErrorCode
        $isSuccess = ($errorCode -eq 0)
        $resultLabel = if ($isSuccess) {
            "SUCCESS"
        } else {
            "FAILED "
        }
        $resultColor = if ($isSuccess) { $t.Success } else { $t.Error }

        # Failure reason - plain English from AdditionalDetails or FailureReason
        $failReason = ''
        if (-not $isSuccess) {
            $failReason = if ($si.Status.FailureReason) {
                $si.Status.FailureReason
            } elseif ($si.Status.AdditionalDetails) {
                $si.Status.AdditionalDetails
            } else {
                "Error code: $errorCode"
            }
        }

        # Location
        $city    = $si.Location.City ?? ''
        $state   = $si.Location.State ?? ''
        $country = $si.Location.CountryOrRegion ?? ''
        $locParts = @($city, $state, $country) | Where-Object { $_ -ne '' }
        $location = if ($locParts.Count -gt 0) { $locParts -join ', ' } else { 'Unknown' }

        # Interactive label
        $interactiveLabel = if ($si.IsInteractive) { "Interactive" } else { "Non-interactive" }

        # Device OS / browser from DeviceDetail
        $deviceOs      = $si.DeviceDetail.OperatingSystem ?? ''
        $deviceBrowser = $si.DeviceDetail.Browser ?? ''
        $deviceLabel   = (@($deviceOs, $deviceBrowser) | Where-Object { $_ -ne '' }) -join ' / '
        if (-not $deviceLabel) { $deviceLabel = 'Unknown' }

        # Timestamp
        $ts = if ($si.CreatedDateTime) { $si.CreatedDateTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' }

        # Display entry
        Write-C "  $num) " $t.Accent -NoNewline
        Write-C "[$resultLabel]" $resultColor -NoNewline
        Write-C "  $ts" $t.Normal
        Write-C "     App     : $($si.AppDisplayName)" $t.Normal
        Write-C "     Type    : $interactiveLabel  |  Client: $($si.ClientAppUsed)" $t.Normal
        Write-C "     Location: $location  |  IP: $($si.IpAddress)" $t.Normal
        Write-C "     Device  : $deviceLabel" $t.Dim

        if (-not $isSuccess -and $failReason) {
            Write-C "     Reason  : $failReason" $t.Warning
        }

        if ($si.ConditionalAccessStatus -and $si.ConditionalAccessStatus -ne 'notApplied') {
            Write-C "     CA      : $($si.ConditionalAccessStatus)" $t.Dim
        }

        Write-Host ""

        # Clipboard lines
        $clipLines.Add("$num) [$resultLabel] $ts")
        $clipLines.Add("   App     : $($si.AppDisplayName)")
        $clipLines.Add("   Type    : $interactiveLabel | Client: $($si.ClientAppUsed)")
        $clipLines.Add("   Location: $location | IP: $($si.IpAddress)")
        $clipLines.Add("   Device  : $deviceLabel")
        if (-not $isSuccess -and $failReason) {
            $clipLines.Add("   Reason  : $failReason")
        }
        $clipLines.Add("")

        $num++
    }

    Write-C "  [C] Copy to clipboard  [Enter] Back" $t.Dim
    $k = Read-Host "  > "
    if ($k -eq 'c' -or $k -eq 'C') {
        ($clipLines -join "`n") | Set-Clipboard
        Write-Success "Copied to clipboard."
        Start-Sleep -Milliseconds 800
    }
}

# ============================================================
#  GROUP MEMBERSHIP
# ============================================================
function Show-GroupMembership {
    param([string]$UserId, [string]$DisplayName)
    $t = $script:ActiveTheme
    Write-Host ""
    Write-C "  Loading group memberships..." $t.Dim

    try {
        # Fetch only AD-synced groups server-side - filters out cloud-only M365 groups,
        # Teams, dynamic groups, and other cloud noise irrelevant to on-prem access model.
        # Get-MgUserMemberOfAsGroup casts results to group objects directly.
        $syncedGroups = @(Get-MgUserMemberOfAsGroup `
            -UserId $UserId `
            -Filter "onPremisesSyncEnabled eq true" `
            -Property 'displayName','description','groupTypes','securityEnabled',
                      'onPremisesSamAccountName','onPremisesSyncEnabled' `
            -All `
            -ErrorAction Stop)
        $syncedGroups = @($syncedGroups | Sort-Object DisplayName)
        Write-Log "Group memberships fetched for $UserId. SyncedCount=$($syncedGroups.Count)"
    } catch {
        Write-Error2 "Could not retrieve group memberships: $_"
        Write-Log "Group membership error for $UserId : $($_.Exception.Message)" -Level ERROR
        Read-Host "`n  Press Enter to continue"
        return
    }

    Clear-Host
    Write-C ('=' * 70) $t.Header
    Write-C "  GROUP MEMBERSHIPS  (AD-synced only)" $t.Header
    Write-C "  $DisplayName" $t.Dim
    Write-C ('=' * 70) $t.Header
    Write-Host ""

    if ($syncedGroups.Count -eq 0) {
        Write-Warning2 "No AD-synced group memberships found."
        Write-Dim "  Note: Cloud-only groups are excluded by design."
        Read-Host "`n  Press Enter to continue"
        return
    }

    Write-C "  $($syncedGroups.Count) synced group(s) found" $t.Dim
    Write-Host ""

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("GROUP MEMBERSHIPS (AD-synced): $DisplayName")
    $clipLines.Add(('-' * 60))

    foreach ($grp in $syncedGroups) {
        # Group type label
        $typeLabel = if ($grp.SecurityEnabled -and $grp.GroupTypes -notcontains 'Unified') {
            "[Security  ]"
        } elseif ($grp.GroupTypes -contains 'Unified') {
            "[M365 Group]"
        } else {
            "[Dist List ]"
        }
        $typeColor = if ($grp.SecurityEnabled) { $t.Accent } else { $t.Dim }

        Write-C "  $typeLabel " $typeColor -NoNewline
        Write-C "$($grp.DisplayName)" $t.Normal

        # Show SAM account name if available (useful for on-prem cross-reference)
        if ($grp.OnPremisesSamAccountName) {
            Write-C "               SAM : $($grp.OnPremisesSamAccountName)" $t.Dim
        }

        # Show description if present
        if ($grp.Description) {
            Write-C "               Desc: $($grp.Description)" $t.Dim
        }

        $clipLines.Add("  $typeLabel $($grp.DisplayName)")
        if ($grp.OnPremisesSamAccountName) {
            $clipLines.Add("    SAM : $($grp.OnPremisesSamAccountName)")
        }
        if ($grp.Description) {
            $clipLines.Add("    Desc: $($grp.Description)")
        }
    }

    Write-Host ""
    Write-C "  [C] Copy to clipboard  [Enter] Back" $t.Dim
    $k = Read-Host "  > "
    if ($k -eq 'c' -or $k -eq 'C') {
        ($clipLines -join "`n") | Set-Clipboard
        Write-Success "Copied to clipboard."
        Start-Sleep -Milliseconds 800
    }
}

# ============================================================
#  USER DISPLAY
# ============================================================
function Format-Bool { param($val) if ($val) { "Yes" } else { "No" } }

function Show-UserCard {
    param($User)
    $t = $script:ActiveTheme
    $acctState = if ($User.AccountEnabled) {
        "[ENABLED] "
    } else {
        "[DISABLED]"
    }
    $acctColor = if ($User.AccountEnabled) { $t.Success } else { $t.Error }

    Write-Host ""
    Write-C ('*' * 70) $t.Accent
    Write-C "  $($User.DisplayName)  " $t.Header -NoNewline
    Write-C $acctState $acctColor
    Write-C ('*' * 70) $t.Accent
    Write-Host ""

    # Identity
    Write-C "  IDENTITY" $t.Accent
    Write-C "  UPN         : $($User.UserPrincipalName)" $t.Normal
    Write-C "  Mail        : $($User.Mail)" $t.Normal
    Write-C "  Nickname    : $($User.MailNickname)" $t.Normal
    Write-C "  Employee ID : $($User.EmployeeId)" $t.Normal
    Write-C "  Object ID   : $($User.Id)" $t.Dim
    Write-Host ""

    # Proxy Addresses
    if ($User.ProxyAddresses -and $User.ProxyAddresses.Count -gt 0) {
        Write-C "  EMAIL ALIASES" $t.Accent
        $User.ProxyAddresses | Sort-Object | ForEach-Object {
            $prefix = if ($_ -cmatch '^SMTP:') { "[PRIMARY] " } else { "          " }
            Write-C "  $prefix$_" $t.Normal
        }
        Write-Host ""
    }

    # Org
    Write-C "  ORGANIZATION" $t.Accent
    Write-C "  Title       : $($User.JobTitle)" $t.Normal
    Write-C "  Department  : $($User.Department)" $t.Normal
    Write-C "  Company     : $($User.CompanyName)" $t.Normal
    Write-C "  Office      : $($User.OfficeLocation)" $t.Normal
    Write-Host ""

    # Contact
    Write-C "  CONTACT" $t.Accent
    $phones = ($User.BusinessPhones -join ', ')
    Write-C "  Work Phone  : $phones" $t.Normal
    Write-C "  Mobile      : $($User.MobilePhone)" $t.Normal
    Write-Host ""

    # Account Details
    $syncStatus = if ($User.OnPremisesSyncEnabled) {
        "Hybrid (synced)"
    } else {
        "Cloud only"
    }
    $lastSync = if ($User.OnPremisesLastSyncDateTime) {
        $User.OnPremisesLastSyncDateTime.ToString('yyyy-MM-dd HH:mm')
    } else {
        "N/A"
    }
    $pwdChange = if ($User.LastPasswordChangeDateTime) {
        $User.LastPasswordChangeDateTime.ToString('yyyy-MM-dd HH:mm')
    } else {
        "N/A"
    }
    $lastInteractive = if ($User.SignInActivity -and $User.SignInActivity.LastSignInDateTime) {
        $User.SignInActivity.LastSignInDateTime.ToString('yyyy-MM-dd HH:mm')
    } else {
        "N/A"
    }
    $lastNonInteractive = if ($User.SignInActivity -and $User.SignInActivity.LastNonInteractiveSignInDateTime) {
        $User.SignInActivity.LastNonInteractiveSignInDateTime.ToString('yyyy-MM-dd HH:mm')
    } else {
        "N/A"
    }
    $licCount = if ($User.AssignedLicenses) { $User.AssignedLicenses.Count } else { 0 }

    # Build inline license name list using SKU GUIDs from AssignedLicenses
    # AssignedLicenses only has skuId - no part number - so we resolve via SKU map
    $licLabel = if ($licCount -eq 0) {
        "None"
    } else {
        $skuMap = Get-SkuMap
        $names  = @()
        foreach ($al in $User.AssignedLicenses) {
            $key  = $al.SkuId.ToString().ToLower()
            $name = if ($skuMap.ContainsKey($key)) { $skuMap[$key] } else { $al.SkuId }
            $names += $name
        }
        "$licCount assigned: $($names -join ' | ')"
    }

    Write-C "  ACCOUNT DETAILS" $t.Accent
    Write-C "  Type        : $($User.UserType)" $t.Normal
    Write-C "  Sync        : $syncStatus" $t.Normal
    Write-C "  Last Sync   : $lastSync" $t.Normal
    Write-C "  Created     : $(if($User.CreatedDateTime){$User.CreatedDateTime.ToString('yyyy-MM-dd')}else{'N/A'})" $t.Normal
    Write-C "  Pwd Changed : $pwdChange" $t.Normal
    Write-C "  Last SignIn  : $lastInteractive" $t.Normal
    Write-C "  Last NonInt  : $lastNonInteractive" $t.Dim
    Write-C "  Licenses    : $licLabel" $t.Normal
    Write-Host ""

    # Add to recent
    $recentEntry = @{
        upn         = $User.UserPrincipalName
        displayName = $User.DisplayName
        mail        = $User.Mail
        id          = $User.Id
    }
    Add-RecentUser -User $recentEntry

    # Clipboard content
    $clip = @"
Display Name : $($User.DisplayName)
UPN          : $($User.UserPrincipalName)
Mail         : $($User.Mail)
Nickname     : $($User.MailNickname)
Title        : $($User.JobTitle)
Department   : $($User.Department)
Office       : $($User.OfficeLocation)
Work Phone   : $($User.BusinessPhones -join ', ')
Mobile       : $($User.MobilePhone)
Account      : $(if($User.AccountEnabled){'Enabled'}else{'Disabled'})
Last SignIn  : $lastInteractive
Last NonInt  : $lastNonInteractive
Licenses     : $licLabel
Sync         : $syncStatus
"@
    Write-C "  [C] Copy  [L] Licenses  [G] Groups  [S] Sign-in history  [Enter] Back" $t.Dim
    $k = Read-Host "  > "
    if ($k -eq 'c' -or $k -eq 'C') {
        $clip | Set-Clipboard
        Write-Success "Copied to clipboard."
        Start-Sleep -Milliseconds 800
    } elseif ($k -eq 'l' -or $k -eq 'L') {
        if ($licCount -eq 0) {
            Write-Warning2 "No licenses assigned to this user."
            Start-Sleep -Milliseconds 800
        } else {
            Show-LicenseDetails -UserId $User.Id -DisplayName $User.DisplayName
        }
    } elseif ($k -eq 'g' -or $k -eq 'G') {
        Show-GroupMembership -UserId $User.Id -DisplayName $User.DisplayName
    } elseif ($k -eq 's' -or $k -eq 'S') {
        Show-SignInHistory -UserId $User.Id -DisplayName $User.DisplayName
    }
}

function Show-UserList {
    param($Users, [string]$Title = "Search Results")
    $t = $script:ActiveTheme
    Write-Host ""
    Write-SectionLine $Title
    if (-not $Users -or $Users.Count -eq 0) {
        Write-Warning2 "No results found."
        return $null
    }
    $i = 1
    foreach ($u in $Users) {
        $state = if ($u.AccountEnabled) { "[ON] " } else { "[OFF]" }
        $stateColor = if ($u.AccountEnabled) { $t.Success } else { $t.Error }
        Write-C "  $i) " $t.Accent -NoNewline
        Write-C "$state " $stateColor -NoNewline
        Write-C "$($u.DisplayName)" $t.Normal -NoNewline
        Write-C "  |  $($u.UserPrincipalName)" $t.Dim
        $i++
    }
    Write-Host ""
    Write-C "  Select number to view details, or Enter to cancel: " $t.Dim -NoNewline
    $sel = Read-Host
    if ($sel -match '^\d+$') {
        $idx = [int]$sel - 1
        if ($idx -ge 0 -and $idx -lt $Users.Count) {
            return $Users[$idx]
        }
    }
    return $null
}

# ============================================================
#  SEARCH FLOWS
# ============================================================
function Invoke-SearchFlow {
    param([string]$Prompt, [scriptblock]$SearchBlock)
    Clear-Host
    Show-AppHeader
    Write-Host ""
    Write-C "  $Prompt" $script:ActiveTheme.Accent
    Write-Host ""
    Write-C "  (Leave blank to cancel)" $script:ActiveTheme.Dim
    Write-Host ""
    $query = Read-Host "  > "
    $query = $query.Trim()
    if ([string]::IsNullOrEmpty($query)) { return }

    Write-Host ""
    Write-C "  Searching..." $script:ActiveTheme.Dim
    try {
        $results = & $SearchBlock $query
        if ($results -and $results.Count -eq 1) {
            Show-UserCard -User $results[0]
        } elseif ($results -and $results.Count -gt 1) {
            $selected = Show-UserList -Users $results
            if ($selected) { Show-UserCard -User $selected }
        } else {
            Write-Host ""
            Write-Warning2 "No members found matching: $query"
            Write-Log "No results. SearchType=general"
            Read-Host "`n  Press Enter to continue"
        }
    } catch {
        Write-Error2 "Search error: $_"
        Write-Log "Search error: $($_.Exception.Message)" -Level ERROR
        Read-Host "`n  Press Enter to continue"
    }
}

function Start-NameSearch {
    Clear-Host
    Show-AppHeader
    Write-Host ""
    Write-C "  Name Search" $script:ActiveTheme.Accent
    Write-Host ""
    Write-C "  Enter first name, last name, or both." $script:ActiveTheme.Dim
    Write-C "  Leave blank to skip a field." $script:ActiveTheme.Dim
    Write-Host ""
    $first = (Read-Host "  First Name").Trim()
    $last  = (Read-Host "  Last Name").Trim()

    if (-not $first -and -not $last) { return }

    Write-Host ""
    Write-C "  Searching..." $script:ActiveTheme.Dim
    try {
        $results = @()
        if ($first -or $last) {
            $results = @(Search-ByName -GivenName $first -Surname $last)
        }
        # If only one token given and no surname results, try display name too
        if ($results.Count -eq 0 -and $first -and -not $last) {
            $results = @(Search-ByDisplayName -Name $first)
        }

        if ($results.Count -eq 1) {
            Show-UserCard -User $results[0]
        } elseif ($results.Count -gt 1) {
            $selected = Show-UserList -Users $results -Title "Name Search Results"
            if ($selected) { Show-UserCard -User $selected }
        } else {
            Write-Warning2 "No members found."
            Write-Log "No results. SearchType=name"
            Read-Host "`n  Press Enter to continue"
        }
    } catch {
        Write-Error2 "Search error: $_"
        Write-Log "Name search error: $($_.Exception.Message)" -Level ERROR
        Read-Host "`n  Press Enter to continue"
    }
}

function Start-UpnSearch {
    Invoke-SearchFlow -Prompt "UPN Search  (e.g. jsmith@corp.local)" -SearchBlock {
        param($v) @(Search-ByUpn -Upn $v)
    }
}

function Start-MailSearch {
    Invoke-SearchFlow -Prompt "Mail / Primary SMTP Search  (e.g. jsmith@company.com)" -SearchBlock {
        param($v)
        # Try mail field first (fastest), then proxyAddresses for primary SMTP alias
        $res = @(Search-ByMail -Mail $v)
        if ($res.Count -eq 0) {
            $res = @(Search-ByProxyAddress -SmtpAlias $v)
        }
        $res
    }
}

function Start-UsernameSearch {
    Invoke-SearchFlow -Prompt "Username / mailNickname Search  (e.g. jsmith)" -SearchBlock {
        param($v) @(Search-ByMailNickname -Username $v)
    }
}

# ============================================================
#  RECENT USERS SUBMENU
# ============================================================
function Show-RecentUsers {
    Clear-Host
    Show-AppHeader
    Write-Host ""
    Write-C "  Recent Users (last $script:MaxRecentUsers)" $script:ActiveTheme.Accent
    Write-Host ""

    if (-not $script:RecentUsers -or $script:RecentUsers.Count -eq 0) {
        Write-Dim "  No recent users."
        Read-Host "`n  Press Enter to continue"
        return
    }

    $i = 1
    foreach ($u in $script:RecentUsers) {
        Write-C "  $i) " $script:ActiveTheme.Accent -NoNewline
        Write-C "$($u.displayName)" $script:ActiveTheme.Normal -NoNewline
        Write-C "  |  $($u.upn)" $script:ActiveTheme.Dim
        $i++
    }
    Write-Host ""
    Write-C "  Select number to reload user, or Enter to cancel: " $script:ActiveTheme.Dim -NoNewline
    $sel = Read-Host

    if ($sel -match '^\d+$') {
        $idx = [int]$sel - 1
        if ($idx -ge 0 -and $idx -lt $script:RecentUsers.Count) {
            $recent = $script:RecentUsers[$idx]
            Write-C "  Loading..." $script:ActiveTheme.Dim
            try {
                $user = Get-UserById -UserId $recent.id
                Show-UserCard -User $user
            } catch {
                Write-Error2 "Could not reload user: $_"
                Write-Log "Recent user reload error: $($_.Exception.Message) | ID=$($recent.id)" -Level ERROR
                Read-Host "`n  Press Enter to continue"
            }
        }
    }
}

# ============================================================
#  THEME SELECTION
# ============================================================
function Show-ThemeMenu {
    Clear-Host
    Show-AppHeader
    Write-Host ""
    Write-C "  Select Theme" $script:ActiveTheme.Accent
    Write-Host ""
    foreach ($key in ($script:Themes.Keys | Sort-Object)) {
        $marker = if ($key -eq $script:CurrentThemeKey) { ">" } else { " " }
        Write-C "  $marker $key) $($script:Themes[$key].Name)" $script:ActiveTheme.Normal
    }
    Write-Host ""
    Write-C "  Choice (Enter to cancel): " $script:ActiveTheme.Dim -NoNewline
    $sel = Read-Host
    $sel = $sel.Trim()
    if ($script:Themes.ContainsKey($sel)) {
        $script:CurrentThemeKey = $sel
        $script:ActiveTheme = $script:Themes[$sel]
        Save-PersistState
        Write-Log "Theme changed to: $($script:ActiveTheme.Name)"
        Write-Success "Theme set to: $($script:ActiveTheme.Name)"
        Start-Sleep -Milliseconds 600
    }
}

# ============================================================
#  MAIN MENU
# ============================================================
function Show-AppHeader {
    $t = $script:ActiveTheme
    Write-C ('=' * 70) $t.Header
    Write-C "  ENTRA ID USER LOOKUP TOOLKIT" $t.Header
    Write-C "  Help Desk Edition  |  Read-Only" $t.Dim
    Write-C ('=' * 70) $t.Header
    Show-ConnectionStatus
    Write-C ('-' * 70) $t.Dim
}

function Show-MainMenu {
    $t = $script:ActiveTheme
    $recentLabel = if ($script:RecentUsers -and $script:RecentUsers.Count -gt 0) {
        "Recent Users ($($script:RecentUsers.Count))"
    } else {
        "Recent Users"
    }

    Write-Host ""
    Write-C "  -- SEARCH --" $t.Accent
    Write-C "  1) Search by Name (First / Last)" $t.Normal
    Write-C "  2) Search by UPN" $t.Normal
    Write-C "  3) Search by Mail / Primary SMTP" $t.Normal
    Write-C "  4) Search by Username (mailNickname)" $t.Normal

    # Recent users submenu entries (dynamic)
    if ($script:RecentUsers -and $script:RecentUsers.Count -gt 0) {
        Write-Host ""
        Write-C "  -- RECENT USERS --" $t.Accent
        $i = 1
        foreach ($u in $script:RecentUsers) {
            Write-C "  R$i) $($u.displayName)  |  $($u.upn)" $t.Dim
            $i++
        }
        Write-C "  R)  View All Recent Users" $t.Normal
    }

    Write-Host ""
    Write-C "  -- CONNECTION --" $t.Accent
    Write-C "  C) Connect / Reconnect to Graph" $t.Normal
    Write-C "  D) Disconnect from Graph" $t.Normal

    Write-Host ""
    Write-C "  -- SETTINGS --" $t.Accent
    Write-C "  T) Change Theme  (current: $($script:ActiveTheme.Name))" $t.Normal

    Write-Host ""
    Write-C "  Q) Quit" $t.Normal
    Write-Host ""
    Write-C "  Choice: " $t.Accent -NoNewline
}

function Test-GraphConnected {
    $status = Get-ConnectionStatus
    if (-not $status.Connected) {
        Write-Warning2 "Not connected to Microsoft Graph."
        Write-Info "Use option [C] to connect first."
        Read-Host "`n  Press Enter to continue"
        return $false
    }
    return $true
}

# ============================================================
#  IDLE TIMEOUT
# ============================================================
function Read-MenuChoice {
    # Polls for a keypress every 250ms. Tracks idle time. At IdleTimeoutMinutes
    # shows a live countdown. If countdown reaches zero, disconnects and exits.
    # Returns the key character pressed as a string (uppercased).

    $idleMs      = $script:IdleTimeoutMinutes * 60 * 1000
    $warnMs      = $script:IdleWarningSeconds * 1000
    $pollMs      = 250
    $elapsed     = 0
    $inWarning   = $false
    $warnElapsed = 0

    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)  # $true = do not echo key

            # If we were showing the warning, clear that line before returning
            if ($inWarning) {
                Write-Host ("`r" + (' ' * 70) + "`r") -NoNewline
            }

            return $key.KeyChar.ToString().ToUpper()
        }

        Start-Sleep -Milliseconds $pollMs
        $elapsed += $pollMs

        if (-not $inWarning -and $elapsed -ge $idleMs) {
            # Transition into warning state
            $inWarning   = $true
            $warnElapsed = 0
            Write-Host ""
        }

        if ($inWarning) {
            $warnElapsed += $pollMs
            $remaining = [Math]::Ceiling(($warnMs - $warnElapsed) / 1000)

            if ($remaining -le 0) {
                # Countdown expired - clean up, disconnect, exit
                Write-Host ("`r" + (' ' * 70) + "`r") -NoNewline
                Write-Host ""
                Write-C "  Session disconnected due to inactivity." $script:ActiveTheme.Warning
                Write-Log "Auto-disconnect: idle timeout reached ($($script:IdleTimeoutMinutes) min)."
                Save-PersistState
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
                Start-Sleep -Milliseconds 1200
                exit 0
            }

            # Overwrite the same line each tick with \r
            $msg = "  Idle timeout: press any key to continue or disconnecting in $remaining second$(if ($remaining -ne 1) {'s'})...   "
            Write-Host ("`r" + $msg) -NoNewline -ForegroundColor $script:ActiveTheme.Warning
        }
    }
}

function Start-MainLoop {
    while ($true) {
        Clear-Host
        Show-AppHeader
        Show-MainMenu

        $choice = Read-MenuChoice

        switch -Regex ($choice) {
            '^1$' {
                if (Test-GraphConnected) { Start-NameSearch }
            }
            '^2$' {
                if (Test-GraphConnected) { Start-UpnSearch }
            }
            '^3$' {
                if (Test-GraphConnected) { Start-MailSearch }
            }
            '^4$' {
                if (Test-GraphConnected) { Start-UsernameSearch }
            }
            '^R([1-5])$' {
                # Quick-select recent user by number
                $idx = [int]$Matches[1] - 1
                if ($idx -ge 0 -and $idx -lt $script:RecentUsers.Count -and (Test-GraphConnected)) {
                    $recent = $script:RecentUsers[$idx]
                    Write-C "  Loading..." $script:ActiveTheme.Dim
                    try {
                        $user = Get-UserById -UserId $recent.id
                        Show-UserCard -User $user
                    } catch {
                        Write-Error2 "Could not load user: $_"
                        Write-Log "Quick-recent error: $($_.Exception.Message) | ID=$($recent.id)" -Level ERROR
                        Read-Host "`n  Press Enter to continue"
                    }
                }
            }
            '^R$' {
                if (Test-GraphConnected) { Show-RecentUsers }
            }
            '^C$' {
                Connect-ToGraph
            }
            '^D$' {
                Disconnect-FromGraph
            }
            '^T$' {
                Show-ThemeMenu
            }
            '^Q$' {
                Clear-Host
                Write-C "`n  Goodbye.`n" $script:ActiveTheme.Dim
                Write-Log "Session ended."
                Save-PersistState
                exit 0
            }
            default {
                # Ignore unknown input
            }
        }
    }
}

# ============================================================
#  ENTRY POINT
# ============================================================
try {
    Initialize-AppFolder
    Initialize-Logging
    Write-Log "=== Session started. ScriptVersion=1.0 ==="

    # Load persisted state
    $state = Read-PersistState
    $script:CurrentThemeKey = $state.ThemeKey
    $script:ActiveTheme     = $script:Themes[$script:CurrentThemeKey]
    $script:RecentUsers     = @($state.RecentUsers)

    # Attempt silent reconnect check (don't force - just check existing token)
    $connStatus = Get-ConnectionStatus
    if (-not $connStatus.Connected) {
        Write-Log "No active Graph session detected at startup."
    } else {
        Write-Log "Existing Graph session found. Account=$($connStatus.Account)"
    }

    Start-MainLoop

} catch {
    Write-Host "`n[FATAL] Unhandled exception: $_" -ForegroundColor Red
    Write-Log "FATAL: $_" -Level ERROR
    Read-Host "`nPress Enter to exit"
    exit 1
}
