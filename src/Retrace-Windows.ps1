<#
.SYNOPSIS
    Retrace — forensic browser-trail reconstruction for DFIR (Windows).

.DESCRIPTION
    Retrace parses Chrome, Edge, Brave, Vivaldi and Firefox history for
    Visits/Downloads/Keywords with transition decoding, URL/Base64 decoding,
    de-fanging, redirect-chain analysis and navigation-chain tracing. The -Path
    parameter points the tool at a specific browser profile directory or a
    single history database file (e.g. a mounted image or an extracted profile);
    when omitted, all local profiles are auto-discovered. WAL/SHM sidecars are
    copied so a running browser's most recent activity is captured.

    FORENSIC SAFETY
      * Original databases are NEVER modified or locked. Each is copied (with
        its -wal/-shm/-journal sidecars) into a private temp directory; all
        queries run against the copy, which is removed once processed.
      * Only a built-in Windows component is used: winsqlite3.dll (shipped
        with Windows 10/11) via a compiled P/Invoke helper. Nothing is
        installed.
      * Copying an original database updates its access time (last access),
        not its content or last-write time.

.PARAMETER Browser
    Browser(s) to query: Chrome, Edge, Firefox, Vivaldi, Brave, or All (default All).

.PARAMETER UserName
    Username or full profile path to query. Default: all profiles (Administrator)
    or the current user.

.PARAMETER Path
    A browser profile directory or a single history database file to analyze.
    Overrides -UserName and the normal AppData auto-discovery. A directory is
    searched recursively for History / places.sqlite files.

.PARAMETER SearchTerm
    SQL LIKE filter on URL / Title / download path / keyword URL.

.PARAMETER SearchRegex
    Regex filter (post-extraction) on URL / SearchURL / Path / Title.

.PARAMETER FollowChain
    Trace the full navigation chain around a specific VisitID (+/- 5 min window).

.PARAMETER LastHours
    Records from the last N hours (UTC).

.PARAMETER LastDays
    Records from the last N days (UTC, from midnight N days ago).

.PARAMETER Since
    Records on/after this UTC date/time.

.PARAMETER Before
    Records before this UTC date/time.

.PARAMETER Private
    Opt-in WHOLE-PROFILE private-browsing investigation (orphan favicons/typed URLs
    with no matching history visit, plus incognito posture). Cannot be combined with
    time filters, search, -FollowChain, or record-type options. Anti-forensics /
    history-cleaning detection is separate and runs automatically on a normal run.

.EXAMPLE
    .\Retrace-Windows.ps1 -Private -Browser Chrome

.EXAMPLE
    .\Retrace-Windows.ps1 -Path "E:\evidence\Chrome\Default\History" -Browser Chrome

.EXAMPLE
    .\Retrace-Windows.ps1 -Path "E:\image\Users\spatel\AppData\Local" -LastDays 30

.EXAMPLE
    .\Retrace-Windows.ps1 -LastHours 24

.NOTES
    Author      : Deep Patel, Suvas Patel
    Version     : 1.4.0
    License     : MIT
    Platform    : Windows 10/11
    Requires    : Windows PowerShell 5.1+ or PowerShell 7+, winsqlite3.dll (built in)
    Usage       : see USAGE-Windows.md, or run Get-Help .\Retrace-Windows.ps1 -Full
    Disclaimer  : For authorized digital-forensics / incident-response and
                  educational use only. Use only on systems you own or are
                  explicitly permitted to examine.
#>
[CmdletBinding(DefaultParameterSetName = 'DefaultTime')]
[OutputType([string])]
param(
[Parameter(Mandatory = $false, Position = 0)]
[ValidateSet('Chrome', 'Edge', 'Firefox', 'Vivaldi', 'Brave', 'All')]
[string[]]$Browser = 'All',
[Parameter(Mandatory = $false)]
[string]$UserName,
[Parameter(Mandatory = $false)]
[string]$Path,
[Parameter(Mandatory = $false)]
[string]$SearchTerm,
[Parameter(Mandatory = $false)]
[string]$SearchRegex,
[Parameter(Mandatory = $false)]
[switch]$NoDefang,
[Parameter(Mandatory = $false)]
[switch]$Visits,
[Parameter(Mandatory = $false)]
[switch]$Downloads,
[Parameter(Mandatory = $false)]
[switch]$IncludeKeywords,
[Parameter(Mandatory = $false)]
[bool]$IncludeVisitsWithTransitions = $true,
[Parameter(Mandatory = $false)]
[bool]$IncludeDetailedDownloads = $true,
[Parameter(Mandatory = $false)]
[bool]$AnalyzeRedirectChains = $true,
[Parameter(Mandatory = $false)]
[switch]$VerboseLogging,
[Parameter(Mandatory = $false)]
[switch]$Private,
[Parameter(Mandatory = $false)]
[switch]$Version,
[Parameter(Mandatory = $true, ParameterSetName = 'FollowChain')]
[ValidateRange(1, [long]::MaxValue)]
[long]$FollowChain,
[Parameter(Mandatory = $true, ParameterSetName = 'RecentHours')]
[Alias('lh')]
[ValidateRange(1, [int]::MaxValue)]
[int]$LastHours,
[Parameter(Mandatory = $true, ParameterSetName = 'RecentDays')]
[Alias('ld')]
[ValidateRange(1, [int]::MaxValue)]
[int]$LastDays,
[Parameter(Mandatory = $false, ParameterSetName = 'DateRange')]
[Alias('s')]
[datetime]$Since,
[Parameter(Mandatory = $false, ParameterSetName = 'DateRange')]
[Alias('b')]
[datetime]$Before
)
$ErrorActionPreference = 'Stop'
# -----------------------------------------------------------------------------
# Script metadata
# -----------------------------------------------------------------------------
$Script:ScriptVersion = '1.4.0'
$Script:ScriptAuthor = 'Deep Patel and Suvas Patel'
if ($Version) {
Write-Output "Retrace-Windows.ps1 v$Script:ScriptVersion by $Script:ScriptAuthor"
return
}
$Script:DisplayMessages = @()
$Script:TotalRecordsScanned = 0
# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
function Write-Message {
param(
[Parameter(Mandatory=$false)][string]$Message = "",
[ValidateSet('Normal','Verbose','Debug','Warning')][string]$Level = 'Normal'
)
$prefix = switch ($Level) {
'Verbose' { if (-not $VerboseLogging) { return }; "[VERBOSE] " }
'Debug'   { if (-not $VerboseLogging) { return }; "[DEBUG] " }
'Warning' { "WARNING: " }
'Normal'  { "" }
}
$Script:DisplayMessages += "$prefix$Message"
}
function Flush-Messages {
if ($Script:DisplayMessages.Count -gt 0) {
$Script:DisplayMessages | Write-Output
$Script:DisplayMessages = @()
}
}
function Get-InvocationArguments {
# Rebuilt from $PSBoundParameters rather than $MyInvocation.Line, which is not
# reliably populated when the script is dispatched by an EDR console.
param([hashtable]$BoundParameters)
if (-not $BoundParameters -or $BoundParameters.Count -eq 0) { return '(none)' }
$parts = @()
foreach ($key in ($BoundParameters.Keys | Sort-Object)) {
$value = $BoundParameters[$key]
if ($value -is [System.Management.Automation.SwitchParameter]) {
# An explicitly negated switch (-Name:$false) is still bound and must be shown.
$parts += $(if ($value.IsPresent) { "-$key" } else { "-${key}:`$false" })
continue
}
$text = if ($value -is [array]) { $value -join ',' } else { [string]$value }
if ([string]::IsNullOrEmpty($text) -or $text -match '\s') { $text = "'" + $text.Replace("'", "''") + "'" }
$parts += "-$key $text"
}
if ($parts.Count -eq 0) { return '(none)' }
return ($parts -join ' ')
}
function Write-CollectionHeader {
# Collection provenance banner - emitted once at the top of every run so the
# report carries its own chain-of-custody context (who/where/when/how).
param([hashtable]$BoundParameters)
$collectionHost = if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
Write-Message ("=" * 65)
Write-Message ("{0}: {1}" -f 'Hostname'.PadRight(20), $collectionHost)
Write-Message ("{0}: {1}" -f 'Time of Collection'.PadRight(20), ("{0:u}" -f [DateTime]::UtcNow))
Write-Message ("{0}: {1}" -f 'Author'.PadRight(20), "$Script:ScriptAuthor (v$Script:ScriptVersion)")
Write-Message ("{0}: {1}" -f 'Command Arguments'.PadRight(20), (Get-InvocationArguments -BoundParameters $BoundParameters))
Write-Message ("=" * 65)
Write-Message ""
}
# -----------------------------------------------------------------------------
# Formatting helpers
# -----------------------------------------------------------------------------
function Format-InvariantNumber {
param(
[Parameter(Mandatory=$true)]
$Number,
[int]$DecimalPlaces = -1
)
if ($DecimalPlaces -ge 0) {
$rounded = [Math]::Round([double]$Number, $DecimalPlaces)
return $rounded.ToString([System.Globalization.CultureInfo]::InvariantCulture)
} else {
return $Number.ToString([System.Globalization.CultureInfo]::InvariantCulture)
}
}
$Script:DecodingAvailable = $true
try {
Write-Message "Loading System.Web assembly for URL decoding..." -Level Verbose
Add-Type -AssemblyName System.Web
Write-Message "System.Web assembly loaded successfully." -Level Verbose
} catch {
Write-Message "Failed to load System.Web assembly. URL parameter decoding will not be available. Error: $($_.Exception.Message)" -Level Warning
$Script:DecodingAvailable = $false
}
Flush-Messages
# -----------------------------------------------------------------------------
# SQLite native interop (winsqlite3.dll via P/Invoke)
# -----------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'SqliteHelper').Type) {
Write-Message "Compiling SQLite Helper Class..." -Level Verbose
try {
Add-Type -ReferencedAssemblies System.Collections, System.Data, System.Data.Common, System.Xml, System.ComponentModel.TypeConverter -TypeDefinition @"
using System;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;
public static class SqliteHelper {
private const string DllName = "winsqlite3.dll";
[DllImport(DllName, CharSet = CharSet.Unicode, EntryPoint = "sqlite3_open16", CallingConvention = CallingConvention.Cdecl)]
private static extern int open(string filename, out IntPtr db);
[DllImport(DllName, EntryPoint = "sqlite3_extended_result_codes", CallingConvention = CallingConvention.Cdecl)]
private static extern int result_codes(IntPtr db, int onOrOff);
[DllImport(DllName, EntryPoint = "sqlite3_close_v2", CallingConvention = CallingConvention.Cdecl)]
private static extern int close(IntPtr db);
[DllImport(DllName, CharSet = CharSet.Unicode, EntryPoint = "sqlite3_prepare16", CallingConvention = CallingConvention.Cdecl)]
private static extern int prepare(IntPtr db, string query, int len, out IntPtr stmt, IntPtr dummy);
[DllImport(DllName, EntryPoint = "sqlite3_step", CallingConvention = CallingConvention.Cdecl)]
private static extern int step(IntPtr stmt);
[DllImport(DllName, EntryPoint = "sqlite3_column_count", CallingConvention = CallingConvention.Cdecl)]
private static extern int column_count(IntPtr stmt);
[DllImport(DllName, EntryPoint = "sqlite3_column_name16", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr column_name(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_type", CallingConvention = CallingConvention.Cdecl)]
private static extern int column_type(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_double", CallingConvention = CallingConvention.Cdecl)]
private static extern double column_double(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_int64", CallingConvention = CallingConvention.Cdecl)]
private static extern Int64 column_int64(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_text16", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr column_text(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_blob", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr column_blob(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_bytes", CallingConvention = CallingConvention.Cdecl)]
private static extern int column_bytes(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_column_bytes16", CallingConvention = CallingConvention.Cdecl)]
private static extern int column_bytes16(IntPtr stmt, int col);
[DllImport(DllName, EntryPoint = "sqlite3_finalize", CallingConvention = CallingConvention.Cdecl)]
private static extern int finalize(IntPtr stmt);
private const int SQLITE_OK = 0;
private const int SQLITE_ROW = 100;
private const int SQLITE_DONE = 101;
private const int SQLITE_BUSY = 5;
private const int SQLITE_LOCKED = 6;
private const int SQLITE_INTEGER = 1;
private const int SQLITE_FLOAT = 2;
private const int SQLITE_TEXT = 3;
private const int SQLITE_BLOB = 4;
private const int SQLITE_NULL = 5;
private const int MaxColumnBytes = 256 * 1024 * 1024; // sanity cap against a corrupted/adversarial DB
public class SqliteException : Exception {
public int NativeErrorCode { get; private set; }
public SqliteException(int code) : this(String.Format("SQLite API call failed with result code {0}.", code), code) { }
public SqliteException(string message, int code) : base(message) { NativeErrorCode = code; }
public SqliteException(string message) : base(message) { NativeErrorCode = -1; }
}
public static IntPtr Open(string filename) {
IntPtr db;
int result = open(filename, out db);
if (result != SQLITE_OK) throw new SqliteException("SQLite open failed.", result);
result_codes(db, 1);
return db;
}
public static void Close(IntPtr db) {
int result = close(db);
if (result != SQLITE_OK && result != SQLITE_BUSY && result != SQLITE_LOCKED) { /* Optional: Log warning */ }
}
public static DataTable Execute(IntPtr db, string query) {
IntPtr stmt = IntPtr.Zero;
DataTable dt = new DataTable();
int lastStepResult = SQLITE_OK;
int result = prepare(db, query, -1, out stmt, IntPtr.Zero);
if (result != SQLITE_OK) throw new SqliteException(string.Format("SQLite prepare failed (Code: {0}) for query: {1}", result, query), result);
try {
int colCount = column_count(stmt);
lastStepResult = step(stmt);
if (lastStepResult == SQLITE_ROW) {
string[] colNames = new string[colCount];
for (int c = 0; c < colCount; c++) {
string potentialColName = Marshal.PtrToStringUni(column_name(stmt, c));
string colName = string.IsNullOrEmpty(potentialColName) ? string.Format("Column_{0}", c) : potentialColName;
int suffix = 1;
string baseName = colName;
while (Array.IndexOf(colNames, colName, 0, c) > -1) {
colName = string.Format("{0}_{1}", baseName, suffix++);
}
colNames[c] = colName;
dt.Columns.Add(colName, typeof(object));
}
do {
DataRow row = dt.NewRow();
for (int i = 0; i < colCount; i++) {
object value = DBNull.Value;
switch (column_type(stmt, i)) {
case SQLITE_INTEGER: value = column_int64(stmt, i); break;
case SQLITE_FLOAT: value = column_double(stmt, i); break;
case SQLITE_TEXT:
IntPtr textPtr = column_text(stmt, i);
if (textPtr != IntPtr.Zero) {
int byteLen = column_bytes16(stmt, i);
if (byteLen > MaxColumnBytes) byteLen = MaxColumnBytes;
if (byteLen > 0) {
byte[] buffer = new byte[byteLen];
Marshal.Copy(textPtr, buffer, 0, byteLen);
value = Encoding.Unicode.GetString(buffer, 0, byteLen);
} else { value = string.Empty; }
}
break;
case SQLITE_BLOB:
IntPtr blobPtr = column_blob(stmt, i);
int blobLen = column_bytes(stmt, i);
if (blobLen > MaxColumnBytes) blobLen = MaxColumnBytes;
if (blobLen > 0 && blobPtr != IntPtr.Zero) {
byte[] blobArr = new byte[blobLen];
Marshal.Copy(blobPtr, blobArr, 0, blobLen);
value = blobArr;
}
break;
case SQLITE_NULL: break;
default: break;
}
row[colNames[i]] = value;
}
dt.Rows.Add(row);
lastStepResult = step(stmt);
} while (lastStepResult == SQLITE_ROW);
if (lastStepResult != SQLITE_DONE) throw new SqliteException("SQLite step failed after returning rows.", lastStepResult);
} else if (lastStepResult != SQLITE_DONE) {
throw new SqliteException("SQLite step failed on first attempt.", lastStepResult);
}
} finally {
if (stmt != IntPtr.Zero) finalize(stmt);
}
return dt;
}
}
"@
Write-Message "SQLite Helper Class compiled." -Level Verbose
} catch {
Write-Message "Failed to compile SQLite Helper Class: $($_.Exception.Message)" -Level Warning
Flush-Messages
throw
}
} else {
Write-Message "SQLite Helper Class already loaded in this session." -Level Verbose
}
Flush-Messages
# -----------------------------------------------------------------------------
# Config / context builders
# -----------------------------------------------------------------------------
function New-ConversionContext {
param(
[string]$UserName,
[string]$Browser,
[bool]$NoDefang,
[bool]$DecodingAvailable,
[System.Data.DataColumnCollection]$Columns
)
return @{
UserName = $UserName
Browser = $Browser
NoDefang = $NoDefang
DecodingAvailable = $DecodingAvailable
Columns = $Columns
}
}
function New-TimeFilterConfig {
param(
[nullable[datetime]]$StartDate,
[nullable[datetime]]$EndDate,
[string]$Description,
[bool]$IsActive
)
return @{
StartDate = $StartDate
EndDate = $EndDate
Description = $Description
IsActive = $IsActive
}
}
function New-QuerySettings {
param(
[bool]$RunVisits,
[bool]$RunDownloads,
[bool]$RunKeywords,
[bool]$IncludeTransitions,
[bool]$IncludeDetails,
[string]$SearchTerm,
[string]$SearchRegex,
[hashtable]$TimeFilter
)
return @{
RunVisits = $RunVisits
RunDownloads = $RunDownloads
RunKeywords = $RunKeywords
IncludeTransitions = $IncludeTransitions
IncludeDetails = $IncludeDetails
SearchTerm = $SearchTerm
SearchRegex = $SearchRegex
TimeFilter = $TimeFilter
}
}
# -----------------------------------------------------------------------------
# Profile discovery (auto-discovery of browser profiles)
# -----------------------------------------------------------------------------
function Get-UserPaths {
param([string]$SpecificUser)
Write-Message "Entering Get-UserPaths with SpecificUser: '$SpecificUser'" -Level Debug
$userPaths = @{}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.principal.WindowsBuiltInRole]::Administrator)
try {
$profilesDir = "C:\Users"
try {
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
if (Test-Path $regPath) {
$regValue = Get-ItemProperty -Path $regPath -Name "ProfilesDirectory" -ErrorAction SilentlyContinue
if ($regValue -and $regValue.ProfilesDirectory) {
$expandedPath = [System.Environment]::ExpandEnvironmentVariables($regValue.ProfilesDirectory)
if (Test-Path $expandedPath -PathType Container) {
$profilesDir = $expandedPath
Write-Message "Using profiles directory from registry: $profilesDir" -Level Verbose
}
}
}
} catch {
Write-Message "Registry lookup failed, using fallback: $profilesDir" -Level Debug
}
if (-not [string]::IsNullOrWhiteSpace($SpecificUser)) {
Write-Message "Specific user '$SpecificUser' requested." -Level Verbose
if (-not $isAdmin) {
Write-Message "Querying specific user '$SpecificUser' may require Administrator privileges if it's not the current user." -Level Warning
}
if ($SpecificUser -match '^[A-Za-z]:\\' -or $SpecificUser.StartsWith('\')) {
if ((Test-Path $SpecificUser -PathType Container) -and
(Test-Path (Join-Path $SpecificUser 'NTUSER.DAT') -PathType Leaf)) {
$userName = Split-Path $SpecificUser -Leaf
$userPaths[$userName] = $SpecificUser
Write-Message "Validated full path for user '$userName': $SpecificUser" -Level Verbose
} else {
Write-Message "Specified path does not exist or is not a valid user profile: $SpecificUser" -Level Warning
}
} else {
$foundInRegistry = $false
try {
$profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$profileSubKeys = Get-ChildItem -Path $profileListKey -ErrorAction SilentlyContinue
foreach ($subKey in $profileSubKeys) {
$profileInfo = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
if ($profileInfo.ProfileImagePath) {
$profilePath = [System.Environment]::ExpandEnvironmentVariables($profileInfo.ProfileImagePath)
$userName = Split-Path $profilePath -Leaf
if ($userName -ieq $SpecificUser -and (Test-Path $profilePath -PathType Container) -and
(Test-Path (Join-Path $profilePath 'NTUSER.DAT') -PathType Leaf)) {
$userPaths[$userName] = $profilePath
$foundInRegistry = $true
Write-Message "Found user '$SpecificUser' via registry: $profilePath" -Level Verbose
break
}
}
}
} catch { Write-Message "Registry enumeration failed for specific user" -Level Debug }
if (-not $foundInRegistry) {
$constructedPath = Join-Path $profilesDir $SpecificUser
if ((Test-Path $constructedPath -PathType Container) -and
(Test-Path (Join-Path $constructedPath 'NTUSER.DAT') -PathType Leaf)) {
$userPaths[$SpecificUser] = $constructedPath
Write-Message "Found user '$SpecificUser' via constructed path: $constructedPath" -Level Verbose
} else {
Write-Message "Could not find profile for user: $SpecificUser" -Level Warning
}
}
}
} elseif ($isAdmin) {
Write-Message "Running as Admin and no specific user requested. Scanning all profiles." -Level Verbose
try {
$profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$profileSubKeys = Get-ChildItem -Path $profileListKey -ErrorAction SilentlyContinue
foreach ($subKey in $profileSubKeys) {
$profileInfo = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
if ($profileInfo.ProfileImagePath) {
$profilePath = [System.Environment]::ExpandEnvironmentVariables($profileInfo.ProfileImagePath)
if ($profilePath -notlike "*\system32\*" -and $profilePath -notlike "*\ServiceProfiles\*" -and $profilePath -notlike "*\systemprofile*") {
$userName = Split-Path $profilePath -Leaf
if ($userName -notin @('All Users', 'Default', 'Default User', 'Public', 'Public User') -and
$userName -notlike '.*' -and $userName -notlike '*$' -and
(Test-Path $profilePath -PathType Container) -and
(Test-Path (Join-Path $profilePath 'NTUSER.DAT') -PathType Leaf)) {
$userPaths[$userName] = $profilePath
Write-Message "Found user profile via registry: $userName -> $profilePath" -Level Verbose
}
}
}
}
} catch { Write-Message "Registry enumeration failed" -Level Debug }
if ($userPaths.Count -eq 0 -and (Test-Path $profilesDir -PathType Container)) {
try {
$userDirs = Get-ChildItem -Path $profilesDir -Directory -ErrorAction Stop
foreach($dir in $userDirs) {
if ($dir.Name -notin @('All Users', 'Default', 'Default User', 'Public', 'Public User') -and
$dir.Name -notlike '.*' -and
(Test-Path (Join-Path $dir.FullName 'NTUSER.DAT') -PathType Leaf -ErrorAction SilentlyContinue)) {
$userPaths[$dir.Name] = $dir.FullName
Write-Message "Found user profile via directory scan: $($dir.Name)" -Level Verbose
}
}
} catch {
Write-Message "Could not access profiles directory '$profilesDir'. Error: $($_.Exception.Message)" -Level Warning
}
}
} else {
Write-Message "Not running as Admin and no specific user requested. Querying current user only." -Level Verbose
$currentUser = [string]$env:USERNAME
$currentUserPath = [string]$env:USERPROFILE
if (-not [string]::IsNullOrWhiteSpace($currentUser) -and -not [string]::IsNullOrWhiteSpace($currentUserPath)) {
if (Test-Path -Path $currentUserPath -PathType Container) {
$userPaths[$currentUser] = $currentUserPath
Write-Message "NOTE: Not running as Administrator. Only querying current user ($currentUser)."
} else {
Write-Message "Could not access current user profile path: $currentUserPath" -Level Warning
}
} else {
Write-Message "Could not determine current user or user profile path." -Level Warning
}
}
} catch {
Write-Message "Error in Get-UserPaths: $($_.Exception.Message)" -Level Warning
Write-Message "Get-UserPaths error details: $($_.Exception | Format-List * | Out-String)" -Level Debug
Flush-Messages
throw
}
Write-Message "Get-UserPaths returning $($userPaths.Count) user paths" -Level Debug
return $userPaths
}
# -----------------------------------------------------------------------------
# Time filter
# -----------------------------------------------------------------------------
function Initialize-TimeFilters {
param(
[hashtable]$BoundParameters,
[System.Management.Automation.PSCmdlet]$Cmdlet
)
$StartDate = $null
$EndDate = $null
$TimeFilterDescription = "ALL history (default)"
$usedTimeParam = $false
$activeTimeSet = $Cmdlet.ParameterSetName
Write-Message "Active parameter set: $activeTimeSet" -Level Verbose
Write-Message "BoundParameters keys: $($BoundParameters.Keys -join ', ')" -Level Verbose
try {
switch ($activeTimeSet) {
'RecentHours' {
$UtcNow = [DateTime]::UtcNow
$StartDate = $UtcNow.AddHours(-$BoundParameters['LastHours'])
$EndDate = $UtcNow
$TimeFilterDescription = "Last $($BoundParameters['LastHours']) hour(s) (relative to UTC now)"
$usedTimeParam = $true
Write-Message "RecentHours: StartDate=$StartDate, EndDate=$EndDate" -Level Verbose
break
}
'RecentDays' {
$UtcNow = [DateTime]::UtcNow
$StartDate = $UtcNow.AddDays(-$BoundParameters['LastDays']).Date
$EndDate = $UtcNow
$TimeFilterDescription = "Last $($BoundParameters['LastDays']) day(s) (since $($StartDate.ToString('u')) relative to UTC now)"
$usedTimeParam = $true
Write-Message "RecentDays: StartDate=$StartDate, EndDate=$EndDate" -Level Verbose
break
}
'DateRange' {
Write-Message "Processing DateRange parameter set" -Level Verbose
if ($BoundParameters.ContainsKey('Since')) {
$originalSince = $BoundParameters['Since']
Write-Message "Original Since parameter: $originalSince (Kind: $($originalSince.Kind))" -Level Verbose
if ($originalSince.Kind -ne [DateTimeKind]::Utc) {
Write-Message "Converting Since to UTC" -Level Verbose
$StartDate = [DateTime]::SpecifyKind($originalSince, [DateTimeKind]::Utc)
} else {
$StartDate = $originalSince
}
Write-Message "Final StartDate: $StartDate" -Level Verbose
}
if ($BoundParameters.ContainsKey('Before')) {
$originalBefore = $BoundParameters['Before']
Write-Message "Original Before parameter: $originalBefore (Kind: $($originalBefore.Kind))" -Level Verbose
if ($originalBefore.Kind -ne [DateTimeKind]::Utc) {
Write-Message "Converting Before to UTC" -Level Verbose
$EndDate = [DateTime]::SpecifyKind($originalBefore, [DateTimeKind]::Utc)
} else {
$EndDate = $originalBefore
}
Write-Message "Final EndDate: $EndDate" -Level Verbose
}
if ($StartDate -ne $null -and $EndDate -ne $null) {
$TimeFilterDescription = "between $($StartDate.ToString('u')) and $($EndDate.ToString('u'))"
} elseif ($StartDate -ne $null) {
$TimeFilterDescription = "since $($StartDate.ToString('u'))"
} elseif ($EndDate -ne $null) {
$TimeFilterDescription = "before $($EndDate.ToString('u'))"
}
if ($StartDate -ne $null -and $EndDate -ne $null -and $StartDate -ge $EndDate) {
throw "Invalid date range: The -Since date ('$($StartDate.ToString('u'))') must be earlier than the -Before date ('$($EndDate.ToString('u'))')."
}
$usedTimeParam = $true
Write-Message "DateRange processed: StartDate=$StartDate, EndDate=$EndDate" -Level Verbose
break
}
'FollowChain' {
$StartDate = $null
$EndDate = $null
$TimeFilterDescription = "Chain tracing mode (no time filter)"
$usedTimeParam = $false
Write-Message "FollowChain parameter set detected. Time filtering disabled for chain tracing." -Level Verbose
break
}
'DefaultTime' {
$StartDate = $null
$EndDate = $null
$TimeFilterDescription = "ALL history (no time filter applied by default)"
Write-Message "No time filter specified. Retrieving all history." -Level Verbose
break
}
default {
Write-Message "Could not determine active time parameter set: '$activeTimeSet'. Retrieving all history." -Level Warning
$StartDate = $null
$EndDate = $null
$TimeFilterDescription = "ALL history (fallback)"
}
}
} catch {
Write-Message "Error in Initialize-TimeFilters: $($_.Exception.Message)" -Level Warning
Flush-Messages
throw
}
Write-Message "Final time filter values: StartDate=$StartDate, EndDate=$EndDate, IsActive=$usedTimeParam" -Level Verbose
return New-TimeFilterConfig -StartDate $StartDate -EndDate $EndDate -Description $TimeFilterDescription -IsActive $usedTimeParam
}
# -----------------------------------------------------------------------------
# URL parameter decoding
# -----------------------------------------------------------------------------
function Get-DecodedUrlParameters {
param(
[string]$URL,
[bool]$DecodingAvailable
)
$decodedParams = @{}
$minReadableLen = 4
if (-not $DecodingAvailable -or [string]::IsNullOrWhiteSpace($URL)) {
return $decodedParams
}
try {
$uri = [System.Uri]$URL
if ([string]::IsNullOrWhiteSpace($uri.Query)) {
return $decodedParams
}
$queryCollection = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
foreach ($key in $queryCollection.AllKeys) {
if ([string]::IsNullOrWhiteSpace($key)) { continue }
$urlDecodedValue = $null
try {
$urlDecodedValue = [System.Web.HttpUtility]::UrlDecode($queryCollection[$key])
} catch {
$urlDecodedValue = $queryCollection[$key]
}
$finalValue = $urlDecodedValue
if (-not [string]::IsNullOrWhiteSpace($urlDecodedValue)) {
try {
$base64Standard = $urlDecodedValue.Replace('-', '+').Replace('_', '/')
$padding = (4 - ($base64Standard.Length % 4)) % 4
if ($padding -ne 0 -and -not $base64Standard.Contains('=')) {
$base64Padded = $base64Standard.PadRight($base64Standard.Length + $padding, '=')
} else {
$base64Padded = $base64Standard
}
$bytes = [System.Convert]::FromBase64String($base64Padded)
$extractedStrings = $null
try {
$utf8String = [System.Text.Encoding]::UTF8.GetString($bytes)
$regexPattern = "([\x20-\x7E]{$minReadableLen,})"
$matches = [regex]::Matches($utf8String, $regexPattern, [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(5))
if ($matches.Count -gt 0) {
$extractedStrings = @()
foreach ($match in $matches) {
$extractedStrings += $match.Groups[1].Value
}
}
} catch {
Write-Message "[$key] Error processing decoded Base64 bytes: $($_.Exception.Message)" -Level Debug
}
if ($extractedStrings) {
$finalValue = "[Base64->ASCII]: " + ($extractedStrings -join ' | ')
}
} catch [System.FormatException] {
} catch {
$finalValue = $urlDecodedValue + " [Base64 Decode Error]"
Write-Message "[$key] Other error during Base64 decode: $($_.Exception.Message)" -Level Warning
}
}
$decodedParams[$key] = $finalValue
}
} catch [System.UriFormatException] {
Write-Message "Invalid URL format for URL '$URL'." -Level Debug
} catch {
Write-Message "Error parsing/decoding URL '$URL': $($_.Exception.Message)" -Level Debug
}
return $decodedParams
}
# -----------------------------------------------------------------------------
# Row / column helpers
# -----------------------------------------------------------------------------
function Test-ValidRow {
param(
[System.Data.DataRow]$Row,
[System.Data.DataColumnCollection]$Columns,
[string[]]$RequiredColumns = @('VisitTimeUTC', 'LastVisitTimeUTC', 'DownloadStartTimeUTC', 'DownloadTimeUTC')
)
if ($Row -eq $null) { return $false }
foreach ($reqCol in $RequiredColumns) {
if ($Columns.Contains($reqCol) -and $Row[$reqCol] -ne [System.DBNull]::Value -and $Row[$reqCol] -ne $null) {
$timestampString = ([string]$Row[$reqCol]) -replace '\.(\d{2})\.(\d{3})$', '.$1$2'
if (-not [string]::IsNullOrEmpty($timestampString)) {
return $true
}
}
}
return $false
}
function Get-SafeColumnValue {
param(
[System.Data.DataRow]$Row,
[System.Data.DataColumnCollection]$Columns,
[string]$ColumnName,
[object]$DefaultValue = $null
)
if ($Columns.Contains($ColumnName) -and $Row[$ColumnName] -ne [System.DBNull]::Value -and $Row[$ColumnName] -ne $null) {
return [string]$Row[$ColumnName]
}
return $DefaultValue
}
function Get-FirstAvailableColumnValue {
param(
[System.Data.DataRow]$Row,
[System.Data.DataColumnCollection]$Columns,
[string[]]$ColumnNames
)
foreach ($colName in $ColumnNames) {
$value = Get-SafeColumnValue -Row $Row -Columns $Columns -ColumnName $colName
if (-not [string]::IsNullOrWhiteSpace($value)) {
return $value
}
}
return ''
}
function Format-Bytes {
param([ValidateNotNullOrEmpty()]$BytesObject)
$Bytes = 0L
if (-not [long]::TryParse($BytesObject.ToString(), [ref]$Bytes)) {
return $BytesObject.ToString()
}
$kb = $Bytes / 1KB; $mb = $Bytes / 1MB; $gb = $Bytes / 1GB
if ($gb -ge 0.9) { return "{0:N2} GB" -f $gb }
if ($mb -ge 0.9) { return "{0:N2} MB" -f $mb }
if ($kb -ge 0.9) { return "{0:N2} KB" -f $kb }
return "$Bytes Bytes"
}
# -----------------------------------------------------------------------------
# De-fanging (URL neutralization)
# -----------------------------------------------------------------------------
function Invoke-SmartDefang {
param([string]$Text)
if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
if ($Text -match '^([A-Za-z]:\\|^\\\\|^file:///)') {
return $Text
}
$Text = $Text -replace '\bhttps://', 'hxxps[://]'
$Text = $Text -replace '\bhttp://', 'hxxp[://]'
$Text = $Text -replace '\bftp://', 'fxp[://]'
$Text = $Text -replace '\bsmtp://', 'sxxp[://]'
$Text = $Text -replace '\bldaps://', 'lxxps[://]'
$Text = $Text -replace '\bldap://', 'lxxp[://]'
$Text = $Text -replace '([a-zA-Z0-9-]+)\.([a-zA-Z]{2,})', '$1[.]$2'
$Text = $Text -replace '\b(\d{1,3})\.(\d{1,3}\.\d{1,3}\.\d{1,3})\b', '$1[.]$2'
return $Text
}
function Apply-SmartDefanging {
param([PSCustomObject]$OutputObject, [bool]$NoDefang)
if ($NoDefang) { return $OutputObject }
$fieldsToCheck = @(
'URL', 'SourceURL', 'DownloadURL', 'SearchURL',
'ReferrerURL', 'NextURL',
'Title', 'SourceTitle', 'ReferrerTitle', 'NextTitle',
'DecodedParams'
)
foreach ($field in $fieldsToCheck) {
if ($OutputObject.PSObject.Properties[$field]) {
$value = $OutputObject.$field
if ($null -ne $value -and $value -is [string] -and $value.Trim().Length -gt 0 -and $value -ne 'N/A') {
$defangedValue = Invoke-SmartDefang -Text $value
$OutputObject.$field = $defangedValue
}
}
}
return $OutputObject
}
# -----------------------------------------------------------------------------
# Browser database discovery
# -----------------------------------------------------------------------------
function Find-BrowserDbPaths {
param([string]$UserProfilePath, [string[]]$BrowsersToFind)
Write-Message "Entering Find-BrowserDbPaths with UserProfilePath: '$UserProfilePath', BrowsersToFind: $($BrowsersToFind -join ', ')" -Level Debug
$dbPaths = @{}
if ([string]::IsNullOrWhiteSpace($UserProfilePath)) {
Write-Message "Invalid UserProfilePath provided to Find-BrowserDbPaths" -Level Warning
return $dbPaths
}
if (-not $BrowsersToFind -or $BrowsersToFind.Count -eq 0) {
Write-Message "No browsers specified to find" -Level Warning
return $dbPaths
}
$browserConfigs = @{
'Chrome' = @{
BasePath = "AppData\Local\Google\Chrome\User Data"
HistoryFile = "History"
}
'Edge' = @{
BasePath = "AppData\Local\Microsoft\Edge\User Data"
HistoryFile = "History"
}
'Vivaldi' = @{
BasePath = "AppData\Local\Vivaldi\User Data"
HistoryFile = "History"
}
'Brave' = @{
BasePath = "AppData\Local\BraveSoftware\Brave-Browser\User Data"
HistoryFile = "History"
}
'Firefox' = @{
BasePath = "AppData\Roaming\Mozilla\Firefox\Profiles"
HistoryFile = "places.sqlite"
}
}
try {
foreach ($browser in $BrowsersToFind) {
$foundPaths = @()
try {
$config = $browserConfigs[$browser]
if (-not $config) {
Write-Message "No configuration found for browser: $browser" -Level Debug
continue
}
$basePath = [string]$config.BasePath
$historyFile = [string]$config.HistoryFile
Write-Message "Browser: $browser, BasePath type: $($config.BasePath.GetType().Name), value: '$($config.BasePath)'" -Level Debug
Write-Message "Browser: $browser, HistoryFile type: $($config.HistoryFile.GetType().Name), value: '$($config.HistoryFile)'" -Level Debug
if ([string]::IsNullOrWhiteSpace($basePath)) {
Write-Message "Invalid BasePath configuration for $browser" -Level Warning
continue
}
if ([string]::IsNullOrWhiteSpace($historyFile)) {
Write-Message "Invalid HistoryFile configuration for $browser" -Level Warning
continue
}
Write-Message "Processing $browser - BasePath: '$basePath', HistoryFile: '$historyFile'" -Level Debug
if ($browser -eq 'Firefox') {
Write-Message "About to call Join-Path for Firefox with '$UserProfilePath' and '$basePath'" -Level Debug
$firefoxProfilesBase = Join-Path $UserProfilePath $basePath
Write-Message "Firefox profiles base path: $firefoxProfilesBase" -Level Debug
if (Test-Path -Path $firefoxProfilesBase -PathType Container) {
$firefoxProfiles = Get-ChildItem -Path $firefoxProfilesBase -Directory -ErrorAction SilentlyContinue
foreach ($profile in $firefoxProfiles) {
if ($profile -and $profile.FullName) {
Write-Message "About to call Join-Path for Firefox profile with '$($profile.FullName)' and '$historyFile'" -Level Debug
$placesPath = Join-Path $profile.FullName $historyFile
if (Test-Path -Path $placesPath -PathType Leaf) {
Write-Message "Found Firefox history in profile '$($profile.Name)': $placesPath" -Level Verbose
$foundPaths += $placesPath
}
}
}
} else {
Write-Message "Firefox profiles base path not found: $firefoxProfilesBase" -Level Debug
}
} else {
Write-Message "About to call Join-Path for $browser with '$UserProfilePath' and '$basePath'" -Level Debug
$browserBase = Join-Path $UserProfilePath $basePath
Write-Message "$browser base path: $browserBase" -Level Debug
if (Test-Path $browserBase -PathType Container) {
$browserProfiles = Get-ChildItem -Path $browserBase -Directory -ErrorAction SilentlyContinue | Where-Object {
$_.Name -eq 'Default' -or $_.Name -like 'Profile *'
}
foreach ($profile in $browserProfiles) {
if ($profile -and $profile.FullName) {
Write-Message "About to call Join-Path for $browser profile with '$($profile.FullName)' and '$historyFile'" -Level Debug
$historyPath = Join-Path $profile.FullName $historyFile
if (Test-Path -Path $historyPath -PathType Leaf) {
Write-Message "Found $browser history for profile '$($profile.Name)': $historyPath" -Level Verbose
$foundPaths += $historyPath
}
}
}
} else {
Write-Message "$browser base path not found: $browserBase" -Level Debug
}
}
if ($foundPaths.Count -gt 0) {
$dbPaths[$browser] = $foundPaths
} else {
Write-Message "No history databases found for $browser in profile: $UserProfilePath" -Level Verbose
}
} catch {
Write-Message "Error finding paths for $browser in '$UserProfilePath': $($_.Exception.Message)" -Level Warning
Write-Message "Full error details: $($_.Exception | Format-List * | Out-String)" -Level Debug
Flush-Messages
}
}
} catch {
Write-Message "Error in Find-BrowserDbPaths: $($_.Exception.Message)" -Level Warning
Write-Message "Find-BrowserDbPaths error details: $($_.Exception | Format-List * | Out-String)" -Level Debug
Flush-Messages
throw
}
Write-Message "Find-BrowserDbPaths returning $($dbPaths.Count) browser entries" -Level Debug
return $dbPaths
}
function Find-BrowserDbPathsFromCustom {
param([string]$CustomPath, [string[]]$BrowsersToFind)
Write-Message "Entering Find-BrowserDbPathsFromCustom with CustomPath: '$CustomPath'" -Level Debug
$dbPaths = @{}
if ([string]::IsNullOrWhiteSpace($CustomPath) -or -not (Test-Path -Path $CustomPath)) {
Write-Message "Custom -Path not found or invalid: $CustomPath" -Level Warning
return $dbPaths
}
$chromiumSelected = @($BrowsersToFind | Where-Object { $_ -in @('Chrome', 'Edge', 'Vivaldi', 'Brave') })
$firefoxSelected = $BrowsersToFind -contains 'Firefox'
$candidates = @()
if (Test-Path -Path $CustomPath -PathType Leaf) {
$candidates += Get-Item -Path $CustomPath -ErrorAction SilentlyContinue
} else {
$candidates += Get-ChildItem -Path $CustomPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('History', 'places.sqlite') -and -not $_.LinkType }
}
foreach ($f in $candidates) {
if (-not $f) { continue }
$isFirefoxName = ($f.Name -eq 'places.sqlite')
$isChromiumName = ($f.Name -eq 'History')
if ($isFirefoxName) {
if ($firefoxSelected) {
if (-not $dbPaths.ContainsKey('Firefox')) { $dbPaths['Firefox'] = @() }
$dbPaths['Firefox'] += $f.FullName
Write-Message "Custom path matched Firefox database: $($f.FullName)" -Level Verbose
}
continue
}
# History (chromium) or an explicitly supplied file with a non-standard name.
$lower = $f.FullName.ToLower()
$browser = $null
if ($lower -like '*\edge\*' -or $lower -like '*edge*') { $browser = 'Edge' }
elseif ($lower -like '*brave*') { $browser = 'Brave' }
elseif ($lower -like '*vivaldi*') { $browser = 'Vivaldi' }
elseif ($lower -like '*chrome*') { $browser = 'Chrome' }
if (-not $browser) {
if (-not $isChromiumName -and $firefoxSelected -and $chromiumSelected.Count -eq 0) {
# Explicit single file, only Firefox selected -> treat as Firefox.
if (-not $dbPaths.ContainsKey('Firefox')) { $dbPaths['Firefox'] = @() }
$dbPaths['Firefox'] += $f.FullName
Write-Message "Custom path file treated as Firefox (by selection): $($f.FullName)" -Level Verbose
continue
}
$browser = if ($chromiumSelected.Count -eq 1) { $chromiumSelected[0] } else { 'Chrome' }
}
if ($browser -in $BrowsersToFind) {
if (-not $dbPaths.ContainsKey($browser)) { $dbPaths[$browser] = @() }
$dbPaths[$browser] += $f.FullName
Write-Message "Custom path matched $browser database: $($f.FullName)" -Level Verbose
} else {
Write-Message "Skipping $($f.FullName): inferred browser '$browser' not in selected set." -Level Verbose
}
}
Write-Message "Find-BrowserDbPathsFromCustom returning $($dbPaths.Count) browser entries" -Level Debug
return $dbPaths
}
# -----------------------------------------------------------------------------
# Safe DB copy (forensic safety: never touch originals)
# -----------------------------------------------------------------------------
function Copy-DbToTemp {
param([string]$OriginalPath)
if ([string]::IsNullOrWhiteSpace($OriginalPath)) {
Write-Message "Invalid or empty OriginalPath provided to Copy-DbToTemp" -Level Warning
return $null
}
if (-not (Test-Path -Path $OriginalPath -PathType Leaf)) {
Write-Message "Original database file not found: $OriginalPath" -Level Warning
return $null
}
if ((Get-Item -Path $OriginalPath -Force).LinkType) {
Write-Message "Refusing to follow symlink/reparse point: $OriginalPath" -Level Warning
return $null
}
try {
$tempFileName = [System.IO.Path]::GetRandomFileName() + "_" + [System.IO.Path]::GetFileName($OriginalPath)
$tempPath = Join-Path ([System.IO.Path]::GetTempPath()) $tempFileName
Write-Message "Copying '$OriginalPath' to '$tempPath'" -Level Debug
Copy-Item -Path $OriginalPath -Destination $tempPath -Force -ErrorAction Stop
# Copy WAL/SHM/journal sidecars so history from a CURRENTLY OPEN/RUNNING browser
# (recent activity not yet checkpointed into the main DB) is captured too.
foreach ($sc in @('-wal','-shm','-journal')) {
if ((Test-Path -Path "$OriginalPath$sc" -PathType Leaf) -and -not (Get-Item -Path "$OriginalPath$sc" -Force).LinkType) {
Copy-Item -Path "$OriginalPath$sc" -Destination "$tempPath$sc" -Force -ErrorAction SilentlyContinue
}
}
Write-Message "Copied '$OriginalPath' to '$tempPath' for querying." -Level Verbose
return $tempPath
} catch {
Write-Message "Failed to copy database file '$OriginalPath' to temp location: $($_.Exception.Message)" -Level Warning
Write-Message "Copy error details: $($_.Exception | Format-List * | Out-String)" -Level Debug
return $null
}
}
# -----------------------------------------------------------------------------
# Transition / visit-type decoding
# -----------------------------------------------------------------------------
function Format-ChromeTransitionDetailed {
param([int]$TransitionValue)
$coreTransition = $TransitionValue -band 0xFF
$isClientRedirect = ($TransitionValue -band 0x40000000) -ne 0
$isServerRedirect = ($TransitionValue -band 0x80000000) -ne 0
$isForwardButton = ($TransitionValue -band 0x02000000) -ne 0
$isBackButton = ($TransitionValue -band 0x04000000) -ne 0
$isFromAddressBar = ($TransitionValue -band 0x08000000) -ne 0
$isHomePage = ($TransitionValue -band 0x10000000) -ne 0
$coreDesc = switch ($coreTransition) {
0 {'Link Click'} 1 {'Typed'} 2 {'Auto Bookmark'} 3 {'Auto Subframe'}
4 {'Manual Subframe'} 5 {'Generated'} 6 {'Start Page'} 7 {'Form Submit'}
8 {'Reload'} 9 {'Keyword'} 10 {'Keyword Generated'}
default {"Unknown Core ($coreTransition)"}
}
$details = @{
CoreType = $coreDesc
IsClientRedirect = $isClientRedirect
IsServerRedirect = $isServerRedirect
IsRedirect = $isClientRedirect -or $isServerRedirect
NavigationContext = @()
RawTransition = $TransitionValue
SuspiciousIndicators = @()
}
if ($isClientRedirect) {
$details.RedirectType = 'Client'
} elseif ($isServerRedirect) {
$details.RedirectType = 'Server'
} else {
$details.RedirectType = 'None'
}
if ($isForwardButton) { $details.NavigationContext += 'Forward Button' }
if ($isBackButton) { $details.NavigationContext += 'Back Button' }
if ($isFromAddressBar) { $details.NavigationContext += 'From Address Bar' }
if ($isHomePage) { $details.NavigationContext += 'Home Page' }
if ($details.IsRedirect -and $coreTransition -eq 0) { $details.SuspiciousIndicators += 'Redirect on Link Click' }
if ($details.IsClientRedirect -and $details.IsServerRedirect) { $details.SuspiciousIndicators += 'Both Client and Server Redirect' }
return $details
}
function Format-FirefoxVisitTypeDetailed {
param([int]$VisitType)
$coreType = switch ($VisitType) {
1 {'Link Click'} 2 {'Typed'} 3 {'Bookmark'} 4 {'Embedded'}
5 {'Permanent Redirect'} 6 {'Temporary Redirect'} 7 {'Download'}
8 {'Framed Link'} default {"Unknown ($VisitType)"}
}
$isRedirect = $VisitType -in @(5, 6)
$redirectType = 'None'
if ($VisitType -eq 5) {
$redirectType = 'Permanent (301)'
} elseif ($VisitType -eq 6) {
$redirectType = 'Temporary (302/307)'
}
$details = @{
CoreType = $coreType
IsRedirect = $isRedirect
RedirectType = $redirectType
RawVisitType = $VisitType
SuspiciousIndicators = @()
}
return $details
}
function Format-TransitionDetails {
param([hashtable]$TransitionDetails)
if (-not $TransitionDetails) { return $null }
$details = @()
if ($TransitionDetails.CoreType) {
$details += "Type: $($TransitionDetails.CoreType)"
}
if ($TransitionDetails.IsRedirect) {
$details += "Redirect: $($TransitionDetails.RedirectType)"
} else {
$details += "Redirect: None"
}
if ($TransitionDetails.NavigationContext -and $TransitionDetails.NavigationContext.Count -gt 0) {
$details += "Context: $($TransitionDetails.NavigationContext -join ', ')"
}
if ($TransitionDetails.SuspiciousIndicators -and $TransitionDetails.SuspiciousIndicators.Count -gt 0) {
$details += "SUSPICIOUS: $($TransitionDetails.SuspiciousIndicators -join ', ')"
}
if ($TransitionDetails.RawTransition) {
$details += "Raw: $($TransitionDetails.RawTransition)"
} elseif ($TransitionDetails.RawVisitType) {
$details += "Raw: $($TransitionDetails.RawVisitType)"
}
return ($details -join ' | ')
}
function Format-ChainInfo {
param([hashtable]$ChainInfo)
if (-not $ChainInfo -or -not $ChainInfo.IsPartOfChain) { return $null }
$details = @()
if ($ChainInfo.ChainPosition) {
$details += "Position: $($ChainInfo.ChainPosition)"
}
if ($ChainInfo.TimeToNext) {
$formattedTime = Format-InvariantNumber $ChainInfo.TimeToNext 3
$details += "Next: ${formattedTime}s"
}
if ($ChainInfo.TimeFromPrevious) {
$formattedTime = Format-InvariantNumber $ChainInfo.TimeFromPrevious 3
$details += "Prev: ${formattedTime}s"
}
if ($ChainInfo.SuspiciousIndicators -and $ChainInfo.SuspiciousIndicators.Count -gt 0) {
$uniqueIndicators = $ChainInfo.SuspiciousIndicators | Sort-Object -Unique
$details += "SUSPICIOUS: $($uniqueIndicators -join ', ')"
}
return ($details -join ' | ')
}
# -----------------------------------------------------------------------------
# Redirect-chain analysis
# -----------------------------------------------------------------------------
function Analyze-RedirectChain {
param([array]$AllRecords)
if (-not $AnalyzeRedirectChains -or $AllRecords.Count -eq 0) {
return $AllRecords
}
Write-Message "Analyzing redirect chains for $($AllRecords.Count) records..." -Level Verbose
$groupedRecords = $AllRecords | Group-Object { "$($_.User)-$($_.Browser)" }
foreach ($group in $groupedRecords) {
$records = $group.Group | Sort-Object TimestampUTC
for ($i = 0; $i -lt $records.Count - 1; $i++) {
$currentRecord = $records[$i]
$nextRecord = $records[$i + 1]
try {
$currentTime = $currentRecord.TimestampUTC
$nextTime = $nextRecord.TimestampUTC
$timeDiff = ($nextTime - $currentTime).TotalSeconds
$isVisitDownloadPair = (
$currentRecord.RecordType -eq 'Visit' -and
$nextRecord.RecordType -eq 'Download' -and
$currentRecord.PSObject.Properties['CurrentVisitID'] -and
$nextRecord.PSObject.Properties['InitiatingVisitID'] -and
$currentRecord.CurrentVisitID -eq $nextRecord.InitiatingVisitID
)
$isDownloadVisitPair = (
$currentRecord.RecordType -eq 'Download' -and
$nextRecord.RecordType -eq 'Visit' -and
$currentRecord.PSObject.Properties['InitiatingVisitID'] -and
$nextRecord.PSObject.Properties['CurrentVisitID'] -and
$currentRecord.InitiatingVisitID -eq $nextRecord.CurrentVisitID
)
if ($isVisitDownloadPair -or $isDownloadVisitPair) {
Write-Message "Skipping visit-download pair: $($currentRecord.RecordType) -> $($nextRecord.RecordType)" -Level Debug
continue
}
if ($timeDiff -le 30 -and $timeDiff -ge 0 -and
$currentRecord.RecordType -eq 'Visit' -and $nextRecord.RecordType -eq 'Visit') {
$suspiciousIndicators = @()
$isLikelyChain = $false
$isMultiTabPattern = $false
$currentReferrer = $null
$nextReferrer = $null
if ($currentRecord.PSObject.Properties['ReferrerURL']) {
$currentReferrer = $currentRecord.ReferrerURL
}
if ($nextRecord.PSObject.Properties['ReferrerURL']) {
$nextReferrer = $nextRecord.ReferrerURL
}
if ($currentReferrer -and $nextReferrer -and
$currentReferrer -eq $nextReferrer -and
$currentRecord.PSObject.Properties['PreviousVisitID'] -and
$nextRecord.PSObject.Properties['PreviousVisitID'] -and
$currentRecord.PreviousVisitID -eq $nextRecord.PreviousVisitID -and
$timeDiff -gt 5) {
$isMultiTabPattern = $true
Write-Message "Multi-tab pattern detected: $($currentRecord.URL) and $($nextRecord.URL) both from $currentReferrer" -Level Debug
}
if (-not $isMultiTabPattern) {
if ($timeDiff -lt 0.1) {
$suspiciousIndicators += 'Very Fast Redirect (<100ms)'
$isLikelyChain = $true
} elseif ($timeDiff -lt 1.0) {
$suspiciousIndicators += 'Fast Redirect (<1s)'
$isLikelyChain = $true
} elseif ($timeDiff -lt 5.0) {
$suspiciousIndicators += 'Rapid Navigation (<5s)'
$isLikelyChain = $true
} elseif ($timeDiff -le 30) {
$isLikelyChain = $true
}
} else {
if ($timeDiff -lt 0.5) {
$suspiciousIndicators += 'Very Fast Multi-Tab Opening'
$isLikelyChain = $true
}
}
try {
$currentDomain = ([System.Uri]($currentRecord.URL -replace '\[:\]', ':' -replace '\[\.\]', '.')).Host
$nextDomain = ([System.Uri]($nextRecord.URL -replace '\[:\]', ':' -replace '\[\.\]', '.')).Host
if ($currentDomain -ne $nextDomain -and -not $isMultiTabPattern) {
$suspiciousIndicators += 'Domain Change'
$isLikelyChain = $true
}
} catch {
}
$currentHasRedirect = $false
$nextHasRedirect = $false
if ($currentRecord.PSObject.Properties['TransitionInfo'] -and $currentRecord.TransitionInfo) {
$transitionInfo = $currentRecord.TransitionInfo.ToString()
if ($transitionInfo.Contains('Permanent Redirect') -or
$transitionInfo.Contains('Temporary Redirect') -or
$transitionInfo.Contains('Server Redirect') -or
$transitionInfo.Contains('Client Redirect') -or
$transitionInfo -match 'Redirect') {
$currentHasRedirect = $true
$suspiciousIndicators += 'Explicit Redirect'
$isLikelyChain = $true
}
}
if ($nextRecord.PSObject.Properties['TransitionInfo'] -and $nextRecord.TransitionInfo) {
$transitionInfo = $nextRecord.TransitionInfo.ToString()
if ($transitionInfo.Contains('Permanent Redirect') -or
$transitionInfo.Contains('Temporary Redirect') -or
$transitionInfo.Contains('Server Redirect') -or
$transitionInfo.Contains('Client Redirect') -or
$transitionInfo -match 'Redirect') {
$nextHasRedirect = $true
if ('Explicit Redirect' -notin $suspiciousIndicators) {
$suspiciousIndicators += 'Explicit Redirect'
}
$isLikelyChain = $true
}
}
if ($isLikelyChain -and $suspiciousIndicators.Count -gt 0) {
if (-not $currentRecord.PSObject.Properties['ChainInfo']) {
$currentRecord | Add-Member -NotePropertyName 'ChainInfo' -NotePropertyValue @{
IsPartOfChain = $true
TimeToNext = [Math]::Round($timeDiff, 3)
NextURL = $nextRecord.URL
ChainPosition = $i + 1
SuspiciousIndicators = $suspiciousIndicators.Clone()
IsMultiTab = $isMultiTabPattern
}
} else {
$currentRecord.ChainInfo.TimeToNext = [Math]::Round($timeDiff, 3)
$currentRecord.ChainInfo.NextURL = $nextRecord.URL
$currentRecord.ChainInfo.SuspiciousIndicators += $suspiciousIndicators
$currentRecord.ChainInfo.SuspiciousIndicators = @($currentRecord.ChainInfo.SuspiciousIndicators | Sort-Object -Unique)
$currentRecord.ChainInfo.IsMultiTab = $isMultiTabPattern
}
if (-not $nextRecord.PSObject.Properties['ChainInfo']) {
$nextRecord | Add-Member -NotePropertyName 'ChainInfo' -NotePropertyValue @{
IsPartOfChain = $true
TimeFromPrevious = [Math]::Round($timeDiff, 3)
PreviousURL = $currentRecord.URL
ChainPosition = $i + 2
SuspiciousIndicators = $suspiciousIndicators.Clone()
IsMultiTab = $isMultiTabPattern
}
} else {
$nextRecord.ChainInfo.TimeFromPrevious = [Math]::Round($timeDiff, 3)
$nextRecord.ChainInfo.PreviousURL = $currentRecord.URL
$nextRecord.ChainInfo.SuspiciousIndicators += $suspiciousIndicators
$nextRecord.ChainInfo.SuspiciousIndicators = @($nextRecord.ChainInfo.SuspiciousIndicators | Sort-Object -Unique)
$nextRecord.ChainInfo.IsMultiTab = $isMultiTabPattern
}
$patternType = if ($isMultiTabPattern) { "multi-tab" } else { "sequential" }
Write-Message "Flagged $patternType navigation: $($currentRecord.URL) -> $($nextRecord.URL) (${timeDiff}s, indicators: $($suspiciousIndicators -join ', '))" -Level Debug
}
}
} catch {
Write-Message "Error parsing timestamps for chain analysis: $($_.Exception.Message)" -Level Debug
}
}
}
return $AllRecords
}
# =============================================================================
# FollowChain mode: navigation-chain tracing
# =============================================================================
function Trace-NavigationChain {
param(
[Parameter(Mandatory = $true)]
[System.IntPtr]$Database,
[Parameter(Mandatory = $true)]
[string]$BrowserType,
[Parameter(Mandatory = $true)]
[long]$StartingVisitID
)
Write-Message "Tracing navigation chain for VisitID: $StartingVisitID in $BrowserType" -Level Verbose
if ($BrowserType -in @('Chrome', 'Edge', 'Vivaldi', 'Brave')) {
return Trace-ChromiumChain -Database $Database -BrowserType $BrowserType -StartingVisitID $StartingVisitID
} elseif ($BrowserType -eq 'Firefox') {
return Trace-FirefoxChain -Database $Database -StartingVisitID $StartingVisitID
}
return $null
}
function Trace-ChromiumChain {
param(
[System.IntPtr]$Database,
[string]$BrowserType,
[long]$StartingVisitID
)
$microsecondsPerSecond = Format-InvariantNumber 1000000
$chromeTimeSelectConv = "/ $microsecondsPerSecond - 11644473600, 'unixepoch'"
$sqliteTimeFormat = "'%Y-%m-%d %H:%M:%S.%f'"
$microsecondDivisor = Format-InvariantNumber 1000000.0
try {
$startingVisitString = Format-InvariantNumber $StartingVisitID
$targetQuery = @"
SELECT
strftime($sqliteTimeFormat, v.visit_time $chromeTimeSelectConv) AS VisitTimeUTC,
v.id AS CurrentVisitID,
v.from_visit AS PreviousVisitID,
u.url AS URL,
COALESCE(u.title, '') AS Title,
v.transition,
v.visit_duration / $microsecondsPerSecond AS VisitDurationSeconds,
v.visit_time,
ref_u.url AS ReferrerURL,
COALESCE(ref_u.title, '') AS ReferrerTitle
FROM visits v
JOIN urls u ON v.url = u.id
LEFT JOIN visits ref_v ON v.from_visit = ref_v.id
LEFT JOIN urls ref_u ON ref_v.url = ref_u.id
WHERE v.id = $startingVisitString;
"@
$targetResult = [SqliteHelper]::Execute($Database, $targetQuery)
if ($targetResult.Rows.Count -eq 0) {
Write-Message "VisitID $StartingVisitID not found in $BrowserType database" -Level Warning
return $null
}
$targetVisitTime = $targetResult.Rows[0]['visit_time']
$windowStart = $targetVisitTime - 300000000
$windowEnd = $targetVisitTime + 300000000
$windowStartString = Format-InvariantNumber $windowStart
$windowEndString = Format-InvariantNumber $windowEnd
$targetVisitTimeString = Format-InvariantNumber $targetVisitTime
$chainQuery = @"
SELECT
strftime($sqliteTimeFormat, v.visit_time $chromeTimeSelectConv) AS VisitTimeUTC,
v.id AS CurrentVisitID,
v.from_visit AS PreviousVisitID,
u.url AS URL,
COALESCE(u.title, '') AS Title,
v.transition AS TransitionValue,
v.visit_duration / $microsecondsPerSecond AS VisitDurationSeconds,
v.visit_time,
COALESCE(ref_u.url, '') AS ReferrerURL,
COALESCE(ref_u.title, '') AS ReferrerTitle,
CASE
WHEN v.id = $startingVisitString THEN 'Center'
WHEN v.visit_time < $targetVisitTimeString THEN 'Backward'
WHEN v.visit_time > $targetVisitTimeString THEN 'Forward'
ELSE 'Center'
END AS ChainDirection,
CASE
WHEN v.id = $startingVisitString THEN 0
WHEN v.visit_time < $targetVisitTimeString THEN
-1 * ROW_NUMBER() OVER (PARTITION BY (v.visit_time < $targetVisitTimeString) ORDER BY v.visit_time DESC)
WHEN v.visit_time > $targetVisitTimeString THEN
ROW_NUMBER() OVER (PARTITION BY (v.visit_time > $targetVisitTimeString) ORDER BY v.visit_time ASC)
ELSE 0
END AS ChainLevel,
LEAD(v.id) OVER (ORDER BY v.visit_time) AS NextVisitID,
LEAD(u.url) OVER (ORDER BY v.visit_time) AS NextURL,
LEAD(COALESCE(u.title, '')) OVER (ORDER BY v.visit_time) AS NextTitle,
(LEAD(v.visit_time) OVER (ORDER BY v.visit_time) - v.visit_time) / $microsecondDivisor AS TimeToNextSeconds
FROM visits v
JOIN urls u ON v.url = u.id
LEFT JOIN visits ref_v ON v.from_visit = ref_v.id
LEFT JOIN urls ref_u ON ref_v.url = ref_u.id
WHERE (
v.id = $startingVisitString OR
(v.visit_time >= $windowStartString AND v.visit_time <= $windowEndString AND v.id != $startingVisitString)
)
ORDER BY v.visit_time;
"@
Write-Message "Enhanced Chromium Chain Query: $chainQuery" -Level Debug
$chainResult = [SqliteHelper]::Execute($Database, $chainQuery)
if ($chainResult.Rows.Count -gt 0) {
return ,$chainResult
} else {
return Create-SingleVisitResult -TargetResult $targetResult
}
} catch {
Write-Message "Error in $BrowserType chain query - $($_.Exception.Message)" -Level Warning
return $null
}
}
function Trace-FirefoxChain {
param(
[System.IntPtr]$Database,
[long]$StartingVisitID
)
$microsecondsPerSecond = Format-InvariantNumber 1000000
$microsecondDivisor = Format-InvariantNumber 1000000.0
$firefoxTimeSelectConv = "/ $microsecondsPerSecond, 'unixepoch'"
$sqliteTimeFormat = "'%Y-%m-%d %H:%M:%S.%f'"
$startingVisitString = Format-InvariantNumber $StartingVisitID
try {
$targetQuery = @"
SELECT
strftime($sqliteTimeFormat, h.visit_date $firefoxTimeSelectConv) AS VisitTimeUTC,
h.id AS CurrentVisitID,
h.visit_date,
h.visit_type AS VisitType,
p.url AS URL,
COALESCE(p.title, '') AS Title
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
WHERE h.id = $startingVisitString;
"@
Write-Message "Getting target visit info for VisitID: $StartingVisitID" -Level Verbose
$targetResult = [SqliteHelper]::Execute($Database, $targetQuery)
if ($targetResult.Rows.Count -eq 0) {
Write-Message "VisitID $StartingVisitID not found in Firefox database" -Level Warning
return $null
}
$targetVisitTime = $targetResult.Rows[0]['visit_date']
Write-Message "Target visit time (microseconds): $targetVisitTime" -Level Verbose
$windowStart = $targetVisitTime - 300000000
$windowEnd = $targetVisitTime + 300000000
$windowStartString = Format-InvariantNumber $windowStart
$windowEndString = Format-InvariantNumber $windowEnd
$targetVisitTimeString = Format-InvariantNumber $targetVisitTime
$chainQuery = @"
SELECT
strftime($sqliteTimeFormat, h.visit_date $firefoxTimeSelectConv) AS VisitTimeUTC,
h.id AS CurrentVisitID,
h.from_visit AS PreviousVisitID,
p.url AS URL,
COALESCE(p.title, '') AS Title,
h.visit_type AS VisitType,
h.visit_date,
COALESCE(ref_p.url, '') AS ReferrerURL,
COALESCE(ref_p.title, '') AS ReferrerTitle,
CASE
WHEN h.id = $startingVisitString THEN 'Center'
WHEN h.visit_date < $targetVisitTimeString THEN 'Backward'
WHEN h.visit_date > $targetVisitTimeString THEN 'Forward'
ELSE 'Center'
END AS ChainDirection,
CASE
WHEN h.id = $startingVisitString THEN 0
WHEN h.visit_date < $targetVisitTimeString THEN
-1 * ROW_NUMBER() OVER (PARTITION BY (h.visit_date < $targetVisitTimeString) ORDER BY h.visit_date DESC)
WHEN h.visit_date > $targetVisitTimeString THEN
ROW_NUMBER() OVER (PARTITION BY (h.visit_date > $targetVisitTimeString) ORDER BY h.visit_date ASC)
ELSE 0
END AS ChainLevel,
LEAD(h.id) OVER (ORDER BY h.visit_date) AS NextVisitID,
LEAD(p.url) OVER (ORDER BY h.visit_date) AS NextURL,
LEAD(COALESCE(p.title, '')) OVER (ORDER BY h.visit_date) AS NextTitle,
(LEAD(h.visit_date) OVER (ORDER BY h.visit_date) - h.visit_date) / $microsecondDivisor AS TimeToNextSeconds
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id
LEFT JOIN moz_places ref_p ON ref_h.place_id = ref_p.id
WHERE (
h.id = $startingVisitString OR
(h.visit_date >= $windowStartString AND h.visit_date <= $windowEndString AND h.id != $startingVisitString)
)
ORDER BY h.visit_date;
"@
Write-Message "Enhanced Firefox Chain Query: $chainQuery" -Level Debug
$chainResult = [SqliteHelper]::Execute($Database, $chainQuery)
Write-Message "Chain query returned $($chainResult.Rows.Count) rows" -Level Verbose
if ($chainResult.Rows.Count -gt 0) {
return ,$chainResult
} else {
return Create-SingleVisitResult -TargetResult $targetResult
}
} catch {
Write-Message "Error in Firefox chain query - $($_.Exception.Message)" -Level Warning
Write-Message "Firefox query error: $($_.Exception | Format-List * | Out-String)" -Level Debug
return $null
}
}
# -----------------------------------------------------------------------------
# Chain output formatting
# -----------------------------------------------------------------------------
function Create-SingleVisitResult {
param([System.Data.DataTable]$TargetResult)
$singleResult = New-Object System.Data.DataTable
foreach ($col in $TargetResult.Columns) {
if ($col.ColumnName -ne 'visit_time' -and $col.ColumnName -ne 'visit_date') {
$newCol = New-Object System.Data.DataColumn($col.ColumnName, [System.Object])
$singleResult.Columns.Add($newCol)
}
}
$chainColumns = @('ChainLevel', 'ChainDirection', 'NextVisitID', 'NextURL', 'NextTitle', 'TimeToNextSeconds', 'TransitionValue', 'VisitType')
foreach ($colName in $chainColumns) {
if (-not $singleResult.Columns.Contains($colName)) {
$singleResult.Columns.Add((New-Object System.Data.DataColumn($colName, [System.Object])))
}
}
$newRow = $singleResult.NewRow()
foreach ($col in $TargetResult.Columns) {
if ($col.ColumnName -ne 'visit_time' -and $col.ColumnName -ne 'visit_date' -and $singleResult.Columns.Contains($col.ColumnName)) {
$newRow[$col.ColumnName] = $TargetResult.Rows[0][$col.ColumnName]
}
}
$newRow['ChainLevel'] = 0
$newRow['ChainDirection'] = 'Center'
$newRow['NextVisitID'] = [System.DBNull]::Value
$newRow['NextURL'] = [System.DBNull]::Value
$newRow['NextTitle'] = [System.DBNull]::Value
$newRow['TimeToNextSeconds'] = [System.DBNull]::Value
if ($singleResult.Columns.Contains('TransitionValue') -and (-not $newRow['TransitionValue'] -or $newRow['TransitionValue'] -eq [System.DBNull]::Value)) {
if ($TargetResult.Columns.Contains('transition')) {
$newRow['TransitionValue'] = $TargetResult.Rows[0]['transition']
} else {
$newRow['TransitionValue'] = 1
}
}
if ($singleResult.Columns.Contains('VisitType') -and (-not $newRow['VisitType'] -or $newRow['VisitType'] -eq [System.DBNull]::Value)) {
if ($TargetResult.Columns.Contains('visit_type')) {
$newRow['VisitType'] = $TargetResult.Rows[0]['visit_type']
} else {
$newRow['VisitType'] = 1
}
}
$singleResult.Rows.Add($newRow)
return ,$singleResult
}
function Format-ChainOutputResults {
param(
[array]$SortedChainResults,
[long]$TargetVisitID
)
Write-Message "`n=== ENHANCED NAVIGATION CHAIN ANALYSIS ==="
Write-Message "Target VisitID: $TargetVisitID"
Write-Message "Total visits in chain: $($SortedChainResults.Count)"
$visitIDs = @()
$referencedVisitIDs = @()
foreach ($result in $SortedChainResults) {
if ($result.PSObject.Properties['CurrentVisitID'] -and $result.CurrentVisitID) {
try {
$visitIDs += [long]$result.CurrentVisitID
} catch {
}
}
if ($result.PSObject.Properties['PreviousVisitID'] -and $result.PreviousVisitID -and $result.PreviousVisitID -ne '0') {
try {
$referencedVisitIDs += [long]$result.PreviousVisitID
} catch { }
}
if ($result.PSObject.Properties['NextVisitID'] -and $result.NextVisitID) {
try {
$referencedVisitIDs += [long]$result.NextVisitID
} catch { }
}
}
if ($visitIDs.Count -gt 1) {
$sortedIDs = $visitIDs | Sort-Object
$minID = $sortedIDs[0]
$maxID = $sortedIDs[-1]
$expectedRange = $minID..$maxID
$missingIDs = @()
foreach ($expectedID in $expectedRange) {
if ($expectedID -notin $visitIDs) {
if ($expectedID -in $referencedVisitIDs) {
Write-Message "INFO: Visit ID $expectedID is referenced but outside analysis window" -Level Verbose
} else {
$missingIDs += $expectedID
}
}
}
if ($missingIDs.Count -gt 0) {
Write-Message "Missing Visit IDs in sequence: $($missingIDs -join ', ')" -Level Warning
Write-Message "This may indicate deleted history, failed page loads, or database cleanup."
}
}
foreach ($result in $SortedChainResults) {
if ($result.NextVisitID -and $result.NextVisitID -notin $visitIDs) {
$nextVisitInChain = $SortedChainResults | Where-Object { $_.CurrentVisitID -eq $result.NextVisitID }
if (-not $nextVisitInChain) {
Write-Message "INFO: Visit $($result.CurrentVisitID) references next visit $($result.NextVisitID) which is outside analysis window" -Level Verbose
}
}
if ($result.PreviousVisitID -and $result.PreviousVisitID -ne '0' -and $result.PreviousVisitID -notin $visitIDs) {
Write-Message "INFO: Visit $($result.CurrentVisitID) references previous visit $($result.PreviousVisitID) which is outside analysis window" -Level Verbose
}
}
$simultaneousVisits = $SortedChainResults | Group-Object TimestampUTC | Where-Object { $_.Count -gt 1 }
$simultaneousVisitCount = 0
if ($simultaneousVisits.Count -gt 0) {
$simultaneousGroups = @()
foreach ($group in $simultaneousVisits) {
$visitIDs_simultaneous = @()
foreach ($visit in $group.Group) {
if ($visit.PSObject.Properties['CurrentVisitID'] -and $visit.CurrentVisitID) {
$visitIDs_simultaneous += $visit.CurrentVisitID
$simultaneousVisitCount++
}
}
if ($visitIDs_simultaneous.Count -gt 1) {
$simultaneousGroups += @{
Timestamp = $group.Name
VisitIDs = $visitIDs_simultaneous
}
}
}
if ($simultaneousGroups.Count -gt 0) {
foreach ($group in $simultaneousGroups) {
Write-Message "INFO: Simultaneous visits detected at $($group.Timestamp): Visit IDs $($group.VisitIDs -join ', ')" -Level Verbose
}
Write-Message "This may indicate rapid redirects, JavaScript navigation, or database precision limits."
}
}
Write-Message ("=" * 65)
$properlyOrderedResults = $SortedChainResults | Sort-Object @{
Expression = {
if ($_.PSObject.Properties['ChainLevel']) {
[int]$_.ChainLevel
} else {
0
}
}
}, @{
Expression = 'TimestampUTC'
}, @{
Expression = {
if ($_.PSObject.Properties['CurrentVisitID']) {
[long]$_.CurrentVisitID
} else {
0
}
}
}
Write-Message "Displaying chain in chronological order (oldest to newest):"
Write-Message ""
for ($i = 0; $i -lt $properlyOrderedResults.Count; $i++) {
$result = $properlyOrderedResults[$i]
$chainIndicator = ""
if ($result.PSObject.Properties['ChainLevel']) {
$chainLevel = $result.ChainLevel
if ($chainLevel -lt 0) {
$chainIndicator = "[BACKWARD CHAIN - Level $chainLevel] "
} elseif ($chainLevel -eq 0) {
$chainIndicator = "[TARGET VISIT - Level 0] "
} else {
$chainIndicator = "[FORWARD CHAIN - Level $chainLevel] "
}
}
Write-Message "$chainIndicator--- Visit $($i + 1) of $($properlyOrderedResults.Count) ---"
$outputLines = @()
$outputLines += "RecordType        : $($result.RecordType)"
$outputLines += "User              : $($result.User)"
$outputLines += "Browser           : $($result.Browser)"
$outputLines += "TimestampUTC      : $("{0:yyyy-MM-dd HH:mm:ss.fff}" -f $result.TimestampUTC)"
$outputLines += "URL               : $($result.URL)"
if ($result.Title -and $result.Title -ne 'N/A') {
$outputLines += "Title             : $($result.Title)"
}
if ($result.CurrentVisitID) {
$outputLines += "VisitID           : $($result.CurrentVisitID)"
}
if ($result.DecodedParams) {
$outputLines += "DecodedParams     : $($result.DecodedParams)"
}
if ($result.TransitionInfo -and $result.TransitionInfo -ne 'N/A') {
$outputLines += "TransitionInfo    : $($result.TransitionInfo)"
}
if ($result.TransitionDetails -and $result.TransitionDetails -ne 'N/A') {
$outputLines += "TransitionDetails : $($result.TransitionDetails)"
}
if ($result.ReferrerURL -and $result.ReferrerURL -ne 'N/A') {
$outputLines += "ReferrerURL       : $($result.ReferrerURL)"
}
if ($result.ReferrerTitle -and $result.ReferrerTitle -ne 'N/A') {
$outputLines += "ReferrerTitle     : $($result.ReferrerTitle)"
}
if ($result.VisitDurationSeconds -ne $null -and $result.VisitDurationSeconds -ne 0) {
$outputLines += "VisitDuration     : $($result.VisitDurationSeconds)s"
}
if ($result.PreviousVisitID -and $result.PreviousVisitID -ne '0') {
$outputLines += "PreviousVisitID   : $($result.PreviousVisitID)"
}
if ($result.NextVisitID) {
$outputLines += "NextVisitID       : $($result.NextVisitID)"
}
if ($result.NextURL -and $result.NextURL -ne 'N/A') {
$outputLines += "NextURL           : $($result.NextURL)"
}
if ($result.PSObject.Properties['TimeToNextSeconds'] -and $result.TimeToNextSeconds -ne $null) {
$timeValue = $result.TimeToNextSeconds
$numericTime = $null
if ([double]::TryParse($timeValue.ToString(), [ref]$numericTime)) {
if ($numericTime -gt 0) {
if ($numericTime -lt 0.001) {
$outputLines += "TimeToNext        : <0.001s (simultaneous)"
} elseif ($numericTime -lt 0.01) {
$outputLines += "TimeToNext        : <0.01s (near-simultaneous)"
} else {
$formattedTime = Format-InvariantNumber $numericTime 3
$outputLines += "TimeToNext        : ${formattedTime}s"
}
} elseif ($numericTime -eq 0 -and $result.NextVisitID) {
$outputLines += "TimeToNext        : <0.001s (simultaneous)"
}
} elseif ($result.NextVisitID) {
$nextVisitInResults = $properlyOrderedResults | Where-Object { $_.CurrentVisitID -eq $result.NextVisitID }
if (-not $nextVisitInResults) {
$outputLines += "TimeToNext        : [Gap - next visit outside analysis window]"
} else {
$outputLines += "TimeToNext        : $timeValue"
}
}
} elseif ($result.NextVisitID) {
$nextVisitInResults = $properlyOrderedResults | Where-Object { $_.CurrentVisitID -eq $result.NextVisitID }
if (-not $nextVisitInResults) {
$outputLines += "TimeToNext        : [Gap - next visit outside analysis window]"
}
}
if ($result.ChainLevel -ne $null) {
$outputLines += "ChainLevel        : $($result.ChainLevel)"
}
if ($result.ChainDirection) {
$outputLines += "ChainDirection    : $($result.ChainDirection)"
}
if ($result.ChainPosition) {
$outputLines += "ChainPosition     : $($result.ChainPosition)"
}
Write-Message ($outputLines -join "`n")
Write-Message ""
}
$multiTabGroups = @()
$multiTabVisitCount = 0
$candidateVisits = $properlyOrderedResults | Where-Object {
$_.PSObject.Properties['ReferrerURL'] -and $_.ReferrerURL -and $_.ReferrerURL -ne 'N/A' -and
$_.PSObject.Properties['PreviousVisitID'] -and $_.PreviousVisitID -and $_.PreviousVisitID -ne '0'
}
$referrerGroups = $candidateVisits | Group-Object ReferrerURL, PreviousVisitID
foreach ($group in $referrerGroups) {
if ($group.Count -gt 1) {
$genuineMultiTabVisits = @()
$sortedGroupVisits = $group.Group | Sort-Object TimestampUTC
foreach ($visit in $sortedGroupVisits) {
$isSequential = $false
foreach ($otherVisit in $properlyOrderedResults) {
if ($otherVisit.PSObject.Properties['NextVisitID'] -and
$otherVisit.NextVisitID -eq $visit.CurrentVisitID -and
$otherVisit.CurrentVisitID -eq $visit.PreviousVisitID) {
$isSequential = $true
Write-Message "Visit $($visit.CurrentVisitID) is sequential from $($otherVisit.CurrentVisitID), excluding from multi-tab" -Level Debug
break
}
}
if (-not $isSequential) {
$genuineMultiTabVisits += $visit
}
}
if ($genuineMultiTabVisits.Count -gt 1) {
$multiTabGroups += @{Group = $genuineMultiTabVisits; Name = $group.Name}
$multiTabVisitCount += $genuineMultiTabVisits.Count
$visitIDs_multitab = @()
$visitTimes = @()
foreach ($visit in $genuineMultiTabVisits) {
if ($visit.PSObject.Properties['CurrentVisitID'] -and $visit.CurrentVisitID) {
$visitIDs_multitab += $visit.CurrentVisitID
}
$visitTimes += $visit.TimestampUTC
}
$referrerInfo = ($group.Name -split ', ')[0]
Write-Message "Multi-tab pattern detected: Visits $($visitIDs_multitab -join ', ') all launched from referrer: $referrerInfo" -Level Debug
if ($visitTimes.Count -gt 1) {
$sortedTimes = $visitTimes | Sort-Object
$timeSpan = ($sortedTimes[-1] - $sortedTimes[0]).TotalSeconds
Write-Message "Multi-tab time span: $(Format-InvariantNumber $timeSpan 2) seconds" -Level Debug
}
}
}
}
Write-Message "=== CHAIN ANALYSIS SUMMARY ==="
if ($properlyOrderedResults.Count -gt 1) {
$lastIndex = $properlyOrderedResults.Count - 1
$totalTimeSpan = ($properlyOrderedResults[$lastIndex].TimestampUTC - $properlyOrderedResults[0].TimestampUTC).TotalSeconds
} else {
$totalTimeSpan = 0
}
Write-Message "Analysis Duration : $(Format-InvariantNumber $totalTimeSpan 2) seconds"
Write-Message "Total Visits      : $($properlyOrderedResults.Count)"
$backwardVisits = @($properlyOrderedResults | Where-Object {
$_.PSObject.Properties['ChainLevel'] -and $_.ChainLevel -lt 0
})
$forwardVisits = @($properlyOrderedResults | Where-Object {
$_.PSObject.Properties['ChainLevel'] -and $_.ChainLevel -gt 0
})
Write-Message "Backward Steps    : $($backwardVisits.Count)"
Write-Message "Forward Steps     : $($forwardVisits.Count)"
$actualChainRecords = @($properlyOrderedResults | Where-Object {
$_.PSObject.Properties['ChainInfo'] -and
$_.ChainInfo -and
$_.ChainInfo.IsPartOfChain -and
$_.ChainInfo.SuspiciousIndicators -and
$_.ChainInfo.SuspiciousIndicators.Count -gt 0
})
$multiTabRecords = @($actualChainRecords | Where-Object {
$_.ChainInfo.SuspiciousIndicators -contains 'Very Fast Multi-Tab Opening'
})
$genuinelySuspicious = @($actualChainRecords | Where-Object {
$filteredIndicators = $_.ChainInfo.SuspiciousIndicators | Where-Object {
$_ -notin @('Very Fast Multi-Tab Opening', 'Domain Change')
}
$filteredIndicators.Count -gt 0
})
$totalMultiTabVisits = if ($multiTabVisitCount -gt 0) { $multiTabVisitCount } else { $multiTabRecords.Count }
Write-Message "Normal Visits     : $($properlyOrderedResults.Count - $actualChainRecords.Count - $totalMultiTabVisits)"
Write-Message "Multi-Tab Visits  : $totalMultiTabVisits"
Write-Message "Suspicious Visits : $($genuinelySuspicious.Count)"
if ($simultaneousVisitCount -gt 0) {
Write-Message "Simultaneous      : $simultaneousVisitCount visits (identical timestamps)"
}
if ($genuinelySuspicious.Count -gt 0) {
$allSuspiciousIndicators = @()
foreach ($record in $genuinelySuspicious) {
if ($record.ChainInfo.SuspiciousIndicators) {
$allSuspiciousIndicators += $record.ChainInfo.SuspiciousIndicators | Where-Object {
$_ -notin @('Very Fast Multi-Tab Opening')
}
}
}
$indicatorCounts = @{}
foreach ($indicator in $allSuspiciousIndicators) {
if ($indicatorCounts.ContainsKey($indicator)) {
$indicatorCounts[$indicator]++
} else {
$indicatorCounts[$indicator] = 1
}
}
Write-Message "`nSUSPICIOUS PATTERN BREAKDOWN:"
foreach ($indicator in $indicatorCounts.GetEnumerator() | Sort-Object Value -Descending) {
Write-Message "  $($indicator.Key): $($indicator.Value) occurrence(s)"
}
Write-Message "`nRECOMMEND INVESTIGATION of flagged visits."
} else {
Write-Message "`nNO SUSPICIOUS PATTERNS DETECTED"
if ($totalMultiTabVisits -gt 0) {
Write-Message "Multi-tab browsing patterns detected but are considered normal user behavior."
}
if ($simultaneousVisitCount -gt 0) {
Write-Message "Simultaneous visits detected - may indicate rapid redirects or JavaScript navigation."
}
Write-Message "All navigation appears to be normal user browsing behavior."
}
$domainVisitCounts = @{}
foreach ($visit in $properlyOrderedResults) {
if ($visit.URL) {
try {
$cleanUrl = $visit.URL -replace 'hXXp', 'http' -replace 'hXXps', 'https' -replace '\[\.\]', '.' -replace '\[:\]', ':'
$domain = ([System.Uri]$cleanUrl).Host
if ($domain) {
if ($domainVisitCounts.ContainsKey($domain)) {
$domainVisitCounts[$domain]++
} else {
$domainVisitCounts[$domain] = 1
}
}
} catch {
}
}
}
Write-Message "`nDOMAIN ANALYSIS:"
Write-Message "Unique Domains    : $($domainVisitCounts.Count)"
if ($domainVisitCounts.Count -le 20) {
Write-Message "Domains Visited   :"
foreach ($domainEntry in $domainVisitCounts.GetEnumerator() | Sort-Object Key) {
$domain = $domainEntry.Key
$visitCount = $domainEntry.Value
$suspiciousDomainVisits = @($actualChainRecords | Where-Object {
try {
$cleanVisitUrl = $_.URL -replace 'hXXp', 'http' -replace 'hXXps', 'https' -replace '\[\.\]', '.' -replace '\[:\]', ':'
$visitDomain = ([System.Uri]$cleanVisitUrl).Host
return $visitDomain -eq $domain
} catch {
return $false
}
})
$displayDomain = if (-not $NoDefang) { Invoke-SmartDefang -Text $domain } else { $domain }
Write-Message "  $displayDomain ($visitCount visits, $($suspiciousDomainVisits.Count) suspicious)"
}
} else {
Write-Message "Too many domains to list individually ($($domainVisitCounts.Count) total)"
}
Write-Message "`n=== RECOMMENDATIONS ==="
if ($genuinelySuspicious.Count -eq 0) {
Write-Message "[+] No suspicious redirect patterns detected."
Write-Message "[+] All navigation appears to be normal user behavior."
} else {
Write-Message "[!] $($genuinelySuspicious.Count) visits show suspicious patterns - investigate further."
}
if ($totalMultiTabVisits -gt 0) {
Write-Message "[i] $totalMultiTabVisits visits show multi-tab browsing patterns (normal behavior)."
}
if ($simultaneousVisitCount -gt 0) {
Write-Message "[i] Simultaneous timestamps detected - review for rapid navigation or redirects."
}
Write-Message ("=" * 65)
}
function Format-SingleChainVisit {
param(
[PSCustomObject]$Visit,
[bool]$IsCenter = $false
)
Write-Message "TimestampUTC      : $("{0:yyyy-MM-dd HH:mm:ss.fff}" -f $Visit.TimestampUTC)"
Write-Message "URL               : $($Visit.URL)"
if ($Visit.Title) {
Write-Message "Title             : $($Visit.Title)"
}
if ($Visit.CurrentVisitID) {
Write-Message "VisitID           : $($Visit.CurrentVisitID)"
}
if ($Visit.TransitionInfo) {
Write-Message "TransitionInfo    : $($Visit.TransitionInfo)"
}
if ($Visit.TransitionDetails) {
Write-Message "TransitionDetails : $($Visit.TransitionDetails)"
}
if ($Visit.ReferrerURL) {
Write-Message "ReferrerURL       : $($Visit.ReferrerURL)"
}
if ($Visit.ReferrerTitle) {
Write-Message "ReferrerTitle     : $($Visit.ReferrerTitle)"
}
if ($Visit.PreviousVisitID) {
Write-Message "PreviousVisitID   : $($Visit.PreviousVisitID)"
}
if ($Visit.NextVisitID) {
Write-Message "NextVisitID       : $($Visit.NextVisitID)"
}
if ($Visit.NextURL) {
Write-Message "NextURL           : $($Visit.NextURL)"
}
if ($Visit.TimeToNextSeconds) {
Write-Message "TimeToNext        : $($Visit.TimeToNextSeconds)s"
}
if ($Visit.DurationSeconds) {
Write-Message "DurationSeconds   : $($Visit.DurationSeconds)"
}
if ($Visit.ChainDistance) {
Write-Message "ChainDistance     : $($Visit.ChainDistance)"
}
if ($IsCenter -and $Visit.DecodedParams) {
Write-Message "DecodedParams     : $($Visit.DecodedParams)"
}
}
# -----------------------------------------------------------------------------
# SQL query builders (24 canonical columns)
# -----------------------------------------------------------------------------
function Get-HistoryQuery {
param(
[Parameter(Mandatory = $true)][string]$BrowserType,
[Parameter(Mandatory = $true)][string]$QueryType,
[Parameter(Mandatory = $false)][hashtable]$Settings
)
Write-Message "Entering consolidated Get-HistoryQuery for $BrowserType / $QueryType" -Level Debug
if ($QueryType -eq 'Schema') {
return "SELECT name, type, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
}
$microsecondsPerSecond = Format-InvariantNumber 1000000
$microsecondDivisor = Format-InvariantNumber 1000000.0
if ($BrowserType -eq 'Firefox') {
$timeConv = "/ $microsecondsPerSecond, 'unixepoch'"
} else {
$timeConv = "/ $microsecondsPerSecond - 11644473600, 'unixepoch'"
}
$query = ""
if ($BrowserType -in @('Chrome', 'Edge', 'Vivaldi', 'Brave')) {
switch ($QueryType) {
'Visits' {
$query = "SELECT strftime('%Y-%m-%d %H:%M:%S.%f', v.visit_time $timeConv) AS VisitTimeUTC, u.url AS URL, COALESCE(u.title, '') AS Title FROM visits v INNER JOIN urls u ON v.url = u.id"
}
'VisitsWithTransitions' {
$query = @"
SELECT
strftime('%Y-%m-%d %H:%M:%S.%f', v.visit_time $timeConv) AS VisitTimeUTC,
u.url AS URL,
COALESCE(u.title, '') AS Title,
v.transition AS TransitionValue,
v.visit_duration / $microsecondDivisor AS VisitDurationSeconds,
v.from_visit AS PreviousVisitID,
v.id AS CurrentVisitID,
COALESCE(ref_u.url, '') AS ReferrerURL,
COALESCE(ref_u.title, '') AS ReferrerTitle,
-- RESTORED: Next visit information using window functions
LEAD(v.id) OVER (ORDER BY v.visit_time) AS NextVisitID,
LEAD(u_next.url) OVER (ORDER BY v.visit_time) AS NextURL,
LEAD(COALESCE(u_next.title, '')) OVER (ORDER BY v.visit_time) AS NextTitle,
(LEAD(v.visit_time) OVER (ORDER BY v.visit_time) - v.visit_time) / $microsecondDivisor AS TimeToNextSeconds
FROM visits v
JOIN urls u ON v.url = u.id
LEFT JOIN visits ref_v ON v.from_visit = ref_v.id
LEFT JOIN urls ref_u ON ref_v.url = ref_u.id
LEFT JOIN urls u_next ON u_next.id = (
SELECT u2.id FROM visits v2 JOIN urls u2 ON v2.url = u2.id
WHERE v2.visit_time > v.visit_time
ORDER BY v2.visit_time LIMIT 1
)
"@
}
'Downloads' {
$query = "SELECT strftime('%Y-%m-%d %H:%M:%S.%f', d.start_time $timeConv) AS DownloadStartTimeUTC, COALESCE(duc.url, '') AS DownloadURL, COALESCE(d.target_path, '') AS TargetPath FROM downloads d LEFT JOIN downloads_url_chains duc ON duc.id = d.id AND duc.chain_index = (SELECT MAX(chain_index) FROM downloads_url_chains WHERE id = d.id)"
}
'DetailedDownloads' {
$query = @"
SELECT
strftime('%Y-%m-%d %H:%M:%S.%f', d.start_time $timeConv) AS DownloadStartTimeUTC,
strftime('%Y-%m-%d %H:%M:%S.%f', d.end_time $timeConv) AS DownloadEndTimeUTC,
COALESCE(duc.url, '') AS DownloadURL,
COALESCE(d.target_path, '') AS TargetPath,
d.total_bytes AS TotalBytes,
COALESCE(d.mime_type, '') AS MimeType,
CASE d.danger_type
WHEN 0 THEN 'Not Dangerous' WHEN 1 THEN 'Dangerous File' WHEN 2 THEN 'Dangerous URL'
WHEN 3 THEN 'Dangerous Content' WHEN 4 THEN 'Maybe Dangerous Content' WHEN 5 THEN 'Uncommon Content'
WHEN 6 THEN 'User Validated' WHEN 7 THEN 'Dangerous Host' WHEN 8 THEN 'Potentially Unwanted'
WHEN 9 THEN 'Allowlisted by Policy' WHEN 10 THEN 'Async Scanning' WHEN 11 THEN 'Blocked Password Protected'
WHEN 12 THEN 'Blocked Too Large' WHEN 13 THEN 'Sensitive Content Warning' WHEN 14 THEN 'Sensitive Content Block'
WHEN 15 THEN 'Deep Scanned Safe' WHEN 16 THEN 'Deep Scanned Opened Dangerous' WHEN 17 THEN 'Prompt for Scanning'
WHEN 19 THEN 'Dangerous Account Compromise' WHEN 20 THEN 'Deep Scanned Failed' WHEN 21 THEN 'Prompt for Local Password Scanning'
WHEN 22 THEN 'Async Local Password Scanning' WHEN 23 THEN 'Blocked Scan Failed'
ELSE 'Unknown (' || d.danger_type || ')'
END AS DangerType,
CASE d.state
WHEN 0 THEN 'In Progress' WHEN 1 THEN 'Complete' WHEN 2 THEN 'Cancelled'
WHEN 3 THEN 'Interrupted' WHEN 4 THEN 'Interrupted (Resumable)'
ELSE 'Unknown (' || d.state || ')'
END AS State,
CASE d.opened WHEN 0 THEN 'No' WHEN 1 THEN 'Yes' ELSE 'Unknown' END AS OpenedAfterDownload,
v.id AS InitiatingVisitID,
v.id AS CurrentVisitID,
v.transition AS TransitionValue,
v.from_visit AS PreviousVisitID,
strftime('%Y-%m-%d %H:%M:%S.%f', v.visit_time $timeConv) AS InitiatingVisitTimeUTC,
COALESCE(ref_u.url, '') AS ReferrerURL,
COALESCE(ref_u.title, '') AS ReferrerTitle
FROM downloads d
LEFT JOIN downloads_url_chains duc ON duc.id = d.id AND duc.chain_index = (SELECT MAX(chain_index) FROM downloads_url_chains WHERE id = d.id)
LEFT JOIN (
SELECT v.*, u.url as visit_url FROM visits v JOIN urls u ON v.url = u.id
) v ON (
(duc.url = v.visit_url OR d.site_url = v.visit_url OR d.referrer = v.visit_url)
AND ABS(d.start_time - v.visit_time) < 30000000
)
LEFT JOIN visits ref_v ON v.from_visit = ref_v.id
LEFT JOIN urls ref_u ON ref_v.url = ref_u.id
"@
}
'Keywords' {
$query = @"
SELECT
strftime('%Y-%m-%d %H:%M:%S.%f', v.visit_time $timeConv) AS LastVisitTimeUTC,
u.url AS SearchURL,
COALESCE(u.title, '') AS Title,
v.transition AS TransitionValue,
v.from_visit AS PreviousVisitID,
v.id AS CurrentVisitID,
-- RESTORED: Next visit timing information
LEAD(v.id) OVER (ORDER BY v.visit_time) AS NextVisitID,
LEAD(u_next.url) OVER (ORDER BY v.visit_time) AS NextURL,
(LEAD(v.visit_time) OVER (ORDER BY v.visit_time) - v.visit_time) / $microsecondDivisor AS TimeToNextSeconds
FROM visits v
JOIN urls u ON v.url = u.id
LEFT JOIN urls u_next ON u_next.id = (
SELECT u2.id FROM visits v2 JOIN urls u2 ON v2.url = u2.id
WHERE v2.visit_time > v.visit_time
ORDER BY v2.visit_time LIMIT 1
)
"@
}
}
} elseif ($BrowserType -eq 'Firefox') {
switch ($QueryType) {
'Visits' {
$query = "SELECT strftime('%Y-%m-%d %H:%M:%S.%f', h.visit_date $timeConv) AS VisitTimeUTC, p.url AS URL, COALESCE(p.title, '') AS Title FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id"
}
'VisitsWithTransitions' {
$query = @"
SELECT
strftime('%Y-%m-%d %H:%M:%S.%f', h.visit_date $timeConv) AS VisitTimeUTC,
p.url AS URL,
COALESCE(p.title, '') AS Title,
h.visit_type AS VisitType,
h.from_visit AS PreviousVisitID,
h.id AS CurrentVisitID,
COALESCE(ref_p.url, '') AS ReferrerURL,
COALESCE(ref_p.title, '') AS ReferrerTitle,
-- RESTORED: Next visit information
LEAD(h.id) OVER (ORDER BY h.visit_date) AS NextVisitID,
LEAD(p_next.url) OVER (ORDER BY h.visit_date) AS NextURL,
LEAD(COALESCE(p_next.title, '')) OVER (ORDER BY h.visit_date) AS NextTitle,
(LEAD(h.visit_date) OVER (ORDER BY h.visit_date) - h.visit_date) / $microsecondDivisor AS TimeToNextSeconds
FROM moz_historyvisits h
JOIN moz_places p ON h.place_id = p.id
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id
LEFT JOIN moz_places ref_p ON ref_h.place_id = ref_p.id
LEFT JOIN moz_places p_next ON p_next.id = (
SELECT p2.id FROM moz_historyvisits h2 JOIN moz_places p2 ON h2.place_id = p2.id
WHERE h2.visit_date > h.visit_date
ORDER BY h2.visit_date LIMIT 1
)
"@
}
'Downloads' {
$query = "SELECT strftime('%Y-%m-%d %H:%M:%S.%f', a.dateAdded $timeConv) AS DownloadTimeUTC, COALESCE(a.content, '') AS TargetPath, p.url AS SourceURL, COALESCE(p.title, '') AS SourceTitle FROM moz_annos a JOIN moz_places p ON a.place_id = p.id JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id"
}
'DetailedDownloads' {
$query = @"
SELECT
strftime('%Y-%m-%d %H:%M:%S.%f', a.dateAdded $timeConv) AS DownloadTimeUTC,
COALESCE(a.content, '') AS TargetPath,
p.url AS SourceURL,
COALESCE(p.title, '') AS SourceTitle,
h.id AS InitiatingVisitID,
h.id AS CurrentVisitID,
h.visit_type AS VisitType,
COALESCE(ref_p.url, '') AS ReferrerURL,
COALESCE(ref_p.title, '') AS ReferrerTitle,
h.from_visit AS PreviousVisitID,
strftime('%Y-%m-%d %H:%M:%S.%f', h.visit_date $timeConv) AS InitiatingVisitTimeUTC
FROM moz_annos a
JOIN moz_places p ON a.place_id = p.id
JOIN moz_anno_attributes attr ON a.anno_attribute_id = attr.id
LEFT JOIN moz_historyvisits h ON p.id = h.place_id AND ABS(a.dateAdded - h.visit_date) < 5000000
LEFT JOIN moz_historyvisits ref_h ON h.from_visit = ref_h.id
LEFT JOIN moz_places ref_p ON ref_h.place_id = ref_p.id
"@
}
'Keywords' {
$query = "SELECT strftime('%Y-%m-%d %H:%M:%S.%f', p.last_visit_date $timeConv) AS LastVisitTimeUTC, p.url AS SearchURL, COALESCE(p.title, '') AS Title FROM moz_places p"
}
}
}
if ([string]::IsNullOrEmpty($query)) {
Write-Message "Invalid QueryType '$QueryType' for Browser '$BrowserType'." -Level Warning
return $null
}
$whereConditions = @()
if ($Settings -and -not [string]::IsNullOrWhiteSpace($Settings.SearchTerm)) {
$searchTerm = $Settings.SearchTerm.Replace('\', '\\').Replace('%', '\%').Replace('_', '\_').Replace("'", "''")
$likePattern = "'%$searchTerm%' ESCAPE '\'"
$searchFields = @{
'Visits' = if ($BrowserType -eq 'Firefox') { "(p.url LIKE $likePattern OR p.title LIKE $likePattern)" } else { "(u.url LIKE $likePattern OR u.title LIKE $likePattern)" }
'Downloads' = if ($BrowserType -eq 'Firefox') { "(p.url LIKE $likePattern)" } else { "(duc.url LIKE $likePattern OR d.target_path LIKE $likePattern)" }
'Keywords' = if ($BrowserType -eq 'Firefox') { "(p.url LIKE $likePattern OR p.title LIKE $likePattern)" } else { "(u.url LIKE $likePattern OR u.title LIKE $likePattern)" }
}
$searchCondition = $searchFields[($QueryType -replace 'WithTransitions|Detailed')]
if ($searchCondition) { $whereConditions += $searchCondition }
}
if ($Settings -and $Settings.TimeFilter -and $Settings.TimeFilter.IsActive) {
$timeConditions = Build-TimeFilterConditions -BrowserType $BrowserType -QueryType $QueryType -TimeFilter $Settings.TimeFilter
if ($timeConditions) {
$whereConditions += $timeConditions
}
}
if ($BrowserType -eq 'Firefox' -and ($QueryType -like '*Download*')) {
$whereConditions += "attr.name = 'downloads/destinationFileURI'"
} elseif ($QueryType -eq 'Keywords') {
$searchPattern = "(SearchURL LIKE '%google.%/search?%q=%' OR SearchURL LIKE '%bing.com/search?%q=%' OR SearchURL LIKE '%duckduckgo.com/?%q=%')"
$whereConditions += $searchPattern
}
if ($whereConditions.Count -gt 0) {
$query += " WHERE " + ($whereConditions -join " AND ")
}
$orderBy = @{
'Visits' = if($BrowserType -eq 'Firefox') {'h.visit_date DESC'} else {'VisitTimeUTC DESC'}
'Downloads' = if($BrowserType -eq 'Firefox') {'a.dateAdded DESC'} else {'DownloadStartTimeUTC DESC'}
'Keywords' = if($BrowserType -eq 'Firefox') {'p.last_visit_date DESC'} else {'LastVisitTimeUTC DESC'}
}
$orderClause = $orderBy[($QueryType -replace 'WithTransitions|Detailed')]
if ($orderClause) { $query += " ORDER BY $orderClause" }
$query += ";"
Write-Message "Final consolidated query for $BrowserType/${QueryType}: $query" -Level Debug
return $query
}
# -----------------------------------------------------------------------------
# Transition info & time-filter SQL helpers
# -----------------------------------------------------------------------------
function Get-StandardizedTransitionInfo {
param(
[System.Data.DataRow]$Row,
[System.Data.DataColumnCollection]$Columns,
[string]$Browser,
[string]$RecordType = 'Visit'
)
$transitionInfo = "Unknown"
$transitionDetails = "N/A"
try {
if ($Browser -in @('Chrome', 'Edge', 'Vivaldi', 'Brave')) {
if ($Columns.Contains('TransitionInfo') -and $Row['TransitionInfo'] -ne [System.DBNull]::Value -and $Row['TransitionInfo'] -ne $null) {
$transitionInfo = [string]$Row['TransitionInfo']
if ($RecordType -eq 'Download') { $transitionDetails = "Download initiated via: $transitionInfo" }
}
elseif ($Columns.Contains('TransitionValue') -and $Row['TransitionValue'] -ne [System.DBNull]::Value -and $Row['TransitionValue'] -ne $null) {
$transitionValue = 0
if ([int]::TryParse($Row['TransitionValue'].ToString(), [ref]$transitionValue)) {
$details = Format-ChromeTransitionDetailed -TransitionValue $transitionValue
$transitionInfo = $details.CoreType
if ($details.IsRedirect) { $transitionInfo += " [$($details.RedirectType) Redirect]" }
if ($details.NavigationContext.Count -gt 0) { $transitionInfo += " (" + ($details.NavigationContext -join ', ') + ")" }
$transitionDetails = Format-TransitionDetails -TransitionDetails $details
}
}
} elseif ($Browser -eq 'Firefox') {
if ($Columns.Contains('TransitionInfo') -and $Row['TransitionInfo'] -ne [System.DBNull]::Value -and $Row['TransitionInfo'] -ne $null) {
$transitionInfo = [string]$Row['TransitionInfo']
if ($RecordType -eq 'Download') { $transitionDetails = "Download initiated via: $transitionInfo" }
}
elseif ($Columns.Contains('VisitType') -and $Row['VisitType'] -ne [System.DBNull]::Value -and $Row['VisitType'] -ne $null) {
$visitType = 0
if ([int]::TryParse($Row['VisitType'].ToString(), [ref]$visitType)) {
$details = Format-FirefoxVisitTypeDetailed -VisitType $visitType
$transitionInfo = $details.CoreType
if ($details.IsRedirect) { $transitionInfo += " [$($details.RedirectType)]" }
$transitionDetails = Format-TransitionDetails -TransitionDetails $details
}
}
}
if ($transitionInfo -eq "Unknown" -and $RecordType -eq 'Download') {
$transitionInfo = "Download"
$transitionDetails = "File download operation"
}
} catch {
Write-Message "Error processing transition info: $($_.Exception.Message)" -Level Debug
$transitionInfo = "Error"
$transitionDetails = "Processing Error"
}
return @{
TransitionInfo = $transitionInfo
TransitionDetails = $transitionDetails
}
}
function Build-TimeFilterConditions {
param([string]$BrowserType, [string]$QueryType, [hashtable]$TimeFilter)
if (-not $TimeFilter.IsActive -or ($TimeFilter.StartDate -eq $null -and $TimeFilter.EndDate -eq $null)) {
return $null
}
$script:Epoch1601Ticks = 504911232000000000L
$script:TicksPerMicrosecond = 10L
$startEpochMicroseconds = $null
$endEpochMicroseconds = $null
try {
if ($TimeFilter.StartDate -ne $null) {
$startDateUtc = $TimeFilter.StartDate.ToUniversalTime()
if ($BrowserType -in @('Chrome', 'Edge', 'Vivaldi', 'Brave')) {
$startEpochMicroseconds = ($startDateUtc.Ticks - $script:Epoch1601Ticks) / $script:TicksPerMicrosecond
} else {
$startEpochMicroseconds = ([DateTimeOffset]$startDateUtc).ToUnixTimeMilliseconds() * 1000L
}
}
if ($TimeFilter.EndDate -ne $null) {
$endDateUtc = $TimeFilter.EndDate.ToUniversalTime()
if ($BrowserType -in @('Chrome', 'Edge', 'Vivaldi', 'Brave')) {
$endEpochMicroseconds = ($endDateUtc.Ticks - $script:Epoch1601Ticks) / $script:TicksPerMicrosecond
} else {
$endEpochMicroseconds = ([DateTimeOffset]$endDateUtc).ToUnixTimeMilliseconds() * 1000L
}
}
} catch {
Write-Message "Error converting time filter to epoch microseconds: $($_.Exception.Message)" -Level Warning
return $null
}
$timestampColumns = @{
'Visits' = @{ 'Chromium' = 'v.visit_time'; 'Firefox' = 'h.visit_date' }
'VisitsWithTransitions' = @{ 'Chromium' = 'v.visit_time'; 'Firefox' = 'h.visit_date' }
'Downloads' = @{ 'Chromium' = 'd.start_time'; 'Firefox' = 'a.dateAdded' }
'DetailedDownloads' = @{ 'Chromium' = 'd.start_time'; 'Firefox' = 'a.dateAdded' }
'Keywords' = @{ 'Chromium' = 'v.visit_time'; 'Firefox' = 'p.last_visit_date' }
}
$browserFamily = if ($BrowserType -eq 'Firefox') { 'Firefox' } else { 'Chromium' }
$timestampColumn = $timestampColumns[($QueryType -replace 'WithTransitions|Detailed')][$browserFamily]
if (-not $timestampColumn) { return $null }
$conditions = @()
if ($startEpochMicroseconds -ne $null) {
$startEpochString = $startEpochMicroseconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)
$conditions += "($timestampColumn >= $startEpochString)"
}
if ($endEpochMicroseconds -ne $null) {
$endEpochString = $endEpochMicroseconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)
$conditions += "($timestampColumn < $endEpochString)"
}
if ($conditions.Count -gt 0) {
return ($conditions -join " AND ")
} else {
return $null
}
}
# -----------------------------------------------------------------------------
# Record processing pipeline
# -----------------------------------------------------------------------------
function Convert-RowToObject {
param(
[Parameter(Mandatory=$true)][System.Data.DataRow]$Row,
[Parameter(Mandatory=$true)][hashtable]$Context,
[Parameter(Mandatory=$true)][string]$RecordType,
[Parameter(Mandatory=$false)][bool]$IncludeTransitions = $false,
[Parameter(Mandatory=$false)][bool]$IncludeDetails = $false
)
if (-not (Test-ValidRow -Row $Row -Columns $Context.Columns)) { return $null }
$TimestampUTC = $null
$timestampColumn = Get-FirstAvailableColumnValue -Row $Row -Columns $Context.Columns -ColumnNames @('VisitTimeUTC', 'LastVisitTimeUTC', 'DownloadStartTimeUTC', 'DownloadTimeUTC')
if (-not [string]::IsNullOrEmpty($timestampColumn)) {
try {
if ($timestampColumn -match '\.(\d{2})\.(\d{3})$') {
$TimestampUTC = [datetime]($timestampColumn -replace '\.(\d{2})\.(\d{3})$', '.$1$2')
} elseif ($timestampColumn -match '\.(\d{6})$') {
$TimestampUTC = [datetime]($timestampColumn -replace '\.(\d{6})$', '.$1')
} else {
$TimestampUTC = [datetime]$timestampColumn
}
} catch {
Write-Message "Failed to parse timestamp: $timestampColumn - $($_.Exception.Message)" -Level Warning
}
}
if ($TimestampUTC -eq $null) { return $null }
$primaryUrl = Get-FirstAvailableColumnValue -Row $Row -Columns $Context.Columns -ColumnNames @('DownloadURL', 'SourceURL', 'SearchURL', 'URL')
$primaryTitle = Get-FirstAvailableColumnValue -Row $Row -Columns $Context.Columns -ColumnNames @('SourceTitle', 'Title')
$primaryPath = ''
if ($RecordType -eq 'Download') {
$pathValue = Get-FirstAvailableColumnValue -Row $Row -Columns $Context.Columns -ColumnNames @('TargetPath', 'DestinationPathOrMetadata')
if ($pathValue) {
if ($pathValue.StartsWith('file:///')) {
try { $primaryPath = ([System.Uri]$pathValue).LocalPath }
catch { $primaryPath = $pathValue -replace '^file:///', '' -replace '/', '\' }
} else { $primaryPath = $pathValue }
}
}
$decodedParams = Get-DecodedUrlParameters -URL $primaryUrl -DecodingAvailable $Context.DecodingAvailable
$decodedParamsString = if ($decodedParams.Count -gt 0) { ($decodedParams.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' } else { $null }
$outputObject = [PSCustomObject]@{
RecordType = $RecordType
User = $Context.UserName
Browser = $Context.Browser
TimestampUTC = $TimestampUTC
URL = if ($primaryUrl) { $primaryUrl } else { 'N/A' }
Title = if ($primaryTitle) { $primaryTitle } else { 'N/A' }
DecodedParams = $decodedParamsString
}
if ($RecordType -eq 'Download') {
$pathValue = if ($primaryPath) { $primaryPath } else { 'N/A' }
$outputObject | Add-Member NoteProperty Path $pathValue
}
if ($RecordType -eq 'Keyword') {
$searchUrlValue = if ($primaryUrl) { $primaryUrl } else { 'N/A' }
$outputObject | Add-Member NoteProperty SearchURL $searchUrlValue
}
if ($IncludeTransitions) {
$transitionInfo = Get-StandardizedTransitionInfo -Row $Row -Columns $Context.Columns -Browser $Context.Browser -RecordType $RecordType
$outputObject | Add-Member NoteProperty TransitionInfo $transitionInfo.TransitionInfo
$outputObject | Add-Member NoteProperty TransitionDetails $transitionInfo.TransitionDetails
if ($Context.Columns.Contains('VisitDurationSeconds') -and $Row['VisitDurationSeconds'] -ne [System.DBNull]::Value -and $Row['VisitDurationSeconds'] -gt 0) {
$durationValue = $null
if ([double]::TryParse($Row['VisitDurationSeconds'].ToString(), [ref]$durationValue)) {
$formattedDuration = Format-InvariantNumber $durationValue 3
$outputObject | Add-Member NoteProperty VisitDurationSeconds $formattedDuration
}
}
if ($Context.Columns.Contains('TimeToNextSeconds') -and $Row['TimeToNextSeconds'] -ne [System.DBNull]::Value) {
$timeToNextValue = $null
if ([double]::TryParse($Row['TimeToNextSeconds'].ToString(), [ref]$timeToNextValue)) {
$formattedTime = Format-InvariantNumber $timeToNextValue 3
$outputObject | Add-Member NoteProperty TimeToNextSeconds $formattedTime
}
}
$standardTransitionFields = @(
@{Name='ReferrerURL'; Default='N/A'}, @{Name='ReferrerTitle'; Default='N/A'},
@{Name='PreviousVisitID'; Default=$null}, @{Name='CurrentVisitID'; Default=$null},
@{Name='NextVisitID'; Default=$null}, @{Name='NextURL'; Default='N/A'},
@{Name='InitiatingVisitID'; Default=$null}, @{Name='InitiatingVisitTimeUTC'; Default=$null}
)
foreach ($field in $standardTransitionFields) {
$value = Get-SafeColumnValue -Row $Row -Columns $Context.Columns -ColumnName $field.Name -DefaultValue $field.Default
if ($value -ne $null) { $outputObject | Add-Member NoteProperty $field.Name $value }
}
}
if ($IncludeDetails -and $RecordType -eq 'Download') { Add-DownloadDetails -OutputObject $outputObject -Row $Row -Context $Context }
foreach ($fieldName in @('ChainLevel', 'ChainDirection', 'ChainPosition')) {
if ($Context.Columns.Contains($fieldName) -and $Row[$fieldName] -ne [System.DBNull]::Value) {
$outputObject | Add-Member NoteProperty $fieldName $Row[$fieldName]
}
}
$outputObject = Apply-SmartDefanging -OutputObject $outputObject -NoDefang $Context.NoDefang
return $outputObject
}
function Add-DownloadDetails {
param(
[PSCustomObject]$OutputObject,
[System.Data.DataRow]$Row,
[hashtable]$Context
)
$detailFields = @{
'DownloadEndTimeUTC' = 'EndTimeUTC'; 'State' = 'State'; 'TotalBytes' = 'TotalBytes'
'MimeType' = 'MimeType'; 'DangerType' = 'DangerType'; 'OpenedAfterDownload' = 'Opened'
}
foreach ($fieldEntry in $detailFields.GetEnumerator()) {
$sourceField = $fieldEntry.Key; $targetField = $fieldEntry.Value
if ($Context.Columns.Contains($sourceField) -and $Row[$sourceField] -ne [System.DBNull]::Value) {
$value = $Row[$sourceField]
if ($sourceField -eq 'DownloadEndTimeUTC') {
try { $value = [datetime]([string]$value -replace '\.(\d{2})\.(\d{3})$', '.$1$2') } catch { $value = $null }
} elseif ($sourceField -eq 'TotalBytes') {
$OutputObject | Add-Member NoteProperty $targetField $value
$OutputObject | Add-Member NoteProperty SizeFormatted (Format-Bytes -BytesObject $value)
continue
}
if ($value -ne $null) { $OutputObject | Add-Member NoteProperty $targetField $value }
}
}
}
function Execute-RecordQuery {
param(
[System.IntPtr]$Database,
[string]$Browser,
[hashtable]$Context,
[hashtable]$Settings,
[string]$QueryType,
[string]$RecordType
)
$query = Get-HistoryQuery -BrowserType $Browser -QueryType $QueryType -Settings $Settings
if (-not $query) { return @() }
$results = @()
try {
$dataTable = [SqliteHelper]::Execute($Database, $query)
if ($dataTable.Rows.Count -gt 0) {
$Context.Columns = $dataTable.Columns
foreach ($row in $dataTable.Rows) {
$outputObject = Convert-RowToObject -Row $row -Context $Context -RecordType $RecordType -IncludeTransitions $Settings.IncludeTransitions -IncludeDetails $Settings.IncludeDetails
if ($null -ne $outputObject) {
# Counted before -SearchRegex so the summary can report scanned vs matched.
$Script:TotalRecordsScanned++
if (Test-SearchRegexMatch -Object $outputObject -SearchRegex $Settings.SearchRegex) {
$results += $outputObject
}
}
}
}
} catch {
Write-Message "Error executing query for $RecordType in $Browser - $($_.Exception.Message)" -Level Warning
}
return $results
}
function Process-BrowserDatabase {
param(
[string]$DatabasePath,
[string]$Browser,
[string]$UserName,
[hashtable]$Settings,
[array]$Results,
[array]$DatabaseSummaries
)
$tempDbPath = Copy-DbToTemp -OriginalPath $DatabasePath
if ([string]::IsNullOrWhiteSpace($tempDbPath)) {
Write-Message "Skipping locked or inaccessible database: $DatabasePath (Could not copy to temp)" -Level Warning
return @($Results, $DatabaseSummaries)
}
$db = $null
try {
$db = [SqliteHelper]::Open($tempDbPath)
$DatabaseSummaries = Add-DatabaseSummary -Database $db -DatabasePath $DatabasePath -Browser $Browser -UserName $UserName -DatabaseSummaries $DatabaseSummaries -Settings $Settings
$context = New-ConversionContext -UserName $UserName -Browser $Browser -NoDefang $NoDefang -DecodingAvailable $Script:DecodingAvailable -Columns $null
if ($Settings.RunVisits) {
$queryType = if ($Settings.IncludeTransitions) { 'VisitsWithTransitions' } else { 'Visits' }
$Results += Execute-RecordQuery -Database $db -Browser $Browser -Context $context -Settings $Settings -QueryType $queryType -RecordType 'Visit'
}
if ($Settings.RunDownloads) {
$queryType = if ($Settings.IncludeDetails) { 'DetailedDownloads' } else { 'Downloads' }
$Results += Execute-RecordQuery -Database $db -Browser $Browser -Context $context -Settings $Settings -QueryType $queryType -RecordType 'Download'
}
if ($Settings.RunKeywords) {
$Results += Execute-RecordQuery -Database $db -Browser $Browser -Context $context -Settings $Settings -QueryType 'Keywords' -RecordType 'Keyword'
}
} catch {
Write-Message "An unexpected error occurred processing '$tempDbPath' - $($_.Exception.Message)" -Level Warning
Write-Message "Database processing error: $($_.Exception | Format-List * | Out-String)" -Level Debug
} finally {
if ($db -ne $null -and $db -ne [System.IntPtr]::Zero) { [SqliteHelper]::Close($db) }
if (-not [string]::IsNullOrWhiteSpace($tempDbPath)) { foreach ($sc in @('','-wal','-shm','-journal')) { if (Test-Path "$tempDbPath$sc") { Remove-Item -Path "$tempDbPath$sc" -Force -ErrorAction SilentlyContinue } } }
}
return @($Results, $DatabaseSummaries)
}
# -----------------------------------------------------------------------------
# History-cleaning detection (anti-forensics)
# -----------------------------------------------------------------------------
function Get-CleaningReport {
# History-cleaning detection: deleted visits leave gaps in the auto-increment
# visit-id sequence (ids are never reused). Interior gaps + tail deletion
# (sqlite_sequence) = removed records; the bracketing timestamps estimate WHEN.
# Always analyzes the whole database, ignoring any active time filter or
# record-selection switch, so this matches the all-time Visits/Range already
# shown in the summary. A leading gap whose oldest record is ~90 days old is
# treated as normal auto-expiry and NOT counted as cleaning. Returns @{ Note; Detail }.
param([System.IntPtr]$Database, [string]$Browser, [hashtable]$Settings)
$result = @{ Note = $null; Detail = $null }
try {
if ($Browser -eq 'Firefox') {
$table = 'moz_historyvisits'; $dateCol = 'visit_date'; $epochExpr = 'visit_date / 1000000'; $seqName = 'moz_historyvisits'
$urlMmSql = "SELECT COUNT(*) FROM moz_places p WHERE p.visit_count>0 AND NOT EXISTS (SELECT 1 FROM moz_historyvisits h WHERE h.place_id=p.id);"
} else {
$table = 'visits'; $dateCol = 'visit_time'; $epochExpr = 'visit_time / 1000000 - 11644473600'; $seqName = 'visits'
$urlMmSql = "SELECT COUNT(*) FROM urls u WHERE u.visit_count > (SELECT COUNT(*) FROM visits v WHERE v.url=u.id);"
}
$s = [SqliteHelper]::Execute($Database, "SELECT COALESCE(MIN(id),0), COALESCE(MAX(id),0), COUNT(*) FROM $table;")
if ($s.Rows.Count -eq 0) { return $result }
$minId = [long]$s.Rows[0][0]; $maxId = [long]$s.Rows[0][1]; $cnt = [long]$s.Rows[0][2]
$interior = 0
if ($cnt -gt 0) { $interior = $maxId - $minId + 1 - $cnt; if ($interior -lt 0) { $interior = 0 } }
$tail = 0; $seq = $null; $gmax = 0
$seqTbl = [SqliteHelper]::Execute($Database, "SELECT seq FROM sqlite_sequence WHERE name='$seqName';")
if ($seqTbl.Rows.Count -gt 0 -and $seqTbl.Rows[0][0] -ne [System.DBNull]::Value) { $seq = [long]$seqTbl.Rows[0][0] }
$gmTbl = [SqliteHelper]::Execute($Database, "SELECT COALESCE(MAX(id),0) FROM $table;")
if ($gmTbl.Rows.Count -gt 0) { $gmax = [long]$gmTbl.Rows[0][0] }
if ($null -ne $seq -and $seq -gt $gmax) { $tail = $seq - $gmax }
$urlMm = 0; $leading = 0; $expiry = $false; $ageDays = 0
$mmTbl = [SqliteHelper]::Execute($Database, $urlMmSql)
if ($mmTbl.Rows.Count -gt 0 -and $mmTbl.Rows[0][0] -ne [System.DBNull]::Value) { $urlMm = [long]$mmTbl.Rows[0][0] }
if ($minId -gt 0) { $leading = $minId - 1 }
if ($leading -gt 0) {
$meTbl = [SqliteHelper]::Execute($Database, "SELECT CAST(MIN($epochExpr) AS INTEGER) FROM $table WHERE $dateCol>0;")
if ($meTbl.Rows.Count -gt 0 -and $meTbl.Rows[0][0] -ne [System.DBNull]::Value) {
$minEpoch = [long]$meTbl.Rows[0][0]
if ($minEpoch -gt 0) {
$ageDays = [int](([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $minEpoch) / 86400)
if ($ageDays -ge 85) { $expiry = $true }
}
}
}
$suspicious = $interior + $tail
if ($suspicious -gt 0) {
$result.Note = "Possible history cleaning - $suspicious missing visit ID(s) ($interior interior, $tail tail)."
}
if ($suspicious -eq 0 -and $urlMm -eq 0 -and -not $expiry) { return $result }
$sb = New-Object System.Text.StringBuilder
$seqDisp = if ($null -ne $seq) { $seq } else { 'unknown' }
[void]$sb.AppendLine(("  Visit IDs present : {0} (id range {1}-{2}, highest ever assigned {3})" -f $cnt, $minId, $maxId, $seqDisp))
if ($interior -gt 0) {
[void]$sb.AppendLine(("  Interior gaps     : {0} visit(s) deleted between surviving records" -f $interior))
try {
$gapSql = "SELECT prev_ts, cur_ts, (cur_id - prev_id - 1) AS gap FROM (SELECT id AS cur_id, LAG(id) OVER (ORDER BY id) AS prev_id, strftime('%Y-%m-%d %H:%M:%S', $epochExpr, 'unixepoch') AS cur_ts, LAG(strftime('%Y-%m-%d %H:%M:%S', $epochExpr, 'unixepoch')) OVER (ORDER BY id) AS prev_ts FROM $table) WHERE cur_id - prev_id > 1 ORDER BY (cur_id - prev_id) DESC LIMIT 5;"
$gaps = [SqliteHelper]::Execute($Database, $gapSql)
foreach ($g in $gaps.Rows) {
$pt = if ($g[0] -eq [System.DBNull]::Value) { '?' } else { $g[0] }
$ct = if ($g[1] -eq [System.DBNull]::Value) { '?' } else { $g[1] }
[void]$sb.AppendLine(("    est. window : {0} -> {1}  (~{2} visit(s))" -f $pt, $ct, $g[2]))
}
} catch { }
}
if ($tail -gt 0) {
$tt = '?'
try { $ttTbl = [SqliteHelper]::Execute($Database, "SELECT strftime('%Y-%m-%d %H:%M:%S', $epochExpr, 'unixepoch') FROM $table WHERE id=$gmax;"); if ($ttTbl.Rows.Count -gt 0 -and $ttTbl.Rows[0][0] -ne [System.DBNull]::Value) { $tt = $ttTbl.Rows[0][0] } } catch { }
[void]$sb.AppendLine(("  Tail deletion     : {0} recent visit(s) removed after {1}" -f $tail, $tt))
}
if ($urlMm -gt 0) { [void]$sb.AppendLine(("  URL count mismatch: {0} URL(s) record more visits than survive (per-entry deletion)" -f $urlMm)) }
if ($expiry) { [void]$sb.AppendLine(("  Leading gap       : {0} older id(s) absent; oldest record ~{1} days old (consistent with ~90-day auto-expiry, NOT counted as cleaning)" -f $leading, $ageDays)) }
if ($null -eq $seq) { [void]$sb.AppendLine(("  Tail detection    : sqlite_sequence has no row for {0}; tail-deletion detection unavailable (interior gaps still valid)" -f $seqName)) }
$result.Detail = $sb.ToString().TrimEnd()
} catch { }
return $result
}
# -----------------------------------------------------------------------------
# Private-browsing artifact mining
# -----------------------------------------------------------------------------
function Get-PrivateReport {
# Private-browsing artifacts: private/incognito sessions leave no history rows, so
# every parseable profile artifact that records a URL/origin is mined and any host
# with NO matching history visit is reported - evidence a domain was reached but
# never recorded (private OR deleted). Also reports incognito posture and lists
# present-but-binary artifacts we do not parse.
param([System.IntPtr]$Database, [string]$Browser, [string]$DatabasePath)
$sb = New-Object System.Text.StringBuilder
$profDir = Split-Path -Parent $DatabasePath
# URL/host -> plausible hostname (lowercased) or $null (filters template junk).
$normHost = {
param($s)
if (-not $s) { return $null }
$s = ([string]$s).ToLower()
$i = $s.IndexOf('://'); if ($i -ge 0) { $s = $s.Substring($i + 3) }
$a = $s.IndexOf('@');   if ($a -ge 0) { $s = $s.Substring($a + 1) }
foreach ($ch in @('/', '?', '#', '^')) { $p = $s.IndexOf($ch); if ($p -ge 0) { $s = $s.Substring(0, $p) } }
$s = $s.TrimStart('.')
$c = $s.IndexOf(':'); if ($c -ge 0) { $s = $s.Substring(0, $c) }
if ($s -match '^[a-z0-9][a-z0-9.-]*\.[a-z][a-z]+$') { return $s } else { return $null }
}
# History host set to compare against.
$histHosts = New-Object 'System.Collections.Generic.HashSet[string]'
try {
$urlTable = if ($Browser -eq 'Firefox') { 'moz_places' } else { 'urls' }
$ht = [SqliteHelper]::Execute($Database, "SELECT url FROM $urlTable")
foreach ($r in $ht.Rows) { if ($r[0] -ne [System.DBNull]::Value) { $hh = & $normHost $r[0]; if ($hh) { [void]$histHosts.Add($hh) } } }
} catch { }
# Report hosts (from candidate URLs/hosts) that are absent from the history set.
$reportOrphans = {
param($label, $candidates)
$orph = New-Object 'System.Collections.Generic.List[string]'
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($u in $candidates) { $hh = & $normHost $u; if ($hh -and -not $histHosts.Contains($hh) -and $seen.Add($hh)) { [void]$orph.Add($hh) } }
if ($orph.Count -gt 0) {
[void]$sb.AppendLine(("  {0} : {1} domain(s) with no history visit" -f $label.PadRight(23), $orph.Count))
foreach ($hh in ($orph | Select-Object -First 3)) { $disp = if ($NoDefang) { $hh } else { Invoke-SmartDefang -Text $hh }; [void]$sb.AppendLine(("      e.g. {0}" -f $disp)) }
}
}
# Copy an artifact DB, run a URL/host-producing query, report orphan hosts.
$sqliteArtifact = {
param($label, $file, $sql)
if (-not (Test-Path -Path $file -PathType Leaf)) { return }
$tmp = Copy-DbToTemp -OriginalPath $file
if ([string]::IsNullOrWhiteSpace($tmp)) { return }
$h = $null
try {
$h = [SqliteHelper]::Open($tmp)
$t = [SqliteHelper]::Execute($h, $sql)
$vals = @(); foreach ($r in $t.Rows) { if ($r[0] -ne [System.DBNull]::Value) { $vals += [string]$r[0] } }
& $reportOrphans $label $vals
} catch { } finally {
if ($null -ne $h -and $h -ne [System.IntPtr]::Zero) { [SqliteHelper]::Close($h) }
foreach ($sc in @('', '-wal', '-shm', '-journal')) { if (Test-Path "$tmp$sc") { Remove-Item "$tmp$sc" -Force -ErrorAction SilentlyContinue } }
}
}
# Pull http(s) URLs out of a JSON/text file (Bookmarks, logins.json, ...).
$jsonUrls = {
param($file)
if (-not (Test-Path -Path $file -PathType Leaf)) { return @() }
$txt = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
if (-not $txt) { return @() }
try {
[regex]::Matches($txt, 'https?://[^"''<> ]+', [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(5)) | ForEach-Object { $_.Value }
} catch { @() }
}
# List present-but-binary artifacts we do not parse (honest coverage).
$presentBinary = {
param($label, $paths)
$found = @(); foreach ($p in $paths) { if (Test-Path -Path $p) { $found += (Split-Path $p -Leaf) } }
if ($found.Count -gt 0) { [void]$sb.AppendLine(("  {0} : {1}" -f $label.PadRight(23), ($found -join ', '))) }
}
if ($Browser -eq 'Firefox') {
& $sqliteArtifact 'Favicons (pages)'   (Join-Path $profDir 'favicons.sqlite')      'SELECT DISTINCT page_url FROM moz_pages_w_icons'
& $sqliteArtifact 'Cookie domains'     (Join-Path $profDir 'cookies.sqlite')       'SELECT DISTINCT host FROM moz_cookies'
& $sqliteArtifact 'Permission origins' (Join-Path $profDir 'permissions.sqlite')   'SELECT DISTINCT origin FROM moz_perms'
& $sqliteArtifact 'Content-pref sites' (Join-Path $profDir 'content-prefs.sqlite') 'SELECT DISTINCT name FROM groups'
& $reportOrphans 'Saved-login hosts' (& $jsonUrls (Join-Path $profDir 'logins.json'))
$stg = Join-Path (Join-Path $profDir 'storage') 'default'
if (Test-Path $stg) { $so = @(Get-ChildItem -Path $stg -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name -replace '\+\+\+', '://' }); & $reportOrphans 'DOM-storage origins' $so }
$pj = Join-Path $profDir 'prefs.js'; $pba = $null
if (Test-Path $pj -PathType Leaf) {
$m = Select-String -Path $pj -Pattern 'browser\.privatebrowsing\.autostart",\s*(true|false)' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($m) { $pba = $m.Matches[0].Groups[1].Value }
}
if ($pba -eq 'true') { [void]$sb.AppendLine(("  {0} : {1}" -f 'Private posture'.PadRight(23), 'permanent private mode ON (autostart=true)')) }
else { [void]$sb.AppendLine(("  {0} : {1}" -f 'Private posture'.PadRight(23), 'normal (private mode available on demand)')) }
& $presentBinary 'Present (not parsed)' @((Join-Path $profDir 'sessionstore.jsonlz4'), (Join-Path $profDir 'sessionstore-backups'))
} else {
& $sqliteArtifact 'Favicons (pages)'    (Join-Path $profDir 'Favicons')                 'SELECT DISTINCT page_url FROM icon_mapping'
& $sqliteArtifact 'Top Sites'           (Join-Path $profDir 'Top Sites')                'SELECT url FROM top_sites'
& $sqliteArtifact 'Omnibox shortcuts'   (Join-Path $profDir 'Shortcuts')                'SELECT url FROM omni_box_shortcuts'
& $sqliteArtifact 'Typed-URL predictor' (Join-Path $profDir 'Network Action Predictor') 'SELECT DISTINCT url FROM network_action_predictor'
& $sqliteArtifact 'Saved-login origins' (Join-Path $profDir 'Login Data')               'SELECT origin_url FROM logins UNION SELECT action_url FROM logins'
& $sqliteArtifact 'Search keywords'     (Join-Path $profDir 'Web Data')                 'SELECT url FROM keywords'
& $sqliteArtifact 'Media-play origins'  (Join-Path $profDir 'Media History')            'SELECT origin FROM origin'
& $sqliteArtifact 'NEL/report origins'  (Join-Path $profDir 'Reporting and NEL')        'SELECT DISTINCT origin FROM nel_policies'
$cookieDb = Join-Path $profDir 'Cookies'; $netCookies = Join-Path (Join-Path $profDir 'Network') 'Cookies'; if (Test-Path $netCookies -PathType Leaf) { $cookieDb = $netCookies }
& $sqliteArtifact 'Cookie domains'      $cookieDb                                       'SELECT DISTINCT host_key FROM cookies'
& $reportOrphans 'Bookmarked domains' (& $jsonUrls (Join-Path $profDir 'Bookmarks'))
$prefs = Join-Path $profDir 'Preferences'; $lstate = Join-Path (Split-Path -Parent $profDir) 'Local State'; $ima = $null
foreach ($pf in @($prefs, $lstate)) {
if (Test-Path $pf -PathType Leaf) {
$m = Select-String -Path $pf -Pattern '"IncognitoModeAvailability":(\d+)' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($m) { $ima = $m.Matches[0].Groups[1].Value; break }
}
}
switch ($ima) {
'1' { [void]$sb.AppendLine(("  {0} : {1}" -f 'Incognito posture'.PadRight(23), 'DISABLED by policy')) }
'2' { [void]$sb.AppendLine(("  {0} : {1}" -f 'Incognito posture'.PadRight(23), 'FORCED by policy')) }
default { [void]$sb.AppendLine(("  {0} : {1}" -f 'Incognito posture'.PadRight(23), 'available (no restricting policy found)')) }
}
if (Test-Path $prefs -PathType Leaf) {
$mm = Select-String -Path $prefs -Pattern '"incognito":true' -AllMatches -ErrorAction SilentlyContinue
$exti = if ($mm) { ($mm | ForEach-Object { $_.Matches.Count } | Measure-Object -Sum).Sum } else { 0 }
if ($exti -gt 0) { [void]$sb.AppendLine(("  {0} : {1}" -f 'Extensions in incognito'.PadRight(23), "$exti allowed (may persist data from private tabs)")) }
}
& $presentBinary 'Present (not parsed)' @((Join-Path $profDir 'Sessions'), (Join-Path $profDir 'Current Session'), (Join-Path $profDir 'Last Session'), (Join-Path $profDir 'Visited Links'), (Join-Path $profDir 'Cache'))
}
if ($sb.Length -gt 0) { return $sb.ToString().TrimEnd() } else { return $null }
}
# -----------------------------------------------------------------------------
# Database summary
# -----------------------------------------------------------------------------
function Add-DatabaseSummary {
param(
[System.IntPtr]$Database,
[string]$DatabasePath,
[string]$Browser,
[string]$UserName,
[array]$DatabaseSummaries,
[hashtable]$Settings
)
$dbFileInfo = Get-Item -Path $DatabasePath
$dbSizeFormatted = Format-Bytes -BytesObject $dbFileInfo.Length
$totalVisits = 0; $firstVisit = $null; $lastVisit = $null
try {
if ($Browser -eq 'Firefox') {
$visitTable = 'moz_historyvisits'; $dateColumn = 'visit_date'; $timeSelectConv = "/ 1000000, 'unixepoch'"
} else {
$visitTable = 'visits'; $dateColumn = 'visit_time'; $timeSelectConv = "/ 1000000 - 11644473600, 'unixepoch'"
}
$countTable = [SqliteHelper]::Execute($Database, "SELECT COUNT(*) FROM $visitTable;")
$rangeTable = [SqliteHelper]::Execute($Database, "SELECT strftime('%Y-%m-%d %H:%M:%S', MIN($dateColumn) $timeSelectConv), strftime('%Y-%m-%d %H:%M:%S', MAX($dateColumn) $timeSelectConv) FROM $visitTable WHERE $dateColumn > 0;")
if ($countTable.Rows.Count -gt 0) { $totalVisits = $countTable.Rows[0][0] }
if ($rangeTable.Rows.Count -gt 0 -and $rangeTable.Rows[0][0] -ne [System.DBNull]::Value) {
$firstVisit = [datetime]$rangeTable.Rows[0][0]
$lastVisit = [datetime]$rangeTable.Rows[0][1]
}
} catch { Write-Message "Could not query database metadata for '$DatabasePath' - Error: $($_.Exception.Message)" -Level Warning }
# Cleaning detection always runs, on the whole database, regardless of any time
# filter or record-selection switch. Private-browsing analysis is a separate,
# whole-profile check that is opt-in via -Private only.
$privateMode = ($Settings.ContainsKey('Private') -and $Settings.Private)
$cleaningEnabled = $true
$privateEnabled = $privateMode
$cleaning = if ($cleaningEnabled) { Get-CleaningReport -Database $Database -Browser $Browser -Settings $Settings } else { @{ Note = $null; Detail = $null } }
$privateDetail = if ($privateEnabled) { Get-PrivateReport -Database $Database -Browser $Browser -DatabasePath $DatabasePath } else { $null }
$summaryObject = [PSCustomObject]@{
User = $UserName; Browser = $Browser; Path = $DatabasePath; Size = $dbSizeFormatted; TotalVisits = $totalVisits
FirstVisitUTC = $firstVisit; LastVisitUTC = $lastVisit; Note = $cleaning.Note
CleaningDetail = $cleaning.Detail; PrivateDetail = $privateDetail
}
return $DatabaseSummaries + $summaryObject
}
# -----------------------------------------------------------------------------
# Search matching
# -----------------------------------------------------------------------------
function Test-SearchRegexMatch {
param(
[PSCustomObject]$Object,
[string]$SearchRegex
)
if ([string]::IsNullOrWhiteSpace($SearchRegex)) {
return $true
}
$fieldsToCheck = @('URL', 'SearchURL', 'Path', 'Title')
foreach ($field in $fieldsToCheck) {
if ($Object.PSObject.Properties[$field] -and $Object.$field -match $SearchRegex) {
return $true
}
}
return $false
}
# -----------------------------------------------------------------------------
# Query settings
# -----------------------------------------------------------------------------
function Initialize-QuerySettings {
param(
[hashtable]$BoundParameters,
[hashtable]$TimeFilter
)
$runVisits = $false; $runDownloads = $false
$visitsSwitchPresent = $BoundParameters.ContainsKey('Visits')
$downloadsSwitchPresent = $BoundParameters.ContainsKey('Downloads')
if ($visitsSwitchPresent -and $downloadsSwitchPresent) {
Write-Message "Both -Visits and -Downloads specified. Processing BOTH record types." -Level Warning
$runVisits = $true; $runDownloads = $true
} elseif ($visitsSwitchPresent) {
$runVisits = $true
} elseif ($downloadsSwitchPresent) {
$runDownloads = $true
} else {
$runVisits = $true; $runDownloads = $true
}
$runKeywords = $runVisits -and $BoundParameters.ContainsKey('IncludeKeywords')
$searchTerm = if ($BoundParameters.ContainsKey('SearchTerm')) { $BoundParameters['SearchTerm'] } else { $null }
$searchRegex = if ($BoundParameters.ContainsKey('SearchRegex')) { $BoundParameters['SearchRegex'] } else { $null }
$includeTransitions = if ($BoundParameters.ContainsKey('IncludeVisitsWithTransitions')) { $BoundParameters['IncludeVisitsWithTransitions'] } else { $true }
$includeDetails = if ($BoundParameters.ContainsKey('IncludeDetailedDownloads')) { $BoundParameters['IncludeDetailedDownloads'] } else { $true }
return New-QuerySettings -RunVisits $runVisits -RunDownloads $runDownloads -RunKeywords $runKeywords -IncludeTransitions $includeTransitions -IncludeDetails $includeDetails -SearchTerm $searchTerm -SearchRegex $searchRegex -TimeFilter $TimeFilter
}
# -----------------------------------------------------------------------------
# Output formatting
# -----------------------------------------------------------------------------
function Format-OutputResults {
param([array]$SortedResults)
$standardFieldOrder = @(
'RecordType', 'User', 'Browser', 'TimestampUTC', 'URL', 'SearchURL', 'Path', 'Title',
'DecodedParams', 'TransitionInfo', 'TransitionDetails', 'ReferrerURL', 'ReferrerTitle',
'VisitDurationSeconds', 'DurationSeconds', 'TimeToNextSeconds', 'PreviousVisitID',
'CurrentVisitID', 'NextVisitID', 'NextURL', 'InitiatingVisitID', 'InitiatingVisitTimeUTC',
'ChainLevel', 'ChainDirection', 'ChainPosition', 'ChainAnalysis'
)
$additionalDownloadFields = @(
'EndTimeUTC', 'State', 'TotalBytes', 'SizeFormatted', 'MimeType', 'DangerType', 'Opened'
)
foreach ($result in $SortedResults) {
$outputLines = @()
foreach ($fieldName in $standardFieldOrder) {
if ($result.PSObject.Properties[$fieldName]) {
$value = $result.$fieldName
if ($value -eq $null -or ($value -eq "" -and $fieldName -notin @('DecodedParams', 'ChainAnalysis'))) { continue }
if ($value -is [hashtable]) { continue }
$displayValue = $value
if ($fieldName -match 'TimestampUTC|InitiatingVisitTimeUTC') {
try { $displayValue = "{0:yyyy-MM-dd HH:mm:ss.fff}" -f $value } catch { }
} elseif ($fieldName -match 'Seconds$|^TimeToNextSeconds$|^VisitDurationSeconds$|^DurationSeconds$') {
if ($value.ToString() -ne "" -and $value -ne 0) {
if ($fieldName -eq 'TimeToNextSeconds') {
$displayValue = "$(Format-InvariantNumber $value 3)s"
} else {
$displayValue = "$($value)s"
}
} else {
continue
}
} elseif (($fieldName -eq 'SearchURL' -and $result.RecordType -ne 'Keyword') -or ($fieldName -eq 'Path' -and $result.RecordType -ne 'Download')) {
continue
}
$displayFieldName = switch ($fieldName) {
'VisitDurationSeconds' { 'DurationSeconds' }
'TimeToNextSeconds' { 'TimeToNext' }
'InitiatingVisitTimeUTC' { 'InitiatingVisitTime' }
default { $fieldName }
}
$outputLines += "$($displayFieldName.PadRight(17)) : $displayValue"
}
}
if ($result.RecordType -eq 'Download') {
foreach ($fieldName in $additionalDownloadFields) {
if ($result.PSObject.Properties[$fieldName] -and $result.$fieldName -ne $null -and $result.$fieldName -ne "") {
$displayValue = if ($fieldName -eq 'EndTimeUTC') {
try { "{0:yyyy-MM-dd HH:mm:ss.fff}" -f $result.$fieldName }
catch { $result.$fieldName }
} else {
$result.$fieldName
}
$outputLines += "$($fieldName.PadRight(17)) : $displayValue"
}
}
}
Write-Message ($outputLines -join "`n")
Write-Message ""
}
}
function Ensure-OutputConsistency {
param([array]$Results)
if ($Results.Count -eq 0) { return $Results }
Write-Message "Ensuring output consistency across $($Results.Count) results..." -Level Verbose
$standardFields = @(
@{Name='RecordType'; Default='Unknown'}, @{Name='User'; Default='Unknown'}, @{Name='Browser'; Default='Unknown'},
@{Name='TimestampUTC'; Default=$null}, @{Name='URL'; Default='N/A'}, @{Name='Title'; Default='N/A'},
@{Name='DecodedParams'; Default=$null}, @{Name='TransitionInfo'; Default='N/A'}, @{Name='TransitionDetails'; Default='N/A'},
@{Name='ReferrerURL'; Default='N/A'}, @{Name='ReferrerTitle'; Default='N/A'}, @{Name='DurationSeconds'; Default=$null},
@{Name='VisitDurationSeconds'; Default=$null}, @{Name='PreviousVisitID'; Default=$null}, @{Name='CurrentVisitID'; Default=$null},
@{Name='NextVisitID'; Default=$null}, @{Name='NextURL'; Default='N/A'}, @{Name='TimeToNextSeconds'; Default=$null},
@{Name='InitiatingVisitID'; Default=$null}, @{Name='InitiatingVisitTimeUTC'; Default=$null}
)
$recordTypeSpecificFields = @{
'Download' = @('Path', 'EndTimeUTC', 'State', 'TotalBytes', 'SizeFormatted', 'MimeType', 'DangerType', 'Opened')
'Keyword' = @('SearchURL'); 'Visit' = @()
}
foreach ($result in $Results) {
foreach ($field in $standardFields) {
if (-not $result.PSObject.Properties[$field.Name]) {
$result | Add-Member NoteProperty $field.Name $field.Default -Force
}
}
$currentRecordType = $result.RecordType
if ($recordTypeSpecificFields.ContainsKey($currentRecordType)) {
foreach ($specificField in $recordTypeSpecificFields[$currentRecordType]) {
if (-not $result.PSObject.Properties[$specificField]) {
$result | Add-Member NoteProperty $specificField $null -Force
}
}
}
}
Write-Message "Output consistency ensured." -Level Verbose
return $Results
}
# =============================================================================
# Main
# =============================================================================
try {
Write-CollectionHeader -BoundParameters $PSBoundParameters
Write-Message "Initializing time filters..." -Level Debug
$timeFilter = Initialize-TimeFilters -BoundParameters $PSBoundParameters -Cmdlet $PSCmdlet
Flush-Messages
# -Private is a dedicated whole-profile mode; reject any unsupported option combined with it.
if ($Private) {
$unsupported = @('LastHours', 'LastDays', 'Since', 'Before', 'SearchTerm', 'SearchRegex', 'FollowChain', 'Visits', 'Downloads', 'IncludeKeywords') | Where-Object { $PSBoundParameters.ContainsKey($_) }
if ($unsupported.Count -gt 0) {
Write-Message ("ERROR: -Private cannot be combined with: " + (($unsupported | ForEach-Object { "-$_" }) -join ' ')) -Level Warning
Write-Message ""
Write-Message "-Private runs a dedicated WHOLE-PROFILE private-browsing investigation. Private/"
Write-Message "incognito sessions leave no history rows by design, so this scan is not record-"
Write-Message "based and cannot be time-windowed or text-searched. It keeps the standard header"
Write-Message "and per-database summaries (history files, sizes, date ranges) and adds the"
Write-Message "private-browsing artifacts section."
Write-Message ""
Write-Message "Supported with -Private:"
Write-Message "  -Browser <list>    Limit to specific browser(s)          (default: All)"
Write-Message "  -UserName <name>   Limit to one user account"
Write-Message "  -Path <path>       Investigate a specific profile dir or history DB"
Write-Message "  -NoDefang          Do not de-fang URLs in examples"
Write-Message "  -VerboseLogging    Verbose diagnostics to stderr"
Write-Message ""
Write-Message "NOT supported with -Private: -LastHours, -LastDays, -Since, -Before, -SearchTerm,"
Write-Message "  -SearchRegex, -FollowChain, -Visits, -Downloads, -IncludeKeywords."
Write-Message ""
Write-Message "Example:"
Write-Message "  .\Retrace-Windows.ps1 -Private -Browser Chrome"
Flush-Messages
return
}
}
# ---- FollowChain mode ----
if ($PSCmdlet.ParameterSetName -eq 'FollowChain') {
Write-Message "=== FOLLOW CHAIN MODE: Tracing navigation chain for VisitID: $FollowChain ==="
$validBrowsers = @('Chrome', 'Edge', 'Firefox', 'Vivaldi', 'Brave')
$selectedBrowsers = if ($Browser -contains 'All') { $validBrowsers } else { $Browser | Where-Object { $_ -in $validBrowsers } | Select-Object -Unique }
if ($selectedBrowsers.Count -eq 0) { throw "No valid browsers selected. Use 'Chrome', 'Edge', 'Firefox', 'Vivaldi', 'Brave', or 'All'." }
$userProfilePaths = if (-not [string]::IsNullOrWhiteSpace($Path)) { @{ (Split-Path $Path -Leaf) = $Path } } else { Get-UserPaths -SpecificUser $UserName }
if ($null -eq $userProfilePaths -or $userProfilePaths.Count -eq 0) { Write-Message "No user profiles found. Exiting." -Level Warning; Flush-Messages; return }
Write-Message "Found $($userProfilePaths.Count) user profile(s): $($userProfilePaths.Keys -join ', ')"
$chainResults = @(); $foundVisitID = $false
foreach ($userEntry in $userProfilePaths.GetEnumerator()) {
$userDbPaths = if (-not [string]::IsNullOrWhiteSpace($Path)) { Find-BrowserDbPathsFromCustom -CustomPath $userEntry.Value -BrowsersToFind $selectedBrowsers } else { Find-BrowserDbPaths -UserProfilePath $userEntry.Value -BrowsersToFind $selectedBrowsers }
if ($userDbPaths.Count -eq 0) { continue }
foreach ($browserEntry in $userDbPaths.GetEnumerator()) {
foreach ($dbPath in $browserEntry.Value) {
$tempDbPath = Copy-DbToTemp -OriginalPath $dbPath
if (-not $tempDbPath) { continue }
$db = $null
try {
$db = [SqliteHelper]::Open($tempDbPath)
$chainDataTable = Trace-NavigationChain -Database $db -BrowserType $browserEntry.Name -StartingVisitID $FollowChain
if ($chainDataTable -and $chainDataTable -is [System.Data.DataTable] -and $chainDataTable.Rows.Count -gt 0) {
$foundVisitID = $true
Write-Message "  Found VisitID $FollowChain in $($browserEntry.Name) database! Chain contains $($chainDataTable.Rows.Count) visits."
$context = New-ConversionContext -UserName $userEntry.Name -Browser $browserEntry.Name -NoDefang $NoDefang -DecodingAvailable $Script:DecodingAvailable -Columns $chainDataTable.Columns
foreach ($row in $chainDataTable.Rows) {
$outputObject = Convert-RowToObject -Row $row -Context $context -RecordType 'Visit' -IncludeTransitions $true
if ($outputObject) { $chainResults += $outputObject }
}
break
}
} finally {
if ($db) { [SqliteHelper]::Close($db) }
foreach ($sc in @('','-wal','-shm','-journal')) { if (Test-Path "$tempDbPath$sc") { Remove-Item -Path "$tempDbPath$sc" -Force -ErrorAction SilentlyContinue } }
}
}
if ($foundVisitID) { break }
}
if ($foundVisitID) { break }
}
if ($chainResults.Count -gt 0) {
$sortedChainResults = $chainResults | Sort-Object TimestampUTC
Format-ChainOutputResults -SortedChainResults $sortedChainResults -TargetVisitID $FollowChain
} else {
Write-Message "VisitID $FollowChain was not found in any selected browser databases." -Level Warning
}
Flush-Messages
return
}
# ---- Standard query mode ----
$validBrowsers = @('Chrome', 'Edge', 'Firefox', 'Vivaldi', 'Brave')
$selectedBrowsers = if ($Browser -contains 'All') { $validBrowsers } else { $Browser | Where-Object { $_ -in $validBrowsers } | Select-Object -Unique }
if ($selectedBrowsers.Count -eq 0) { throw "No valid browsers selected." }
$userProfilePaths = if (-not [string]::IsNullOrWhiteSpace($Path)) { @{ (Split-Path $Path -Leaf) = $Path } } else { Get-UserPaths -SpecificUser $UserName }
if (-not $userProfilePaths -or $userProfilePaths.Count -eq 0) { Write-Message "No user profiles found. Exiting." -Level Warning; Flush-Messages; return }
$querySettings = Initialize-QuerySettings -BoundParameters $PSBoundParameters -TimeFilter $timeFilter
# -Private is opt-in and focused: enable the private module, keep summaries + the
# anti-forensics module, and suppress the per-record dump (no record queries).
$querySettings.Private = [bool]$Private
if ($Private) { $querySettings.RunVisits = $false; $querySettings.RunDownloads = $false; $querySettings.RunKeywords = $false }
$allResults = @(); $databaseSummaries = @(); $emptyProfiles = @()
foreach ($userEntry in $userProfilePaths.GetEnumerator()) {
$userDbPaths = if (-not [string]::IsNullOrWhiteSpace($Path)) { Find-BrowserDbPathsFromCustom -CustomPath $userEntry.Value -BrowsersToFind $selectedBrowsers } else { Find-BrowserDbPaths -UserProfilePath $userEntry.Value -BrowsersToFind $selectedBrowsers }
if ($userDbPaths.Count -eq 0) { $emptyProfiles += $userEntry.Name; continue }
foreach ($browserEntry in $userDbPaths.GetEnumerator()) {
foreach ($dbPath in $browserEntry.Value) {
try {
$processResult = Process-BrowserDatabase -DatabasePath $dbPath -Browser $browserEntry.Name -UserName $userEntry.Name -Settings $querySettings -Results $allResults -DatabaseSummaries $databaseSummaries
$allResults = $processResult[0]; $databaseSummaries = $processResult[1]
} catch { Write-Message "Error processing database '$dbPath': $($_.Exception.Message)" -Level Warning }
}
}
}
Write-Message ("=" * 65); Write-Message "Identified Database Summaries (Sorted by Most Recent Activity)"; Write-Message (("=" * 65) + "`n")
$sortedSummaries = $databaseSummaries | Sort-Object -Property LastVisitUTC -Descending
foreach ($summary in $sortedSummaries) {
Write-Message "User: $($summary.User) | Browser: $($summary.Browser) | Path: $($summary.Path) | Size: $($summary.Size) | Visits: $($summary.TotalVisits)"
if ($summary.LastVisitUTC) { Write-Message "History Range (UTC): $("{0:u}" -f $summary.FirstVisitUTC) to $("{0:u}" -f $summary.LastVisitUTC)" }
if ($summary.Note) { Write-Message "Note: $($summary.Note)" }
Write-Message ""
}
# Profiles that exist but hold no database for any selected browser are listed
# last - they carry no activity timestamp to sort by.
foreach ($emptyProfile in $emptyProfiles) {
Write-Message "User: $emptyProfile | No browser history databases found"
Write-Message ""
}
if ($Private) {
# Focused mode: no per-record dump; summaries + forensic sections only.
Write-Message ("=" * 65)
Write-Message "Private-Browsing Investigation Complete."
} else {
Write-Message ("=" * 65)
Write-Message "Records Matching Criteria specified:"
Write-Message (("=" * 65) + "`n")
if ($allResults.Count -gt 0) {
$allResults = Ensure-OutputConsistency -Results $allResults
$analyzedResults = Analyze-RedirectChain -AllRecords $allResults
foreach ($result in $analyzedResults) {
if ($result.PSObject.Properties['ChainInfo'] -and $result.ChainInfo.IsPartOfChain) {
$formattedChainInfo = Format-ChainInfo -ChainInfo $result.ChainInfo
if ($formattedChainInfo) { $result | Add-Member NoteProperty ChainAnalysis $formattedChainInfo -Force }
}
}
$sortPropTimestamp = @{Expression = 'TimestampUTC' }
$sortPropVisitId = @{Expression = { if ($_.PSObject.Properties['CurrentVisitID']) { [long]$_.CurrentVisitID } else { 0 } }}
$sortedResults = $analyzedResults | Sort-Object -Property $sortPropTimestamp, $sortPropVisitId
Format-OutputResults -SortedResults $sortedResults
} else {
Write-Message "No results found matching the specified criteria.`n"
}
Write-Message ("=" * 65)
Write-Message "Records Summary"
Write-Message ("=" * 65)
Write-Message "Total Records Found: $Script:TotalRecordsScanned"
Write-Message "Records Matched Criteria: $($allResults.Count)"
if ($AnalyzeRedirectChains -and $allResults.Count -gt 0) {
$chainCount = ($allResults | Where-Object { $_.PSObject.Properties['ChainInfo'] -and $_.ChainInfo.IsPartOfChain }).Count
Write-Message "Records in Redirect Chains: $chainCount"
}
}
# ---- History-cleaning detection (possible anti-forensics) ----
$cleaningItems = @($sortedSummaries | Where-Object { $_.PSObject.Properties['CleaningDetail'] -and $_.CleaningDetail })
if ($cleaningItems.Count -gt 0) {
Write-Message ""
Write-Message ("=" * 65)
Write-Message "=== HISTORY-CLEANING DETECTION (POSSIBLE ANTI-FORENSICS) ==="
Write-Message "Deleted visits leave gaps in the visit-ID sequence (ids are never reused)."
Write-Message "Interior gaps and tail deletions below indicate records were removed; the"
Write-Message "estimated windows bracket when the missing visits occurred."
Write-Message ""
foreach ($s in $cleaningItems) {
Write-Message ("{0} ({1})" -f $s.Browser, $s.Path)
Write-Message $s.CleaningDetail
Write-Message ""
}
}
# ---- Private-browsing artifacts ----
$privateItems = @($sortedSummaries | Where-Object { $_.PSObject.Properties['PrivateDetail'] -and $_.PrivateDetail })
if ($privateItems.Count -gt 0) {
Write-Message ("=" * 65)
Write-Message "=== PRIVATE-BROWSING ARTIFACTS ==="
Write-Message "Private/Incognito sessions are not written to browser history by design, so"
Write-Message "every parseable profile artifact is mined for URLs/origins. A domain that"
Write-Message "appears in an artifact (favicon, top site, omnibox, saved login, cookie,"
Write-Message "bookmark, storage, ...) but has NO matching history visit was reached yet"
Write-Message "never recorded - private OR deleted. First-party artifacts are the strong"
Write-Message "signal; cookies/NEL/storage also include third-party domains. OS-level"
Write-Message "residue (DNS, prefetch, memory) and binary formats (sessions, cache) are"
Write-Message "out of scope / listed but not parsed."
Write-Message ""
foreach ($s in $privateItems) {
Write-Message ("{0} ({1})" -f $s.Browser, $s.Path)
Write-Message $s.PrivateDetail
Write-Message ""
}
}
} catch {
Write-Message "Critical error in main script execution: $($_.Exception.Message)" -Level Warning
Write-Message "Critical error details: $($_.Exception | Format-List * | Out-String)" -Level Debug
throw
} finally {
Flush-Messages
}