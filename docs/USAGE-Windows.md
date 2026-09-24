<h1 align="center">🪟 Retrace — <code>Retrace-Windows.ps1</code></h1>

<p align="center">
  <b>Retrace — forensic browser-trail reconstruction for DFIR.</b><br>
  Windows edition — same options, same output as macOS &amp; Linux.
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-informational">
  <img alt="Version" src="https://img.shields.io/badge/version-1.4.0-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Shell" src="https://img.shields.io/badge/shell-PowerShell-5391FE">
  <img alt="Author" src="https://img.shields.io/badge/author-Deep%20Patel%20%26%20Suvas%20Patel-orange">
</p>

---

The Windows edition of **Retrace**. Parses Chrome, Edge, Brave, Vivaldi and
Firefox history for Visits/Downloads/Keywords with transition decoding,
URL/Base64 decoding, de-fanging, redirect-chain analysis and navigation-chain
tracing, using **winsqlite3.dll** (built into Windows 10/11) via a compiled
P/Invoke helper — **nothing to install**.

> 📌 **Contents:** [Browsers](#browsers-supported) ·
> [Forensic safety](#forensic-safety-important) · [Requirements](#requirements) ·
> [Scope](#permissions--scope) · [Options](#options) ·
> [Evidence-path targeting](#evidence-path-targeting) · [Examples](#examples) ·
> [Forensic modules](#forensic-modules-anti-forensics--private-browsing) ·
> [Running browsers](#running-open-browsers)
>
> 💡 Full parameter reference: `Get-Help .\Retrace-Windows.ps1 -Full`

## Browsers supported
Chrome, Edge, Brave, Vivaldi, and Firefox.

| Browser | Database |
|---|---|
| Chrome | `%LocalAppData%\Google\Chrome\User Data\<Profile>\History` |
| Edge | `%LocalAppData%\Microsoft\Edge\User Data\<Profile>\History` |
| Brave | `%LocalAppData%\BraveSoftware\Brave-Browser\User Data\<Profile>\History` |
| Vivaldi | `%LocalAppData%\Vivaldi\User Data\<Profile>\History` |
| Firefox | `%AppData%\Mozilla\Firefox\Profiles\<profile>\places.sqlite` |

## Forensic safety (important)
- **Originals are never modified or locked.** Each database (with its
  `-wal`/`-shm`/`-journal` sidecars) is copied into a private temp directory
  and all queries run against the copy.
- The temp copy and its sidecars are removed once the database is processed.
- **Nothing is installed.** SQLite access is via `winsqlite3.dll`, a component
  shipped with Windows 10/11, called through a compiled P/Invoke helper.

## Requirements
- Windows PowerShell 5.1+ or PowerShell 7+.
- Windows 10/11 (for `winsqlite3.dll`).
- Administrator, to enumerate **other users'** profiles (`-Path`, or run
  elevated). Reading your own profile needs no special privilege.

## Permissions / scope
- No `-Path`, not elevated → current user only.
- No `-Path`, run as Administrator → scans all local user profiles.
- `-UserName <name>` → just that user's standard AppData locations.
- `-Path <...>` → exactly what you point at (overrides the above).

## Options
| Option | Description |
|---|---|
| `-Browser <list>` | `Chrome`, `Edge`, `Firefox`, `Vivaldi`, `Brave`, or `All` (default `All`). |
| `-UserName <name>` | Username to query. Default: all profiles (Administrator) or the current user. |
| `-Path <path>` | A browser profile directory or a single history DB file (overrides `-UserName` and auto-discovery). |
| `-SearchTerm <text>` | SQL `LIKE` filter on URL / title / download path / keyword URL. |
| `-SearchRegex <regex>` | Regex filter (post-extraction) on URL / SearchURL / Path / Title. |
| `-NoDefang` | Do not de-fang URLs (default rewrites `http`→`hxxp`, `.`→`[.]`, and IPs). |
| `-Visits` / `-Downloads` | Restrict to one record type. Neither = both; both = both. |
| `-IncludeKeywords` | Also extract inferred search-engine keyword queries. |
| `-IncludeVisitsWithTransitions <true\|false>` | Referrer/next/transition detail for visits (default `true`). |
| `-IncludeDetailedDownloads <true\|false>` | Download danger/state/size detail (default `true`). |
| `-AnalyzeRedirectChains <true\|false>` | Flag suspicious redirect chains (default `true`). |
| `-FollowChain <VisitID>` | Trace the navigation chain ±5 min around a visit. |
| `-LastHours <n>` / `-LastDays <n>` | Relative UTC window. |
| `-Since "<datetime>"` / `-Before "<datetime>"` | Absolute UTC range. |
| `-Private` | Opt-in **whole-profile private-browsing investigation** (see below). |
| `-VerboseLogging` | Verbose diagnostics to stderr. |
| `-Version` | Print version and exit. |

Full parameter reference (types, validation, aliases): `Get-Help .\Retrace-Windows.ps1 -Full`.

## Evidence-path targeting
`-Path` points the tool at a **specific browser profile location or history
database** instead of the normal `AppData` auto-discovery — the common DFIR
case: a mounted disk image, an extracted profile folder, or a single carved
database.

`-Path` accepts:

| You give it… | Behavior |
|---|---|
| A **history DB file** (`History` or `places.sqlite`) | That single database is analyzed. Browser type is inferred from the filename/path, or from `-Browser` if you specify one. |
| A **directory** | It is searched recursively for `History` and `places.sqlite` files; each is mapped to a browser by its path (Edge/Brave/Vivaldi/Chrome keywords; `places.sqlite`→Firefox). |

`-Path` **overrides** `-UserName` and the normal profile auto-discovery. The
discovered records are grouped under the user label derived from the path.
Use `-Browser` to constrain which browser types are accepted from the path
(e.g. a generic `History` file with `-Browser Edge` is treated as Edge).

## Examples
```powershell
# Last 24h across all browsers
.\Retrace-Windows.ps1 -LastHours 24

# Single extracted Chrome history database
.\Retrace-Windows.ps1 -Path "E:\evidence\Chrome\Default\History" -Browser Chrome

# A mounted user profile folder — scan every browser DB under it
.\Retrace-Windows.ps1 -Path "E:\image\Users\spatel\AppData\Local" -LastDays 30

# A folder of carved databases, hunting a term
.\Retrace-Windows.ps1 -Path "D:\carved\sqlite" -SearchTerm "dropper" -NoDefang

# Firefox places.sqlite pulled from an image
.\Retrace-Windows.ps1 -Path "D:\ff\places.sqlite" -Browser Firefox -IncludeKeywords

# Trace a redirect chain around a visit id
.\Retrace-Windows.ps1 -FollowChain 4567 -Browser Chrome

# Dedicated private-browsing investigation (whole profile, opt-in)
.\Retrace-Windows.ps1 -Private -Browser Chrome
```

## Forensic modules: anti-forensics & private browsing

Two analyses run beyond the raw history, gated by **how you invoke the tool**
(all option names/values are **case-insensitive**):

**History-cleaning detection (anti-forensics) — automatic.** Deleted visits leave
gaps in the auto-increment visit-ID sequence (IDs are never reused). Retrace
reports interior gaps (with estimated time windows), tail deletions (via
`sqlite_sequence` — "the last N minutes were cleared"), and per-URL count
mismatches, and flags likely `~90-day auto-expiry` separately (not counted as
cleaning).
- **Runs when:** a normal run processes visit records and **no**
  `-SearchTerm`/`-SearchRegex` is active.
- **Honors the time filter:** `-LastHours 2` inspects only those 2 hours (interior
  gaps within the window; tail deletion only when the window reaches "now").
  Whole-DB signals (per-URL mismatch, auto-expiry) show only on an unfiltered run.

**Private-browsing artifacts — opt-in via `-Private`.** Incognito/private sessions
leave no history rows, so this is a **whole-profile** scan (it cannot be
time-windowed or text-searched). It mines every parseable profile artifact that
records a URL/origin and reports any **domain with no matching history visit**
(reached but not recorded → private OR deleted):

- **Chromium:** `Favicons`, `Top Sites`, `Shortcuts`, `Network Action Predictor`,
  `Login Data`, `Web Data` (search keywords), `Media History`, `Reporting and NEL`,
  `Cookies` (incl. `Network\Cookies`), `Bookmarks`.
- **Firefox:** `favicons.sqlite`, `cookies.sqlite`, `permissions.sqlite`,
  `content-prefs.sqlite`, `logins.json`, and `storage\default\` origin dirs.

First-party artifacts are the strong signal; cookies/NEL/storage also include
third-party domains. It also reports incognito posture (`IncognitoModeAvailability`,
extensions allowed in incognito) and lists present-but-binary artifacts (Sessions,
Cache, `sessionstore.jsonlz4`) it does not parse. `-Private` keeps the header and
per-database summaries and adds this section; the per-record dump is skipped.
Combining `-Private` with time/search/`-FollowChain`/record-type options prints a
usage message and exits.

## Running (open) browsers
A browser does not need to be closed. Retrace copies the **`-wal`/`-shm`/`-journal`**
sidecars alongside the main `History` file into the temp location, so recent
activity from a **currently running browser** (not yet checkpointed into the
main DB) is captured as well. The temp copies and their sidecars are removed
after analysis.
