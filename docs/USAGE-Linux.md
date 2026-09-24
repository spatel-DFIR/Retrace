<h1 align="center">🐧 Retrace — <code>Retrace-Linux.sh</code></h1>

<p align="center">
  <b>Retrace — forensic browser-trail reconstruction for DFIR.</b><br>
  Linux edition — same options, same output as Windows &amp; macOS.
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Linux-informational">
  <img alt="Version" src="https://img.shields.io/badge/version-1.4.0-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Shell" src="https://img.shields.io/badge/shell-Bash-lightgrey">
  <img alt="Author" src="https://img.shields.io/badge/author-Deep%20Patel%20%26%20Suvas%20Patel-orange">
</p>

---

The Linux edition of **Retrace**. Same record
structure, options and analysis, implemented in **Bash** using the native
`sqlite3` engine (with an automatic Python `sqlite3` fallback) so it runs on a
client machine with **nothing to install**. (Safari does not exist on Linux.)

> 📌 **Contents:** [Browsers](#browsers-supported) ·
> [Forensic safety](#forensic-safety-important) ·
> [Requirements / SQLite engine](#requirements--sqlite-engine) ·
> [Scope](#permissions--scope) · [Options](#options) · [Examples](#examples) ·
> [Running browsers](#running-open-browsers)

## Browsers supported
Chrome, Chromium, Edge, Brave, Vivaldi, Firefox — including **snap** and
**flatpak** install locations.

| Browser | Database (native; snap/flatpak also probed) |
|---|---|
| Chrome | `~/.config/google-chrome/<Profile>/History` |
| Chromium | `~/.config/chromium/<Profile>/History` (+ `~/snap/chromium/common/chromium`) |
| Edge | `~/.config/microsoft-edge/<Profile>/History` |
| Brave | `~/.config/BraveSoftware/Brave-Browser/<Profile>/History` |
| Vivaldi | `~/.config/vivaldi/<Profile>/History` |
| Firefox | `~/.mozilla/firefox/<profile>/places.sqlite` (+ `~/snap/firefox/common/.mozilla/firefox`, flatpak) |

## Forensic safety (important)
- **Originals are never modified or locked.** Each database is `cp`-copied (with
  any `-wal`/`-shm`/`-journal` sidecars) into a private `mktemp` directory and all
  queries run against the copy.
- The temp directory is removed by an `EXIT`/`INT`/`TERM` **trap** — nothing is
  left behind even on Ctrl-C or error.
- **No packages are installed.** Only native tools are used: `sqlite3`, `awk`,
  `sed`, `date`, `cp`, `find`, `mktemp`, `tr`, `getent`.
- A **preflight check** aborts with a clear error if a required tool is missing,
  so the script can never silently produce empty (false-negative) results.

## Requirements / SQLite engine
The script needs **one** of these — and uses whichever it finds, installing
nothing:

1. the **`sqlite3` command-line tool**, or
2. **any Python with the stdlib `sqlite3` module** (`python3`, `python`, or
   `python2`) — auto-detected as a fallback when the `sqlite3` CLI is absent.

This matters on Linux: the `sqlite3` **command** is often *not* installed on
Debian/Ubuntu or RHEL/CentOS base systems (the shared library usually is, but the
CLI is a separate package — `sqlite3` on Debian/Ubuntu, `sqlite` on
RHEL/CentOS/Fedora). **Python 3, however, is present on essentially every modern
distro and ships `sqlite3` in its standard library**, so the fallback lets the
script run on the large majority of Debian and CentOS/RHEL hosts with no
installation. `-VerboseLogging` prints which engine was selected
(`engine=cli` or `engine=python`).

If neither engine exists, the script aborts with a clear message (never silent
false negatives). In that rare case, copy the database files off-host and analyze
them with `-Path` on a machine that has one.

Other requirements:
- Standard userland: `awk`, `sed`, `date`, `cp`, `find`, `mktemp`, `tr`, `getent`
  (all present on stock Debian/CentOS).
- SQLite ≥ 3.25 for next-visit columns and `-FollowChain`; older versions are
  detected and the script degrades gracefully with a warning. (Both engines use
  the system `libsqlite3`, so the version is the same regardless of CLI vs Python.)
- Run with `sudo`/root to read other users' home directories.

## Permissions / scope
- No `-Path`, not root → current user only (`$HOME`).
- No `-Path`, run as root → scans all human accounts (root + UID ≥ 1000) from
  `/etc/passwd`, plus any `/home/*` directories.
- `-UserName <name>` → that user's home (resolved via `getent`/`/etc/passwd`).
  You may also pass a full path here (e.g. `-UserName /mnt/img/home/spatel`) and it
  is used as the profile home directly.
- `-Path <...>` → exactly what you point at (overrides the above).

## Options
Switches take no value; valued options take a space-separated argument.

| Option | Description |
|---|---|
| `-Browser <list>` | Comma list of `Chrome,Chromium,Edge,Firefox,Vivaldi,Brave` or `All` (default `All`). |
| `-UserName <name\|path>` | Limit to one account by name (resolved via `getent`/`/etc/passwd`), or pass a full profile path. |
| `-Path <path>` | A profile directory or a single history DB file (overrides `-UserName`). |
| `-SearchTerm <text>` | SQL `LIKE` filter (case-insensitive) on URL / title / download target path. Done in SQL. |
| `-SearchRegex <regex>` | Extended-regex filter (case-insensitive) on URL / SearchURL / Path / Title. Applied to the **raw** values **before** chain analysis and the record count, so "Records Matched Criteria" reflects only matches while "Total Records Found" reports everything scanned. |
| `-NoDefang` | Do not de-fang URLs (default rewrites `http`→`hxxp`, `.`→`[.]`, and IPs). File paths are never de-fanged. |
| `-Visits` / `-Downloads` | Restrict to one record type. Neither = both; both = both. |
| `-IncludeKeywords` | Also extract inferred search-engine keyword queries (Google/Bing/DuckDuckGo result pages). |
| `-IncludeVisitsWithTransitions <true\|false>` | Transition / referrer / next-visit / duration detail for visits (default `true`). |
| `-IncludeDetailedDownloads <true\|false>` | Download state / size / mime / danger-type detail (default `true`; `false` = path + URL only). |
| `-AnalyzeRedirectChains <true\|false>` | Flag suspicious redirect chains and emit `ChainAnalysis` lines (default `true`). |
| `-FollowChain <VisitID>` | Trace the navigation chain ±5 min around a visit. Mutually exclusive with time filters. |
| `-LastHours <n>` / `-LastDays <n>` | Relative UTC window. `-LastDays` starts at **midnight UTC** N days ago. |
| `-Since "<datetime>"` / `-Before "<datetime>"` | Absolute UTC range, `YYYY-MM-DD[ HH:MM:SS]`. May be used together or alone. |
| `-Private` | Opt-in **whole-profile private-browsing investigation** (see below). Only `-Browser`/`-UserName`/`-Path`/`-NoDefang`/`-VerboseLogging` may accompany it. |
| `-VerboseLogging` | Verbose diagnostics to stderr, including the selected SQLite engine (`engine=cli`/`engine=python`). |
| `-Version` | Print version and exit. |
| `-Help` | Show built-in help. |

All option **names and values are case-insensitive** (`-Browser chrome` ==
`-BROWSER CHROME`). Defaults with no time option = **all** history. Output is
always sorted by `TimestampUTC`, oldest first. Timestamps are UTC with true
millisecond precision (`yyyy-MM-dd HH:mm:ss.fff`).

**Download records** report one row per download using the final (resolved)
URL. Chrome records every redirect hop of a download in `downloads_url_chains`;
when a download went through one or more redirects, its row adds a
**`RedirectChain`** line showing the full `origin -> … -> final` hop sequence.
Single-hop downloads have no extra line.

## Forensic modules: anti-forensics & private browsing

Two analyses run beyond the raw history, gated by **how you invoke the tool**:

**History-cleaning detection (anti-forensics) — automatic.** Deleted visits leave
gaps in the auto-increment visit-ID sequence (IDs are never reused). The tool
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
  `Cookies`, `Bookmarks`.
- **Firefox:** `favicons.sqlite`, `cookies.sqlite`, `permissions.sqlite`,
  `content-prefs.sqlite`, `logins.json`, and `storage/default/` origin dirs.

First-party artifacts (favicons, top sites, omnibox, logins, bookmarks) are the
strong signal; cookies/NEL/storage also include third-party domains. It also
reports incognito posture and lists present-but-binary artifacts (Sessions, Cache,
`sessionstore.jsonlz4`) it does not parse. `-Private` keeps the header and
per-database summaries and adds this section; the per-record dump is skipped.
Combining `-Private` with time/search/`-FollowChain`/record-type options prints a
usage message and exits.

## Examples
```bash
chmod +x Retrace-Linux.sh

# Last 24h, all browsers, current user
./Retrace-Linux.sh -LastHours 24

# All users (run as root), Chrome + Firefox, last 7 days
sudo ./Retrace-Linux.sh -Browser Chrome,Firefox -LastDays 7

# Investigate an extracted profile or single DB (e.g. mounted image)
./Retrace-Linux.sh -Path "/mnt/evidence/.config/google-chrome" -Browser Chrome

# Keyword hunt with search terms, no de-fang
./Retrace-Linux.sh -SearchTerm "dropper" -IncludeKeywords -NoDefang

# Trace a redirect chain around a visit id
./Retrace-Linux.sh -FollowChain 4567 -Browser Firefox

# Dedicated private-browsing investigation (whole profile, opt-in)
./Retrace-Linux.sh -Private -Browser Chrome
```

## Running (open) browsers
A browser does not need to be closed. When a browser is running, its most recent
activity often lives in the database's **`-wal`** (write-ahead log) and has not
yet been written into the main file. The script copies the `-wal`/`-shm`
sidecars alongside the main DB, so **that recent activity is included**. When a
WAL is present the summary prints:

```
Note: non-empty WAL present (32768 bytes) - uncommitted recent activity is included.
```
