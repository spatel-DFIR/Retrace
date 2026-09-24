<h1 align="center">🍎 Retrace — <code>Retrace-macOS.sh</code></h1>

<p align="center">
  <b>Retrace — forensic browser-trail reconstruction for DFIR.</b><br>
  macOS edition — same options, same output as Windows &amp; Linux.
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS-informational">
  <img alt="Version" src="https://img.shields.io/badge/version-1.4.0-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Shell" src="https://img.shields.io/badge/shell-Bash-lightgrey">
  <img alt="Author" src="https://img.shields.io/badge/author-Deep%20Patel%20%26%20Suvas%20Patel-orange">
</p>

---

The macOS edition of **Retrace**. Same record
structure, options and analysis, implemented in **Bash** using the native
`sqlite3` engine (with an automatic Python `sqlite3` fallback) so it runs on a
client machine with **nothing to install**.

> 📌 **Contents:** [Browsers](#browsers-supported) ·
> [Forensic safety](#forensic-safety-important) · [Requirements](#requirements) ·
> [Scope](#permissions--scope) · [Options](#options) · [Examples](#examples) ·
> [Running browsers](#running-open-browsers) ·
> [Safari &amp; Full Disk Access](#safari-requires-full-disk-access)

## Browsers supported
Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, and **Safari**.

| Browser | Database |
|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/<Profile>/History` |
| Edge | `~/Library/Application Support/Microsoft Edge/<Profile>/History` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/<Profile>/History` |
| Vivaldi | `~/Library/Application Support/Vivaldi/<Profile>/History` |
| Chromium | `~/Library/Application Support/Chromium/<Profile>/History` |
| Firefox | `~/Library/Application Support/Firefox/Profiles/<profile>/places.sqlite` |
| Safari | `~/Library/Safari/History.db` (+ `Downloads.plist` for downloads) |

## Forensic safety (important)
- **Originals are never modified or locked.** Each database is `cp`-copied (with
  any `-wal`/`-shm`/`-journal` sidecars) into a private `mktemp` directory and all
  queries run against the copy.
- The temp directory is removed by an `EXIT`/`INT`/`TERM` **trap** — nothing is
  left behind even on Ctrl-C or error.
- **No packages are installed.** Only native tools are used: `sqlite3`, `awk`,
  `sed`, `date`, `cp`, `find`, `mktemp`, `tr` (and `plutil` for Safari downloads).
- A **preflight check** aborts with a clear error if a required tool is missing,
  so the script can never silently produce empty (false-negative) results.
- **Safari downloads** live in `~/Library/Safari/Downloads.plist`, not SQLite.
  They are read read-only via `plutil -convert xml1 -o -` (stdout only, no file
  written); if `plutil` is unavailable, Safari downloads are skipped with a note.

## Requirements
- macOS ships `/usr/bin/sqlite3` by default, so the SQLite engine is always
  available. (If it were ever missing, the script auto-falls back to any Python
  with the stdlib `sqlite3` module — `python3`/`python`/`python2`. Nothing is
  installed.) `-VerboseLogging` prints which engine was used.
- SQLite ≥ 3.25 for next-visit columns and `-FollowChain` (macOS 10.14+; the
  script detects older SQLite and degrades gracefully with a warning).
- **Full Disk Access** for the running terminal, and/or run with `sudo`, to read
  other users' `~/Library` data. Reading another user's data generally requires
  `sudo`.

## Permissions / scope
- No `-Path`, not root → current user only (`$HOME`).
- No `-Path`, run with `sudo` → scans all `/Users/*` profiles.
- `-UserName <name>` → just that user (`/Users/<name>`). You may also pass a full
  path here (e.g. `-UserName /Volumes/EVIDENCE/Users/spatel`) and it is used as the
  profile home directly.
- `-Path <...>` → exactly what you point at (overrides the above).

## Options
Switches take no value; valued options take a space-separated argument.

| Option | Description |
|---|---|
| `-Browser <list>` | Comma list of `Chrome,Edge,Firefox,Vivaldi,Brave,Chromium,Safari` or `All` (default `All`). |
| `-UserName <name\|path>` | Limit to one account by name (`/Users/<name>`), or pass a full profile path. |
| `-Path <path>` | A profile directory or a single history DB file (overrides `-UserName`). |
| `-SearchTerm <text>` | SQL `LIKE` filter (case-insensitive) on URL / title / download target path. Done in SQL. |
| `-SearchRegex <regex>` | Extended-regex filter (case-insensitive) on URL / SearchURL / Path / Title. Applied to the **raw** values **before** chain analysis and the record count, so "Records Matched Criteria" reflects only matches while "Total Records Found" reports everything scanned. |
| `-NoDefang` | Do not de-fang URLs (default rewrites `http`→`hxxp`, `.`→`[.]`, and IPs). File paths are never de-fanged. |
| `-Visits` / `-Downloads` | Restrict to one record type. Neither = both; both = both. |
| `-IncludeKeywords` | Also extract inferred search-engine keyword queries (Google/Bing/DuckDuckGo result pages). |
| `-IncludeVisitsWithTransitions <true\|false>` | Transition / referrer / next-visit / duration detail for visits (default `true`). |
| `-IncludeDetailedDownloads <true\|false>` | Download state / size / mime / danger-type detail (default `true`; `false` = path + URL only). |
| `-AnalyzeRedirectChains <true\|false>` | Flag suspicious redirect chains and emit `ChainAnalysis` lines (default `true`). |
| `-FollowChain <VisitID>` | Trace the navigation chain ±5 min around a visit. Implemented for Chromium and Firefox (Safari visit IDs are not directly comparable; Safari visits still participate in the general redirect-chain analysis). Mutually exclusive with time filters. |
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
- **Safari:** `CloudTabs.db` (iCloud tabs), `TopSites.plist`, `Bookmarks.plist`,
  `LastSession.plist`, `RecentlyClosedTabs.plist` (via `plutil`); incognito posture
  is *not determinable* (no on-disk config) and `Cookies.binarycookies` / favicon
  cache are listed but not parsed (binary).

First-party artifacts are the strong signal; cookies/NEL/storage also include
third-party domains. It also reports incognito posture and lists present-but-binary
artifacts it does not parse. `-Private` keeps the header and per-database summaries
and adds this section; the per-record dump is skipped. Combining `-Private` with
time/search/`-FollowChain`/record-type options prints a usage message and exits.

## Examples
```bash
chmod +x Retrace-macOS.sh

# Last 24h, all browsers, current user
./Retrace-macOS.sh -LastHours 24

# All users (needs Full Disk Access / sudo), Chrome + Safari, last 7 days
sudo ./Retrace-macOS.sh -Browser Chrome,Safari -LastDays 7

# Investigate an extracted profile or single DB
./Retrace-macOS.sh -Path "/Volumes/EVIDENCE/Default/History" -Browser Chrome

# Keyword hunt with search terms, no de-fang
./Retrace-macOS.sh -SearchTerm "malware" -IncludeKeywords -NoDefang

# Trace a redirect chain around a visit id
./Retrace-macOS.sh -FollowChain 4567 -Browser Chrome

# Dedicated private-browsing investigation (whole profile, opt-in)
./Retrace-macOS.sh -Private -Browser Chrome
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

(Cleanly quitting the browser also flushes the WAL into the main DB; either way
the data is captured.)

## Safari requires Full Disk Access
`~/Library/Safari/` is protected by macOS privacy (TCC). If you see:

```
WARNING: Could not copy /Users/<you>/Library/Safari/History.db: cp: ... Operation not permitted
```

grant **Full Disk Access** to your terminal and re-run:
**System Settings → Privacy & Security → Full Disk Access →** enable Terminal
(or iTerm), then quit and reopen the terminal. Note that **`sudo` does not
bypass TCC** — Full Disk Access is required for Safari (and is also the cleanest
way to read other users' `~/Library` data). Chrome/Firefox/etc. under
`~/Library/Application Support` usually copy without it for your own account.
