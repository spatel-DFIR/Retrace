<h1 align="center">🕵️ Retrace</h1>

<p align="center">
  <b>Retrace — forensic browser-trail reconstruction for DFIR.</b><br>
  Windows · macOS · Linux — same options, same output, one toolkit.
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.4.0-blue">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Shell" src="https://img.shields.io/badge/shell-PowerShell%20%7C%20Bash-lightgrey">
  <img alt="Author" src="https://img.shields.io/badge/author-Deep%20Patel%20%26%20Suvas%20Patel-orange">
</p>

---

## ✨ Overview

`Retrace` extracts and analyzes web browser history for forensic and
incident-response work. It parses the browsers' SQLite databases and reports
**Visits**, **Downloads**, and inferred search **Keywords**, enriched with:

- 🧭 **Transition / visit-type decoding** (link, typed, form-submit, redirect flags…)
- 🔗 **Redirect-chain analysis** — flags fast redirects, domain hops, multi-tab bursts
- 🎯 **`-FollowChain`** — trace the full navigation chain ±5 min around a visit id
- 🔍 **URL-parameter & Base64 decoding** (`DecodedParams`)
- 🛡️ **URL de-fanging** by default (`hxxp[://]`, `domain[.]tld`)
- ⏱️ **Time filtering** (`-LastHours`, `-LastDays`, `-Since`/`-Before`)
- 🔎 **Search** by `LIKE` term or regex
- 🧱 **Per-database summaries** and totals
- 🧹 **History-cleaning detection** (anti-forensics) — visit-ID gap analysis flags deleted history; **automatic** and time-scoped
- 🕵️ **Private-browsing artifacts** — opt-in `-Private` whole-profile scan for orphaned favicons/typed URLs + incognito posture

> All timestamps are **UTC**. Output is sorted oldest → newest.
> All options and values are **case-insensitive** (`-Browser chrome` == `-BROWSER CHROME`).

---

## 📂 Folder layout

```
src/    source scripts
dist/   packed bundles (for constrained/size-limited delivery channels)
docs/   usage documentation (USAGE-*.md)
```

## 📦 Scripts (`src/`)

| Script | Platform | Notes |
|---|---|---|
| [`Retrace-Windows.ps1`](./src/Retrace-Windows.ps1) | 🪟 Windows | Native PowerShell edition, **with `-Path`** + running-browser (WAL) capture. |
| [`Retrace-macOS.sh`](./src/Retrace-macOS.sh) | 🍎 macOS | Native Bash edition. Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, **Safari**. |
| [`Retrace-Linux.sh`](./src/Retrace-Linux.sh) | 🐧 Linux | Native Bash edition. Chrome, Chromium, Edge, Brave, Vivaldi, Firefox (incl. snap/flatpak). |

📖 **Usage docs (`docs/`):**
[Windows](./docs/USAGE-Windows.md) ·
[macOS](./docs/USAGE-macOS.md) ·
[Linux](./docs/USAGE-Linux.md)

📦 **Packed bundles (`dist/`):** self-extracting versions of each script, with
`-LastHours 2` baked in as the editable default
([`Retrace-Windows.packed.ps1`](./dist/Retrace-Windows.packed.ps1),
[`Retrace-macOS.packed.sh`](./dist/Retrace-macOS.packed.sh),
[`Retrace-Linux.packed.sh`](./dist/Retrace-Linux.packed.sh)).
All three are raw-deflate+base85 and unsigned; each decompresses in memory and
runs the inner script. The Windows bundle is sized to fit under a common EDR
console's 40KB script size limit. All three forward any extra arguments you pass.

> The bundles are meant to be run as files, not pasted into a terminal. The
> base85 payload contains `!`, which an interactive `zsh`/`bash` prompt treats
> as history expansion (`event not found`). Run `bash dist/Retrace-macOS.packed.sh`
> instead, or `setopt nobanghist` (`set +H`) before pasting.

---

## 🌐 Supported browsers

| | Chrome | Edge | Brave | Vivaldi | Chromium | Firefox | Safari |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **Windows** | ✅ | ✅ | ✅ | ✅ | – | ✅ | – |
| **macOS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Linux** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | – |

---

## 🚀 Quick start

### 🪟 Windows (PowerShell)
```powershell
# Unblock once (downloaded scripts are blocked by default)
Unblock-File .\src\Retrace-Windows.ps1

# Last 24 hours, all browsers
.\src\Retrace-Windows.ps1 -LastHours 24

# Built-in help
Get-Help .\src\Retrace-Windows.ps1 -Full
```

### 🍎 macOS (Bash)
```bash
chmod +x src/Retrace-macOS.sh
src/Retrace-macOS.sh -LastHours 24
src/Retrace-macOS.sh -Help
```
> 🔐 **Safari needs Full Disk Access** for your terminal (System Settings →
> Privacy &amp; Security → Full Disk Access). `sudo` does **not** bypass this.

### 🐧 Linux (Bash)
```bash
chmod +x src/Retrace-Linux.sh
src/Retrace-Linux.sh -LastHours 24
src/Retrace-Linux.sh -Help
```
> Uses the `sqlite3` CLI, or auto-falls back to **Python's `sqlite3`** when the
> CLI isn't installed — so it runs on most Debian/RHEL hosts with nothing added.

---

## 🧹 Anti-forensics & private-browsing detection

Retrace surfaces two kinds of evidence beyond the raw history. **Which one runs
depends on how you invoke the tool:**

### History-cleaning detection (anti-forensics) — **automatic**

Deleted visits leave gaps in the browser's auto-increment visit-ID sequence (IDs
are never reused), so Retrace reports **interior gaps** (with estimated time
windows), **tail deletions** (via `sqlite_sequence` — i.e. "the last N minutes
were cleared"), and **per-URL count mismatches**.

- **Invoked when:** a *normal* run processes visit records and **no**
  `-SearchTerm`/`-SearchRegex` is active. (Skipped with `-Downloads`-only or a
  content search — a structural gap scan can't honor a text filter.)
- **Honors the time filter:** `-LastHours 2` inspects **only those 2 hours**
  (interior gaps within the window; tail deletion only when the window reaches
  "now"). Whole-database signals (per-URL mismatch, ~90-day auto-expiry
  discrimination) appear only on an **unfiltered** run.
- A leading gap whose oldest record is ~90 days old is reported as normal
  **auto-expiry**, *not* cleaning.

### Private-browsing artifacts — **opt-in via `-Private`**

Incognito/private sessions write nothing to history by design, so this is a
**whole-profile** scan that **cannot be time-windowed or text-searched**. It mines
**every parseable profile artifact** that records a URL/origin — favicons, top
sites, omnibox shortcuts, saved-login origins, search keywords, media/NEL origins,
cookies, bookmarks, DOM storage (Firefox), iCloud tabs / sessions / bookmarks
(Safari), and more — and flags any **domain with no matching history visit**
(reached but not recorded → private *or* deleted). First-party artifacts are the
strong signal; cookies/NEL/storage also include third-party domains. It also
reports **incognito posture** (policy availability, extensions allowed in
incognito) and lists present-but-binary artifacts (sessions, cache, binarycookies)
it does not parse.

- **Invoked only with `-Private`.** It keeps the header and per-database
  summaries (history files, sizes, date ranges) and adds the private-browsing
  section; the per-record dump is skipped.
- **Only** `-Browser`, `-UserName`, `-Path`, `-NoDefang`, `-VerboseLogging` are
  supported alongside it. Combining `-Private` with time, search, `-FollowChain`,
  or record-type options prints a usage message and exits.

```powershell
.\src\Retrace-Windows.ps1 -Private -Browser Chrome     # Windows
src/Retrace-macOS.sh       -Private -Browser Chrome     # macOS
src/Retrace-Linux.sh       -Private -Browser Chrome     # Linux
```

---

## 🛡️ Forensic safety

- **Originals are never modified or locked.** Databases are copied (with their
  `-wal`/`-shm`/`-journal` sidecars) to a private temp location and queried there.
- **Running browsers are supported** — recent activity living in the WAL is
  captured; the summary notes when a browser appears to be running.
- **No artifacts left behind** — the macOS/Linux scripts use `mktemp` + an
  `EXIT/INT/TERM` trap; the Windows tool removes its temp copies. **Nothing is
  installed.**
- **Fail loud, not silent** — a preflight check aborts with a clear message if a
  required tool is missing, so you never get false-negative empty results.

---

## ⚖️ Legal / disclaimer

For **authorized** digital-forensics, incident-response, and educational use
**only**. Use exclusively on systems you own or have explicit, documented
permission to examine. The authors assume no liability for misuse.

---

## 📝 Metadata

| | |
|---|---|
| **Author** | Deep Patel, Suvas Patel |
| **Version** | 1.4.0 |
| **License** | [MIT](./LICENSE) |
