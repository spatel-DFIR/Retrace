#!/usr/bin/env bash
#
# Retrace-Linux.sh
# -----------------------------------------------------------------------------
# Retrace — forensic browser-trail reconstruction for DFIR (Linux). Reads
# Chrome, Chromium, Edge, Brave, Vivaldi and Firefox history databases and
# produces a record structure (Visits / Downloads / Keywords), time
# filtering, search, URL de-fanging, transition decoding, redirect-chain
# analysis and -FollowChain tracing, matching the Windows edition's record
# structure and output. (Safari does not exist on Linux.)
#
# FORENSIC SAFETY
#   * Original databases are NEVER modified or locked. They are only read via
#     'cp' into a private temp directory; all queries run against the copy.
#   * The temp directory is created with mktemp and removed by an EXIT/INT/TERM
#     trap, so nothing is left on the client machine even on Ctrl-C or error.
#   * Only native tooling is used: sqlite3, awk, sed, date, cp, find, mktemp.
#     No packages are installed. A preflight check aborts if a tool is missing
#     so the script can never emit false-negative (empty) results silently.
#   * Copying an original database updates its access time (atime), not its
#     content or modification time (mtime), on filesystems that track atime.
#
# -----------------------------------------------------------------------------
# Author      : Deep Patel, Suvas Patel
# Version     : 1.4.0
# License     : MIT
# Platform    : Linux (Debian/Ubuntu, RHEL/CentOS/Fedora, and derivatives)
# Requires    : bash, sqlite3 (or any python with the sqlite3 module), coreutils
# Usage       : see USAGE-Linux.md, or run with -Help
# Disclaimer  : For authorized digital-forensics / incident-response and
#               educational use only. Use only on systems you own or are
#               explicitly permitted to examine.
# -----------------------------------------------------------------------------

set -u

readonly SCRIPT_VERSION="1.4.0"
readonly SCRIPT_AUTHOR="Deep Patel and Suvas Patel"

# Byte-oriented locale: browser URLs/titles can contain bytes that are not valid
# UTF-8 in the current locale, which makes some awk builds abort with
# "towc: multibyte conversion failure". LC_ALL=C makes awk/sort/tr treat data as
# bytes and pass it through unchanged (still renders as UTF-8 in the terminal).
export LC_ALL=C

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
BROWSER="All"
USERNAME=""
PATH_ARG=""
SEARCHTERM=""
SEARCHREGEX=""
RAW_ARGS=""
SUMMARY_MAXEP=0
EMPTY_PROFILES=""
NODEFANG=0
VISITS=0
DOWNLOADS=0
INCLUDEKEYWORDS=0
INCLUDE_TRANS="true"        # -IncludeVisitsWithTransitions
INCLUDE_DETAILS="true"      # -IncludeDetailedDownloads
ANALYZE_CHAINS="true"       # -AnalyzeRedirectChains
VERBOSE=0
PRIVATE_MODE=0
FOLLOWCHAIN=""
LASTHOURS=""
LASTDAYS=""
SINCE=""
BEFORE=""

PLATFORM="Linux"
VALID_BROWSERS=(Chrome Edge Firefox Vivaldi Brave Chromium)
SEP=$'\x1f'                 # field separator unlikely to appear in browser data

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
log()  { printf '%s\n' "$*"; }
vlog() { [ "$VERBOSE" -eq 1 ] && printf '[VERBOSE] %s\n' "$*" >&2 || true; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

# Re-render one argument for the header: quote only when the value actually
# needs it, so the line reads the way the operator typed it. (bash 3.2's %q
# escapes far more than necessary - 'Edge,Chrome' would come out 'Edge\,Chrome'.)
quote_arg() {
  case "$1" in
    ''|*[!A-Za-z0-9_@%+=:,./-]*)
      local sq="'" esc="'\\''"
      printf "'%s'" "${1//$sq/$esc}" ;;
    *) printf '%s' "$1" ;;
  esac
}
capture_args() {
  if [ "$#" -eq 0 ]; then RAW_ARGS="(none)"; return 0; fi
  local a
  RAW_ARGS=""
  for a in "$@"; do RAW_ARGS="$RAW_ARGS $(quote_arg "$a")"; done
  RAW_ARGS="${RAW_ARGS# }"
}
# Collection provenance banner - emitted once at the top of every run so the
# report carries its own chain-of-custody context (who/where/when/how).
collection_header() {
  local rule; rule=$(printf '=%.0s' $(seq 1 65))
  log "$rule"
  log "$(printf '%-20s: %s' 'Hostname' "$(hostname 2>/dev/null)")"
  log "$(printf '%-20s: %s' 'Time of Collection' "$(date -u '+%Y-%m-%d %H:%M:%SZ')")"
  log "$(printf '%-20s: %s' 'Author' "${SCRIPT_AUTHOR} (v${SCRIPT_VERSION})")"
  log "$(printf '%-20s: %s' 'Command Arguments' "$RAW_ARGS")"
  log "$rule"
  log ""
}

# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
print_usage() {
cat <<USAGE
Retrace-Linux.sh  v${SCRIPT_VERSION}  by ${SCRIPT_AUTHOR}
Linux browser-history forensic collector (Chrome, Chromium, Edge, Brave,
Vivaldi, Firefox). Outputs Visits / Downloads / Keywords with transition
decoding, redirect-chain analysis and navigation-chain tracing.

USAGE:
  ./Retrace-Linux.sh [options]

OPTIONS (values are space-separated):
  -Browser <list>        Comma list: Chrome,Chromium,Edge,Firefox,Vivaldi,Brave,All  (default All)
  -UserName <name>       Limit to one user account (default: current user, or all if run as root)
  -Path <path>           Investigate a specific profile dir or history DB file (overrides -UserName)
  -SearchTerm <text>     SQL LIKE filter on URL/title/path
  -SearchRegex <regex>   Post-filter ERE on URL/SearchURL/Path/Title
  -NoDefang              Do not de-fang URLs (default de-fangs: hxxp[://], domain[.]tld)
  -Private               Opt-in WHOLE-PROFILE private-browsing investigation. Only
                         -Browser/-UserName/-Path/-NoDefang/-VerboseLogging apply;
                         cannot be combined with time, search, chain or record options.
  -Visits                Only Visit records (default: Visits + Downloads)
  -Downloads             Only Download records
  -IncludeKeywords       Also extract search-engine keyword queries
  -IncludeVisitsWithTransitions <true|false>   Referrer/next/transition detail (default true)
  -IncludeDetailedDownloads <true|false>       Download danger/state/size detail (default true)
  -AnalyzeRedirectChains <true|false>          Flag suspicious redirect chains (default true)
  -FollowChain <VisitID> Trace the navigation chain around a visit (+/- 5 min window)
  -LastHours <n>         Only records from the last n hours
  -LastDays <n>          Only records from the last n days
  -Since "<datetime>"    Records on/after this UTC time (YYYY-MM-DD[ HH:MM:SS])
  -Before "<datetime>"   Records before this UTC time
  -VerboseLogging        Verbose diagnostics to stderr (shows the SQLite engine)
  -Version               Print version and exit
  -Help                  Show this help

EXAMPLES:
  # Last 24h across all browsers, current user
  ./Retrace-Linux.sh -LastHours 24

  # All users (run as root), Chrome + Firefox downloads, last 7 days
  sudo ./Retrace-Linux.sh -Browser Chrome,Firefox -Downloads -LastDays 7

  # Investigate an extracted profile or a single database file
  ./Retrace-Linux.sh -Path "/evidence/Default/History" -Browser Chrome

  # Trace the navigation chain around a specific visit id
  ./Retrace-Linux.sh -FollowChain 4567 -Browser Firefox

  # Dedicated private-browsing investigation (whole profile)
  ./Retrace-Linux.sh -Private -Browser Chrome

FORENSIC MODULES:
  Anti-forensics / history-cleaning detection runs AUTOMATICALLY on a normal run
  whenever visit records are processed and no -SearchTerm/-SearchRegex is given.
  It honors the active time filter (interior visit-ID gaps are computed within the
  window; tail deletion shows only when the window reaches "now"); whole-DB signals
  (per-URL mismatch, ~90-day auto-expiry) appear only on an unfiltered run.

  Private-browsing artifacts are OPT-IN via -Private (a whole-profile scan that
  cannot be time-scoped or text-searched). All options are case-insensitive.

Author: ${SCRIPT_AUTHOR}   Version: ${SCRIPT_VERSION}   License: MIT
For authorized forensic/IR and educational use only.
USAGE
}

# -----------------------------------------------------------------------------
# -Private mode: usage message + option validation
# -----------------------------------------------------------------------------
print_private_usage() {
  local badopts="${1:-}"
  {
    [ -n "$badopts" ] && printf 'ERROR: -Private cannot be combined with:%s\n\n' "$badopts"
    cat <<MSG
-Private runs a dedicated WHOLE-PROFILE private-browsing investigation. Private /
incognito sessions leave no history rows by design, so this scan is not record-
based and cannot be time-windowed or text-searched. It keeps the standard header
and per-database summaries (history files, sizes, date ranges) and adds the
private-browsing artifacts section.

Supported with -Private:
  -Browser <list>    Limit to specific browser(s)          (default: All)
  -UserName <name>   Limit to one user account
  -Path <path>       Investigate a specific profile dir or history DB
  -NoDefang          Do not de-fang URLs in examples
  -VerboseLogging    Verbose diagnostics to stderr

NOT supported with -Private: -LastHours, -LastDays, -Since, -Before, -SearchTerm,
  -SearchRegex, -FollowChain, -Visits, -Downloads, -IncludeKeywords.

Example:
  ./Retrace-Linux.sh -Private -Browser Chrome
MSG
  } >&2
}

# Abort with the -Private usage if unsupported options were combined with -Private.
validate_private() {
  [ "$PRIVATE_MODE" -eq 1 ] || return 0
  local bad=""
  [ -n "$LASTHOURS" ]      && bad="$bad -LastHours"
  [ -n "$LASTDAYS" ]       && bad="$bad -LastDays"
  [ -n "$SINCE" ]          && bad="$bad -Since"
  [ -n "$BEFORE" ]         && bad="$bad -Before"
  [ -n "$SEARCHTERM" ]     && bad="$bad -SearchTerm"
  [ -n "$SEARCHREGEX" ]    && bad="$bad -SearchRegex"
  [ -n "$FOLLOWCHAIN" ]    && bad="$bad -FollowChain"
  [ "$VISITS" -eq 1 ]      && bad="$bad -Visits"
  [ "$DOWNLOADS" -eq 1 ]   && bad="$bad -Downloads"
  [ "$INCLUDEKEYWORDS" -eq 1 ] && bad="$bad -IncludeKeywords"
  if [ -n "$bad" ]; then print_private_usage "$bad"; exit 2; fi
}

# -----------------------------------------------------------------------------
# Argument parsing (Pascal-case option names, case-insensitive)
# -----------------------------------------------------------------------------
parse_args() {
  while [ $# -gt 0 ]; do
    local key="$1"; local lk
    lk=$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')
    case "$lk" in
      -browser)        BROWSER="$2"; shift 2 ;;
      -username)       USERNAME="$2"; shift 2 ;;
      -path)           PATH_ARG="$2"; shift 2 ;;
      -searchterm)     SEARCHTERM="$2"; shift 2 ;;
      -searchregex)    SEARCHREGEX="$2"; shift 2 ;;
      -nodefang)       NODEFANG=1; shift ;;
      -private)        PRIVATE_MODE=1; shift ;;
      -visits)         VISITS=1; shift ;;
      -downloads)      DOWNLOADS=1; shift ;;
      -includekeywords) INCLUDEKEYWORDS=1; shift ;;
      -includevisitswithtransitions) INCLUDE_TRANS=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
      -includedetaileddownloads)     INCLUDE_DETAILS=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
      -analyzeredirectchains)        ANALYZE_CHAINS=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
      -followchain)    FOLLOWCHAIN="$2"; shift 2 ;;
      -lasthours|-lh)  LASTHOURS="$2"; shift 2 ;;
      -lastdays|-ld)   LASTDAYS="$2"; shift 2 ;;
      -since|-s)       SINCE="$2"; shift 2 ;;
      -before|-b)      BEFORE="$2"; shift 2 ;;
      -verboselogging|-verbose) VERBOSE=1; shift ;;
      -version|--version) printf 'Retrace-Linux.sh v%s by %s\n' "$SCRIPT_VERSION" "$SCRIPT_AUTHOR"; exit 0 ;;
      -help|-h|--help) print_usage; exit 0 ;;
      *) die "Unknown option: $key (use -Help)" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# Preflight: verify required native tools are present
# -----------------------------------------------------------------------------
HAVE_WINDOW=1
SQLITE_MODE=""      # cli | python
PYBIN=""
preflight() {
  local missing=()
  for t in awk sed date cp find mktemp tr; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    die "Required tool(s) not found: ${missing[*]}. Cannot continue (would produce unreliable results)."
  fi
  # SQLite engine: prefer the native sqlite3 CLI; otherwise fall back to a Python
  # with the stdlib sqlite3 module (present on far more systems than the sqlite3
  # command-line package). No packages are installed either way.
  if command -v sqlite3 >/dev/null 2>&1; then
    SQLITE_MODE=cli
  else
    local p
    for p in python3 python python2; do
      if command -v "$p" >/dev/null 2>&1 && "$p" -c "import sqlite3" >/dev/null 2>&1; then PYBIN="$p"; SQLITE_MODE=python; break; fi
    done
  fi
  [ -n "$SQLITE_MODE" ] || die "No SQLite engine found: neither the 'sqlite3' command nor a Python with the sqlite3 module is present. Run on a host that has one, or copy the databases out and analyze with -Path elsewhere."
  # Window functions (LEAD / ROW_NUMBER) require SQLite >= 3.25. Degrade if older.
  if ! sql_query ":memory:" "SELECT row_number() OVER ();" >/dev/null 2>&1; then
    HAVE_WINDOW=0
    warn "SQLite lacks window functions (<3.25). Next-visit columns and -FollowChain windowing are limited."
  fi
  vlog "Preflight OK. engine=$SQLITE_MODE${PYBIN:+ ($PYBIN)} window=$HAVE_WINDOW"
}

# Run a query, emitting rows as SEP-delimited fields (NULL -> empty string).
# Backed by the sqlite3 CLI when present, else a Python sqlite3 fallback.
sql_query() {
  local db="$1" q="$2"
  if [ "$SQLITE_MODE" = cli ]; then
    sqlite3 -batch -list -noheader -separator "$SEP" -nullvalue '' "$db" "$q" 2>/dev/null
  else
    GIH_SEP="$SEP" GIH_DB="$db" GIH_SQL="$q" "$PYBIN" -c '
import os, sys, sqlite3
sep=os.environ["GIH_SEP"]
try:
    con=sqlite3.connect(os.environ["GIH_DB"])
    con.text_factory=lambda b: b.decode("utf-8","replace") if isinstance(b,(bytes,bytearray)) else b
    for row in con.execute(os.environ["GIH_SQL"]):
        sys.stdout.write(sep.join("" if v is None else str(v) for v in row)+"\n")
except Exception:
    pass
' 2>/dev/null
  fi
}

# Run a query expected to return a single scalar (first column of first row).
sql_scalar() { sql_query "$1" "$2" | head -1; }

# -----------------------------------------------------------------------------
# Date helpers (handle BSD date on macOS and GNU date on Linux)
# -----------------------------------------------------------------------------
DATE_IS_GNU=0
detect_date() {
  if date --version >/dev/null 2>&1; then DATE_IS_GNU=1; else DATE_IS_GNU=0; fi
}
now_epoch() { date -u +%s; }
# Parse "YYYY-MM-DD[ HH:MM:SS]" (treated as UTC) -> unix seconds. Echoes nothing on failure.
to_epoch() {
  local s="$1"
  case "$s" in *:*) : ;; *) s="$s 00:00:00" ;; esac
  if [ "$DATE_IS_GNU" -eq 1 ]; then
    date -u -d "$s" +%s 2>/dev/null
  else
    date -u -j -f "%Y-%m-%d %H:%M:%S" "$s" +%s 2>/dev/null
  fi
}

# -----------------------------------------------------------------------------
# Time filter (computed once, converted per-browser-family in SQL)
# -----------------------------------------------------------------------------
TF_ACTIVE=0
TF_START=""        # unix seconds (float allowed)
TF_END=""
TF_DESC="ALL history (no time filter)"
init_time_filter() {
  local now; now=$(now_epoch)
  if [ -n "$LASTHOURS" ]; then
    TF_START=$(( now - LASTHOURS * 3600 )); TF_END=$now; TF_ACTIVE=1
    TF_DESC="Last ${LASTHOURS} hour(s)"
  elif [ -n "$LASTDAYS" ]; then
    # Start at midnight (UTC) N days ago, not now-24h*N
    TF_START=$(( (now - LASTDAYS * 86400) / 86400 * 86400 )); TF_END=$now; TF_ACTIVE=1
    TF_DESC="Last ${LASTDAYS} day(s) (since midnight UTC)"
  elif [ -n "$SINCE" ] || [ -n "$BEFORE" ]; then
    if [ -n "$SINCE" ]; then TF_START=$(to_epoch "$SINCE"); [ -z "$TF_START" ] && die "Could not parse -Since '$SINCE' (use YYYY-MM-DD[ HH:MM:SS])"; fi
    if [ -n "$BEFORE" ]; then TF_END=$(to_epoch "$BEFORE"); [ -z "$TF_END" ] && die "Could not parse -Before '$BEFORE'"; fi
    if [ -n "$TF_START" ] && [ -n "$TF_END" ] && [ "$TF_START" -ge "$TF_END" ]; then
      die "Invalid range: -Since must be earlier than -Before"
    fi
    TF_ACTIVE=1
    TF_DESC="between ${SINCE:-(any)} and ${BEFORE:-(now)} (UTC)"
  fi
}

# Build a SQL WHERE fragment for the time filter, for a given family + column.
# family: chromium|firefox ; col: native timestamp column.
time_where() {
  local family="$1" col="$2"
  [ "$TF_ACTIVE" -eq 1 ] || { printf ''; return; }
  local s e conds=""
  # Use bash 64-bit integer math: Chromium microsecond epochs (~1.3e16) exceed
  # awk's exact-double range (~9e15) and would round by a few microseconds.
  case "$family" in
    chromium) [ -n "$TF_START" ] && s=$(( (TF_START + 11644473600) * 1000000 ))
              [ -n "$TF_END" ]   && e=$(( (TF_END + 11644473600) * 1000000 )) ;;
    firefox)  [ -n "$TF_START" ] && s=$(( TF_START * 1000000 ))
              [ -n "$TF_END" ]   && e=$(( TF_END * 1000000 )) ;;
  esac
  [ -n "${s:-}" ] && conds="($col >= $s)"
  if [ -n "${e:-}" ]; then [ -n "$conds" ] && conds="$conds AND ($col < $e)" || conds="($col < $e)"; fi
  printf '%s' "$conds"
}

# -----------------------------------------------------------------------------
# Transition decode SQL expressions (done in SQLite: macOS awk has no bitwise)
# -----------------------------------------------------------------------------
chromium_core='CASE (v.transition & 255)
  WHEN 0 THEN '"'"'Link Click'"'"' WHEN 1 THEN '"'"'Typed'"'"' WHEN 2 THEN '"'"'Auto Bookmark'"'"' WHEN 3 THEN '"'"'Auto Subframe'"'"'
  WHEN 4 THEN '"'"'Manual Subframe'"'"' WHEN 5 THEN '"'"'Generated'"'"' WHEN 6 THEN '"'"'Start Page'"'"' WHEN 7 THEN '"'"'Form Submit'"'"'
  WHEN 8 THEN '"'"'Reload'"'"' WHEN 9 THEN '"'"'Keyword'"'"' WHEN 10 THEN '"'"'Keyword Generated'"'"'
  ELSE '"'"'Unknown Core ('"'"'||(v.transition & 255)||'"'"')'"'"' END'

# context raw string (leading ", ") used by both info and details
chromium_ctxraw="(CASE WHEN (v.transition & 33554432)!=0 THEN ', Forward Button' ELSE '' END)||(CASE WHEN (v.transition & 67108864)!=0 THEN ', Back Button' ELSE '' END)||(CASE WHEN (v.transition & 134217728)!=0 THEN ', From Address Bar' ELSE '' END)||(CASE WHEN (v.transition & 268435456)!=0 THEN ', Home Page' ELSE '' END)"

chromium_redir_suffix="CASE WHEN (v.transition & 1073741824)!=0 THEN ' [Client Redirect]' WHEN (v.transition & 2147483648)!=0 THEN ' [Server Redirect]' ELSE '' END"
chromium_redir_word="CASE WHEN (v.transition & 1073741824)!=0 THEN 'Client' WHEN (v.transition & 2147483648)!=0 THEN 'Server' ELSE 'None' END"
chromium_suspraw="(CASE WHEN ((v.transition & 1073741824)!=0 OR (v.transition & 2147483648)!=0) AND (v.transition & 255)=0 THEN ', Redirect on Link Click' ELSE '' END)||(CASE WHEN (v.transition & 1073741824)!=0 AND (v.transition & 2147483648)!=0 THEN ', Both Client and Server Redirect' ELSE '' END)"

build_chromium_tinfo() {
  printf '(%s)||(%s)||(CASE WHEN length(%s)>0 THEN '"'"' ('"'"'||substr(%s,3)||'"'"')'"'"' ELSE '"'"''"'"' END)' \
    "$chromium_core" "$chromium_redir_suffix" "$chromium_ctxraw" "$chromium_ctxraw"
}
build_chromium_tdetails() {
  printf "'Type: '||(%s)||' | Redirect: '||(%s)||(CASE WHEN length(%s)>0 THEN ' | Context: '||substr(%s,3) ELSE '' END)||(CASE WHEN length(%s)>0 THEN ' | SUSPICIOUS: '||substr(%s,3) ELSE '' END)||' | Raw: '||v.transition" \
    "$chromium_core" "$chromium_redir_word" "$chromium_ctxraw" "$chromium_ctxraw" "$chromium_suspraw" "$chromium_suspraw"
}

firefox_core="CASE h.visit_type WHEN 1 THEN 'Link Click' WHEN 2 THEN 'Typed' WHEN 3 THEN 'Bookmark' WHEN 4 THEN 'Embedded' WHEN 5 THEN 'Permanent Redirect' WHEN 6 THEN 'Temporary Redirect' WHEN 7 THEN 'Download' WHEN 8 THEN 'Framed Link' ELSE 'Unknown ('||h.visit_type||')' END"
firefox_redirword="CASE h.visit_type WHEN 5 THEN 'Permanent (301)' WHEN 6 THEN 'Temporary (302/307)' ELSE 'None' END"
build_firefox_tinfo() {
  printf "(%s)||(CASE WHEN h.visit_type IN (5,6) THEN ' ['||(%s)||']' ELSE '' END)" "$firefox_core" "$firefox_redirword"
}
build_firefox_tdetails() {
  printf "'Type: '||(%s)||' | Redirect: '||(%s)||' | Raw: '||h.visit_type" "$firefox_core" "$firefox_redirword"
}

# -----------------------------------------------------------------------------
# Text cleaner: strip embedded newlines so one record == one output line
# -----------------------------------------------------------------------------
clean() { printf "replace(replace(replace(COALESCE(%s,''),char(10),' '),char(13),' '),char(31),' ')" "$1"; }

# Timestamp + epoch expressions per family
ts_chromium() { printf "strftime('%%Y-%%m-%%d %%H:%%M:%%f', %s/1000000.0 - 11644473600, 'unixepoch')" "$1"; }
ep_chromium() { printf "(%s/1000000.0 - 11644473600)" "$1"; }
ts_firefox()  { printf "strftime('%%Y-%%m-%%d %%H:%%M:%%f', %s/1000000.0, 'unixepoch')" "$1"; }
ep_firefox()  { printf "(%s/1000000.0)" "$1"; }

# -----------------------------------------------------------------------------
# Query builders. Each emits 24 data columns in canonical order:
#  1 TimestampUTC 2 EpochSec 3 URL 4 Title 5 SearchURL 6 Path 7 TransitionInfo
#  8 TransitionDetails 9 ReferrerURL 10 ReferrerTitle 11 VisitDurationSeconds
#  12 TimeToNextSeconds 13 PreviousVisitID 14 CurrentVisitID 15 NextVisitID
#  16 NextURL 17 InitiatingVisitID 18 InitiatingVisitTimeUTC 19 EndTimeUTC
#  20 State 21 TotalBytes 22 MimeType 23 DangerType 24 Opened
# -----------------------------------------------------------------------------
EMPTY="''"

search_where() {   # family qtype  -> SQL fragment or empty
  local family="$1" qtype="$2"
  [ -n "$SEARCHTERM" ] || { printf ''; return; }
  local t; t=${SEARCHTERM//\\/\\\\}
  t=${t//%/\\%}
  t=${t//_/\\_}
  t=${t//\'/\'\'}
  local p="'%${t}%' ESCAPE '\\'"
  case "$family-$qtype" in
    chromium-visits)    printf '(u.url LIKE %s OR u.title LIKE %s)' "$p" "$p" ;;
    chromium-downloads) printf '(duc.url LIKE %s OR d.target_path LIKE %s)' "$p" "$p" ;;
    chromium-keywords)  printf '(u.url LIKE %s OR u.title LIKE %s)' "$p" "$p" ;;
    firefox-visits)     printf '(p.url LIKE %s OR p.title LIKE %s)' "$p" "$p" ;;
    firefox-downloads)  printf '(p.url LIKE %s)' "$p" ;;
    firefox-keywords)   printf '(p.url LIKE %s OR p.title LIKE %s)' "$p" "$p" ;;
  esac
}

# Assemble a WHERE clause from fragments
join_where() {
  local out=""
  for c in "$@"; do
    [ -n "$c" ] || continue
    [ -n "$out" ] && out="$out AND $c" || out="$c"
  done
  [ -n "$out" ] && printf ' WHERE %s' "$out"
}

build_sql() {
  local family="$1" qtype="$2"
  local tinfo tdet refurl reftitle nextid nexturl ttn dur
  case "$family" in
    chromium)
      # transition / referrer / next columns only when transitions requested
      if [ "$INCLUDE_TRANS" = "true" ]; then
        tinfo="$(build_chromium_tinfo)"; tdet="$(build_chromium_tdetails)"
        refurl="$(clean ref_u.url)"; reftitle="$(clean ref_u.title)"
        dur="v.visit_duration/1000000.0"
      else
        tinfo=$EMPTY; tdet=$EMPTY; refurl=$EMPTY; reftitle=$EMPTY; dur=$EMPTY
      fi
      if [ "$INCLUDE_TRANS" = "true" ] && [ "$HAVE_WINDOW" -eq 1 ]; then
        nextid="LEAD(v.id) OVER (ORDER BY v.visit_time)"
        nexturl="LEAD($(clean u.url)) OVER (ORDER BY v.visit_time)"
        ttn="(LEAD(v.visit_time) OVER (ORDER BY v.visit_time) - v.visit_time)/1000000.0"
      else
        nextid=$EMPTY; nexturl=$EMPTY; ttn=$EMPTY
      fi
      case "$qtype" in
        visits)
          local w; w=$(join_where "$(search_where chromium visits)" "$(time_where chromium v.visit_time)")
          cat <<SQL
SELECT $(ts_chromium v.visit_time), $(ep_chromium v.visit_time), $(clean u.url), $(clean u.title),
 $EMPTY, $EMPTY, $tinfo, $tdet, $refurl, $reftitle, $dur, $ttn,
 v.from_visit, v.id, $nextid, $nexturl, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY
FROM visits v JOIN urls u ON v.url=u.id
 LEFT JOIN visits ref_v ON v.from_visit=ref_v.id LEFT JOIN urls ref_u ON ref_v.url=ref_u.id
$w ORDER BY v.visit_time DESC;
SQL
          ;;
        downloads)
          local w; w=$(join_where "$(search_where chromium downloads)" "$(time_where chromium d.start_time)")
          # Full redirect chain (origin -> ... -> final) when a download had >1 hop.
          local dlchain="CASE WHEN (SELECT COUNT(*) FROM downloads_url_chains WHERE id=d.id)>1 THEN replace(replace((SELECT group_concat(url,' -> ') FROM (SELECT url FROM downloads_url_chains WHERE id=d.id ORDER BY chain_index)),char(10),' '),char(13),' ') ELSE '' END"
          if [ "$INCLUDE_DETAILS" = "true" ]; then
          cat <<SQL
SELECT $(ts_chromium d.start_time), $(ep_chromium d.start_time), $(clean duc.url), $EMPTY, $EMPTY,
 $(clean d.target_path), $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY,
 $EMPTY, $EMPTY, $(ts_chromium d.end_time),
 CASE d.state WHEN 0 THEN 'In Progress' WHEN 1 THEN 'Complete' WHEN 2 THEN 'Cancelled' WHEN 3 THEN 'Interrupted' WHEN 4 THEN 'Interrupted (Resumable)' ELSE 'Unknown ('||d.state||')' END,
 d.total_bytes, $(clean d.mime_type),
 CASE d.danger_type WHEN 0 THEN 'Not Dangerous' WHEN 1 THEN 'Dangerous File' WHEN 2 THEN 'Dangerous URL' WHEN 3 THEN 'Dangerous Content' WHEN 4 THEN 'Maybe Dangerous Content' WHEN 5 THEN 'Uncommon Content' WHEN 6 THEN 'User Validated' WHEN 7 THEN 'Dangerous Host' WHEN 8 THEN 'Potentially Unwanted' WHEN 9 THEN 'Allowlisted by Policy' WHEN 10 THEN 'Async Scanning' WHEN 11 THEN 'Blocked Password Protected' WHEN 12 THEN 'Blocked Too Large' WHEN 13 THEN 'Sensitive Content Warning' WHEN 14 THEN 'Sensitive Content Block' WHEN 15 THEN 'Deep Scanned Safe' WHEN 16 THEN 'Deep Scanned Opened Dangerous' WHEN 17 THEN 'Prompt for Scanning' WHEN 19 THEN 'Dangerous Account Compromise' WHEN 20 THEN 'Deep Scanned Failed' WHEN 21 THEN 'Prompt for Local Password Scanning' WHEN 22 THEN 'Async Local Password Scanning' WHEN 23 THEN 'Blocked Scan Failed' ELSE 'Unknown ('||d.danger_type||')' END,
 CASE d.opened WHEN 0 THEN 'No' WHEN 1 THEN 'Yes' ELSE 'Unknown' END,
 $dlchain
FROM downloads d LEFT JOIN downloads_url_chains duc
  ON duc.id=d.id AND duc.chain_index=(SELECT MAX(chain_index) FROM downloads_url_chains WHERE id=d.id)
$w ORDER BY d.start_time DESC;
SQL
          else
          cat <<SQL
SELECT $(ts_chromium d.start_time), $(ep_chromium d.start_time), $(clean duc.url), $EMPTY, $EMPTY,
 $(clean d.target_path), $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY,
 $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY,
 $dlchain
FROM downloads d LEFT JOIN downloads_url_chains duc
  ON duc.id=d.id AND duc.chain_index=(SELECT MAX(chain_index) FROM downloads_url_chains WHERE id=d.id)
$w ORDER BY d.start_time DESC;
SQL
          fi
          ;;
        keywords)
          local kw="(u.url LIKE '%google.%/search?%q=%' OR u.url LIKE '%bing.com/search?%q=%' OR u.url LIKE '%duckduckgo.com/?%q=%')"
          local w; w=$(join_where "$(search_where chromium keywords)" "$(time_where chromium v.visit_time)" "$kw")
          cat <<SQL
SELECT $(ts_chromium v.visit_time), $(ep_chromium v.visit_time), $EMPTY, $(clean u.title), $(clean u.url),
 $EMPTY, $tinfo, $tdet, $EMPTY, $EMPTY, $EMPTY, $ttn, v.from_visit, v.id, $nextid, $nexturl,
 $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY
FROM visits v JOIN urls u ON v.url=u.id
$w ORDER BY v.visit_time DESC;
SQL
          ;;
      esac
      ;;
    firefox)
      if [ "$INCLUDE_TRANS" = "true" ]; then
        tinfo="$(build_firefox_tinfo)"; tdet="$(build_firefox_tdetails)"
        refurl="$(clean ref_p.url)"; reftitle="$(clean ref_p.title)"
      else
        tinfo=$EMPTY; tdet=$EMPTY; refurl=$EMPTY; reftitle=$EMPTY
      fi
      if [ "$INCLUDE_TRANS" = "true" ] && [ "$HAVE_WINDOW" -eq 1 ]; then
        nextid="LEAD(h.id) OVER (ORDER BY h.visit_date)"
        nexturl="LEAD($(clean p.url)) OVER (ORDER BY h.visit_date)"
        ttn="(LEAD(h.visit_date) OVER (ORDER BY h.visit_date) - h.visit_date)/1000000.0"
      else
        nextid=$EMPTY; nexturl=$EMPTY; ttn=$EMPTY
      fi
      case "$qtype" in
        visits)
          local w; w=$(join_where "$(search_where firefox visits)" "$(time_where firefox h.visit_date)")
          cat <<SQL
SELECT $(ts_firefox h.visit_date), $(ep_firefox h.visit_date), $(clean p.url), $(clean p.title),
 $EMPTY, $EMPTY, $tinfo, $tdet, $refurl, $reftitle, $EMPTY, $ttn,
 h.from_visit, h.id, $nextid, $nexturl, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY
FROM moz_historyvisits h JOIN moz_places p ON h.place_id=p.id
 LEFT JOIN moz_historyvisits ref_h ON h.from_visit=ref_h.id LEFT JOIN moz_places ref_p ON ref_h.place_id=ref_p.id
$w ORDER BY h.visit_date DESC;
SQL
          ;;
        downloads)
          local dl="attr.name = 'downloads/destinationFileURI'"
          local w; w=$(join_where "$(search_where firefox downloads)" "$(time_where firefox a.dateAdded)" "$dl")
          cat <<SQL
SELECT $(ts_firefox a.dateAdded), $(ep_firefox a.dateAdded), $(clean p.url), $(clean p.title), $EMPTY,
 $(clean a.content), $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY,
 $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY
FROM moz_annos a JOIN moz_places p ON a.place_id=p.id JOIN moz_anno_attributes attr ON a.anno_attribute_id=attr.id
$w ORDER BY a.dateAdded DESC;
SQL
          ;;
        keywords)
          local kw="(p.url LIKE '%google.%/search?%q=%' OR p.url LIKE '%bing.com/search?%q=%' OR p.url LIKE '%duckduckgo.com/?%q=%')"
          local w; w=$(join_where "$(search_where firefox keywords)" "$kw")
          cat <<SQL
SELECT $(ts_firefox p.last_visit_date), $(ep_firefox p.last_visit_date), $EMPTY, $(clean p.title), $(clean p.url),
 $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY,
 $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY, $EMPTY
FROM moz_places p
$w ORDER BY p.last_visit_date DESC;
SQL
          ;;
      esac
      ;;
  esac
}

# -----------------------------------------------------------------------------
# Map a browser name -> family
# -----------------------------------------------------------------------------
family_of() {
  case "$1" in
    Firefox) echo firefox ;;
    *)       echo chromium ;;
  esac
}

# -----------------------------------------------------------------------------
# Safe copy of a DB (+ sidecars) into the temp dir; echoes the temp path
# -----------------------------------------------------------------------------
COPYNUM=0
copy_db() {
  local orig="$1"
  [ -L "$orig" ] && { warn "Refusing to follow symlink: $orig"; return 1; }
  [ -f "$orig" ] || { warn "Database not found: $orig"; return 1; }
  COPYNUM=$((COPYNUM + 1))
  local dst="$TMPDIR_RUN/db${COPYNUM}_$(basename "$orig")"
  local err
  if ! err=$(cp -p "$orig" "$dst" 2>&1); then
    warn "Could not copy $orig: ${err:-unknown error}"
    case "$err" in
      *"Permission denied"*|*"Operation not permitted"*)
        warn "  -> Permission denied. Run as the profile owner, or as root (sudo) to read other users' data." ;;
    esac
    return 1
  fi
  # Copy WAL/SHM/journal sidecars so history from a CURRENTLY OPEN/RUNNING browser
  # (recent activity not yet checkpointed into the main DB) is captured too.
  for sc in "-wal" "-shm" "-journal"; do
    [ -f "${orig}${sc}" ] && [ ! -L "${orig}${sc}" ] && cp -p "${orig}${sc}" "${dst}${sc}" 2>/dev/null || true
  done
  printf '%s' "$dst"
}

# -----------------------------------------------------------------------------
# Discovery: build a list of "User<SEP>Browser<SEP>DbPath" lines
# -----------------------------------------------------------------------------
DISCOVERED=""

# Platform browser base paths relative to a user home.
# For Chromium browsers the snap/flatpak variants are also probed.
browser_base() {   # home browser -> one or more candidate base dirs (newline separated)
  local home="$1" b="$2"
  case "$b" in
    Chrome)
      echo "$home/.config/google-chrome"
      echo "$home/.var/app/com.google.Chrome/config/google-chrome" ;;
    Edge)
      echo "$home/.config/microsoft-edge"
      echo "$home/.var/app/com.microsoft.Edge/config/microsoft-edge" ;;
    Brave)
      echo "$home/.config/BraveSoftware/Brave-Browser"
      echo "$home/snap/brave/current/.config/BraveSoftware/Brave-Browser"
      echo "$home/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser" ;;
    Vivaldi)
      echo "$home/.config/vivaldi" ;;
    Chromium)
      echo "$home/.config/chromium"
      echo "$home/snap/chromium/common/chromium"
      echo "$home/.var/app/org.chromium.Chromium/config/chromium" ;;
    Firefox)
      echo "$home/.mozilla/firefox"
      echo "$home/snap/firefox/common/.mozilla/firefox"
      echo "$home/.var/app/org.mozilla.firefox/.mozilla/firefox" ;;
  esac
}

discover_for_home() {
  local user="$1" home="$2"
  local b base pf name
  local before="$DISCOVERED"
  for b in "${SELECTED[@]}"; do
    # browser_base may return several candidate roots (native / snap / flatpak)
    while IFS= read -r base; do
      [ -n "$base" ] && [ -d "$base" ] || continue
      if [ "$b" = "Firefox" ]; then
        while IFS= read -r pf; do
          [ -f "$pf/places.sqlite" ] && DISCOVERED+="$user$SEP$b$SEP$pf/places.sqlite"$'\n'
        done < <(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
      else
        while IFS= read -r pf; do
          name=$(basename "$pf")
          case "$name" in
            Default|Profile\ *) [ -f "$pf/History" ] && DISCOVERED+="$user$SEP$b$SEP$pf/History"$'\n' ;;
          esac
        done < <(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
      fi
    done < <(browser_base "$home" "$b")
  done
  # A profile holding no database for any selected browser is still reported, so
  # the summary section shows every account that was examined.
  [ "$DISCOVERED" = "$before" ] && EMPTY_PROFILES+="$user"$'\n'
  return 0
}

# Custom -Path discovery (file or directory)
discover_custom() {
  local cp="$1" leaf="CustomPath"
  [ -e "$cp" ] || die "-Path not found: $cp"
  local chromium_sel=0 firefox_sel=0 b
  for b in "${SELECTED[@]}"; do
    case "$b" in Firefox) firefox_sel=1 ;; *) chromium_sel=$((chromium_sel+1)) ;; esac
  done
  local files=()
  if [ -f "$cp" ]; then
    files=("$cp")
  else
    while IFS= read -r f; do files+=("$f"); done < <(find "$cp" \( -name History -o -name places.sqlite \) -type f 2>/dev/null)
  fi
  local f low brow
  for f in "${files[@]}"; do
    local bn; bn=$(basename "$f")
    if [ "$bn" = "places.sqlite" ]; then
      [ "$firefox_sel" -eq 1 ] && DISCOVERED+="$leaf${SEP}Firefox$SEP$f"$'\n'
      continue
    fi
    # 'History' (chromium) or explicit file
    low=$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')
    brow=""
    case "$low" in
      *edge*) brow=Edge ;; *brave*) brow=Brave ;; *vivaldi*) brow=Vivaldi ;; *chromium*) brow=Chromium ;; *chrome*) brow=Chrome ;;
    esac
    if [ -z "$brow" ]; then
      if [ "$bn" != "History" ] && [ "$firefox_sel" -eq 1 ] && [ "$chromium_sel" -eq 0 ]; then
        DISCOVERED+="$leaf${SEP}Firefox$SEP$f"$'\n'; continue
      fi
      brow=Chrome
    fi
    in_selected "$brow" && DISCOVERED+="$leaf$SEP$brow$SEP$f"$'\n'
  done
}

in_selected() { local x; for x in "${SELECTED[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# Look up a user's home directory from the passwd database (getent if present)
home_of_user() {
  local u="$1" h=""
  if command -v getent >/dev/null 2>&1; then
    h=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
  fi
  [ -z "$h" ] && h=$(awk -F: -v u="$u" '$1==u{print $6}' /etc/passwd 2>/dev/null)
  [ -z "$h" ] && [ -d "/home/$u" ] && h="/home/$u"
  printf '%s' "$h"
}

# Enumerate target users/homes (Linux: /etc/passwd homes + /home + root)
enumerate_targets() {
  if [ -n "$PATH_ARG" ]; then
    discover_custom "$PATH_ARG"; return
  fi
  if [ -n "$USERNAME" ]; then
    local home
    case "$USERNAME" in
      /*) home="$USERNAME" ;;                       # a full profile path was given
      *)  home=$(home_of_user "$USERNAME") ;;
    esac
    [ -n "$home" ] && [ -d "$home" ] || { warn "User home not found for '$USERNAME'"; return; }
    discover_for_home "$(basename "$home")" "$home"; return
  fi
  if [ "$(id -u)" -eq 0 ]; then
    vlog "Running as root: scanning all human user profiles"
    local line u h seen=""
    # Real users (uid >= 1000) from passwd, plus root, de-duplicated by home path.
    while IFS=: read -r u _ uid _ _ h _; do
      [ "$u" = "root" ] || { [ "${uid:-0}" -ge 1000 ] && [ "${uid:-0}" -lt 65534 ]; } || continue
      [ -n "$h" ] && [ -d "$h" ] || continue
      case "$seen" in *"|$h|"*) continue ;; esac
      seen="$seen|$h|"
      discover_for_home "$u" "$h"
    done < /etc/passwd
    # Fallback: any /home/* dirs not already covered
    local d name
    while IFS= read -r d; do
      name=$(basename "$d")
      case "$seen" in *"|$d|"*) continue ;; esac
      discover_for_home "$name" "$d"
    done < <(find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
  else
    discover_for_home "$(id -un)" "$HOME"
  fi
}

# -----------------------------------------------------------------------------
# AWK: per-record formatting + de-fang + DecodedParams + redirect-chain analysis
# Single-quoted so bash does not expand $ — control values are passed via -v.
# -----------------------------------------------------------------------------
read -r -d '' AWK_FORMAT <<'AWKEOF' || true
# --- hex / url-decode helpers (no gawk-only builtins) ---
function hexval(c,   d){ d=index("0123456789abcdef", tolower(c)); return d-1 }
function urldecode(s,   out,i,c,h1,h2){
  out=""; i=1
  while(i<=length(s)){
    c=substr(s,i,1)
    if(c=="%" && i+2<=length(s)){
      h1=hexval(substr(s,i+1,1)); h2=hexval(substr(s,i+2,1))
      if(h1>=0 && h2>=0){ out=out sprintf("%c", h1*16+h2); i+=3; continue }
    }
    if(c=="+") c=" "
    out=out c; i++
  }
  return out
}
# base64 decode -> returns printable runs (len>=4) joined by " | ", or ""
function b64char(c){ return index("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", c)-1 }
function b64extract(s,   t,i,c,n,acc,bits,bytes,b,run,res,ch){
  gsub(/-/,"+",s); gsub(/_/,"/",s); gsub(/=+$/,"",s)
  if(length(s)<8) return ""
  t=""
  for(i=1;i<=length(s);i++){ c=substr(s,i,1); if(b64char(c)<0) return "" }
  acc=0; bits=0; bytes=""
  for(i=1;i<=length(s);i++){
    acc=acc*64 + b64char(substr(s,i,1)); bits+=6
    if(bits>=8){ bits-=8; b=int(acc/ (2^bits)); acc=acc - b*(2^bits); bytes=bytes sprintf("%c", b%256) }
  }
  # extract printable runs len>=4
  res=""; run=""
  for(i=1;i<=length(bytes);i++){
    ch=substr(bytes,i,1)
    if(ch ~ /[\040-\176]/){ run=run ch }
    else { if(length(run)>=4){ res=(res==""?run:res" | "run) } run="" }
  }
  if(length(run)>=4){ res=(res==""?run:res" | "run) }
  return res
}
function decode_params(url,   q,pairs,np,i,kv,k,v,b,out){
  if(url=="" || url=="N/A") return ""
  i=index(url,"?"); if(i==0) return ""
  q=substr(url,i+1)
  # strip fragment
  j=index(q,"#"); if(j>0) q=substr(q,1,j-1)
  np=split(q,pairs,"&"); out=""
  for(i=1;i<=np;i++){
    kv=pairs[i]; if(kv=="") continue
    k=kv; v=""
    eq=index(kv,"="); if(eq>0){ k=substr(kv,1,eq-1); v=substr(kv,eq+1) }
    if(k=="") continue
    v=urldecode(v)
    b=b64extract(v)
    if(b!="") v="[Base64->ASCII]: " b
    out=(out=="" ? k"="v : out"; "k"="v)
  }
  return out
}
# --- de-fang (skips file/local paths). awk gsub has no backrefs, so dots are
#     rewritten with a left-to-right match() pass; intervals {n,} are avoided
#     for mawk portability. ---
function defang_dots(s,   out,rest,seg,dp){
  out=""; rest=s
  while(match(rest, /[A-Za-z0-9-]+\.[A-Za-z][A-Za-z]+/)){
    seg=substr(rest,RSTART,RLENGTH); dp=index(seg,".")
    out=out substr(rest,1,RSTART-1) substr(seg,1,dp-1) "[.]" substr(seg,dp+1)
    rest=substr(rest,RSTART+RLENGTH)
  }
  return out rest
}
function defang_ip(s,   out,rest,seg,dp){
  out=""; rest=s
  while(match(rest, /[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*/)){
    seg=substr(rest,RSTART,RLENGTH); dp=index(seg,".")
    out=out substr(rest,1,RSTART-1) substr(seg,1,dp-1) "[.]" substr(seg,dp+1)
    rest=substr(rest,RSTART+RLENGTH)
  }
  return out rest
}
function defang2(s,   r){
  if(NODEFANG==1) return s
  if(s=="" || s=="N/A") return s
  if(s ~ /^[A-Za-z]:\\/ || s ~ /^\\\\/ || s ~ /^file:\/\/\//) return s
  r=s
  gsub(/https:\/\//,"hxxps[://]",r); gsub(/http:\/\//,"hxxp[://]",r)
  gsub(/ftp:\/\//,"fxp[://]",r)
  r=defang_ip(defang_dots(r))
  return r
}
function host_of(u,   s,h,i){
  s=u
  gsub(/hxxps\[:\/\/\]/,"https://",s); gsub(/hxxp\[:\/\/\]/,"http://",s)
  gsub(/\[\.\]/,".",s); gsub(/\[:\]/,":",s)
  i=index(s,"://"); if(i>0) s=substr(s,i+3)
  i=index(s,"/"); if(i>0) s=substr(s,1,i-1)
  i=index(s,"?"); if(i>0) s=substr(s,1,i-1)
  return s
}
function fmt3(x,   r){ r=sprintf("%.3f", x+0); sub(/0+$/,"",r); sub(/\.$/,"",r); return r }
function human(b,   x){
  b=b+0
  if(b>=1073741824*0.9) return sprintf("%.2f GB", b/1073741824)
  if(b>=1048576*0.9)    return sprintf("%.2f MB", b/1048576)
  if(b>=1024*0.9)       return sprintf("%.2f KB", b/1024)
  return b " Bytes"
}
BEGIN{ FS=sep; OFS=sep; n=0; rxl=tolower(rx) }
{
  if($4=="") next   # no valid timestamp -> skip (parity with Windows Test-ValidRow)
  if(rx!=""){
    if(!(tolower($6) ~ rxl || tolower($8) ~ rxl || tolower($9) ~ rxl || tolower($7) ~ rxl)) next
  }
  n++
  user[n]=$1; browser[n]=$2; rtype[n]=$3
  ts[n]=$4; epoch[n]=$5+0; url[n]=$6; title[n]=$7; searchurl[n]=$8; path[n]=$9
  tinfo[n]=$10; tdet[n]=$11; refurl[n]=$12; reftitle[n]=$13; dur[n]=$14; ttn[n]=$15
  prev[n]=$16; cur[n]=$17; nextid[n]=$18; nexturl[n]=$19; initid[n]=$20; inittime[n]=$21
  endt[n]=$22; state[n]=$23; bytes[n]=$24; mime[n]=$25; danger[n]=$26; opened[n]=$27
  dlchain[n]=$28
  chain[n]=""
}
END{
  # ---- redirect chain analysis (per user|browser, time-ordered) ----
  if(analyze=="true"){
    for(i=1;i<=n;i++){
      g=user[i] "|" browser[i]
      if(g in lastidx){
        p=lastidx[g]
        diff=epoch[i]-epoch[p]
        # skip visit<->download pairs
        skip=0
        if(rtype[p]=="Visit" && rtype[i]=="Download" && cur[p]!="" && initid[i]!="" && cur[p]==initid[i]) skip=1
        if(rtype[p]=="Download" && rtype[i]=="Visit" && initid[p]!="" && cur[i]!="" && initid[p]==cur[i]) skip=1
        if(!skip && diff>=0 && diff<=30 && rtype[p]=="Visit" && rtype[i]=="Visit"){
          ind=""; like=0; multitab=0
          if(refurl[p]!="" && refurl[p]!="N/A" && refurl[p]==refurl[i] && prev[p]!="" && prev[p]==prev[i] && diff>5) multitab=1
          if(!multitab){
            if(diff<0.1){ ind=addind(ind,"Very Fast Redirect (<100ms)"); like=1 }
            else if(diff<1.0){ ind=addind(ind,"Fast Redirect (<1s)"); like=1 }
            else if(diff<5.0){ ind=addind(ind,"Rapid Navigation (<5s)"); like=1 }
            else { like=1 }
          } else {
            if(diff<0.5){ ind=addind(ind,"Very Fast Multi-Tab Opening"); like=1 }
          }
          if(!multitab){
            hp=host_of(url[p]); hi=host_of(url[i])
            if(hp!="" && hi!="" && hp!=hi){ ind=addind(ind,"Domain Change"); like=1 }
          }
          if(tinfo[p] ~ /Redirect/){ ind=addind(ind,"Explicit Redirect"); like=1 }
          if(tinfo[i] ~ /Redirect/){ ind=addind(ind,"Explicit Redirect"); like=1 }
          if(like && ind!=""){
            cpos[g]++
            # current record
            ttonext[p]=diff; suspd[p]=merge(suspd[p],ind); part[p]=1; if(pos[p]=="") pos[p]=cpos[g]
            # next record
            tfromprev[i]=diff; suspd[i]=merge(suspd[i],ind); part[i]=1; pos[i]=cpos[g]+1
          }
        }
      }
      lastidx[g]=i
    }
    for(i=1;i<=n;i++){
      if(part[i]==1){
        s=""
        if(pos[i]!="")        s=add(s,"Position: " pos[i])
        if(ttonext[i]!="")    s=add(s,"Next: " fmt3(ttonext[i]) "s")
        if(tfromprev[i]!="")  s=add(s,"Prev: " fmt3(tfromprev[i]) "s")
        if(suspd[i]!="")      s=add(s,"SUSPICIOUS: " suspd[i])
        chain[i]=s
      }
    }
  }
  # ---- output in incoming order (already globally sorted by epoch asc) ----
  for(i=1;i<=n;i++){
    emit("RecordType", rtype[i])
    emit("User", user[i])
    emit("Browser", browser[i])
    emit("TimestampUTC", ts[i])
    emiturl("URL", url[i])
    if(rtype[i]=="Keyword") emiturl("SearchURL", searchurl[i])
    if(rtype[i]=="Download") emit("Path", localpath(path[i]))
    emit("Title", defangtitle(title[i]))
    dp=decode_params(url[i]); if(dp!="") emit("DecodedParams", defang2(dp))
    emit("TransitionInfo", tinfo[i])
    emit("TransitionDetails", tdet[i])
    emiturlne("ReferrerURL", refurl[i])
    emitne("ReferrerTitle", reftitle[i])
    if(dur[i]!="" && dur[i]+0!=0) emit("DurationSeconds", fmt3(dur[i]) "s")
    if(ttn[i]!="" && ttn[i]+0!=0) emit("TimeToNext", fmt3(ttn[i]) "s")
    emitne("PreviousVisitID", prev[i])
    emitne("CurrentVisitID", cur[i])
    emitne("NextVisitID", nextid[i])
    emiturlne("NextURL", nexturl[i])
    emitne("InitiatingVisitID", initid[i])
    emitne("InitiatingVisitTime", inittime[i])
    if(rtype[i]=="Download"){
      if(dlchain[i]!="") emit("RedirectChain", defang2(dlchain[i]))
      emitne("EndTimeUTC", endt[i])
      emitne("State", state[i])
      if(bytes[i]!="" ){ emit("TotalBytes", bytes[i]); emit("SizeFormatted", human(bytes[i])) }
      emitne("MimeType", mime[i])
      emitne("DangerType", danger[i])
      emitne("Opened", opened[i])
    }
    if(chain[i]!="") emit("ChainAnalysis", chain[i])
    print ""
  }
}
function add(s,t){ return (s==""? t : s " | " t) }
function addind(s,t){ if(index(s,t)>0) return s; return (s==""? t : s ", " t) }
function merge(a,b,   arr,na,i,seen,out,parts,np,j){
  out=a
  np=split(b,parts,", ")
  for(j=1;j<=np;j++){ if(parts[j]!="" && index(out,parts[j])==0) out=(out==""?parts[j]:out", "parts[j]) }
  return out
}
function defangtitle(t){ return t }  # titles are not de-fanged in original
function localpath(p){ if(p ~ /^file:\/\/\//){ sub(/^file:\/\//,"",p); gsub(/%20/," ",p) } return p }
function emit(label,val){ if(val=="") return; printf "%-17s : %s\n", label, val }
function emitne(label,val){ if(val=="" || val=="N/A") return; printf "%-17s : %s\n", label, val }
function emiturl(label,val,   v){ if(val=="") val="N/A"; v=defang2(val); printf "%-17s : %s\n", label, v }
function emiturlne(label,val,   v){ if(val=="" || val=="N/A") return; v=defang2(val); printf "%-17s : %s\n", label, v }
AWKEOF

# -----------------------------------------------------------------------------
# Database summary
# -----------------------------------------------------------------------------
db_summary() {
  local user="$1" family="$2" db="$3" browser="$4" origpath="$5"
  local table datecol econv
  case "$family" in
    firefox) table=moz_historyvisits; datecol=visit_date; econv="/1000000.0" ;;
    *)       table=visits;            datecol=visit_time; econv="/1000000.0 - 11644473600" ;;
  esac
  local cnt rng size maxep
  size=$(ls -lh "$origpath" 2>/dev/null | awk '{print $5}')
  cnt=$(sql_scalar "$db" "SELECT COUNT(*) FROM $table;")
  rng=$(sql_query "$db" "SELECT strftime('%Y-%m-%d %H:%M:%S', MIN($datecol)$econv,'unixepoch'), strftime('%Y-%m-%d %H:%M:%S', MAX($datecol)$econv,'unixepoch'), CAST(COALESCE(MAX($datecol)$econv,0) AS INTEGER) FROM $table WHERE $datecol > 0;")
  # Last-visit epoch doubles as the sort key for the summary section; the caller
  # reads it back out of SUMMARY_MAXEP (redirection does not spawn a subshell).
  maxep=$(printf '%s' "$rng" | awk -v s="$SEP" 'BEGIN{FS=s}{print $3}')
  SUMMARY_MAXEP=${maxep:-0}
  log "User: $user | Browser: $browser | Path: $origpath | Size: ${size:-?} | Visits: ${cnt:-0}"
  if [ -n "$rng" ]; then
    local rngfmt; rngfmt=$(printf '%s' "$rng" | awk -v s="$SEP" 'BEGIN{FS=s}{if($1!="")print $1" to "$2}')
    [ -n "$rngfmt" ] && log "History Range (UTC): $rngfmt"
  fi
  # A non-empty WAL means there is uncommitted data that our copy merges in.
  # (An empty/0-byte -wal is just a leftover and says nothing about a running browser.)
  if [ -s "${origpath}-wal" ]; then
    local walsz; walsz=$(wc -c < "${origpath}-wal" 2>/dev/null | tr -d ' ')
    log "Note: non-empty WAL present (${walsz} bytes) - uncommitted recent activity is included."
  fi
  analyze_cleaning "$family" "$db" "$browser" "$origpath"
  log ""
}

# -----------------------------------------------------------------------------
# History-cleaning detection: visit-ID gap census (interior + tail + leading),
# per-URL count mismatch, and ~90-day auto-expiry discrimination. Deleted visits
# leave gaps in the auto-increment id sequence (ids are never reused), so gaps =
# deleted records and the bracketing timestamps estimate WHEN. Prints a one-line
# note in the summary and appends a detail block to $CLEANING_DETAIL.
# -----------------------------------------------------------------------------
analyze_cleaning() {
  local family="$1" db="$2" browser="$3" origpath="$4"
  [ "${CLEANING_ENABLED:-0}" -eq 1 ] || return 0
  local table datecol econv seqname urlmm_sql
  case "$family" in
    firefox) table=moz_historyvisits; datecol=visit_date; econv="/1000000.0"; seqname=moz_historyvisits
             urlmm_sql="SELECT COUNT(*) FROM moz_places p WHERE p.visit_count>0 AND NOT EXISTS (SELECT 1 FROM moz_historyvisits h WHERE h.place_id=p.id);" ;;
    *)       table=visits; datecol=visit_time; econv="/1000000.0 - 11644473600"; seqname=visits
             urlmm_sql="SELECT COUNT(*) FROM urls u WHERE u.visit_count > (SELECT COUNT(*) FROM visits v WHERE v.url=u.id);" ;;
  esac

  # Always analyzes the whole database, ignoring any active time filter or
  # record-selection switch, so this matches the all-time Visits/Range already
  # shown in the summary.
  local stats min_id max_id cnt
  stats=$(sql_query "$db" "SELECT COALESCE(MIN(id),0), COALESCE(MAX(id),0), COUNT(*) FROM $table;")
  min_id=$(printf '%s' "$stats" | awk -v s="$SEP" 'BEGIN{FS=s}{print $1+0; exit}')
  max_id=$(printf '%s' "$stats" | awk -v s="$SEP" 'BEGIN{FS=s}{print $2+0; exit}')
  cnt=$(printf '%s' "$stats"   | awk -v s="$SEP" 'BEGIN{FS=s}{print $3+0; exit}')

  local interior=0
  if [ "${cnt:-0}" -gt 0 ]; then interior=$(( max_id - min_id + 1 - cnt )); [ "$interior" -lt 0 ] && interior=0; fi

  local tail=0 seq="" seq_known=0 gmax=0
  seq=$(sql_scalar "$db" "SELECT seq FROM sqlite_sequence WHERE name='$seqname';")
  case "$seq" in ''|*[!0-9]*) seq="" ;; *) seq_known=1 ;; esac
  gmax=$(sql_scalar "$db" "SELECT COALESCE(MAX(id),0) FROM $table;"); case "$gmax" in ''|*[!0-9]*) gmax=0 ;; esac
  [ "$seq_known" -eq 1 ] && [ "$seq" -gt "$gmax" ] && tail=$(( seq - gmax ))

  local urlmm=0 leading=0 expiry=0 age_days=0
  urlmm=$(sql_scalar "$db" "$urlmm_sql"); case "$urlmm" in ''|*[!0-9]*) urlmm=0 ;; esac
  [ "${min_id:-0}" -gt 0 ] && leading=$(( min_id - 1 ))
  if [ "$leading" -gt 0 ]; then
    local min_epoch; min_epoch=$(sql_scalar "$db" "SELECT CAST(MIN($datecol)$econv AS INTEGER) FROM $table WHERE $datecol>0;")
    case "$min_epoch" in ''|*[!0-9]*) min_epoch=0 ;; esac
    if [ "$min_epoch" -gt 0 ]; then age_days=$(( ( $(now_epoch) - min_epoch ) / 86400 )); [ "$age_days" -ge 85 ] && expiry=1; fi
  fi

  local suspicious=$(( interior + tail ))
  if [ "$suspicious" -gt 0 ]; then
    log "Note: Possible history cleaning - ${suspicious} missing visit ID(s) (${interior} interior, ${tail} tail)."
  fi

  [ "$suspicious" -eq 0 ] && [ "$urlmm" -eq 0 ] && [ "$expiry" -eq 0 ] && return 0

  {
    printf '%s (%s)\n' "$browser" "$origpath"
    printf '  Visit IDs present : %s (id range %s-%s, highest ever assigned %s)\n' "$cnt" "$min_id" "$max_id" "${seq:-unknown}"
    if [ "$interior" -gt 0 ]; then
      printf '  Interior gaps     : %s visit(s) deleted between surviving records\n' "$interior"
      if [ "$HAVE_WINDOW" -eq 1 ]; then
        sql_query "$db" "
SELECT prev_ts, cur_ts, (cur_id - prev_id - 1) FROM (
  SELECT id AS cur_id, LAG(id) OVER (ORDER BY id) AS prev_id,
   strftime('%Y-%m-%d %H:%M:%S', $datecol$econv,'unixepoch') AS cur_ts,
   LAG(strftime('%Y-%m-%d %H:%M:%S', $datecol$econv,'unixepoch')) OVER (ORDER BY id) AS prev_ts
  FROM $table
) WHERE cur_id - prev_id > 1 ORDER BY (cur_id - prev_id) DESC LIMIT 5;" \
        | awk -v s="$SEP" 'BEGIN{FS=s}{printf "    est. window : %s -> %s  (~%s visit(s))\n",($1==""?"?":$1),($2==""?"?":$2),$3}'
      fi
    fi
    if [ "$tail" -gt 0 ]; then
      local tts; tts=$(sql_scalar "$db" "SELECT strftime('%Y-%m-%d %H:%M:%S', $datecol$econv,'unixepoch') FROM $table WHERE id=$gmax;")
      printf '  Tail deletion     : %s recent visit(s) removed after %s\n' "$tail" "${tts:-?}"
    fi
    [ "$urlmm" -gt 0 ] && printf '  URL count mismatch: %s URL(s) record more visits than survive (per-entry deletion)\n' "$urlmm"
    [ "$expiry" -eq 1 ] && printf '  Leading gap       : %s older id(s) absent; oldest record ~%s days old (consistent with ~90-day auto-expiry, NOT counted as cleaning)\n' "$leading" "$age_days"
    [ "$seq_known" -eq 0 ] && printf '  Tail detection    : sqlite_sequence has no row for %s; tail-deletion detection unavailable (interior gaps still valid)\n' "$seqname"
    printf '\n'
  } >> "$CLEANING_DETAIL"
  return 0
}

# Print stdin with URLs de-fanged (scheme + dotted tokens), honoring -NoDefang.
defang_lines() {
  [ "$NODEFANG" -eq 1 ] && { cat; return; }
  awk '
    function defang_dots(s,   out,rest,seg,dp){
      out=""; rest=s
      while(match(rest, /[A-Za-z0-9-]+\.[A-Za-z][A-Za-z]+/)){
        seg=substr(rest,RSTART,RLENGTH); dp=index(seg,".")
        out=out substr(rest,1,RSTART-1) substr(seg,1,dp-1) "[.]" substr(seg,dp+1)
        rest=substr(rest,RSTART+RLENGTH)
      }
      return out rest
    }
    { s=$0; gsub(/https:\/\//,"hxxps[://]",s); gsub(/http:\/\//,"hxxp[://]",s); gsub(/ftp:\/\//,"fxp[://]",s); print defang_dots(s) }'
}

# Normalize URLs / host strings to plausible hostnames (lowercased), one per line.
# Handles full URLs, cookie host_keys (leading dot), userinfo@, ports, partitions;
# filters template placeholders and bare words so only real hostnames survive.
normalize_hosts() {
  awk '
    { s=tolower($0)
      i=index(s,"://"); if(i>0) s=substr(s,i+3)
      a=index(s,"@");   if(a>0) s=substr(s,a+1)
      p=index(s,"/");   if(p>0) s=substr(s,1,p-1)
      p=index(s,"?");   if(p>0) s=substr(s,1,p-1)
      p=index(s,"#");   if(p>0) s=substr(s,1,p-1)
      p=index(s,"^");   if(p>0) s=substr(s,1,p-1)
      sub(/^\./,"",s)
      c=index(s,":");   if(c>0) s=substr(s,1,c-1)
      if(s ~ /^[a-z0-9][a-z0-9.-]*\.[a-z][a-z]+$/) print s
    }'
}

# Given candidate URLs/hosts on stdin, print a report block for hosts absent from
# the history-host set ($HISTHOSTS). Prints nothing when there are no orphans.
report_orphan_hosts() {   # $1=label
  local label="$1" orph oc
  orph=$(normalize_hosts | sort -u | awk -v hf="$HISTHOSTS" '
    BEGIN{ while((getline h < hf) > 0) seen[h]=1 } ($0!="" && !($0 in seen))')
  oc=$(printf '%s\n' "$orph" | grep -c .)
  [ "${oc:-0}" -gt 0 ] || return 0
  printf '  %-23s : %s domain(s) with no history visit\n' "$label" "$oc"
  printf '%s\n' "$orph" | head -3 | defang_lines | sed 's/^/      e.g. /'
}

# Copy an artifact SQLite DB, run a URL/host-producing query, report orphan hosts.
sqlite_artifact() {   # $1=label $2=file $3=sql
  local label="$1" file="$2" sql="$3"
  [ -f "$file" ] || return 0
  local t; t=$(copy_db "$file") || return 0
  sql_query "$t" "$sql" | report_orphan_hosts "$label"
  rm -f "$t" "$t"-* 2>/dev/null
}

# Pull http(s) URLs out of a JSON/text file (Bookmarks, logins.json, ...).
json_urls() { [ -f "$1" ] && grep -oE 'https?://[^"'"'"' <>]+' "$1" 2>/dev/null; }

# Chromium incognito posture (best-effort, from on-disk config).
private_posture_chromium() {
  local profdir="$1" prefs="$profdir/Preferences" lstate; lstate="$(dirname "$profdir")/Local State"
  local ima="" pf
  for pf in "$prefs" "$lstate"; do
    [ -f "$pf" ] || continue
    ima=$(grep -o '"IncognitoModeAvailability":[0-9]*' "$pf" 2>/dev/null | head -1 | grep -o '[0-9]*$')
    [ -n "$ima" ] && break
  done
  case "$ima" in
    1) printf '  %-23s : DISABLED by policy\n' 'Incognito posture' ;;
    2) printf '  %-23s : FORCED by policy\n'   'Incognito posture' ;;
    *) printf '  %-23s : available (no restricting policy found)\n' 'Incognito posture' ;;
  esac
  if [ -f "$prefs" ]; then
    local exti; exti=$(grep -o '"incognito":true' "$prefs" 2>/dev/null | grep -c .)
    [ "${exti:-0}" -gt 0 ] && printf '  %-23s : %s allowed (may persist data from private tabs)\n' 'Extensions in incognito' "$exti"
  fi
}

# Firefox private-browsing posture.
private_posture_firefox() {
  local pj="$1/prefs.js" pba=""
  [ -f "$pj" ] && pba=$(grep 'browser.privatebrowsing.autostart' "$pj" 2>/dev/null | grep -o 'true\|false' | head -1)
  case "$pba" in
    true) printf '  %-23s : permanent private mode ON (autostart=true)\n' 'Private posture' ;;
    *)    printf '  %-23s : normal (private mode available on demand)\n'  'Private posture' ;;
  esac
}

# Firefox DOM-storage origin directories -> origin URLs (dir listing, no parse).
ff_storage_hosts() {
  [ -d "$1/storage/default" ] || return 0
  find "$1/storage/default" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
    | while IFS= read -r d; do basename "$d"; done | sed 's/+++/:\/\//'
}

# Note present-but-binary artifacts we do not parse (honest coverage).
present_binary() {   # $1=label $2..=candidate paths
  local label="$1"; shift
  local p found=""
  for p in "$@"; do [ -e "$p" ] && found="$found, $(basename "$p")"; done
  [ -n "$found" ] && printf '  %-23s : %s\n' "$label" "${found#, }"
}

# -----------------------------------------------------------------------------
# Private-browsing artifacts (opt-in via -Private). Private/incognito sessions
# leave no history rows, so we mine EVERY parseable profile artifact that records
# a URL/origin and report any host with NO matching history visit - evidence a
# domain was reached but never recorded (private OR deleted). First-party
# navigation artifacts (favicons, top sites, omnibox, saved logins, bookmarks)
# are the strong signal; contact/embedded artifacts (cookies, NEL, storage) also
# include third-party domains. Also reports incognito posture and lists
# present-but-binary artifacts we do not parse. Appends one block per DB.
# -----------------------------------------------------------------------------
collect_private() {
  local family="$1" histtmp="$2" browser="$3" origpath="$4" user="$5"
  [ "${PRIVATE_ENABLED:-0}" -eq 1 ] || return 0
  local profdir; profdir=$(dirname "$origpath")
  local bodyfile="$histtmp.privbody"; : > "$bodyfile"
  HISTHOSTS="$histtmp.histhosts"

  if [ "$family" = "chromium" ]; then
    sql_query "$histtmp" "SELECT url FROM urls" | normalize_hosts | sort -u > "$HISTHOSTS"
    local cookiedb="$profdir/Cookies"; [ -f "$profdir/Network/Cookies" ] && cookiedb="$profdir/Network/Cookies"
    {
      sqlite_artifact 'Favicons (pages)'    "$profdir/Favicons"                 'SELECT DISTINCT page_url FROM icon_mapping'
      sqlite_artifact 'Top Sites'           "$profdir/Top Sites"                'SELECT url FROM top_sites'
      sqlite_artifact 'Omnibox shortcuts'   "$profdir/Shortcuts"                'SELECT url FROM omni_box_shortcuts'
      sqlite_artifact 'Typed-URL predictor' "$profdir/Network Action Predictor" 'SELECT DISTINCT url FROM network_action_predictor'
      sqlite_artifact 'Saved-login origins' "$profdir/Login Data"               'SELECT origin_url FROM logins UNION SELECT action_url FROM logins'
      sqlite_artifact 'Search keywords'     "$profdir/Web Data"                 'SELECT url FROM keywords'
      sqlite_artifact 'Media-play origins'  "$profdir/Media History"            'SELECT origin FROM origin'
      sqlite_artifact 'NEL/report origins'  "$profdir/Reporting and NEL"        'SELECT DISTINCT origin FROM nel_policies'
      sqlite_artifact 'Cookie domains'      "$cookiedb"                         'SELECT DISTINCT host_key FROM cookies'
      json_urls "$profdir/Bookmarks" | report_orphan_hosts 'Bookmarked domains'
      private_posture_chromium "$profdir"
      present_binary 'Present (not parsed)' "$profdir/Sessions" "$profdir/Current Session" "$profdir/Last Session" "$profdir/Visited Links" "$profdir/Cache"
    } >> "$bodyfile"
  elif [ "$family" = "firefox" ]; then
    sql_query "$histtmp" "SELECT url FROM moz_places" | normalize_hosts | sort -u > "$HISTHOSTS"
    {
      sqlite_artifact 'Favicons (pages)'   "$profdir/favicons.sqlite"      'SELECT DISTINCT page_url FROM moz_pages_w_icons'
      sqlite_artifact 'Cookie domains'     "$profdir/cookies.sqlite"       'SELECT DISTINCT host FROM moz_cookies'
      sqlite_artifact 'Permission origins' "$profdir/permissions.sqlite"   'SELECT DISTINCT origin FROM moz_perms'
      sqlite_artifact 'Content-pref sites' "$profdir/content-prefs.sqlite" 'SELECT DISTINCT name FROM groups'
      json_urls "$profdir/logins.json" | report_orphan_hosts 'Saved-login hosts'
      ff_storage_hosts "$profdir" | report_orphan_hosts 'DOM-storage origins'
      private_posture_firefox "$profdir"
      present_binary 'Present (not parsed)' "$profdir/sessionstore.jsonlz4" "$profdir/sessionstore-backups"
    } >> "$bodyfile"
  fi

  if [ -s "$bodyfile" ]; then
    { printf '%s (%s)\n' "$browser" "$origpath"; cat "$bodyfile"; printf '\n'; } >> "$PRIVATE_DETAIL"
  fi
  rm -f "$bodyfile" "$HISTHOSTS" 2>/dev/null
}

# =============================================================================
# FollowChain mode
# =============================================================================
follow_chain() {
  local target="$1"
  log ""
  log "=== ENHANCED NAVIGATION CHAIN ANALYSIS ==="
  log "Target VisitID: $target"
  enumerate_targets
  [ -n "$DISCOVERED" ] || { warn "No databases found."; return; }
  local found=0
  while IFS="$SEP" read -r user browser db; do
    [ -n "$db" ] || continue
    local family; family=$(family_of "$browser")
    local tmp; tmp=$(copy_db "$db") || continue
    local rows; rows=$(chain_query "$family" "$tmp" "$target")
    if [ -n "$rows" ]; then
      found=1
      log "Found VisitID $target in $browser ($user)"
      log "$(printf '=%.0s' $(seq 1 65))"
      printf '%s\n' "$rows" | awk -v sep="$SEP" -v nodefang="$NODEFANG" -v target="$target" "$AWK_CHAIN"
      break
    fi
  done <<< "$DISCOVERED"
  [ "$found" -eq 0 ] && warn "VisitID $target was not found in any selected (Chromium/Firefox) database."
}

chain_query() {
  local family="$1" db="$2" target="$3"
  [ "$HAVE_WINDOW" -eq 1 ] || { warn "Window functions unavailable; -FollowChain needs SQLite>=3.25"; return; }
  local tinfo tdet
  if [ "$family" = "chromium" ]; then
    tinfo="$(build_chromium_tinfo)"; tdet="$(build_chromium_tdetails)"
    local tt; tt=$(sql_scalar "$db" "SELECT visit_time FROM visits WHERE id=$target;")
    [ -n "$tt" ] || return
    local ws we; ws=$((tt-300000000)); we=$((tt+300000000))
    sql_query "$db" "
SELECT
 CASE WHEN v.id=$target THEN 0
   WHEN v.visit_time<$tt THEN -1*ROW_NUMBER() OVER (PARTITION BY (v.visit_time<$tt) ORDER BY v.visit_time DESC)
   WHEN v.visit_time>$tt THEN ROW_NUMBER() OVER (PARTITION BY (v.visit_time>$tt) ORDER BY v.visit_time ASC) ELSE 0 END,
 CASE WHEN v.id=$target THEN 'Center' WHEN v.visit_time<$tt THEN 'Backward' ELSE 'Forward' END,
 $(ts_chromium v.visit_time), $(ep_chromium v.visit_time), $(clean u.url), $(clean u.title),
 v.id, v.from_visit, $tinfo, $tdet, $(clean ref_u.url), $(clean ref_u.title),
 LEAD(v.id) OVER (ORDER BY v.visit_time), LEAD($(clean u.url)) OVER (ORDER BY v.visit_time),
 (LEAD(v.visit_time) OVER (ORDER BY v.visit_time)-v.visit_time)/1000000.0
FROM visits v JOIN urls u ON v.url=u.id
 LEFT JOIN visits ref_v ON v.from_visit=ref_v.id LEFT JOIN urls ref_u ON ref_v.url=ref_u.id
WHERE v.id=$target OR (v.visit_time>=$ws AND v.visit_time<=$we AND v.id!=$target)
ORDER BY v.visit_time;" 2>/dev/null
  else
    tinfo="$(build_firefox_tinfo)"; tdet="$(build_firefox_tdetails)"
    local tt; tt=$(sql_scalar "$db" "SELECT visit_date FROM moz_historyvisits WHERE id=$target;")
    [ -n "$tt" ] || return
    local ws we; ws=$((tt-300000000)); we=$((tt+300000000))
    sql_query "$db" "
SELECT
 CASE WHEN h.id=$target THEN 0
   WHEN h.visit_date<$tt THEN -1*ROW_NUMBER() OVER (PARTITION BY (h.visit_date<$tt) ORDER BY h.visit_date DESC)
   WHEN h.visit_date>$tt THEN ROW_NUMBER() OVER (PARTITION BY (h.visit_date>$tt) ORDER BY h.visit_date ASC) ELSE 0 END,
 CASE WHEN h.id=$target THEN 'Center' WHEN h.visit_date<$tt THEN 'Backward' ELSE 'Forward' END,
 $(ts_firefox h.visit_date), $(ep_firefox h.visit_date), $(clean p.url), $(clean p.title),
 h.id, h.from_visit, $tinfo, $tdet, $(clean ref_p.url), $(clean ref_p.title),
 LEAD(h.id) OVER (ORDER BY h.visit_date), LEAD($(clean p.url)) OVER (ORDER BY h.visit_date),
 (LEAD(h.visit_date) OVER (ORDER BY h.visit_date)-h.visit_date)/1000000.0
FROM moz_historyvisits h JOIN moz_places p ON h.place_id=p.id
 LEFT JOIN moz_historyvisits ref_h ON h.from_visit=ref_h.id LEFT JOIN moz_places ref_p ON ref_h.place_id=ref_p.id
WHERE h.id=$target OR (h.visit_date>=$ws AND h.visit_date<=$we AND h.id!=$target)
ORDER BY h.visit_date;" 2>/dev/null
  fi
}

read -r -d '' AWK_CHAIN <<'AWKEOF' || true
function defang_dots(s,   out,rest,seg,dp){
  out=""; rest=s
  while(match(rest, /[A-Za-z0-9-]+\.[A-Za-z][A-Za-z]+/)){
    seg=substr(rest,RSTART,RLENGTH); dp=index(seg,".")
    out=out substr(rest,1,RSTART-1) substr(seg,1,dp-1) "[.]" substr(seg,dp+1)
    rest=substr(rest,RSTART+RLENGTH)
  }
  return out rest
}
function defang2(s,   r){
  if(nodefang==1) return s
  if(s=="" || s=="N/A") return s
  r=s
  gsub(/https:\/\//,"hxxps[://]",r); gsub(/http:\/\//,"hxxp[://]",r); gsub(/ftp:\/\//,"fxp[://]",r)
  r=defang_dots(r)
  return r
}
function host_of(u,   s,i){ s=u; gsub(/\[\.\]/,".",s); gsub(/\[:\]/,":",s); i=index(s,"://"); if(i>0)s=substr(s,i+3); i=index(s,"/"); if(i>0)s=substr(s,1,i-1); i=index(s,"?"); if(i>0)s=substr(s,1,i-1); return s }
function fmt2(x){ return sprintf("%.2f", x+0) }
BEGIN{ FS=sep; n=0 }
{
  n++; lvl[n]=$1; dir[n]=$2; ts[n]=$3; ep[n]=$4+0; url[n]=$5; title[n]=$6; cur[n]=$7; prev[n]=$8
  tinfo[n]=$9; tdet[n]=$10; refurl[n]=$11; reftitle[n]=$12; nextid[n]=$13; nexturl[n]=$14; ttn[n]=$15
}
END{
  print "Total visits in chain: " n
  print "Displaying chain in chronological order (oldest to newest):"
  print ""
  back=0; fwd=0
  for(i=1;i<=n;i++){
    ind=""
    if(lvl[i]<0){ ind="[BACKWARD CHAIN - Level " lvl[i] "] "; back++ }
    else if(lvl[i]==0){ ind="[TARGET VISIT - Level 0] " }
    else { ind="[FORWARD CHAIN - Level " lvl[i] "] "; fwd++ }
    print ind "--- Visit " i " of " n " ---"
    printf "%-17s : %s\n","RecordType","Visit"
    printf "%-17s : %s\n","TimestampUTC", ts[i]
    printf "%-17s : %s\n","URL", defang2(url[i])
    if(title[i]!="" && title[i]!="N/A") printf "%-17s : %s\n","Title", title[i]
    if(cur[i]!="")  printf "%-17s : %s\n","VisitID", cur[i]
    if(tinfo[i]!="" && tinfo[i]!="N/A") printf "%-17s : %s\n","TransitionInfo", tinfo[i]
    if(tdet[i]!="" && tdet[i]!="N/A")   printf "%-17s : %s\n","TransitionDetails", tdet[i]
    if(refurl[i]!="" && refurl[i]!="N/A") printf "%-17s : %s\n","ReferrerURL", defang2(refurl[i])
    if(reftitle[i]!="" && reftitle[i]!="N/A") printf "%-17s : %s\n","ReferrerTitle", reftitle[i]
    if(prev[i]!="" && prev[i]!="0") printf "%-17s : %s\n","PreviousVisitID", prev[i]
    if(nextid[i]!="") printf "%-17s : %s\n","NextVisitID", nextid[i]
    if(nexturl[i]!="" && nexturl[i]!="N/A") printf "%-17s : %s\n","NextURL", defang2(nexturl[i])
    if(ttn[i]!="" && ttn[i]+0>0) printf "%-17s : %ss\n","TimeToNext", sprintf("%.3f",ttn[i]+0)
    printf "%-17s : %s\n","ChainLevel", lvl[i]
    printf "%-17s : %s\n","ChainDirection", dir[i]
    print ""
  }
  print "=== CHAIN ANALYSIS SUMMARY ==="
  span=(n>1)? ep[n]-ep[1] : 0
  printf "%-17s : %s seconds\n","Analysis Duration", fmt2(span)
  printf "%-17s : %s\n","Total Visits", n
  printf "%-17s : %s\n","Backward Steps", back
  printf "%-17s : %s\n","Forward Steps", fwd
  # domain analysis
  for(i=1;i<=n;i++){ h=host_of(url[i]); if(h!=""){ if(!(h in dc)) du++; dc[h]++ } }
  print ""
  print "DOMAIN ANALYSIS:"
  printf "%-17s : %s\n","Unique Domains", du
  if(du<=20){ print "Domains Visited   :"; for(h in dc) print "  " defang2(h) " (" dc[h] " visits)" }
  print ""
  print "=== RECOMMENDATIONS ==="
  print "[i] Review TimeToNext values < 1s and Domain changes for redirect activity."
  for(i=0;i<65;i++) printf "="; print ""
}
AWKEOF

# =============================================================================
# Main
# =============================================================================
main() {
  capture_args "$@"
  parse_args "$@"
  preflight
  detect_date
  collection_header

  # Validate numeric inputs (prevent arithmetic errors / malformed SQL)
  for pair in "FollowChain:$FOLLOWCHAIN" "LastHours:$LASTHOURS" "LastDays:$LASTDAYS"; do
    local nm="${pair%%:*}" vl="${pair#*:}"
    [ -n "$vl" ] && case "$vl" in *[!0-9]*) die "-$nm must be a positive integer (got '$vl')" ;; esac
  done

  # -Private is a dedicated mode; reject any unsupported option combined with it.
  validate_private

  # Resolve selected browsers
  SELECTED=()
  if printf '%s' "$BROWSER" | grep -qi '\ball\b'; then
    SELECTED=("${VALID_BROWSERS[@]}")
  else
    local IFS=','; local req=($BROWSER); unset IFS
    local r v ok
    for r in "${req[@]}"; do
      r=$(printf '%s' "$r" | sed 's/^ *//;s/ *$//')
      ok=0
      for v in "${VALID_BROWSERS[@]}"; do
        if [ "$(printf '%s' "$r" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" ]; then SELECTED+=("$v"); ok=1; fi
      done
      [ "$ok" -eq 0 ] && warn "Ignoring unknown browser: $r"
    done
  fi
  [ "${#SELECTED[@]}" -gt 0 ] || die "No valid browsers selected."

  # private temp workspace, auto-removed
  TMPDIR_RUN=$(mktemp -d "${TMPDIR:-/tmp}/gih.XXXXXX") || die "Cannot create temp dir"
  trap 'rm -rf "$TMPDIR_RUN" 2>/dev/null' EXIT INT TERM
  vlog "Temp workspace: $TMPDIR_RUN"

  init_time_filter

  if [ -n "$FOLLOWCHAIN" ]; then
    follow_chain "$FOLLOWCHAIN"
    return
  fi

  # record-type selection
  local run_visits=0 run_downloads=0
  if [ "$VISITS" -eq 1 ] && [ "$DOWNLOADS" -eq 1 ]; then run_visits=1; run_downloads=1
  elif [ "$VISITS" -eq 1 ]; then run_visits=1
  elif [ "$DOWNLOADS" -eq 1 ]; then run_downloads=1
  else run_visits=1; run_downloads=1; fi
  local run_keywords=0
  [ "$run_visits" -eq 1 ] && [ "$INCLUDEKEYWORDS" -eq 1 ] && run_keywords=1

  # Forensic-module gating.
  #  - Anti-forensics / history-cleaning detection always runs, on the whole
  #    database, regardless of any time filter or record-selection switch.
  #  - Private-browsing analysis is OPT-IN via -Private only. In -Private mode the
  #    per-record dump is skipped (focused, whole-profile investigation) while the
  #    header, per-database summaries and the anti-forensics section are kept.
  CLEANING_ENABLED=1; PRIVATE_ENABLED=0
  if [ "$PRIVATE_MODE" -eq 1 ]; then
    run_visits=0; run_downloads=0; run_keywords=0
    PRIVATE_ENABLED=1
  fi

  enumerate_targets
  # No early return when nothing was discovered: the summary section still has to
  # list every profile that was examined, and the record sections still report 0.
  [ -n "$DISCOVERED" ] || warn "No browser history databases found."

  local ALL="$TMPDIR_RUN/all.records"
  : > "$ALL"

  # Accumulators for the end-of-output forensic sections (one block per database).
  CLEANING_DETAIL="$TMPDIR_RUN/cleaning.detail"; : > "$CLEANING_DETAIL"
  PRIVATE_DETAIL="$TMPDIR_RUN/private.detail";   : > "$PRIVATE_DETAIL"

  # Summaries are buffered (prefixed with their last-visit epoch) so the section
  # can be emitted in most-recent-activity order once every database is read.
  local SUMMARIES="$TMPDIR_RUN/summaries"; : > "$SUMMARIES"
  local SUMBLOCK="$TMPDIR_RUN/summary.block"

  while IFS="$SEP" read -r user browser db; do
    [ -n "$db" ] || continue
    local family; family=$(family_of "$browser")
    local tmp; tmp=$(copy_db "$db") || continue
    SUMMARY_MAXEP=0
    db_summary "$user" "$family" "$tmp" "$browser" "$db" > "$SUMBLOCK"
    awk -v k="$SUMMARY_MAXEP" -v s="$SEP" '{print k s $0}' "$SUMBLOCK" >> "$SUMMARIES"
    collect_private "$family" "$tmp" "$browser" "$db" "$user"

    if [ "$run_visits" -eq 1 ]; then
      local sql; sql=$(build_sql "$family" visits)
      [ -n "$sql" ] && sql_query "$tmp" "$sql" \
        | while IFS= read -r line; do printf '%s%s%s%sVisit%s%s\n' "$user" "$SEP" "$browser" "$SEP" "$SEP" "$line"; done >> "$ALL"
    fi
    if [ "$run_downloads" -eq 1 ]; then
      local sql; sql=$(build_sql "$family" downloads)
      [ -n "$sql" ] && sql_query "$tmp" "$sql" \
        | while IFS= read -r line; do printf '%s%s%s%sDownload%s%s\n' "$user" "$SEP" "$browser" "$SEP" "$SEP" "$line"; done >> "$ALL"
    fi
    if [ "$run_keywords" -eq 1 ]; then
      local sql; sql=$(build_sql "$family" keywords)
      [ -n "$sql" ] && sql_query "$tmp" "$sql" \
        | while IFS= read -r line; do printf '%s%s%s%sKeyword%s%s\n' "$user" "$SEP" "$browser" "$SEP" "$SEP" "$line"; done >> "$ALL"
    fi
    rm -f "$tmp" "$tmp"-* 2>/dev/null
  done <<< "$DISCOVERED"

  log "$(printf '=%.0s' $(seq 1 65))"
  log "Identified Database Summaries (Sorted by Most Recent Activity)"
  log "$(printf '=%.0s' $(seq 1 65))"
  log ""
  LC_ALL=C sort -t "$SEP" -k1,1nr -s "$SUMMARIES" | cut -d "$SEP" -f2-
  # Listed last - an empty profile carries no activity timestamp to sort by.
  while IFS= read -r emptyuser; do
    [ -n "$emptyuser" ] || continue
    log "User: $emptyuser | No browser history databases found"
    log ""
  done <<< "$EMPTY_PROFILES"

  if [ "$PRIVATE_MODE" -eq 1 ]; then
    # Focused mode: no per-record dump; summaries + forensic sections only.
    log "$(printf '=%.0s' $(seq 1 65))"
    log "Private-Browsing Investigation Complete."
  else
    # Apply -SearchRegex BEFORE counting/chain-analysis (filters per-record as
    # results are collected). Matched against the raw
    # URL / SearchURL / Path / Title, case-insensitively.
    local total_found; total_found=$(wc -l < "$ALL" | tr -d ' ')
    if [ -n "$SEARCHREGEX" ]; then
      awk -v sep="$SEP" -v rx="$SEARCHREGEX" 'BEGIN{FS=sep; rxl=tolower(rx)}
        { if(tolower($6)~rxl || tolower($8)~rxl || tolower($9)~rxl || tolower($7)~rxl) print }' "$ALL" > "$ALL.f" 2>/dev/null && mv "$ALL.f" "$ALL"
    fi

    local total; total=$(wc -l < "$ALL" | tr -d ' ')
    log "$(printf '=%.0s' $(seq 1 65))"
    log "Records Matching Criteria specified:"
    log "$(printf '=%.0s' $(seq 1 65))"
    log ""

    if [ "$total" -gt 0 ]; then
      # sort globally by epoch asc then current visit id, then format + analyze
      LC_ALL=C sort -t "$SEP" -k5,5n -k17,17n "$ALL" \
        | awk -v sep="$SEP" -v NODEFANG="$NODEFANG" -v analyze="$ANALYZE_CHAINS" "$AWK_FORMAT"
    else
      log "No results found matching the specified criteria."
    fi

    log "$(printf '=%.0s' $(seq 1 65))"
    log "Records Summary"
    log "$(printf '=%.0s' $(seq 1 65))"
    log "Total Records Found: $total_found"
    log "Records Matched Criteria: $total"
  fi

  # ---- History-cleaning detection (possible anti-forensics) ----
  if [ -s "$CLEANING_DETAIL" ]; then
    log ""
    log "$(printf '=%.0s' $(seq 1 65))"
    log "=== HISTORY-CLEANING DETECTION (POSSIBLE ANTI-FORENSICS) ==="
    log "Deleted visits leave gaps in the visit-ID sequence (ids are never reused)."
    log "Interior gaps and tail deletions below indicate records were removed; the"
    log "estimated windows bracket when the missing visits occurred."
    log ""
    printf '%s' "$(cat "$CLEANING_DETAIL")"
    log ""
  fi

  # ---- Private-browsing artifacts ----
  if [ -s "$PRIVATE_DETAIL" ]; then
    log "$(printf '=%.0s' $(seq 1 65))"
    log "=== PRIVATE-BROWSING ARTIFACTS ==="
    log "Private/Incognito sessions are not written to browser history by design, so"
    log "every parseable profile artifact is mined for URLs/origins. A domain that"
    log "appears in an artifact (favicon, top site, omnibox, saved login, cookie,"
    log "bookmark, storage, ...) but has NO matching history visit was reached yet"
    log "never recorded - private OR deleted. First-party artifacts are the strong"
    log "signal; cookies/NEL/storage also include third-party domains. OS-level"
    log "residue (DNS, prefetch, memory) and binary formats (sessions, cache) are"
    log "out of scope / listed but not parsed."
    log ""
    printf '%s' "$(cat "$PRIVATE_DETAIL")"
    log ""
  fi
}

main "$@"
