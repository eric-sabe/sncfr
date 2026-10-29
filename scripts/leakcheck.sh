#!/usr/bin/env bash
# leakcheck: keep organization-specific values out of the sncfr repository (HYG-1, NA-11).
#
# Rules:
#   host-not-allowlisted  any *.service-now.com / *.servicenowservices.com host other than
#                         exactly example.service-now.com or mycompany.service-now.com
#   denylist              any (case-insensitive) term from the denylist file
#
# Findings print only "<location> <rule>", never the matched text, so CI logs cannot leak
# the denylist they protect.
#
# Usage:
#   scripts/leakcheck.sh                 scan tracked files in the working tree
#   scripts/leakcheck.sh --staged        scan the index (use as a pre-commit hook)
#   scripts/leakcheck.sh --log <range>   also scan commit messages in <range> (e.g. base..head)
#   scripts/leakcheck.sh --self-test     run built-in pass/fail vectors
#
# Denylist: $LEAKCHECK_DENYLIST_FILE, else .leakcheck/denylist.txt (gitignored; one term per
# line, '#' comments). CI writes it from the LEAKCHECK_DENYLIST secret.
set -euo pipefail

HOST_RE='[a-z0-9-]+\.(service-now|servicenowservices)\.com'
DENY_FILE="${LEAKCHECK_DENYLIST_FILE:-.leakcheck/denylist.txt}"

# Reads "<location>:<matched host>" lines and reports hosts outside the allowlist.
filter_hosts() {
  awk -F: '{
    host = tolower($NF); loc = $1; for (i = 2; i < NF; i++) loc = loc ":" $i
    if (host != "example.service-now.com" && host != "mycompany.service-now.com") {
      print loc " host-not-allowlisted"; bad = 1
    }
  } END { exit bad ? 1 : 0 }'
}

# git grep, where "no match" (exit 1) is success; real errors still fail.
gg() {
  local rc=0
  git grep "$@" || rc=$?
  if [ "$rc" -gt 1 ]; then echo "leakcheck: git grep failed ($rc)" >&2; return "$rc"; fi
}

# Prints denylist terms (comments and blank lines removed) to a temp file; echoes its path.
denylist_terms() {
  [ -f "$DENY_FILE" ] || return 1
  local terms
  terms="$(mktemp)"
  grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$DENY_FILE" > "$terms" || true
  [ -s "$terms" ] || { rm -f "$terms"; return 1; }
  echo "$terms"
}

scan_tree() {
  local cached=("$@") status=0 terms
  gg "${cached[@]}" -n -I -i -o -E "$HOST_RE" -- . | filter_hosts || status=1
  if terms="$(denylist_terms)"; then
    if gg "${cached[@]}" -n -I -i -F -f "$terms" -- . | cut -d: -f1,2 | sed 's/$/ denylist/' | grep .; then
      status=1
    fi
    rm -f "$terms"
  else
    echo "leakcheck: denylist: SKIPPED (no $DENY_FILE)" >&2
  fi
  return $status
}

scan_log() {
  local range=$1 status=0 terms commit
  for commit in $(git rev-list "$range"); do
    git log -1 --format=%B "$commit" | { grep -n -i -o -E "$HOST_RE" || true; } |
      sed "s/^/commit ${commit:0:12} line /" | filter_hosts || status=1
    if terms="$(denylist_terms)"; then
      if git log -1 --format=%B "$commit" | grep -q -i -F -f "$terms"; then
        echo "commit ${commit:0:12} denylist"; status=1
      fi
      rm -f "$terms"
    fi
  done
  return $status
}

self_test() {
  local dir out status=0 me
  me="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
  dir="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand $dir now: it is local and gone when the trap fires
  trap "rm -rf '$dir'" RETURN
  # Vectors are assembled at runtime so this script never contains a flagged host itself.
  local sn=".service-now.com" gov=".servicenowservices.com" secret="zebra-quokka-term"
  (
    cd "$dir"
    git init -q && git config user.email t@example.invalid && git config user.name t
    printf 'nothing to see\n' > plain.txt && git add plain.txt
    "$me" >/dev/null 2>&1 || { echo "self-test: a repo with no hosts was flagged"; exit 1; }
    printf 'ok https://example%s/x\nok mycompany%s\n' "$sn" "$sn" > allowed.txt
    git add allowed.txt && git commit -q -m allowed
    "$me" >/dev/null 2>&1 || { echo "self-test: allowlisted hosts were flagged"; exit 1; }
    for bad in "realco$sn" "notexample$sn" "REALCO$(echo "$sn" | tr '[:lower:]' '[:upper:]')" "agency$gov"; do
      printf 'see %s\n' "$bad" > bad.txt && git add bad.txt
      out="$("$me" 2>/dev/null)" && { echo "self-test: '$bad' was not flagged"; exit 1; }
      [ "$out" = "bad.txt:1 host-not-allowlisted" ] || { echo "self-test: unexpected output: $out"; exit 1; }
      "$me" --staged >/dev/null 2>&1 && { echo "self-test: --staged missed '$bad'"; exit 1; }
    done
    git rm -q --cached bad.txt && rm bad.txt
    mkdir -p .leakcheck && printf '# comment\n%s\n' "$secret" > .leakcheck/denylist.txt
    printf 'mentions %s here\n' "$(echo "$secret" | tr '[:lower:]' '[:upper:]')" > deny.txt && git add deny.txt
    out="$("$me" 2>/dev/null)" && { echo "self-test: denylist term was not flagged"; exit 1; }
    [ "$out" = "deny.txt:1 denylist" ] || { echo "self-test: unexpected denylist output: $out"; exit 1; }
    case "$out" in *"$secret"*|*ZEBRA*) echo "self-test: denylist term leaked into output"; exit 1;; esac
    git rm -q --cached deny.txt && rm deny.txt
    git commit -q --allow-empty -m "plain message"
    "$me" --log HEAD~1..HEAD >/dev/null 2>&1 || { echo "self-test: a clean commit message was flagged"; exit 1; }
    git commit -q --allow-empty -m "release for realco$sn"
    out="$("$me" --log HEAD~1..HEAD 2>/dev/null)" && { echo "self-test: commit message host was not flagged"; exit 1; }
    case "$out" in *"host-not-allowlisted"*) ;; *) echo "self-test: unexpected log output: $out"; exit 1;; esac
  ) || status=1
  [ $status -eq 0 ] && echo "leakcheck self-test: ok"
  return $status
}

main() {
  local mode=tree range=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --staged) mode=staged ;;
      --log) range="${2:?--log needs a range}"; shift ;;
      --self-test) self_test; return ;;
      -h|--help) sed -n '2,20p' "$0"; return 0 ;;
      *) echo "leakcheck: unknown argument $1" >&2; return 2 ;;
    esac
    shift
  done
  local status=0
  if [ "$mode" = staged ]; then scan_tree --cached || status=1; else scan_tree || status=1; fi
  if [ -n "$range" ]; then scan_log "$range" || status=1; fi
  [ $status -eq 0 ] && echo "leakcheck: clean" >&2
  return $status
}

main "$@"
