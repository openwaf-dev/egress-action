#!/usr/bin/env bash
# leak-guard.sh [--history] [dir] — refuses (exit 1) when a file of the OpenWAF Egress CI repository carries
# something that must stay private. Scans the files git would publish (tracked and untracked, minus .gitignore) or,
# outside a git repository, every regular file; binary files are skipped. Prints file:line and the rule, never the
# match.
#
# --history also scans every blob reachable from any ref (each file as it was in every commit, reported as
# path@blob) and the author and committer addresses and message of every commit (reported as commit@sha).
#
# Built-in rules: IPv4 addresses other than loopback, 0.0.0.0 and the documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24), private keys, tokens in real format (GitHub, OpenWAF, AWS access key ids other
# than AWS's documented example, sk- keys), and e-mail addresses outside openwaf.dev and the example domains.
#
# LEAK_DENYLIST_FILE adds a private denylist: one extended regular expression per line (a leading "i:" makes it
# case-insensitive; "#" starts a comment). It is kept out of the repository (the CI reads it from a secret); hits are
# reported by line number of the denylist only.
#
# Lines can be exempted in .leak-guard-allow (path<TAB>ERE matched against the line), for reviewed false positives.
# The path is the file's path in the tree and applies to its older versions in --history too; path@blob (the first
# 12 hex digits, as reported) or commit@sha exempts only that version of the file or that commit.
set -euo pipefail
history=0
if [ "${1:-}" = --history ]; then history=1; shift; fi
dir=${1:-.}
cd "$dir"
root=$(pwd)

work=$(mktemp -d)
findings="$work/findings"
: >"$findings"
trap 'rm -rf "$work"' EXIT

# Everything is scanned from a copy under $work: tree/<path> (the files as they are), blobs/<blob>/<path> (every
# version in the history) and commits/<sha> (addresses and message). report() maps them back to their paths.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  files=$(git ls-files -co --exclude-standard)
else
  [ "$history" = 0 ] || { echo "leak-guard: --history needs a git repository" >&2; exit 2; }
  files=$(find . -type f -not -path './.git/*' | sed 's|^\./||')
fi
n=0
while IFS= read -r f; do
  [ -n "$f" ] && [ "$f" != .leak-guard-allow ] && [ -f "$f" ] || continue
  mkdir -p "$work/tree/$(dirname "$f")"
  cp "$f" "$work/tree/$f"
  n=$((n + 1))
done <<<"$files"
[ "$n" -gt 0 ] || { echo "leak-guard: no files under $dir" >&2; exit 2; }
summary="$n files"
if [ "$history" = 1 ]; then
  nb=0
  while read -r obj path; do
    [ -n "$path" ] && [ "$path" != .leak-guard-allow ] || continue
    [ "$(git cat-file -t "$obj")" = blob ] || continue
    mkdir -p "$work/blobs/$obj/$(dirname "$path")"
    git cat-file blob "$obj" >"$work/blobs/$obj/$path"
    nb=$((nb + 1))
  done < <(git rev-list --objects --all)
  mkdir -p "$work/commits"
  nc=0
  while read -r c; do
    git show -s --format='%ae%n%ce%n%B' "$c" >"$work/commits/$c"
    nc=$((nc + 1))
  done < <(git rev-list --all)
  summary="$summary, $nb blobs and $nc commits of history"
fi
cd "$work"

allowed() { # allowed <path> <line text>
  [ -f "$root/.leak-guard-allow" ] || return 1
  local path re
  while IFS=$'\t' read -r path re; do
    case $path in '' | '#'*) continue ;; esac
    [ "$path" = "$1" ] && printf '%s\n' "$2" | grep -qE -- "$re" && return 0
  done <"$root/.leak-guard-allow"
  return 1
}
report() { # report <rule>, with file:line:text lines on stdin
  local rule=$1 loc file rest line path shown blob
  while IFS= read -r loc; do
    file=${loc%%:*}; rest=${loc#*:}; line=${rest%%:*}
    case $file in
      tree/*) path=${file#tree/}; shown=$path ;;
      blobs/*) blob=${file#blobs/}; blob=${blob%%/*}; path=${file#blobs/*/}; shown="$path@${blob:0:12}" ;;
      commits/*) path=COMMIT; shown="commit@$(printf '%s' "${file#commits/}" | cut -c1-12)" ;;
      *) continue ;;
    esac
    { allowed "$path" "${rest#*:}" || allowed "$shown" "${rest#*:}"; } && continue
    printf '%s:%s: %s\n' "$shown" "$line" "$rule" | tee -a "$findings"
  done
}
each() { find tree blobs commits -type f -print0 2>/dev/null; }
scan() { # scan <rule> <grep options…> -- pattern
  local rule=$1; shift
  each | xargs -0 grep -HnI "$@" 2>/dev/null | report "$rule" || true
}

# IPv4: everything but loopback, 0.0.0.0 and the documentation ranges.
each | xargs -0 grep -HnIoE '(^|[^0-9.])[0-9]{1,3}(\.[0-9]{1,3}){3}([^0-9.]|$)' 2>/dev/null |
  sed -E 's/^([^:]*:[0-9]+:)[^0-9]*([0-9.]+).*$/\1\2/' |
  grep -vE ':(127\.[0-9.]+|0\.0\.0\.0|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+)$' |
  report "IPv4 address outside the documentation ranges" || true
scan "private key" -E -- '-----BEGIN [A-Z ]*PRIVATE KEY-----'
scan "GitHub token in real format" -E -- '(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})'
scan "OpenWAF token in real format" -E -- '(owf_[A-Za-z0-9_-]{24,}|OWE_CI_[A-Za-z0-9_-]{16,})'
each | xargs -0 grep -HnIoE 'A(KIA|SIA)[0-9A-Z]{16}' 2>/dev/null | grep -vE ':AKIAIOSFODNN7EXAMPLE$' |
  report "AWS access key id other than AWS's documented example" || true
scan "API key in real format (sk-…)" -E -- 'sk-(proj-|ant-)?[A-Za-z0-9_-]{32,}'
each | xargs -0 grep -HnIoE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null |
  grep -vE '@((www\.)?openwaf\.dev|example\.(com|org|net)|[a-z0-9.-]+\.example|[a-z0-9.-]+\.test)$' |
  grep -vE ':[^:@]+@[0-9]+\.[0-9]' | report "e-mail address outside openwaf.dev and the example domains" || true

if [ -n "${LEAK_DENYLIST_FILE:-}" ]; then
  [ -r "$LEAK_DENYLIST_FILE" ] || { echo "leak-guard: LEAK_DENYLIST_FILE not readable" >&2; exit 2; }
  n=0
  while IFS= read -r re || [ -n "$re" ]; do
    n=$((n + 1))
    case $re in '' | '#'*) continue ;; esac
    if [ "${re#i:}" != "$re" ]; then scan "private denylist line $n" -i -E -- "${re#i:}"; else scan "private denylist line $n" -E -- "$re"; fi
  done <"$LEAK_DENYLIST_FILE"
  echo "leak-guard: private denylist applied ($n lines)"
else
  echo "leak-guard: no private denylist (LEAK_DENYLIST_FILE unset): built-in rules only"
fi

hits=$(wc -l <"$findings" | tr -d ' ')
if [ "$hits" -gt 0 ]; then
  echo "leak-guard: $hits finding(s): refused" >&2
  exit 1
fi
echo "leak-guard: clean ($summary)"
