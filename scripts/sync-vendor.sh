#!/usr/bin/env bash
# sync-vendor.sh — fetch each vendored artifact from its canonical source at the
# pinned ref and overwrite the local copy. Run this after bumping a `ref` in a
# vendor/SOURCE file, then commit. CI runs the same fetch in --check mode and
# fails the build if the committed copy differs from the canonical.
#
# Usage:
#   scripts/sync-vendor.sh          # overwrite vendored copies from canonical
#   scripts/sync-vendor.sh --check  # diff only; exit 1 if any copy has drifted
set -euo pipefail

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATUS=0

# Locate every vendored artifact by its SOURCE pin file.
while IFS= read -r src; do
  dir="$(dirname "$src")"
  repo="$(grep -E '^repo=' "$src" | cut -d= -f2-)"
  path="$(grep -E '^path=' "$src" | cut -d= -f2-)"
  ref="$(grep -E '^ref='  "$src" | cut -d= -f2-)"
  target="$dir/$(basename "$path")"
  url="https://raw.githubusercontent.com/${repo}/${ref}/${path}"

  tmp="$(mktemp)"
  if ! curl -fsSL "$url" -o "$tmp"; then
    echo "ERROR: could not fetch $url" >&2
    STATUS=1; rm -f "$tmp"; continue
  fi

  if [[ "$CHECK" -eq 1 ]]; then
    if ! diff -q "$tmp" "$target" >/dev/null 2>&1; then
      echo "DRIFT: $target differs from ${repo}@${ref}:${path}" >&2
      diff "$target" "$tmp" >&2 || true
      STATUS=1
    else
      echo "OK: $target matches ${repo}@${ref}"
    fi
  else
    cp "$tmp" "$target"
    echo "synced: $target <- ${repo}@${ref}"
  fi
  rm -f "$tmp"
done < <(find "$ROOT" -type f -path '*/vendor/SOURCE')

exit "$STATUS"
