#!/usr/bin/env bash
#
# Caddy build script. Automates proper versioning.
#
# Usage:
#
#     $ ./build.bash [output_filename] [git_repo]
#
# Outputs compiled program in current directory.
# Default file name is 'ecaddy'.
# Default git repo is current directory.
# Builds always take place from current directory.

set -euo pipefail

: ${output_filename:="${1:-}"}
: ${output_filename:="ecaddy"}

: ${git_repo:="${2:-}"}
: ${git_repo:="."}

pkg=main
ldflags=("-w" "-s")

# Timestamp of build
name="${pkg}.buildDate"
value="$(date --utc +"%F %H:%M:%SZ")"
ldflags+=("-X" "\"${name}=${value}\"")

# Current tag, if HEAD is on a tag
name="${pkg}.gitTag"
set +e
value="$(git -C "${git_repo}" describe --exact-match HEAD 2>/dev/null)"
set -e
ldflags+=("-X" "\"${name}=${value}\"")

# Nearest tag on branch
name="${pkg}.gitNearestTag"
value="$(git -C "${git_repo}" describe --abbrev=0 --tags HEAD)"
ldflags+=("-X" "\"${name}=${value}\"")

# Commit SHA
name="${pkg}.gitCommit"
value="$(git -C "${git_repo}" rev-parse --short HEAD)"
ldflags+=("-X" "\"${name}=${value}\"")

# Summary of uncommitted changes
name="${pkg}.gitShortStat"
value="$(git -C "${git_repo}" diff-index --shortstat HEAD)"
ldflags+=("-X" "\"${name}=${value}\"")

# List of modified files
name="${pkg}.gitFilesModified"
value="$(git -C "${git_repo}" diff-index --name-only HEAD)"
ldflags+=("-X" "\"${name}=${value}\"")

set -x
go build \
  -tags "alttls" \
  -ldflags "${ldflags[*]}" \
  -o "${output_filename}"
