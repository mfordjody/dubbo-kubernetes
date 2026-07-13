#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Syncs a release to the website repository (kdubbo.github.io):
#   1. Inserts the "## 公告" bullets from releasenotes/<version>.md as a new
#      entry at the top of the announcement board
#      (docs/latest/release/index.md).
#   2. Replaces the previous latest version number with <version> in every
#      file listed in VERSION_FILES.
#
# Idempotent: if the announcement entry already exists, nothing is changed.
#
# Usage:
#   sync-website.sh <version> [website-dir]
#   WEBSITE_DIR=/path/to/kdubbo.github.io sync-website.sh <version>

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:?usage: sync-website.sh <version> [website-dir]}"
VERSION="${VERSION#v}"
WEBSITE_DIR="${2:-${WEBSITE_DIR:-${ROOT}/../kdubbo.github.io}}"

RELEASE_PAGE="docs/latest/release/index.md"
# Files whose embedded version numbers track the latest release.
VERSION_FILES="docs/overview/index.md"

NOTES="${ROOT}/release/release-notes.sh"
PAGE="${WEBSITE_DIR}/${RELEASE_PAGE}"

if [ ! -f "${PAGE}" ]; then
  echo "error: announcement page not found: ${PAGE}" >&2
  echo "Set WEBSITE_DIR to your kdubbo.github.io checkout." >&2
  exit 1
fi

"${NOTES}" verify "${VERSION}" >/dev/null
DATE="$("${NOTES}" date "${VERSION}")"

if grep -q "^    ### ${VERSION}\$" "${PAGE}"; then
  echo "announcement for ${VERSION} already present in ${RELEASE_PAGE}; nothing to do"
  exit 0
fi

# Previous latest release = first "### x.y.z" entry on the board.
PREV_RAW="$(awk '/^[[:space:]]*### /{print $2; exit}' "${PAGE}")"
PREV="${PREV_RAW#v}"

MAJOR_MINOR="$(echo "${VERSION}" | cut -d. -f1-2)"
SECTION_HEADER="    ## ${MAJOR_MINOR}.x"

# Build the new announcement block (content inside mkdocs tabs is indented
# by four spaces).
BLOCK="$(mktemp)"
trap 'rm -f "${BLOCK}"' EXIT
{
  echo "    ### ${VERSION}"
  echo ""
  echo "    发布日期：${DATE}"
  echo ""
  "${NOTES}" extract-announcement "${VERSION}" | sed 's/^/    /'
  echo ""
  echo "    [查看 GitHub Release](https://github.com/apache/dubbo-kubernetes/releases/tag/${VERSION})"
  echo ""
  echo "    ---"
} > "${BLOCK}"

TMP_PAGE="$(mktemp)"
if grep -q "^${SECTION_HEADER}\$" "${PAGE}"; then
  # Insert right below the existing "## x.y.x" section header.
  awk -v hdr="${SECTION_HEADER}" -v blk="${BLOCK}" '
    BEGIN { while ((getline l < blk) > 0) b[bn++] = l }
    { print }
    !done && $0 == hdr {
      print ""
      for (i = 0; i < bn; i++) print b[i]
      done = 1
    }
  ' "${PAGE}" > "${TMP_PAGE}"
else
  # New minor version: create the section at the top of the release tab.
  awk -v hdr="${SECTION_HEADER}" -v blk="${BLOCK}" '
    BEGIN { while ((getline l < blk) > 0) b[bn++] = l }
    { print }
    !done && $0 ~ /^=== "发布公告"/ {
      print ""
      print hdr
      print ""
      for (i = 0; i < bn; i++) print b[i]
      done = 1
    }
  ' "${PAGE}" > "${TMP_PAGE}"
fi
mv "${TMP_PAGE}" "${PAGE}"
echo "inserted announcement for ${VERSION} into ${RELEASE_PAGE}"

# Bump version references (previous latest -> new version).
if [ -n "${PREV}" ] && [ "${PREV}" != "${VERSION}" ]; then
  for f in ${VERSION_FILES}; do
    target="${WEBSITE_DIR}/${f}"
    if [ ! -f "${target}" ]; then
      echo "warn: version file not found, skipping: ${f}" >&2
      continue
    fi
    count="$(grep -c -F "${PREV}" "${target}" || true)"
    if [ "${count}" -gt 0 ]; then
      perl -pi -e "s/\Q${PREV}\E/${VERSION}/g" "${target}"
      echo "bumped ${count} occurrence(s) of ${PREV} -> ${VERSION} in ${f}"
    else
      echo "no occurrences of ${PREV} in ${f}; nothing to bump"
    fi
  done
else
  echo "no previous version detected; skipping version bumps"
fi

echo "done. Review the diff in ${WEBSITE_DIR}, then commit and push."
