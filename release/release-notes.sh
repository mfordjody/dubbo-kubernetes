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

# Reads structured release notes from releasenotes/<version>.md.
#
# Usage:
#   release-notes.sh verify               <version>
#   release-notes.sh date                 <version>
#   release-notes.sh extract-notes        <version>   # GitHub Release body
#   release-notes.sh extract-announcement <version>   # website bullets (中文)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CMD="${1:?usage: release-notes.sh <verify|date|extract-notes|extract-announcement> <version>}"
VERSION="${2:?missing version argument}"
VERSION="${VERSION#v}"
FILE="${ROOT}/releasenotes/${VERSION}.md"

if [ ! -f "${FILE}" ]; then
  echo "error: release notes file not found: releasenotes/${VERSION}.md" >&2
  echo "Create it from releasenotes/TEMPLATE.md before releasing ${VERSION}." >&2
  exit 1
fi

release_date() {
  sed -n 's/^date:[[:space:]]*//p' "${FILE}" | head -1
}

# Prints the body of a "## <heading>" section, with surrounding blank
# lines trimmed.
extract_section() {
  awk -v heading="## $1" '
    $0 == heading { insec = 1; next }
    /^## / && insec { insec = 0 }
    insec { lines[n++] = $0 }
    END {
      while (n > 0 && lines[n-1] ~ /^[[:space:]]*$/) n--
      s = 0
      while (s < n && lines[s] ~ /^[[:space:]]*$/) s++
      for (i = s; i < n; i++) print lines[i]
    }
  ' "${FILE}"
}

case "${CMD}" in
  date)
    release_date
    ;;
  extract-notes)
    extract_section "Notes"
    ;;
  extract-announcement)
    extract_section "公告"
    ;;
  verify)
    errors=0
    d="$(release_date)"
    if ! echo "${d}" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
      echo "error: releasenotes/${VERSION}.md: missing or malformed 'date: YYYY-MM-DD' line (got: '${d}')" >&2
      errors=1
    fi
    if [ -z "$(extract_section "Notes")" ]; then
      echo "error: releasenotes/${VERSION}.md: '## Notes' section is missing or empty" >&2
      errors=1
    fi
    if [ -z "$(extract_section "公告")" ]; then
      echo "error: releasenotes/${VERSION}.md: '## 公告' section is missing or empty" >&2
      errors=1
    fi
    if [ "${errors}" -ne 0 ]; then
      exit 1
    fi
    echo "releasenotes/${VERSION}.md OK (date: ${d})"
    ;;
  *)
    echo "error: unknown command '${CMD}'" >&2
    exit 2
    ;;
esac
