
[private]
default:
    just --list

# Find the merge-base between the current branch and `ref`, then print all commits since.
changelog ref:
    #!/usr/bin/env bash
    set -euo pipefail
    resolved="{{ ref }}"
    if ! git rev-parse --verify "${resolved}" >/dev/null 2>&1; then
        resolved="origin/{{ ref }}"
    fi
    base=$(git merge-base HEAD "${resolved}")
    breaking=""
    changes=""
    while IFS= read -r msg; do
        if echo "${msg}" | grep -qE '^[a-z]+(\(.+\))?!:'; then
            breaking="${breaking}- ${msg}"$'\n'
        else
            changes="${changes}- ${msg}"$'\n'
        fi
    done < <(git log --format=%s "${base}..HEAD")
    if [ -n "${breaking}" ]; then
        echo "## Breaking Changes"
        echo ""
        echo "${breaking}"
    fi
    if [ -n "${changes}" ]; then
        echo "## Changes"
        echo ""
        echo "${changes}"
    fi
