#!/usr/bin/env bash
# bump-version.sh <new-version>
# Updates version across all SDK packages, commits, and creates a git tag.
#
# Usage:
#   ./scripts/bump-version.sh 0.2.0
#   ./scripts/bump-version.sh 0.2.0-beta.1
#
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <new-version>" >&2
  exit 1
fi

# Validate semver-ish (allow pre-release suffixes)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: version must be semver (e.g. 1.2.3 or 1.2.3-beta.1)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "Bumping all packages to v${VERSION}"

# ── TypeScript — packages/core/package.json ──────────────────────────────────
jq ".version = \"${VERSION}\"" "${ROOT}/packages/core/package.json" > /tmp/pkg.json
mv /tmp/pkg.json "${ROOT}/packages/core/package.json"
echo "  ✓ packages/core/package.json"

# ── TypeScript — packages/express/package.json ───────────────────────────────
jq ".version = \"${VERSION}\"" "${ROOT}/packages/express/package.json" > /tmp/pkg.json
mv /tmp/pkg.json "${ROOT}/packages/express/package.json"
# Also update peer dep on core
jq ".peerDependencies[\"@autoblock/core\"] = \"^${VERSION}\"" /tmp/pkg.json 2>/dev/null || true
echo "  ✓ packages/express/package.json"

# ── Python — packages/fastapi/pyproject.toml ─────────────────────────────────
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" "${ROOT}/packages/fastapi/pyproject.toml"
echo "  ✓ packages/fastapi/pyproject.toml"

# ── Java — packages/spring/pom.xml ───────────────────────────────────────────
# Replace only the project version (first occurrence)
awk "NR==1,/<version>/{if(!done && /<version>/) {sub(/<version>[^<]*<\/version>/, \"<version>${VERSION}-SNAPSHOT</version>\"); done=1}} 1" \
  "${ROOT}/packages/spring/pom.xml" > /tmp/pom.xml
mv /tmp/pom.xml "${ROOT}/packages/spring/pom.xml"
echo "  ✓ packages/spring/pom.xml"

# ── Go — packages/go/go.mod doesn't carry a version; tag drives it ───────────
echo "  ✓ packages/go — module version set by git tag (no go.mod change needed)"

# ── Commit and tag ────────────────────────────────────────────────────────────
cd "${ROOT}"
git add \
  packages/core/package.json \
  packages/express/package.json \
  packages/fastapi/pyproject.toml \
  packages/spring/pom.xml

git commit -m "chore(release): bump version to ${VERSION}"
git tag -a "v${VERSION}" -m "Release v${VERSION}"

echo ""
echo "Done! Created commit + tag v${VERSION}."
echo "Push with: git push origin main v${VERSION}"
