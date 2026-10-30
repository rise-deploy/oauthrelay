#!/usr/bin/env bash

set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  printf 'Usage: %s <version>\n' "$0" >&2
  exit 2
fi

version=$1
tag="v$version"

for command in cargo gh git perl; do
  command -v "$command" >/dev/null || {
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  }
done

if [[ -n "$(git status --porcelain)" ]]; then
  printf 'Working tree must be clean.\n' >&2
  exit 1
fi

if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
  printf 'Tag already exists: %s\n' "$tag" >&2
  exit 1
fi

RELEASE_VERSION=$version perl -0pi -e 's/(\[workspace\.package\]\nversion = ")[^"]+("\n)/$1$ENV{RELEASE_VERSION}$2/' Cargo.toml
cargo check --workspace --all-targets

git add Cargo.toml Cargo.lock
git commit -m "release $version"
git tag --annotate "$tag" --message "release $version"
git push origin HEAD --follow-tags
gh release create "$tag" --verify-tag --generate-notes
