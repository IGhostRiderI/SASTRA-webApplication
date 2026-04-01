#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

repo_path="$(pwd)"
echo "Repository path: ${repo_path}"

echo "==> Remote configuration"
git remote -v

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "${branch}" = "HEAD" ]; then
  echo "Error: detached HEAD state detected. Please checkout a branch first."
  exit 1
fi

echo "==> Current branch: ${branch}"

echo "==> Fetching latest changes from origin"
git fetch origin "${branch}"

echo "==> Checking git status"
git status --short --branch

echo "==> Pulling latest changes from origin/${branch}"
git pull --ff-only origin "${branch}"

echo "==> Staging local changes"
git add .

if git diff --cached --quiet; then
  echo "No changes to commit."
else
  commit_message="Sync local changes with GitHub"
  if [ $# -gt 0 ]; then
    commit_message="$*"
  fi
  echo "Committing staged changes with message: ${commit_message}"
  git commit -m "${commit_message}"
fi

echo "==> Pushing changes to origin/${branch}"
git push origin "${branch}"

echo "Done."
