#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "Repository path: $(pwd)"

echo "==> Checking git status"
git status --short --branch

echo "==> Pulling latest changes from origin/main"
git pull origin main

echo "==> Staging local changes"
git add .

if git diff --cached --quiet; then
  echo "No changes to commit."
else
  echo "Committing staged changes"
  git commit -m "Sync local changes with GitHub"
fi

echo "==> Pushing changes to origin/main"
git push origin main

echo "Done."
