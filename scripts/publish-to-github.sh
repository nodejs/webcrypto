#!/bin/bash
echo "//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}" > "$HOME/.npmrc"

COMMIT_HSAH=$(git rev-parse --short HEAD)
npm --no-git-tag-version version "0.0.0-$COMMIT_HSAH"
npm publish --tag unstable
