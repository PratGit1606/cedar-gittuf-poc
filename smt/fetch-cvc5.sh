#!/usr/bin/env bash
# Download cvc5 into smt/.tools/cvc5-$VERSION/ (gitignored) and print its path.
# VERSION defaults to 1.2.1 (requested); the symcc 0.7.0 README names 1.3.1.
set -euo pipefail
VERSION=${CVC5_VERSION:-1.2.1}
here=$(cd "$(dirname "$0")" && pwd)
dir="$here/.tools/cvc5-$VERSION"
bin="$dir/bin/cvc5"
if [ ! -x "$bin" ]; then
  mkdir -p "$dir"
  zip="$dir/cvc5.zip"
  curl -fsSL -o "$zip" "https://github.com/cvc5/cvc5/releases/download/cvc5-$VERSION/cvc5-Linux-x86_64-static.zip"
  echo "sha256 $(sha256sum "$zip" | cut -d' ' -f1)  cvc5-$VERSION Linux-x86_64-static.zip" >&2
  python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$zip" "$dir/unzipped"
  mkdir -p "$dir/bin"
  cp "$(find "$dir/unzipped" -type f -path '*/bin/cvc5' | head -1)" "$bin"
  chmod +x "$bin"
  rm -rf "$zip" "$dir/unzipped"
fi
echo "$bin"
