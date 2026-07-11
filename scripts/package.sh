#!/bin/sh
set -eu

version=${1:?用法：scripts/package.sh <版本> <目标三元组>}
target=${2:?用法：scripts/package.sh <版本> <目标三元组>}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist="$root/dist"
archive="bash-guard-${version}-${target}"

cargo build --manifest-path "$root/Cargo.toml" --release --target "$target"
rm -rf "$dist/$archive"
mkdir -p "$dist/$archive"
cp "$root/target/$target/release/bash-guard" "$dist/$archive/"
cp "$root/LICENSE" "$root/README.md" "$dist/$archive/"
(
  cd "$dist"
  tar -czf "$archive.tar.gz" "$archive"
  shasum -a 256 "$archive.tar.gz" > "$archive.tar.gz.sha256"
)
printf '%s\n' "$dist/$archive.tar.gz"
