#!/usr/bin/env bash
# One command for both SMT proofs:  smt/run.sh
#  1. compile smt/docs/*.json with the Go compiler (p1_*: gittuf mode, p2_*: strict mode)
#  2. fetch cvc5 1.2.1 if needed (smt/fetch-cvc5.sh)
#  3. run the queries (cargo run --release)
# Needs Go, and Rust >= 1.89 (cedar-policy-symcc 0.7.0's MSRV). Set CARGO to a
# specific cargo binary if the one on PATH is older.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out="$here/target/compiled"
rm -rf "$out" && mkdir -p "$out"
for doc in "$here"/docs/*.json; do
  name=$(basename "$doc" .json)
  mode=gittuf; [[ $name == p2_* ]] && mode=strict
  (cd "$here/../go" && go run ./cmd/gcedar compile -mode "$mode" -out "$out/$name" "$doc")
done
export CVC5=${CVC5:-$("$here/fetch-cvc5.sh")}
"$CVC5" --version | head -1
cd "$here"
# cargo runs the rustc on PATH; with CARGO set, use the rustc next to it.
if [ -n "${CARGO:-}" ] && [ -x "$(dirname "$CARGO")/rustc" ]; then
  export RUSTC=${RUSTC:-$(dirname "$CARGO")/rustc}
fi
"${CARGO:-cargo}" run --quiet --release -- "$out"
