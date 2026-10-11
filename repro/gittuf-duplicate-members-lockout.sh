#!/usr/bin/env bash
# Minimal reproducer: gittuf accepts a rule whose threshold exceeds its number
# of DISTINCT principals when a principal is listed twice, and that rule can
# then never be satisfied (the protected namespace is locked).
#
# Requires: git >= 2.34, ssh-keygen, and either
#   - the pinned gittuf checkout from oracle/setup.sh (default
#     <repo>/.gittuf-oracle, or $GITTUF); the CLI is built from it with Go, or
#   - GITTUF_BIN=/path/to/gittuf, a prebuilt gittuf CLI (standalone use).
# Tested against gittuf 0b0278ec1d484e59d2107c38f38c059908a33856.
#
# Cause (at that commit): internal/tuf/v02/targets.go AddRule checks
#   len(authorizedPrincipalIDs) < threshold
# on the list as given, then stores set.NewSetFromItems(authorizedPrincipalIDs...),
# which deduplicates. Verification counts distinct principals.
set -euo pipefail
SHA=0b0278ec1d484e59d2107c38f38c059908a33856
if [ -z "${GITTUF_BIN:-}" ]; then
  src=${GITTUF:-$(cd "$(dirname "$0")/.." && pwd)/.gittuf-oracle}
  head=$(git -C "$src" rev-parse HEAD 2>/dev/null) || {
    echo "no gittuf checkout at $src; run oracle/setup.sh (or set GITTUF_BIN to a gittuf binary)" >&2; exit 1; }
  [ "$head" = "$SHA" ] || { echo "$src is at $head, expected $SHA; run oracle/setup.sh" >&2; exit 1; }
  GITTUF_BIN=$(mktemp -d)/gittuf
  (cd "$src" && go build -o "$GITTUF_BIN" .)
fi
GITTUF=$GITTUF_BIN
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

work=$(mktemp -d)
cd "$work"
mkdir keys
for k in root alice; do ssh-keygen -q -t ed25519 -N "" -C "$k" -f "keys/$k"; done
ALICE_ID=$(ssh-keygen -lf keys/alice.pub | awk '{print $2}')   # gittuf's ID for an SSH key

git init -q -b main repo && cd repo
git config user.name repro && git config user.email repro@example.invalid
git config gpg.format ssh && git config user.signingkey ../keys/root
git commit -q --allow-empty -m initial

"$GITTUF" trust init -k ../keys/root
"$GITTUF" trust add-policy-key -k ../keys/root --policy-key ../keys/root.pub
"$GITTUF" policy init -k ../keys/root --policy-name targets
"$GITTUF" policy add-key -k ../keys/root --public-key ../keys/alice.pub

echo "== control: alice listed once, threshold 2 (expected: rejected)"
if "$GITTUF" policy add-rule -k ../keys/root --rule-name protect-main \
     --rule-pattern git:refs/heads/main --authorize "$ALICE_ID" --threshold 2; then
  echo "UNEXPECTED: accepted"; exit 1
fi

echo "== bug: alice listed twice, threshold 2 (accepted)"
"$GITTUF" policy add-rule -k ../keys/root --rule-name protect-main \
  --rule-pattern git:refs/heads/main --authorize "$ALICE_ID" --authorize "$ALICE_ID" --threshold 2
"$GITTUF" policy stage --local-only
"$GITTUF" policy apply --local-only
"$GITTUF" policy list-rules

echo "== alice (the only authorized principal) pushes to main"
git config user.signingkey ../keys/alice
git commit -q --allow-empty -m "change by alice"
"$GITTUF" rsl record main --local-only
if "$GITTUF" verify-ref main --latest-only; then
  echo "RESULT: verification passed (bug not reproduced)"
else
  echo "RESULT: verification failed: the rule stored as 2-of-{alice} can never be met; main is locked"
fi
echo "(workdir: $work)"
