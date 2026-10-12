#!/usr/bin/env bash
# Set up the gittuf checkout the oracle tests run against.
#
#   oracle/setup.sh                 # clone into <repo>/.gittuf-oracle (gitignored)
#   GITTUF=/some/dir oracle/setup.sh  # clone there, and link <repo>/.gittuf-oracle to it
#
# Clones https://github.com/gittuf/gittuf, checks out the pinned commit, and
# fails unless HEAD is exactly that commit. Safe to re-run. It refuses to touch
# a directory whose origin is not upstream gittuf or that has local changes.
set -euo pipefail

SHA=0b0278ec1d484e59d2107c38f38c059908a33856
URL=https://github.com/gittuf/gittuf
repo=$(cd "$(dirname "$0")/.." && pwd)
default="$repo/.gittuf-oracle"
dir=${GITTUF:-$default}

die() { echo "setup.sh: $*" >&2; exit 1; }

if [ ! -e "$dir" ]; then
  echo "cloning $URL into $dir"
  git clone -q "$URL" "$dir"
fi
[ -d "$dir/.git" ] || die "$dir exists but is not a git checkout"

origin=$(git -C "$dir" remote get-url origin 2>/dev/null || true)
case "$origin" in
  "$URL" | "$URL.git") ;;
  *) die "$dir has origin '$origin', expected $URL; refusing to modify it" ;;
esac
[ -z "$(git -C "$dir" status --porcelain)" ] || die "$dir has local changes; refusing to modify it"

if ! git -C "$dir" cat-file -e "$SHA^{commit}" 2>/dev/null; then
  git -C "$dir" fetch -q origin
fi
git -C "$dir" checkout -q --detach "$SHA"
head=$(git -C "$dir" rev-parse HEAD)
[ "$head" = "$SHA" ] || die "HEAD of $dir is $head, expected $SHA"

# oracle/go.mod compiles against <repo>/.gittuf-oracle, so point it at $dir.
if [ "$(cd "$dir" && pwd -P)" != "$(cd "$default" 2>/dev/null && pwd -P || true)" ]; then
  if [ -e "$default" ] && [ ! -L "$default" ]; then
    die "$default exists and is not a symlink; remove it or unset GITTUF"
  fi
  ln -sfn "$(cd "$dir" && pwd -P)" "$default"
fi

echo "gittuf oracle ready: $dir at $SHA"
