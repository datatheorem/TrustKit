#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

case "${1:-}" in
    "")      CHECK=false ;;
    --check) CHECK=true ;;
    *)
        echo "usage: $0 [--check]" >&2
        exit 1
        ;;
esac

# depot_tools ships clang-format and swift-format wrappers that shadow Homebrew's.
PATH="/opt/homebrew/bin:$PATH"

# --cached still lists files deleted from the working tree but not yet staged.
existing() { while IFS= read -r -d '' f; do if [[ -e "$f" ]]; then printf '%s\0' "$f"; fi; done; }
swift_files() { git ls-files -z --cached --others --exclude-standard -- '*.swift' | existing; }
objc_files() { git ls-files -z --cached --others --exclude-standard -- '*.h' '*.m' ':!TrustKit/Dependencies' | existing; }

if ! $CHECK; then
    swift_files | xargs -0 xcrun swift format --in-place --parallel
    swiftlint --fix --quiet
    objc_files | xargs -0 clang-format -i
fi

# `swiftlint --fix` exits 0 even when violations it cannot correct remain, so always lint afterwards.
FAILED=0
swift_files | xargs -0 xcrun swift format lint --strict --parallel || FAILED=1
swiftlint lint --strict --quiet || FAILED=1
objc_files | xargs -0 clang-format --dry-run --Werror || FAILED=1
exit $FAILED
