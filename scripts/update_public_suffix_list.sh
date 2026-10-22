#!/usr/bin/env bash

. "$(dirname "$0")/lib.sh"

REGISTRY_DIR="TrustKit/Dependencies/domain_registry"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

curl --fail --silent --show-error --location \
    --output "${WORK_DIR}/public_suffix_list.dat" \
    https://publicsuffix.org/list/public_suffix_list.dat
VERSION="$(grep -m 1 -o 'VERSION: .*' "${WORK_DIR}/public_suffix_list.dat")" \
    || { echo "No VERSION line in the downloaded list" >&2; exit 1; }

python3 -B scripts/registry_tables_generator/registry_tables_generator.py \
    "${WORK_DIR}/public_suffix_list.dat" \
    "${WORK_DIR}/registry_tables.h" \
    "${WORK_DIR}/registry_tables_test.h"

cp -R "$REGISTRY_DIR" "${WORK_DIR}/domain_registry"
{
    echo "/* Generated from public_suffix_list.dat ${VERSION} */"
    cat "${WORK_DIR}/registry_tables.h"
} > "${WORK_DIR}/domain_registry/registry_tables_genfiles/registry_tables.h"

cat > "${WORK_DIR}/verify.c" <<'EOF'
#include <stdio.h>
#include "domain_registry.h"

struct TestEntry {
    const char *hostname;
    size_t registry_len;
    int is_exception_rule;
};

#include "registry_tables_test.h"

int main(void) {
    size_t count = sizeof(kTestTable) / sizeof(kTestTable[0]);
    size_t failures = 0;
    InitializeDomainRegistry();
    for (size_t i = 0; i < count; i++) {
        size_t actual = GetRegistryLength(kTestTable[i].hostname);
        if (actual != kTestTable[i].registry_len) {
            fprintf(stderr, "%s: expected registry length %zu, got %zu\n",
                    kTestTable[i].hostname, kTestTable[i].registry_len, actual);
            failures++;
        }
    }
    printf("Verified %zu rules, %zu failures\n", count, failures);
    return failures == 0 ? 0 : 1;
}
EOF
clang -Wall -Werror \
    -I "${WORK_DIR}/domain_registry" \
    -o "${WORK_DIR}/verify" \
    "${WORK_DIR}/verify.c" "${WORK_DIR}"/domain_registry/private/*.c
"${WORK_DIR}/verify"

cp "${WORK_DIR}/domain_registry/registry_tables_genfiles/registry_tables.h" \
    "${REGISTRY_DIR}/registry_tables_genfiles/registry_tables.h"
echo "Updated ${REGISTRY_DIR}/registry_tables_genfiles/registry_tables.h to ${VERSION}"
