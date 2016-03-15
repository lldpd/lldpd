#!/bin/sh

set -e

# Handle coverity scan
case "${RUN_COVERITY}","${TRAVIS_BRANCH}" in
    0,"${COVERITY_SCAN_BRANCH_PATTERN}")
        exit 0
        ;;
    1,"${COVERITY_SCAN_BRANCH_PATTERN}")
        [ x"${COVERITY_SCAN_TOKEN}" = x"" ] || \
            curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh | \
                COVERITY_SCAN_PROJECT_NAME="$TRAVIS_REPO_SLUG" \
                COVERITY_SCAN_BUILD_COMMAND="make CFLAGS=-Werror" \
                bash
        exit $?
        ;;
    1,*)
        exit 0
        ;;
esac

./autogen.sh
./configure $LLDPD_CONFIG_ARGS --enable-pie CFLAGS="-O0 -g"
make all check CFLAGS=-Werror
make distcheck
