#!/bin/sh

set -e

if [ x"${RUN_COVERITY}" = x"1" ] && \
    [ x"${COVERITY_SCAN_BRANCH_PATTERN}" != x"${TRAVIS_BRANCH}" ]; then
    exit 0
fi

./autogen.sh
./configure $LLDPD_CONFIG_ARGS

if [ x"${RUN_COVERITY}" = x"1" ]; then
    # Coverity build
    [ x"${COVERITY_SCAN_TOKEN}" = x"" ] || \
        curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh | \
        COVERITY_SCAN_PROJECT_NAME="$TRAVIS_REPO_SLUG" \
        COVERITY_SCAN_BUILD_COMMAND="make" \
        bash
else
    # Regular build
    LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --with-systemdsystemunitdir=no"
    LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --with-launchddaemonsdir=no"
    make distcheck DISTCHECK_CONFIGURE_FLAGS="$LLDPD_CONFIG_ARGS"
fi
