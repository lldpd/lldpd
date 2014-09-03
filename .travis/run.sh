#!/bin/sh

set -e

case "${RUN_COVERITY}","${TRAVIS_BRANCH}" in
    0,"${COVERITY_SCAN_BRANCH_PATTERN}")
        exit 0
        ;;
    1,"${COVERITY_SCAN_BRANCH_PATTERN}")
        # OK
        ;;
    1,*)
        exit 0
        ;;
esac

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
    LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --with-sysusersdir=no"
    make distcheck DISTCHECK_CONFIGURE_FLAGS="$LLDPD_CONFIG_ARGS"
fi
