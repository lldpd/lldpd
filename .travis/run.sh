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
./configure $LLDPD_CONFIG_ARGS --enable-pie --localstatedir=/var --sysconfdir=/etc --prefix=/usr CFLAGS="-O0 -g"

if [ x"${RUN_COVERITY}" = x"1" ]; then
    # Coverity build
    [ x"${COVERITY_SCAN_TOKEN}" = x"" ] || \
        curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh | \
        COVERITY_SCAN_PROJECT_NAME="$TRAVIS_REPO_SLUG" \
        COVERITY_SCAN_BUILD_COMMAND="make CFLAGS=-Werror" \
        bash
else
    # Regular build
    make all check CFLAGS=-Werror
    make distcheck
    if [ x"$TRAVIS_OS_NAME" = x"osx" ]; then
        make -C osx pkg
    fi
    if [ x"$TRAVIS_OS_NAME" = x"linux" ]; then
        cd tests/integration
        sudo $(which python3) -m pytest -n 5 -vvv -x --boxed
    fi
fi
