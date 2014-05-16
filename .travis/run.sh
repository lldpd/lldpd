#!/bin/sh

set -e

./autogen.sh
./configure $LLDPD_CONFIG_ARGS

# When running coverity, do not run make
[ "${COVERITY_SCAN_BRANCH}" != 1 ] || exit 0

LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --with-systemdsystemunitdir=no"
LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --with-launchddaemonsdir=no"
make distcheck DISTCHECK_CONFIGURE_FLAGS="$LLDPD_CONFIG_ARGS"
