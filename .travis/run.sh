#!/bin/sh

set -e

./autogen.sh
./configure $LLDPD_CONFIG_ARGS
make distcheck DISTCHECK_CONFIGURE_FLAGS="$LLDPD_CONFIG_ARGS"
sudo make install
