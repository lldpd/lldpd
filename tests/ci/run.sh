#!/bin/sh

set -e

[ $CC != gcc ] || CC=gcc-5
LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-pie"
LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --localstatedir=/var --sysconfdir=/etc --prefix=/usr"
case "$(uname -s)" in
    Linux)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-sanitizers"
        ;;
    Darwin)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS LDFLAGS=-fuse-ld=gold"
        ;;
esac

./autogen.sh
./configure $LLDPD_CONFIG_ARGS CFLAGS="-O1 -g" || {
    cat config.log
    exit 1
}
make all check CFLAGS=-Werror
make distcheck

case "$(uname -s)" in
    Darwin)
        # Create a package
        make -C osx pkg
        ;;
    Linux)
        # Integration tests
        cd tests/integration
        sudo $(which python3) -m pytest -n 5 -vv --boxed || \
            sudo $(which python3) -m pytest -vvv --last-failed --maxfail=5
        ;;
esac
