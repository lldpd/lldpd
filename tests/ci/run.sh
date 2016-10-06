#!/bin/sh

set -e

[ $CC != gcc ] || CC=gcc-5
[ $(uname -s) != Linux ] || LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-sanitizers"

./autogen.sh
./configure $LLDPD_CONFIG_ARGS \
            --enable-pie \
            --localstatedir=/var --sysconfdir=/etc --prefix=/usr \
            CFLAGS="-O1 -g" LDFLAGS="-fuse-ld=gold" || {
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
