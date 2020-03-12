#!/bin/sh

set -e

LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-pie"
case "$(uname -s)" in
    Linux)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --localstatedir=/var --sysconfdir=/etc --prefix=/usr"
        [ $(uname -m) != x86_64 ] || \
            LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-sanitizers"
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS LDFLAGS=-fuse-ld=gold"
        ;;
    Darwin)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS CFLAGS=-mmacosx-version-min=10.9"
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS LDFLAGS=-mmacosx-version-min=10.9"
        ;;
esac

./autogen.sh
./configure $LLDPD_CONFIG_ARGS || {
    cat config.log
    exit 1
}
make all ${MAKE_ARGS-CFLAGS=-Werror} || make all ${MAKE_ARGS-CFLAGS=-Werror} V=1
make check ${MAKE_ARGS-CFLAGS=-Werror} || {
    [ ! -f tests/test-suite.log ] || cat tests/test-suite.log
    exit 1
}
make distcheck

case "$(uname -s)" in
    Darwin)
        # Create a package
        make -C osx pkg
        otool -l osx/lldpd*/usr/local/sbin/lldpd
        mkdir upload
        mv *.pkg upload
        ;;
    Linux)
        # Integration tests
        cd tests/integration
        sudo $(which python3) -m pytest -n 5 -vv --boxed || \
            sudo $(which python3) -m pytest -vvv --last-failed --maxfail=5
        ;;
esac
