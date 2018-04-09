#!/bin/sh

set -e

[ $CC != gcc ] || CC=gcc-5
LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-pie"
case "$(uname -s)" in
    Linux)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --localstatedir=/var --sysconfdir=/etc --prefix=/usr"
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
make all check ${MAKE_ARGS-CFLAGS=-Werror}
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
