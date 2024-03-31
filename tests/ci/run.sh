#!/bin/sh

set -e

LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-pie"
case "$(uname -s)" in
    Linux)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --localstatedir=/var --sysconfdir=/etc --prefix=/usr"
        [ $(uname -m) != x86_64 ] || \
            LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS --enable-sanitizers"
        ;;
    Darwin)
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS CFLAGS=-mmacosx-version-min=11.1"
        LLDPD_CONFIG_ARGS="$LLDPD_CONFIG_ARGS LDFLAGS=-mmacosx-version-min=11.1"
        MAKE_ARGS=""
        ;;
    OpenBSD)
        export AUTOCONF_VERSION=2.71
        export AUTOMAKE_VERSION=1.16
        ;;
esac

./autogen.sh
mkdir build && cd build
../configure $LLDPD_CONFIG_ARGS || {
    cat config.log
    exit 1
}
make all ${MAKE_ARGS-CFLAGS=-Werror} || make all ${MAKE_ARGS-CFLAGS=-Werror} V=1
make check ${MAKE_ARGS-CFLAGS=-Werror} || {
    [ ! -f tests/test-suite.log ] || cat tests/test-suite.log
    exit 1
}
if [ "$LLDPD_RELEASE" = "true" ]; then
    make distcheck
fi


case "$(uname -s)" in
    Darwin)
        # Create a package
        make -C osx pkg # ARCHS="x86_64 arm64"
        otool -l osx/lldpd*/usr/local/sbin/lldpd
        ;;
    Linux)
        # Integration tests
        cd ../tests/integration
        sudo $(which python3) -m pytest -n 5 -vv || \
            sudo $(which python3) -m pytest -vvv --last-failed --maxfail=5
        ;;
esac
