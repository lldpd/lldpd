#!/bin/sh

set -e

case "$(uname -s)" in
    Darwin)
        brew update
        # Workaround a bug in Travis:
        # https://github.com/Homebrew/legacy-homebrew/issues/43874
        brew uninstall libtool
        brew install libtool jansson libxml2 check
        ;;
    Linux)
        # We prefer gcc-5
        [ $CC != gcc ] || \
            sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check libc6-dbg libevent-dbg libseccomp-dev \
            libpcap-dev
        [ $CC != gcc ] || \
            sudo apt-get -qqy install gcc-5
        # For integration tests
        sudo -H $(which python3) -m pip install -r tests/integration/requirements.txt
        ;;
esac
