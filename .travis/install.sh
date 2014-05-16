#!/bin/sh

# Setup dev environment for Travis

set -e

if [ x"${RUN_COVERITY}" = x"1" ] && \
    [ x"${COVERITY_SCAN_BRANCH_PATTERN}" != x"${TRAVIS_BRANCH}" ]; then
    exit 0
fi

case "$(uname -s)" in
    Darwin)
        # OS X
        brew update
        brew install \
            pkg-config autoconf automake libtool \
            readline libevent jansson libxml2 check
        brew install net-snmp --devel
        ;;
    *)
        # Linux
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev libjansson-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check
        ;;
esac
