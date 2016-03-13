#!/bin/sh

# Setup dev environment for Travis

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

case "$(uname -s)" in
    Darwin)
        # OS X
        brew update
        brew install libevent jansson libxml2 check net-snmp
        ;;
    *)
        # Linux
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev libjansson-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check
        python3 -V && \
            python3 -m pip -V && \
            sudo -H $(which python3) -m pip install -r tests/integration/requirements.txt
        ;;
esac
