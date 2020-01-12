#!/bin/sh

set -e

case "$(uname -s)" in
    Darwin)
        brew update
        brew install libtool libxml2 check
        ;;
    Linux)
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check libc6-dbg libseccomp-dev \
            libpcap-dev libcap-dev \
            snmpd snmp \
            python3-pip python3-setuptools python3-wheel
        # For integration tests
        sudo -H $(which python3) -m pip install -r tests/integration/requirements.txt
        ;;
esac
