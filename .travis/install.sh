#!/bin/sh

set -e

case "$(uname -s)" in
    Darwin)
        brew update
        brew install \
            pkg-config autoconf automake libtool \
            readline libevent net-snmp jansson libxml2 check
        ;;
    *)
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev libjansson-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check
        ;;
esac
