#!/bin/sh

set -e

case "$(uname -s)" in
    OpenBSD)
        sudo pkg_add -I \
             automake-1.16.5 autoconf-2.71 libtool \
             libevent libxml check \
             git
        ;;
    FreeBSD)
        sudo env ASSUME_ALWAYS_YES=true pkg install \
             automake autoconf libtool pkgconf \
             libevent libxml2 check \
             git
        ;;
    NetBSD)
        sudo pkgin -y update
        sudo pkgin -y install \
             automake autoconf libtool pkg-config \
             libevent libxml2 check \
             git
        ;;
    Darwin)
        # See https://github.com/Homebrew/homebrew-cask/issues/150323
        brew update > /dev/null || true
        brew bundle --file=- <<-EOS
brew "automake"
brew "autoconf"
brew "libtool"
brew "check"
EOS
        ;;
    Linux)
        sudo apt-get -qqy update
        sudo apt-get -qqy install \
            automake autoconf libtool pkg-config \
            libsnmp-dev libxml2-dev \
            libevent-dev libreadline-dev libbsd-dev \
            check libc6-dbg libseccomp-dev \
            libpcap-dev libcap-dev systemtap-sdt-dev \
            snmpd snmp \
            python3-pip python3-setuptools python3-wheel
        # For integration tests
        sudo -H $(which python3) -m pip install -r tests/integration/requirements.txt --break-system-packages
        ;;
esac
