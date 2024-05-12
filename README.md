# lldpd: implementation of IEEE 802.1ab (LLDP)

![Build Status](https://github.com/lldpd/lldpd/workflows/CI/badge.svg)

  https://lldpd.github.io/

## Features

LLDP (Link Layer Discovery Protocol) is an industry standard protocol
designed to supplant proprietary Link-Layer protocols such as
Extreme's EDP (Extreme Discovery Protocol) and CDP (Cisco Discovery
Protocol). The goal of LLDP is to provide an inter-vendor compatible
mechanism to deliver Link-Layer notifications to adjacent network
devices.

lldpd implements both reception and sending. It also implements an
SNMP subagent for net-snmp to get local and remote LLDP
information. The LLDP-MIB is partially implemented but the most useful
tables are here. lldpd also partially implements LLDP-MED.

lldpd supports bridge, vlan and bonding.

The following OS are supported:

 * FreeBSD
 * GNU/Linux
 * macOS
 * NetBSD
 * OpenBSD
 * Solaris

Windows is not supported but you can use
[WinLLDPService](https://github.com/raspi/WinLLDPService/) as a
transmit-only agent.

## Installation

For general instructions [prefer the
website](https://lldpd.github.io/installation.html),
including building from released tarballs.

To compile lldpd from Git, use the following commands:

```sh
./autogen.sh
./configure
make
sudo make install
```

lldpd uses privilege separation to increase its security. Two
processes, one running as root and doing minimal stuff and the other
running as an unprivileged user into a chroot doing most of the stuff,
are cooperating. You need to create a user called `_lldpd` in a group
`_lldpd` (this can be change with `./configure`). You also need to
create an empty directory `/usr/local/var/run/lldpd` (it needs to be
owned by root, not `_lldpd`!). If you get fuzzy timestamps from
syslog, copy `/etc/locatime` into the chroot.

`lldpcli` lets one query information collected through the command
line. If you don't want to run it as root, just install it setuid or
setgid `_lldpd`.

## Installation (Docker)

You can use Docker to run `lldpd`:

```sh
docker run --rm --net=host --uts=host \
           -v /etc/os-release:/etc/os-release \
           --cap-add=NET_RAW --cap-add=NET_ADMIN \
           --name lldpd \
           ghcr.io/lldpd/lldpd:latest
```

In place of `latest` which provides you with the latest stable
version, you may use `1`, `1.0`, `1.0.12` to match specific versions,
or `master` to get the development version.

To execute `lldpcli`, use:

```sh
docker exec lldpd lldpcli show neighbors
```

Or to get the command-line:

```sh
docker exec -it lldpd lldpcli
```

## Installation (macOS)

The same procedure as above applies for macOS. However, there are
simpler alternatives:

 1. Use [Homebrew](https://brew.sh):
```sh
brew install lldpd
# Or, for the latest version:
brew install https://raw.github.com/lldpd/lldpd/master/osx/lldpd.rb
```
 2. Build an macOS installer package which should work on the same
    version of macOS (it is important to use a separate build
    directory):
```sh
mkdir build && cd build
../configure --prefix=/usr/local --localstatedir=/var --sysconfdir=/private/etc --with-embedded-libevent \
   --without-snmp
make -C osx pkg
```
If you want to compile for an older version of OS X, you need
commands like:
```sh
mkdir build && cd build
../configure --prefix=/usr/local --localstatedir=/var --sysconfdir=/private/etc --with-embedded-libevent \
   --without-snmp \
   CFLAGS="-mmacosx-version-min=11.1" \
   LDFLAGS="-mmacosx-version-min=11.1"
make -C osx pkg
```
You can check with `otool -l` that you got what you expected in
term of supported versions. If you are running on ARM64, you can
configure a binary supporting both architectures by adding
`ARCHS="arm64 x86_64"` to the arguments of the `make` command.

If you don't follow the above procedures, you will have to create the
user/group `_lldpd`. Have a look at how this is done in
`osx/scripts/postinstall`.

## Installation (Android)

1. Don't clone the repo or download the master branch from GitHub. Instead, download the official release from the website [https://lldpd.github.io/](https://lldpd.github.io/installation.html#install-from-source). Unpack into a working directory.

2. Download the [Android NDK](https://developer.android.com/ndk/downloads#stable-downloads) (version 22 or later). Unpack into a working directory next to the `lldpd` directory.

3. Install `automake`, `libtool`, and `pkg-config`. (`sudo apt-get install automake libtool pkg-config`)

4. In the root of the `lldpd` directory, make a `compile.sh` file containing this script:

```sh
export TOOLCHAIN=$PWD/android-ndk/toolchains/llvm/prebuilt/linux-x86_64
export TARGET=armv7a-linux-androideabi
export API=30
# DO NOT TOUCH BELOW
export AR=$TOOLCHAIN/bin/llvm-ar
export CC=$TOOLCHAIN/bin/$TARGET$API-clang
export CXX=$TOOLCHAIN/bin/$TARGET$API-clang++
export LD=$TOOLCHAIN/bin/ld
export RANLIB=$TOOLCHAIN/bin/llvm-ranlib
export STRIP=$TOOLCHAIN/bin/llvm-strip
export AS=$CC
./autogen.sh
mkdir -p build && cd build
../configure \
    --host=$TARGET \
    --with-sysroot=$TOOLCHAIN/sysroot \
    --prefix=/system \
    --sbindir=/system/bin \
    --runstatedir=/data/data/lldpd \
    --with-privsep-user=root \
    --with-privsep-group=root \
    PKG_CONFIG=/bin/false
make
make install DESTDIR=$PWD/install
```

5. In the **Android NDK** directory, locate the `toolchains/llvm/prebuilt/linux-x86_64` directory and change the `TOOLCHAIN` variable of the above script to match the path where the `linux-x86_64` directory resides.

```sh
export TOOLCHAIN=$PWD/android-ndk-r22b-linux-x86_64/android-ndk-r22b/toolchains/llvm/prebuilt/linux-x86_64
```

6. Determine the CPU architecture target (`adb shell getprop ro.product.cpu.abi`). Change the `TARGET` variable in the above script to match the target architecture. The target name will not exactly match the output of the `adb` command as there will be a trailing suffix to the target name, so look in the `linux-x86_64/bin` directory for the `clang` file that starts with the CPU architecture target. Don't include the API version in the target name.
```sh
$ adb shell getprop ro.product.cpu.abi
armeabi-v7a
```
```sh
linux-x86_64/bin$ ls *-clang
aarch64-linux-android21-clang     armv7a-linux-androideabi23-clang  i686-linux-android26-clang
aarch64-linux-android22-clang     armv7a-linux-androideabi24-clang  i686-linux-android27-clang
aarch64-linux-android23-clang     armv7a-linux-androideabi26-clang  i686-linux-android28-clang
aarch64-linux-android24-clang     armv7a-linux-androideabi27-clang  i686-linux-android29-clang
aarch64-linux-android26-clang     armv7a-linux-androideabi28-clang  i686-linux-android30-clang
aarch64-linux-android27-clang     armv7a-linux-androideabi29-clang  x86_64-linux-android21-clang
aarch64-linux-android28-clang     armv7a-linux-androideabi30-clang  x86_64-linux-android22-clang
aarch64-linux-android29-clang     i686-linux-android16-clang        x86_64-linux-android23-clang
aarch64-linux-android30-clang     i686-linux-android17-clang        x86_64-linux-android24-clang
armv7a-linux-androideabi16-clang  i686-linux-android18-clang        x86_64-linux-android26-clang
armv7a-linux-androideabi17-clang  i686-linux-android19-clang        x86_64-linux-android27-clang
armv7a-linux-androideabi18-clang  i686-linux-android21-clang        x86_64-linux-android28-clang
armv7a-linux-androideabi19-clang  i686-linux-android22-clang        x86_64-linux-android29-clang
armv7a-linux-androideabi21-clang  i686-linux-android23-clang        x86_64-linux-android30-clang
armv7a-linux-androideabi22-clang  i686-linux-android24-clang
```
```sh
export TARGET=armv7a-linux-androideabi
```

7. Set the `API` variable in the script above to your target API version. Check in the same `linux-x86_64/bin` to ensure the API you are targeting has a supported `clang` file for that CPU architecture and version. As of this writing, there is support for API `21-30` included for all architectures and some CPU architectures supported back to version `16`.
```sh
export API=30
```

8. Run the compile script (`./compile.sh`).

9. Copy the `./bin/*` and `./lib/*.so` files from `lldpd/build/install/system` to the target system (`./bin/*` to `/system/bin`, `./lib/*.so` to `/system/lib64`):
```sh
# Push files to target
cd build/install/system
adb shell mkdir -p /sdcard/Download/lldpd/bin
adb push bin/lldpcli /sdcard/Download/lldpd/bin/lldpcli
adb push bin/lldpd /sdcard/Download/lldpd/bin/lldpd
adb shell mkdir -p /sdcard/Download/lldpd/lib64
adb push lib/liblldpctl.so /sdcard/Download/lldpd/lib64/liblldpctl.so

# Enter target shell and move files
adb shell

# Run as root for all commands
su
# Make /system writeable
mount -o rw,remount /system
mv /sdcard/Download/lldpd/bin/lldpcli /system/bin/lldpcli
chmod 755 /system/bin/lldpcli
chown root:shell /system/bin/lldpcli
mv /sdcard/Download/lldpd/bin/lldpd /system/bin/lldpd
chmod 755 /system/bin/lldpd
chown root:shell /system/bin/lldpd
chmod 755 /system/bin/lldpctl
chown root:shell /system/bin/lldpctl
mv /sdcard/Download/lldpd/lib64/liblldpctl.so /system/lib64/liblldpctl.so
chmod 644 /system/lib64/liblldpctl.so
chown root:root /system/lib64/liblldpctl.so
# Make /system readonly again
mount -o ro,remount /system
# Might not be necessary on some systems
mkdir /data/data/lldpd
chmod 700 /data/data/lldpd
chown shell:shell /data/data/lldpd
# Clean up
rm -rf /sdcard/Download/lldpd
```

## Usage

lldpd also implements CDP (Cisco Discovery Protocol), FDP (Foundry
Discovery Protocol), SONMP (Nortel Discovery Protocol) and EDP
(Extreme Discovery Protocol). However, recent versions of IOS should
support LLDP and most Extreme stuff support LLDP. When a EDP, CDP or
SONMP frame is received on a given interface, lldpd starts sending
EDP, CDP, FDP or SONMP frame on this interface. Informations collected
through EDP/CDP/FDP/SONMP are integrated with other informations and
can be queried with `lldpcli` or through SNMP.

More information:
 * http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol
 * http://standards.ieee.org/getieee802/download/802.1AB-2005.pdf
 * https://gitlab.com/wireshark/wireshark/-/wikis/LinkLayerDiscoveryProtocol

## Compatibility with older kernels

If you have a kernel older than Linux 4.0, you need to compile lldpd with
`--enable-oldies` to enable some compatibility functions: otherwise, lldpd will
only rely on Netlink to receive wireless, bridge, bond and VLAN information.

For bonding, you need 2.6.24 (in previous version, PACKET_ORIGDEV
affected only non multicast packets). See:

 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=80feaacb8a6400a9540a961b6743c69a5896b937
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=8032b46489e50ef8f3992159abd0349b5b8e476c

Otherwise, a packet received on a bond will be affected to all
interfaces of the bond. In this case, lldpd will affect a received
randomly to one of the interface (so a neighbor may be affected to the
wrong interface).

On 2.6.27, we are able to receive packets on real interface for enslaved
devices. This allows one to get neighbor information on active/backup
bonds. Without the 2.6.27, lldpd won't receive any information on
inactive slaves. Here are the patchs (thanks to Joe Eykholt):

 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=0d7a3681232f545c6a59f77e60f7667673ef0e93
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=cc9bd5cebc0825e0fabc0186ab85806a0891104f
 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=f982307f22db96201e41540295f24e8dcc10c78f

On FreeBSD, only a recent 9 kernel (9.1 or more recent) will allow to
send LLDP frames on enslaved devices. See this bug report for more
information:

 * http://www.freebsd.org/cgi/query-pr.cgi?pr=138620

Some devices (notably Cisco IOS) send frames tagged with the native
VLAN while they should send them untagged. If your network card does
not support accelerated VLAN, you will receive those frames as long as
the corresponding interface exists (see below). However, if your
network card handles VLAN encapsulation/decapsulation (check with
`ethtool -k`), you need a recent kernel to be able to receive those
frames without listening on all available VLAN. Starting from Linux
2.6.27, lldpd is able to capture VLAN frames when VLAN acceleration is
supported by the network card. Here is the patch:

 * http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=bc1d0411b804ad190cdadabac48a10067f17b9e6

On some other versions, frames are sent on VLAN 1. If this is not the
native VLAN and if your network card support accelerated VLAN, you
need to subscribe to this VLAN as well. The Linux kernel does not
provide any interface for this. The easiest way is to create the VLAN
for each port:
```sh
ip link add link eth0 name eth0.1 type vlan id 1
ip link set up dev eth0.1
```
You can check both cases using tcpdump:
```sh
tcpdump -epni eth0 ether host 01:80:c2:00:00:0e
tcpdump -eni eth0 ether host 01:80:c2:00:00:0e
```
If the first command does not display received LLDP packets but the
second one does, LLDP packets are likely encapsulated into a VLAN:

    10:54:06.431154 f0:29:29:1d:7c:01 > 01:80:c2:00:00:0e, ethertype 802.1Q (0x8100), length 363: vlan 1, p 7, ethertype LLDP, LLDP, name SW-APP-D07.VTY, length 345

In this case, just create VLAN 1 will fix the situation. There are
other solutions:

 1. Disable VLAN acceleration on the receive side (`ethtool -K eth0
    rxvlan off`) but this may or may not work. Check if there are
    similar properties that could apply with `ethtool -k eth0`.
 2. Put the interface in promiscuous mode with `ip link set
    promisc on dev eth0`.

The last solution can be done directly by `lldpd` (on Linux only) by
using the option `configure system interface promiscuous`.

On modern networks, the performance impact should be nonexistent.

## Development

During development, you may want to execute lldpd at its current
location instead of doing `make install`. The correct way to do this is
to issue the following command:
```sh
sudo libtool execute src/daemon/lldpd -L $PWD/src/client/lldpcli -d
```
You can append any further arguments. If lldpd is unable to find
`lldpcli` it will start in an unconfigured mode and won't send or
accept LLDP frames.

There is a general test suite with `make check`. It's also possible to
run integration tests. They need [pytest](http://pytest.org/latest/)
and rely on Linux containers to be executed.

To enable code coverage, use:
```sh
../configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
             --enable-sanitizers --enable-gcov --with-snmp \
             CFLAGS="-O0 -g"
make
make check
# maybe, run integration tests
lcov --base-directory $PWD/src/lib \
     --directory src --capture --output-file gcov.info
genhtml gcov.info --output-directory coverage
```
## Fuzzing

### With [libfuzzer](https://llvm.org/docs/LibFuzzer.html)

Using address sanitizer:
```bash
export CC=clang
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
```

Using undefined-behaviour sanitizer:
```bash
export CC=clang
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
```

Using memory sanitizer:
```bash
export CC=clang
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -fsanitize=memory -fsanitize-memory-track-origins -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
```

Build and run:
```sh
./configure --disable-shared --enable-pie --enable-fuzzer=$LIB_FUZZING_ENGINE
make
cd tests/
./fuzz_cdp   fuzzing_seed_corpus/fuzz_cdp_seed_corpus
./fuzz_edp   fuzzing_seed_corpus/fuzz_edp_seed_corpus
./fuzz_lldp  fuzzing_seed_corpus/fuzz_lldp_seed_corpus
./fuzz_sonmp fuzzing_seed_corpus/fuzz_sonmp_seed_corpus
```

### With [AFL++](https://aflplus.plus)

You can use AFL++ to test some other aspects of lldpd. To test frame decoding:
```bash
export CC=afl-clang-fast
./configure --disable-shared --enable-pie
make clean check
cd tests
mkdir inputs
mv *.pcap inputs
afl-fuzz -i inputs -o outputs ./decode @@
```

## Embedding

To embed lldpd into an existing system, there are two points of entry:

 1. If your system does not use standard Linux interface, you can
    support additional interfaces by implementing the appropriate
    `struct lldpd_ops`. You can look at
    `src/daemon/interfaces-linux.c` for examples. Also, have a look at
    `interfaces_update()` which is responsible for discovering and
    registering interfaces.

 2. `lldpcli` provides a convenient way to query `lldpd`. It also
    comes with various outputs, including XML which allows one to
    parse its output for integration and automation purpose. Another
    way is to use SNMP support. A third way is to write your own
    controller using `liblldpctl.so`. Its API is described in
    `src/lib/lldpctl.h`. The custom binary protocol between
    `liblldpctl.so` and `lldpd` is not stable. Therefore, the library
    should always be shipped with `lldpd`. On the other hand, programs
    using `liblldpctl.so` can rely on the classic ABI rules.

## Troubleshooting

You can use `tcpdump` to capture the packets received and sent by
`lldpd`. To capture LLDPU, use:
```sh
tcpdump -s0 -vv -pni eth0 ether dst 01:80:c2:00:00:0e
```
Intel X710 cards may handle LLDP themselves, intercepting any incoming
packets. If you don't see anything through `tcpdump`, check if you
have such a card (with `lspci`) and stop the embedded LLDP daemon:
```sh
for f in /sys/kernel/debug/i40e/*/command; do
    echo lldp stop > $f
done
```
On FreeBSD, use `sysctl` stop the embedded LLDP daemon:
```sh
for oid in $(sysctl -Nq dev.ixl | grep fw_lldp); do
    sysctl $oid=0
done
```
This may also apply to the `ice` (Intel E8xx cards) driver. These
steps are not necessary with a recent version of `lldpd` (1.0.11+ for
Linux, 1.0.19+ for FreeBSD).

## License

lldpd is distributed under the ISC license:

 > Permission to use, copy, modify, and/or distribute this software for any
 > purpose with or without fee is hereby granted, provided that the above
 > copyright notice and this permission notice appear in all copies.
 >
 > THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 > WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 > MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 > ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 > WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 > ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 > OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

Also, `lldpcli` will be linked to GNU Readline (which is GPL licensed)
if available. To avoid this, use `--without-readline` as a configure
option.
