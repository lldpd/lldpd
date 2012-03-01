#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#######################
### Base configuration

# Configure autoconf
AC_PREREQ([2.64])

dnl Use something like this if you need to patch autoconf files and
dnl regenerate configure outside upstream git tree:
dnl AC_INIT([lldpd], [0.5.7], [bernat@luffy.cx])
AC_INIT([lldpd],
        [m4_esyscmd_s([git describe --tags --always 2> /dev/null || date +%F])],
        [bernat@luffy.cx])

AC_CONFIG_SRCDIR([src/lldpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile tests/Makefile])
AC_CONFIG_MACRO_DIR([m4])

# Configure automake
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

# Configure libtool
#LT_PREREQ([2.2])
LT_INIT

#######################
### Checks

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Check some compiler flags
AX_CFLAGS_GCC_OPTION([-fdiagnostics-show-option])
AX_CFLAGS_GCC_OPTION([-std=gnu99])
AX_CFLAGS_GCC_OPTION([-pipe])
AX_CFLAGS_GCC_OPTION([-Wall])
AX_CFLAGS_GCC_OPTION([-W])
AX_CFLAGS_GCC_OPTION([-Wextra])
AX_CFLAGS_GCC_OPTION([-Wformat])
AX_CFLAGS_GCC_OPTION([-Wformat-security])
AX_CFLAGS_GCC_OPTION([-Wcast-align])
AX_CFLAGS_GCC_OPTION([-Winline])
AX_CFLAGS_GCC_OPTION([-fstack-protector])
AX_CFLAGS_GCC_OPTION([-D_FORTIFY_SOURCE=2])
AX_CFLAGS_GCC_OPTION([-Wno-unused-parameter])
AX_CFLAGS_GCC_OPTION([-Wno-sign-compare]) dnl Should be fixed later
AX_LDFLAGS_OPTION([-Wl,-z,relro])
AX_LDFLAGS_OPTION([-Wl,-z,now])

AC_CACHE_SAVE

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  fcntl.h \
  malloc.h \
  netdb.h \
  netinet/in.h \
  stdlib.h \
  string.h \
  sys/ioctl.h \
  sys/param.h \
  sys/socket.h \
  sys/time.h \
  sys/queue.h \
  syslog.h \
  unistd.h \
  net/if.h \
  linux/sockios.h \
],,AC_MSG_ERROR([Required header missing.]))
AC_CHECK_HEADERS([ \
  linux/wireless.h \
  linux/if_bonding.h \
  linux/if_bridge.h \
  linux/if_packet.h \
],,AC_MSG_ERROR([Required header missing.]),[
@%:@include <arpa/inet.h>
@%:@include <linux/if.h>
])
AC_CHECK_HEADERS([ \
  linux/filter.h \
],,AC_MSG_ERROR([Required header missing.]),[
@%:@include <linux/types.h>
])
AC_CHECK_HEADERS([ \
  linux/if_vlan.h \
],,AC_MSG_ERROR([You should get linux/if_vlan.h from some other place. See README file.]),[
@%:@include <arpa/inet.h>
@%:@include <linux/if.h>
])

AC_CACHE_SAVE

# Check for sys/queue.h completeness, missing bits will be in compat.h
AC_CHECK_DECLS([
TAILQ_FIRST,
TAILQ_NEXT,
TAILQ_FOREACH,
TAILQ_EMPTY,
SLIST_HEAD,
SLIST_ENTRY,
SLIST_INIT,
SLIST_INSERT_HEAD,
SLIST_FIRST,
SLIST_NEXT,
SLIST_REMOVE_HEAD,
SLIST_EMPTY],[],[],[[@%:@include <sys/queue.h>]])

# On some systems, some ioctl are not declared
AC_CHECK_DECLS([
SIOCGIFVLAN,
SIOCBONDINFOQUERY,
SIOCBONDSLAVEINFOQUERY],[],[],[[@%:@include <linux/sockios.h>]])
AC_CHECK_MEMBERS([ifslave.slave_name, ifbond.num_slaves], [],
   [AC_MSG_ERROR([linux/if_bonding.h is incomplete. See README file.])],
   [
@%:@include <arpa/inet.h>
@%:@include <linux/if.h>
@%:@include <linux/if_bonding.h>
])

# Do we have PACKET_ORIGDEV (it can be present at runtime, put it in compat.h)
AC_CHECK_DECLS([PACKET_ORIGDEV],[],[],[[@%:@include <linux/if_packet.h>]])

# Check for ethtool stuff
lldp_CHECK_HEADER_ETHTOOL
AC_CHECK_DECLS([
ADVERTISED_2500baseX_Full,
ADVERTISED_Pause,
ADVERTISED_Asym_Pause,
ADVERTISED_10000baseT_Full,
SPEED_10000],[],[],[[@%:@include <linux/ethtool.h>]])

# Check for ETHERTYPE_VLAN, put it in compat.h if not defined
AC_CHECK_DECLS([ETHERTYPE_VLAN],[],[],[[@%:@include <net/ethernet.h>]])

# Check some stuff in linux/if_vlan.h
AC_CHECK_DECLS([GET_VLAN_REALDEV_NAME_CMD,GET_VLAN_VID_CMD],[],[],
               [[@%:@include <linux/if_vlan.h>]])

AC_CACHE_SAVE

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
lldp_CHECK___PROGNAME
lldp_CHECK_FD_SETSIZE

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ \
   atexit \
   gethostbyname \
   inet_ntoa memset \
   regcomp \
   select \
   setenv \
   socket \
   strchr \
   strdup \
   strerror \
   strndup \
   tzset \
   uname \
],,[AC_MSG_ERROR(Required function not found.)])

AC_REPLACE_FUNCS([strlcpy])
AC_REPLACE_FUNCS([getifaddrs])

AC_CACHE_SAVE

## Unit tests wich check
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])

#######################
### Options

# SNMP
AC_ARG_WITH([snmp],
  AS_HELP_STRING(
    [--with-snmp],
    [Enable the use of SNMP @<:@default=no@:>@]
  ))
if test x"$with_snmp" = x"yes"; then
   lldp_CHECK_SNMP
fi

AC_ARG_WITH([xml],
  AC_HELP_STRING(
    [--with-xml],
    [Enable XML output via libxml2 @<:@default=no@:>@]
  ))
if test x"$with_xml" = x"yes"; then
   lldp_CHECK_XML2
fi

# Privsep settings
lldp_ARG_WITH([privsep-user], [Which user to use for privilege separation], [_lldpd])
lldp_ARG_WITH([privsep-group], [Which group to use for privilege separation], [_lldpd])
lldp_ARG_WITH([privsep-chroot], [Which directory to use to chroot lldpd], [/var/run/lldpd])

# CDP/FDP/EDP/SONMP
lldp_ARG_ENABLE([cdp], [Cisco Discovery Protocol], [yes])
lldp_ARG_ENABLE([fdp], [Foundry Discovery Protocol], [yes])
lldp_ARG_ENABLE([edp], [Extreme Discovery Protocol], [yes])
lldp_ARG_ENABLE([sonmp], [SynOptics Network Management Protocol], [yes])

# LLDPMED/Dot1/Dot3
lldp_ARG_ENABLE([lldpmed], [LLDP-MED extension], [yes])
lldp_ARG_ENABLE([dot1], [Dot1 extension (VLAN stuff)], [yes])
lldp_ARG_ENABLE([dot3], [Dot3 extension (PHY stuff)], [yes])

#######################
# Output results
AM_CONDITIONAL([HAVE_CHECK], [test x"$have_check" = x"yes"])
AM_CONDITIONAL([USE_SNMP], [test x"$with_snmp" = x"yes"])
AM_CONDITIONAL([USE_XML], [test x"$with_xml" = x"yes"])
AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
 Optional features:
  SNMP support...: ${with_snmp-no}
  CDP............: $enable_cdp
  FDP............: $enable_fdp
  EDP............: $enable_edp
  SONMP..........: $enable_sonmp
  LLDPMED........: $enable_lldpmed
  DOT1...........: $enable_dot1
  DOT3...........: $enable_dot3
  XML output.....: ${with_xml-no}
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
