#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#######################
### Base configuration

# Configure autoconf
AC_PREREQ([2.64])

AC_INIT([lldpd],
        [m4_esyscmd_s([./get-version])],
        [https://github.com/vincentbernat/lldpd/issues],
        [lldpd],
        [http://vincentbernat.github.io/lldpd/])

AC_CONFIG_SRCDIR([src/log.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile src/compat/Makefile src/daemon/Makefile
			  src/lib/Makefile src/lib/lldpctl.pc src/client/Makefile
			  tests/Makefile])
AC_CONFIG_FILES([osx/Makefile osx/distribution.xml osx/im.bernat.lldpd.plist])
AC_CONFIG_FILES([osx/scripts/preinstall], [chmod +x osx/scripts/preinstall])
AC_CONFIG_FILES([osx/scripts/postinstall], [chmod +x osx/scripts/postinstall])
AC_CONFIG_FILES([src/daemon/lldpd.service])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([CONFIGURE_ARGS], [$ac_configure_args])

# Configure automake
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

# Automake 1.12...
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

# Configure libtool
LT_INIT

#######################
### Checks

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_EGREP
AC_PROG_AWK

# Doxygen
DX_HTML_FEATURE(ON)
DX_DOT_FEATURE(OFF)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN([lldpd], [doxygen.cfg], [doxygen])

# Check some compiler flags
AX_CFLAGS_GCC_OPTION([-fdiagnostics-show-option])
AX_CFLAGS_GCC_OPTION([-pipe])
AX_CFLAGS_GCC_OPTION([-Wall])
AX_CFLAGS_GCC_OPTION([-W])
AX_CFLAGS_GCC_OPTION([-Wextra])
AX_CFLAGS_GCC_OPTION([-Wformat])
AX_CFLAGS_GCC_OPTION([-Wformat-security])
AX_CFLAGS_GCC_OPTION([-Wfatal-errors])
AX_CFLAGS_GCC_OPTION([-Wcast-align])
AX_CFLAGS_GCC_OPTION([-Winline])
AX_CFLAGS_GCC_OPTION([-fstack-protector])
AX_CFLAGS_GCC_OPTION([-fno-omit-frame-pointer])
AX_CFLAGS_GCC_OPTION([-D_FORTIFY_SOURCE=2])
AX_CFLAGS_GCC_OPTION([-Wno-unused-parameter])
AX_CFLAGS_GCC_OPTION([-Wno-missing-field-initializers])
AX_CFLAGS_GCC_OPTION([-Wno-sign-compare]) dnl Should be fixed later
AX_LDFLAGS_OPTION([-Wl,-z,relro])
AX_LDFLAGS_OPTION([-Wl,-z,now])

# OS
lldp_CHECK_OS

# Additional OS dependents compiler flags. If they cause problem, we
# can enable them for some OS only.
AX_CFLAGS_GCC_OPTION([-D_GNU_SOURCE])    dnl GNU systems (asprintf, ...)
AX_CFLAGS_GCC_OPTION([-D__EXTENSIONS__]) dnl Solaris (CMSG_*)
AX_CFLAGS_GCC_OPTION([-D_XPG4_2])        dnl Solaris (CMSG_*)
AX_CFLAGS_GCC_OPTION([-D_XOPEN_SOURCE=500])      dnl HP-UX
AX_CFLAGS_GCC_OPTION([-D_XOPEN_SOURCE_EXTENDED]) dnl HP-UX

AC_CACHE_SAVE

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([valgrind/valgrind.h])
lldp_CHECK_STDINT

AC_CACHE_SAVE

# Checks for typedefs, structures, and compiler characteristics.
lldp_CHECK___PROGNAME
lldp_CHECK_ALIGNOF

# Checks for library functions.
AC_CONFIG_LIBOBJ_DIR([src/compat])
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_FORK
# setproctitle (maybe through libbsd)
AC_SEARCH_LIBS([setproctitle], [util bsd])
AC_REPLACE_FUNCS([setproctitle])
AC_CHECK_FUNCS([setproctitle_init])
# Other functions
AC_REPLACE_FUNCS([strlcpy
                  strnlen
                  strndup
                  fgetln
                  asprintf
                  vsyslog
                  daemon])
# Optional functions
AC_CHECK_FUNCS([setresuid setresgid])

case " $LIBS " in
     *\ -lbsd\ *)
        AC_DEFINE(HAVE_LIBBSD, 1, [Define if libbsd is used])
        ;;
esac

# Check for res_init. On OSX, res_init is a symbol in libsystem_info
# and a macro in resolv.h. We need to ensure we test with resolv.h.
m4_pushdef([AC_LANG_CALL(C)], [
  AC_LANG_PROGRAM([$1
@%:@include <resolv.h>], [return $2 ();])])
AC_SEARCH_LIBS([res_init], resolv bind,
               AC_DEFINE([HAVE_RES_INIT], 1,
               [Define to indicate that res_init() exists]))
m4_popdef([AC_LANG_CALL(C)])

AC_CACHE_SAVE

## Unit tests wich check
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])

# Libevent
lldp_CHECK_LIBEVENT

#######################
### Options

# Readline
AC_ARG_WITH([readline],
  AS_HELP_STRING(
    [--with-readline],
    [Enable the use of readline-like library @<:@default=check@:>@]),
  [],
  [with_readline=check])
if test x"$with_readline" != x"no"; then
   AX_LIB_READLINE
   if test x"$with_readline" != x"check"; then
     if test x"$ax_cv_lib_readline" = x"no"; then
       AC_MSG_FAILURE([*** no readline support found])
     fi
   fi
else
   ax_cv_lib_readline="no"
fi

# SNMP
AC_ARG_WITH([snmp],
  AS_HELP_STRING(
    [--with-snmp],
    [Enable the use of SNMP @<:@default=no@:>@]
  ))
if test x"$with_snmp" = x"yes"; then
   lldp_CHECK_SNMP
fi

# XML
AC_ARG_WITH([xml],
  AS_HELP_STRING(
    [--with-xml],
    [Enable XML output via libxml2 @<:@default=no@:>@]
  ))
if test x"$with_xml" = x"yes"; then
   lldp_CHECK_XML2
fi

# JSON
AC_ARG_WITH([json],
  AS_HELP_STRING(
    [--with-json],
    [Enable JSON output via Jansson @<:@default=no@:>@]
  ))
if test x"$with_json" = x"yes"; then
   lldp_CHECK_JANSSON
fi

# Seccomp
AC_ARG_WITH([seccomp],
  AS_HELP_STRING(
    [--with-seccomp],
    [Enable seccomp support (with libseccomp) @<:@default=no@:>@]),
  [],
  [with_seccomp=no])
lldp_CHECK_SECCOMP

# OS X launchd support
lldp_ARG_WITH([launchddaemonsdir], [Directory for launchd configuration file (OSX)],
                                   [/Library/LaunchDaemons])
AC_SUBST([launchddaemonsdir], [$with_launchddaemonsdir])
AM_CONDITIONAL(HAVE_LAUNCHDDAEMONSDIR,
    [test -n "$with_launchddaemonsdir" -a "x$with_launchddaemonsdir" != xno ])

# Systemd
lldp_ARG_WITH([systemdsystemunitdir], [Directory for systemd service files],
              [$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMDSYSTEMUNITDIR,
    [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

# Systemtap/DTrace
lldp_SYSTEMTAP

# Privsep settings
lldp_ARG_ENABLE([privsep], [Privilege separation], [yes])
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

# Oldies
lldp_ARG_ENABLE([oldies], [compatibility with Linux kernel older than 2.6.18], [no])

#######################
# Output results
AM_CONDITIONAL([HAVE_CHECK], [test x"$have_check" = x"yes"])
AM_CONDITIONAL([USE_SNMP], [test x"$with_snmp" = x"yes"])
AM_CONDITIONAL([USE_XML], [test x"$with_xml" = x"yes"])
AM_CONDITIONAL([USE_JSON], [test x"$with_json" = x"yes"])
AM_CONDITIONAL([USE_SECCOMP], [test x"$with_seccomp" = x"yes"])
AC_OUTPUT

if test x"$LIBEVENT_EMBEDDED" = x; then
   libevent=system
else
   libevent=embedded
fi

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  OS.............: $os
  Prefix.........: $prefix
  C Compiler.....: $CC $CFLAGS $CPPFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
  Libevent.......: $libevent
  Readline.......: ${ax_cv_lib_readline}
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
  JSON output....: ${with_json-no}
  Oldies support.: $enable_oldies
  seccomp........: ${with_seccomp-no}
 Privilege separation:
  Enabled........: $enable_privsep
  User/group.....: ${with_privsep_user-_lldpd}/${with_privsep_group-_lldpd}
  Chroot.........: ${with_privsep_chroot-/var/run/lldpd}
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
