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
AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/compat/Makefile
                 src/daemon/Makefile
		 src/lib/Makefile
                 src/client/Makefile
	         tests/Makefile
                 osx/Makefile])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([CONFIGURE_ARGS], [$ac_configure_args])

# Configure automake
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
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
if test x"$ac_cv_prog_cc_c99" = x"no"; then
  AC_MSG_FAILURE([*** C99 support is mandatory])
fi
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
AX_CFLAGS_GCC_OPTION([-fdiagnostics-color=auto])
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
AX_CFLAGS_GCC_OPTION([-fstack-protector-strong])
AX_CFLAGS_GCC_OPTION([-fno-omit-frame-pointer])
AX_CFLAGS_GCC_OPTION([-D_FORTIFY_SOURCE=2], [CPPFLAGS])
AX_CFLAGS_GCC_OPTION([-Wno-unused-parameter])
AX_CFLAGS_GCC_OPTION([-Wno-missing-field-initializers])
AX_CFLAGS_GCC_OPTION([-Wno-sign-compare]) dnl Should be fixed later
AX_LDFLAGS_OPTION([-Wl,-z,relro])
AX_LDFLAGS_OPTION([-Wl,-z,now])

# OS
lldp_CHECK_OS
lldp_CFLAGS_OS

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

# Compatibility with pkg.m4 < 0.27
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR],
         [AC_ARG_WITH([pkgconfigdir],
                      [AS_HELP_STRING([--with-pkgconfigdir],
                      [install directory for *.pc pkg-config file])],
                      [],[with_pkgconfigdir='$(libdir)/pkgconfig'])
          AC_SUBST([pkgconfigdir], [${with_pkgconfigdir}])])

#######################
### Options

# Readline
AC_ARG_WITH([readline],
  AS_HELP_STRING(
    [--with-readline],
    [Enable the use of readline-like library @<:@default=auto@:>@]),
  [],
  [with_readline=auto])
if test x"$with_readline" != x"no"; then
   AX_LIB_READLINE
   if test x"$with_readline" != x"check" -a x"$with_readline" != x"auto"; then
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
    [Enable the use of SNMP @<:@default=no@:>@]),
  [],
  [with_snmp=no])
lldp_CHECK_SNMP

# XML
AC_ARG_WITH([xml],
  AS_HELP_STRING(
    [--with-xml],
    [Enable XML output via libxml2 @<:@default=auto@:>@]),
  [],
  [with_xml=auto])
lldp_CHECK_XML2

# JSON
AC_ARG_WITH([json],
  AS_HELP_STRING(
    [--with-json],
    [Enable JSON output via janson or json-c @<:@default=auto@:>@]),
  [],
  [with_json=auto])
if test x"$with_json" = x"yes" -o x"$with_json" = x"auto"; then
   _with_json="$with_json"
   with_json=auto
   lldp_CHECK_JANSSON
   if test x"$with_json" = x"no"; then
     with_json=auto
     lldp_CHECK_JSONC
   fi
   if test x"$with_json" = x"no" -a x"$_with_json" = x"yes"; then
     AC_MSG_FAILURE([*** no JSON support found])
   fi
else
   lldp_CHECK_JANSSON
   lldp_CHECK_JSONC
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
              [$($PKG_CONFIG --variable=systemdsystemunitdir systemd 2> /dev/null)])
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
AM_CONDITIONAL(HAVE_SYSTEMDSYSTEMUNITDIR,
    [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

# sysusers
lldp_ARG_WITH([sysusersdir], [Directory for sysusers files],
              [$($PKG_CONFIG --variable=sysusersdir systemd 2> /dev/null)])
AC_SUBST([sysusersdir], [$with_sysusersdir])
AM_CONDITIONAL(HAVE_SYSUSERSDIR,
    [test -n "$with_sysusersdir" -a "x$with_sysusersdir" != xno ])

# Systemtap/DTrace
lldp_SYSTEMTAP

# Privsep settings
lldp_ARG_ENABLE([privsep], [Privilege separation], [yes])
lldp_ARG_WITH([privsep-user], [Which user to use for privilege separation], [_lldpd])
lldp_ARG_WITH([privsep-group], [Which group to use for privilege separation], [_lldpd])

# Directories
dnl On autoconf 2.69 and before, runstatedir is not configurable, let be able to use it anyway
if test "x$runstatedir" = x; then
    AC_SUBST([runstatedir], ['${localstatedir}/run'])
fi
lldp_ARG_WITH([privsep-chroot], [Which directory to use to chroot lldpd], [${runstatedir}/lldpd])
lldp_ARG_WITH([lldpd-ctl-socket], [Path to socket for communication with lldpd], [${runstatedir}/lldpd.socket])
lldp_ARG_WITH([lldpd-pid-file], [Path to lldpd PID file], [${runstatedir}/lldpd.pid])

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
AC_SUBST([LLDP_CFLAGS], [$CFLAGS])
AC_SUBST([LLDP_CPPFLAGS], [$CPPFLAGS])
AC_SUBST([LLDP_LDFLAGS], [$LDFLAGS])
CFLAGS=
CPPFLAGS=
LDFLAGS=
AM_CONDITIONAL([HAVE_CHECK], [test x"$have_check" = x"yes"])
AM_CONDITIONAL([USE_SNMP], [test x"$with_snmp" = x"yes"])
AM_CONDITIONAL([USE_XML], [test x"$with_xml" = x"yes"])
AM_CONDITIONAL([USE_JSON], [test x"$with_json" = x"json-c" || test -x"$with_json" = x"jansson"])
AM_CONDITIONAL([USE_JANSSON], [test x"$with_json" = x"jansson"])
AM_CONDITIONAL([USE_JSONC], [test x"$with_json" = x"json-c"])
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
  C Compiler.....: $CC $LLDP_CFLAGS $LLDP_CPPFLAGS
  Linker.........: $LD $LLDP_LDFLAGS $LIBS
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
  User/group.....: ${with_privsep_user}/${with_privsep_group}
  Chroot.........: ${with_privsep_chroot}
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
